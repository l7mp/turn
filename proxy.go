// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package turn

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/transport/v4"
	"github.com/pion/transport/v4/udp"
)

// Proxy errors.
var (
	ErrProxyClosed        = errors.New("proxy closed")
	ErrPeerLimitReached   = errors.New("peer limit reached")
	ErrInvalidPeerNetwork = errors.New("invalid peer network: only udp/tcp variants allowed")
)

// PeerManager manages peers for a proxy.
type PeerManager interface {
	AddPeer(network, address string) error
	RemovePeer(network, address string)
}

// Proxy is a proxy with peer management and close capability.
type Proxy interface {
	PeerManager
	Close() error
}

// peerManager manages a set of peer addresses with optional limit.
type peerManager struct {
	allocation Allocation
	peers      map[string]net.Addr // key: "network:address"
	limit      int                 // 0 = unlimited
	mu         sync.RWMutex
	log        logging.LeveledLogger
}

// newPeerManager creates a new peer manager with the given limit.
func newPeerManager(limit int, log logging.LeveledLogger) *peerManager {
	return &peerManager{
		peers: make(map[string]net.Addr),
		limit: limit,
		log:   log,
	}
}

// setAllocation sets the allocation for permission management.
func (pm *peerManager) setAllocation(alloc Allocation) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.allocation = alloc
}

// resolvePeerAddr resolves a peer address, only allowing udp/tcp variants.
func resolvePeerAddr(network, address string) (net.Addr, error) {
	switch network {
	case "udp", "udp4", "udp6": //nolint:goconst
		return net.ResolveUDPAddr(network, address)
	case "tcp", "tcp4", "tcp6": //nolint:goconst
		return net.ResolveTCPAddr(network, address)
	default:
		return nil, ErrInvalidPeerNetwork
	}
}

// AddPeer adds a peer to the manager and creates a TURN permission.
func (pm *peerManager) AddPeer(network, address string) error {
	addr, err := resolvePeerAddr(network, address)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s:%s", network, address)

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if already exists.
	if _, exists := pm.peers[key]; exists {
		return nil // Already added, no-op.
	}

	// Check limit.
	if pm.limit > 0 && len(pm.peers) >= pm.limit {
		return ErrPeerLimitReached
	}

	// Create permission if allocation is ready.
	if pm.allocation != nil {
		if err := pm.allocation.CreatePermission(addr); err != nil {
			return fmt.Errorf("failed to create permission for %s: %w", address, err)
		}
		pm.log.Debugf("Created permission for peer %s", addr)
	}

	pm.peers[key] = addr

	return nil
}

// RemovePeer removes a peer from the manager.
// Note: TURN permissions are NOT removed (protocol doesn't support it).
// Silently returns nil if the peer doesn't exist.
func (pm *peerManager) RemovePeer(network, address string) {
	key := fmt.Sprintf("%s:%s", network, address)
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.peers, key)
}

// hasPeer checks if a peer address is in the manager.
func (pm *peerManager) hasPeer(addr net.Addr) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	addrStr := addr.String()
	for _, peerAddr := range pm.peers {
		if peerAddr.String() == addrStr {
			return true
		}
	}

	return false
}

// getPeers returns all peer addresses in the manager.
func (pm *peerManager) getPeers() []net.Addr {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	addrs := make([]net.Addr, 0, len(pm.peers))
	for _, addr := range pm.peers {
		addrs = append(addrs, addr)
	}

	return addrs
}

// ForwardProxy forwards connections from a local listener to a peer via TURN.
// It implements the Proxy interface.
type ForwardProxy struct {
	*peerManager
	listener   net.Listener
	allocation Allocation
	network    string // network type for dialing (udp4, udp6, tcp4, tcp6)
	log        logging.LeveledLogger
	closeOnce  sync.Once
	wg         sync.WaitGroup
}

// Ensure ForwardProxy implements Proxy.
var _ Proxy = (*ForwardProxy)(nil)

// NewForwardProxy creates a forward proxy with its own TURN allocation.
// The proxy starts forwarding immediately. Call Close() to stop.
func NewForwardProxy(
	listener net.Listener,
	network string,
	cc *ClientConfig,
	lf logging.LoggerFactory,
) (*ForwardProxy, error) {
	if lf == nil {
		lf = logging.NewDefaultLoggerFactory()
	}
	log := lf.NewLogger("forward-proxy")

	// Create allocation.
	alloc, err := NewAllocation(network, cc)
	if err != nil {
		return nil, fmt.Errorf("failed to create allocation: %w", err)
	}

	log.Infof("Created allocation with relay address %s", alloc.Addr())

	fp := &ForwardProxy{
		peerManager: newPeerManager(1, log), // limit=1 for forward
		listener:    listener,
		allocation:  alloc,
		network:     network,
		log:         log,
	}
	fp.peerManager.setAllocation(alloc)

	// Start forwarding goroutine.
	fp.wg.Add(1)
	go fp.runForwardLoop()

	return fp, nil
}

// RelayAddr returns the TURN relay address for this proxy.
func (fp *ForwardProxy) RelayAddr() net.Addr {
	return fp.allocation.Addr()
}

// Close stops the proxy and releases resources.
func (fp *ForwardProxy) Close() error {
	var err error
	fp.closeOnce.Do(func() {
		// Close listener to unblock Accept.
		fp.listener.Close() //nolint:errcheck,gosec

		// Close allocation to unblock any active connections.
		if fp.allocation != nil {
			if closeErr := fp.allocation.Close(); closeErr != nil {
				err = closeErr
			}
		}

		// Wait for goroutines.
		fp.wg.Wait()
	})

	return err
}

// runForwardLoop accepts connections and forwards them to the peer.
func (fp *ForwardProxy) runForwardLoop() {
	defer fp.wg.Done()

	for {
		localConn, err := fp.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, udp.ErrClosedListener) {
				fp.log.Warnf("Accept error: %v", err)
			}

			return
		}

		fp.log.Debugf("Accepted connection from %s", localConn.RemoteAddr())

		// Get the peer address (should be exactly one for forward proxy).
		peers := fp.getPeers()
		if len(peers) == 0 {
			fp.log.Warnf("No peer configured, dropping connection from %s", localConn.RemoteAddr())
			localConn.Close() //nolint:errcheck,gosec

			continue
		}

		peerAddr := peers[0]

		// Dial to peer via TURN.
		peerConn, err := fp.allocation.Dial(fp.network, peerAddr.String())
		if err != nil {
			fp.log.Warnf("Failed to dial peer %s: %v", peerAddr, err)
			localConn.Close() //nolint:errcheck,gosec

			continue
		}

		fp.log.Debugf("Dialed peer %s via TURN", peerAddr)

		// Start bidirectional forwarding.
		fp.wg.Add(1)
		go fp.forwardData(localConn, peerConn)
	}
}

// forwardData copies data bidirectionally between two connections.
func (fp *ForwardProxy) forwardData(conn1, conn2 net.Conn) {
	defer fp.wg.Done()

	done := make(chan struct{})
	var once sync.Once
	go func() {
		io.Copy(conn2, conn1) //nolint:errcheck,gosec
		once.Do(func() { close(done) })
	}()
	go func() {
		io.Copy(conn1, conn2) //nolint:errcheck,gosec
		once.Do(func() { close(done) })
	}()

	<-done
	conn1.Close() //nolint:errcheck,gosec
	conn2.Close() //nolint:errcheck,gosec
}

// ReverseProxy forwards connections from TURN peers to a local client.
// It implements the Proxy interface.
type ReverseProxy struct {
	*peerManager
	dialer        transport.Dialer
	clientNetwork string
	clientAddr    string
	allocation    Allocation
	log           logging.LeveledLogger
	closeOnce     sync.Once
	wg            sync.WaitGroup
}

// Ensure ReverseProxy implements Proxy.
var _ Proxy = (*ReverseProxy)(nil)

// NewReverseProxy creates a reverse proxy with its own TURN allocation.
// The proxy starts accepting immediately. Call Close() to stop.
func NewReverseProxy(
	dialer transport.Dialer,
	clientNetwork, clientAddr, network string,
	cc *ClientConfig,
	lf logging.LoggerFactory,
) (*ReverseProxy, error) {
	if lf == nil {
		lf = logging.NewDefaultLoggerFactory()
	}
	log := lf.NewLogger("reverse-proxy")

	// Create allocation.
	alloc, err := NewAllocation(network, cc)
	if err != nil {
		return nil, fmt.Errorf("failed to create allocation: %w", err)
	}

	log.Infof("Created allocation with relay address %s", alloc.Addr())

	rp := &ReverseProxy{
		peerManager:   newPeerManager(0, log), // no limit for reverse
		dialer:        dialer,
		clientNetwork: clientNetwork,
		clientAddr:    clientAddr,
		allocation:    alloc,
		log:           log,
	}
	rp.peerManager.setAllocation(alloc)

	// Start acceptor goroutine.
	rp.wg.Add(1)
	go rp.runReverseLoop()

	return rp, nil
}

// RelayAddr returns the TURN relay address for this proxy.
func (rp *ReverseProxy) RelayAddr() net.Addr {
	return rp.allocation.Addr()
}

// Close stops the proxy and releases resources.
func (rp *ReverseProxy) Close() error {
	var err error
	rp.closeOnce.Do(func() {
		// Close allocation to unblock Accept.
		if rp.allocation != nil {
			if closeErr := rp.allocation.Close(); closeErr != nil {
				err = closeErr
			}
		}

		// Wait for goroutines.
		rp.wg.Wait()
	})

	return err
}

// runReverseLoop accepts connections from TURN and forwards them to the client.
func (rp *ReverseProxy) runReverseLoop() {
	defer rp.wg.Done()

	for {
		peerConn, err := rp.allocation.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, ErrAllocationClosed) {
				rp.log.Warnf("Accept error: %v", err)
			}

			return
		}

		rp.log.Debugf("Accepted connection from peer %s", peerConn.RemoteAddr())

		// Check if peer is allowed.
		if !rp.hasPeer(peerConn.RemoteAddr()) {
			rp.log.Warnf("Unknown peer %s not in peer manager, dropping connection", peerConn.RemoteAddr())
			peerConn.Close() //nolint:errcheck,gosec

			continue
		}

		// Dial to the client destination.
		localConn, err := rp.dialer.Dial(rp.clientNetwork, rp.clientAddr)
		if err != nil {
			rp.log.Warnf("Failed to dial client %s:%s: %v", rp.clientNetwork, rp.clientAddr, err)
			peerConn.Close() //nolint:errcheck,gosec

			continue
		}

		rp.log.Debugf("Connected to client %s:%s for peer %s", rp.clientNetwork, rp.clientAddr, peerConn.RemoteAddr())

		// Start bidirectional forwarding.
		rp.wg.Add(1)
		go rp.forwardData(peerConn, localConn)
	}
}

// forwardData copies data bidirectionally between two connections.
func (rp *ReverseProxy) forwardData(conn1, conn2 net.Conn) {
	defer rp.wg.Done()

	done := make(chan struct{})
	var once sync.Once
	go func() {
		io.Copy(conn2, conn1) //nolint:errcheck,gosec
		once.Do(func() { close(done) })
	}()
	go func() {
		io.Copy(conn1, conn2) //nolint:errcheck,gosec
		once.Do(func() { close(done) })
	}()

	<-done
	conn1.Close() //nolint:errcheck,gosec
	conn2.Close() //nolint:errcheck,gosec
}
