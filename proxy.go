// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package turn contains the public API for pion/turn, a toolkit for building TURN clients and servers
package turn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/logging"
	"github.com/pion/transport/v3"
	"github.com/pion/transport/v3/stdnet"
	"github.com/pion/turn/v3/internal/offload"
	"github.com/pion/turn/v3/internal/proto"
)

// AuthGen is a callback used to generate TURN credentials.
type AuthGen func() (string, string, error)

// RelayConnGen is used to generate a PacketConns that the proxy can use to connect to the TURN server.
type RelayConnGen func(protocol, addr string) (net.PacketConn, error)

// DefaultRelayConnGen is a default relay connection generator that knows how to generate relay connections for the proxy. Set insecure to true to let the proxy accept self-signed server-side TLS certificates.
func DefaultRelayConnGen(insecure bool) RelayConnGen {
	return func(proto, addr string) (net.PacketConn, error) {
		switch proto {
		case "udp":
			t, err := net.ListenPacket("udp", "0.0.0.0:0")
			if err != nil {
				return nil, err
			}
			return t, nil
		case "tcp":
			c, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			return NewSTUNConn(c), nil
		case "tls":
			c, err := tls.Dial("tcp", addr, &tls.Config{
				MinVersion:         tls.VersionTLS10,
				InsecureSkipVerify: insecure, //nolint:gosec
			})
			if err != nil {
				return nil, err
			}
			return NewSTUNConn(c), nil
		case "dtls":
			server, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}

			conn, err := dtls.Dial("udp", server, &dtls.Config{
				InsecureSkipVerify: insecure,
			})
			if err != nil {
				return nil, err
			}
			return NewSTUNConn(conn), err
		default:
			return nil, fmt.Errorf("%w: invalid protocol", errProxyConnFail)
		}
	}
}

// ProxyConfig configures the Pion TURN proxy.
type ProxyConfig struct {
	// Listeners is a list of client listeners.
	Listeners []net.Listener

	// TURN server URI as of RFC7065.
	TURNServerURI string

	// Address:port for the peer to access.
	PeerAddr string

	// Callback for generating PacketConns that can be used by the proxy to connect to the TURN server.
	RelayConnGen RelayConnGen

	// AuthGen is a callback used to generate TURN authentication credentials.
	AuthGen AuthGen

	// LoggerFactory must be set for logging from this proxy.
	LoggerFactory logging.LoggerFactory

	Net transport.Net
}

func (c *ProxyConfig) validate() error {
	if c.Listeners == nil || len(c.Listeners) == 0 {
		return fmt.Errorf("%w: invalid listener", errInvalidProxyConfig)
	}

	if _, err := ParseURI(c.TURNServerURI); err != nil {
		return err
	}

	if _, err := net.ResolveUDPAddr("udp", c.PeerAddr); err != nil {
		return fmt.Errorf("%w: invalid peer", errInvalidProxyConfig)
	}

	if c.AuthGen == nil || c.RelayConnGen == nil {
		return fmt.Errorf("%w: invalid auth or relay-conn generator", errInvalidProxyConfig)
	}

	return nil
}

type connection struct {
	listener net.Conn       // Client connection.
	client   *Client        // TURN client associated with the connection.
	conn     net.PacketConn // Connection associated with the TURN client.
	relay    net.PacketConn // Relayed TURN connection to server.
}

// Proxy is an instance of the Pion TURN Proxy.
type Proxy struct {
	serverURI     URI
	peerAddr      net.Addr
	connTrack     map[string]*connection // Conntrack table.
	lock          *sync.Mutex            // Sync access to the conntrack state.
	relayConnGen  RelayConnGen
	authGen       AuthGen
	loggerFactory logging.LoggerFactory
	log           logging.LeveledLogger
	cancel        context.CancelFunc
	net           transport.Net
}

// NewProxy creates and starts a Pion TURN Proxy.
//
//nolint:gocognit
func NewProxy(config ProxyConfig) (*Proxy, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	if config.Net == nil {
		n, err := stdnet.NewNet()
		if err != nil {
			return nil, err
		}
		config.Net = n
	}

	turn, _ := ParseURI(config.TURNServerURI)             //nolint:errcheck
	peer, _ := net.ResolveUDPAddr("udp", config.PeerAddr) //nolint:errcheck

	p := &Proxy{
		serverURI:     turn,
		peerAddr:      peer,
		connTrack:     make(map[string]*connection),
		lock:          new(sync.Mutex),
		relayConnGen:  config.RelayConnGen,
		authGen:       config.AuthGen,
		loggerFactory: loggerFactory,
		log:           loggerFactory.NewLogger("proxy"),
		net:           config.Net,
	}

	for _, listener := range config.Listeners {
		go func(l net.Listener) {
			p.readListener(l)
		}(listener)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	//nolint:goconst
	if p.serverURI.Transport == "udp" {
		go p.offload(ctx)
	}

	return p, nil
}

// Close stops the TURN Proxy. It cleans up any associated state and
// closes all connections it is managing.
func (p *Proxy) Close() {
	for _, client := range p.connTrack {
		p.delete(client)
	}
	p.cancel()
	p.clearOffloads()
}

// ConnCount returns the number of active connections via all listeners.
func (p *Proxy) ConnCount() int {
	p.lock.Lock()
	defer p.lock.Unlock()
	return len(p.connTrack)
}

// readListener accepts new connection from a listener and runs a readLoop for each.
func (p *Proxy) readListener(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			p.log.Debugf("failed to accept: %s", err)
			return
		}

		client, err := p.allocate(conn)
		if err != nil {
			p.log.Warnf("relay setup failed for client %s: %s",
				conn.RemoteAddr().String(), err.Error())
			if err := conn.Close(); err != nil {
				p.log.Warnf("error closing client connection: %s", err)
			}
			continue
		}

		p.readLoop(client)
	}
}

// newConnection creates a new TURN allocation for the client connection.
func (p *Proxy) allocate(conn net.Conn) (*connection, error) {
	clientAddr := conn.RemoteAddr()
	p.log.Debugf("new connection from client %s:%s", clientAddr.Network(), clientAddr.String())

	client := &connection{listener: conn}

	user, passwd, err := p.authGen()
	if err != nil {
		return nil, err
	}

	// connection for the TURN client
	server := fmt.Sprintf("%s:%d", p.serverURI.Host, p.serverURI.Port)

	proto := p.serverURI.Transport
	if p.serverURI.Scheme == "turns" {
		if proto == "udp" {
			proto = "dtls"
		} else {
			proto = "tls"
		}
	}

	turnConn, err := p.relayConnGen(proto, server)
	if err != nil {
		return nil, err
	}
	client.conn = turnConn

	turnClient, err := NewClient(&ClientConfig{
		STUNServerAddr: server,
		TURNServerAddr: server,
		Conn:           turnConn,
		Username:       user,
		Password:       passwd,
		LoggerFactory:  p.loggerFactory,
		Net:            p.net,
	})
	if err != nil {
		p.delete(client)
		return nil, err
	}

	if err = turnClient.Listen(); err != nil {
		p.delete(client)
		return nil, err
	}
	client.client = turnClient

	p.log.Tracef("creating TURN allocation for %s:%s", clientAddr.Network(), clientAddr.String())
	relayConn, err := turnClient.Allocate()
	if err != nil {
		p.delete(client)
		return nil, err
	}
	client.relay = relayConn

	p.lock.Lock()
	defer p.lock.Unlock()
	p.connTrack[clientAddr.String()] = client

	p.log.Infof("new client: client=%s, relay-address=%s, peer: %s",
		clientAddr.String(), client.relay.LocalAddr().String(), p.peerAddr.String())

	return client, nil
}

// delete removes a client connection. Delete can be used any number of times and it will do the right thing.
func (p *Proxy) delete(client *connection) {
	clientAddr := client.listener.RemoteAddr()
	p.log.Debugf("closing client connection to %s", clientAddr.String())

	if client.listener != nil {
		if err := client.listener.Close(); err != nil {
			p.log.Warnf("error closing client connection for %s: %s", clientAddr.String(), err.Error())
		}
	}

	if client.relay != nil {
		if err := client.relay.Close(); err != nil {
			p.log.Warnf("error closing TURN relay connection for %s: %s",
				clientAddr.String(), err.Error())
		}
	}

	if client.client != nil {
		client.client.Close()
	}

	if client.conn != nil {
		if err := client.conn.Close(); err != nil {
			p.log.Warnf("error closing client connection: %s", err)
		}
	}

	p.lock.Lock()
	defer p.lock.Unlock()
	delete(p.connTrack, clientAddr.String())
}

// readLoop is the main event loop constaning two goroutines. One goroutine reads the client connection and forwards data to the TURN server, and toher other one does the reverse: reads the TURN client and forwards data to the client.
func (p *Proxy) readLoop(client *connection) {
	clientAddr := fmt.Sprintf("%s:%s", client.listener.RemoteAddr().Network(), client.listener.RemoteAddr().String())
	peerAddr := fmt.Sprintf("udp:%s", p.peerAddr.String())

	// read from server
	go func() {
		defer p.delete(client)

		buffer := make([]byte, defaultInboundMTU)
		for {
			n, peer, readErr := client.relay.ReadFrom(buffer[0:])
			if readErr != nil {
				if !errors.Is(readErr, net.ErrClosed) {
					p.log.Debugf("cannot read from TURN relay connection for client %s: %s",
						clientAddr, readErr.Error())
				}
				return
			}

			p.log.Tracef("forwarding packet of %d bytes from peer %s to client %s",
				n, peer, clientAddr)

			if _, writeErr := client.listener.Write(buffer[0:n]); writeErr != nil {
				p.log.Debugf("cannot write to client %s: %s",
					clientAddr, writeErr.Error())
				return
			}
		}
	}()

	// read from client
	go func() {
		defer p.delete(client)

		buffer := make([]byte, defaultInboundMTU)
		for {
			n, readErr := client.listener.Read(buffer)
			if readErr != nil {
				if !errors.Is(readErr, net.ErrClosed) {
					p.log.Debugf("cannot read from client %s: %s",
						clientAddr, readErr.Error())
				}
				return
			}

			p.log.Tracef("forwarding packet of %d bytes from client %s to peer %s",
				n, clientAddr, peerAddr)

			if _, writeErr := client.relay.WriteTo(buffer[0:n], p.peerAddr); writeErr != nil {
				p.log.Debugf("cannot write to TURN relay connection for client %s: %s",
					clientAddr, writeErr.Error())
				return
			}
		}
	}()
}

// clearOffloads removes all offload from the offload engine
func (p *Proxy) clearOffloads() {
	connections, err := offload.Engine.List()
	p.log.Debugf("offloaded connections: %+v", connections)
	if err != nil {
		p.log.Errorf("cannot list offloads: %s", err.Error())
	}
	for k, v := range connections {
		err := offload.Engine.Remove(k, v)
		if err != nil {
			p.log.Errorf("cannot remove offload %+v:%+v: %s", k, v, err.Error())
		}
	}
}

// removeObsoleteOffloads removes offloads from the offload engine that are not in use
func (p *Proxy) removeObsoleteOffloads(offloads map[offload.Connection]offload.Connection) {
	for k, v := range offloads {
		if v.RemoteAddr == nil {
			p.log.Warnf("cannot find connection in conntrack: %+v", k)
			continue
		}
		if _, ok := p.connTrack[v.RemoteAddr.String()]; !ok {
			if err := offload.Engine.Remove(k, v); err != nil {
				p.log.Errorf("cannot remove offload %+v:%+v: %s", k, v, err.Error())
			}
		}
	}
}

// addNewOffloads registers the new offloads to the offload engine
func (p *Proxy) addNewOffloads(offloads map[offload.Connection]offload.Connection) {
	for _, v := range p.connTrack {
		clientLocal := v.client.conn.LocalAddr()
		chNum, ok := v.client.relayedConn.FindChannelNumberByAddr(p.peerAddr)
		if !ok {
			p.log.Errorf("cannot find channel number for the address %s", clientLocal)
		}
		kc := offload.Connection{
			RemoteAddr: v.client.turnServerAddr,
			LocalAddr:  clientLocal,
			Protocol:   proto.ProtoUDP, // TODO check
			ChannelID:  uint32(chNum),
		}
		if _, ok := offloads[kc]; !ok {
			vc := offload.Connection{
				RemoteAddr: p.peerAddr,
				LocalAddr:  v.listener.LocalAddr(),
				Protocol:   proto.ProtoUDP,
			}
			if err := offload.Engine.Upsert(kc, vc); err != nil {
				p.log.Errorf("cannot upsert offload %+v:%+v: %s", kc, vc, err.Error())
			}
		}
	}
}

func (p *Proxy) offload(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			offloads, err := offload.Engine.List()
			if err != nil {
				p.log.Errorf("cannot list offloads: %s", err.Error())
			}
			p.removeObsoleteOffloads(offloads)
			p.addNewOffloads(offloads)
		}
	}
}
