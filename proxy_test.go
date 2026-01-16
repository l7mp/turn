// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package turn

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v4/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testUsername = "testuser"
	testPassword = "testpass"
	testRealm    = "pion.ly"
)

// testTURNServer wraps a TURN server for testing.
type testTURNServer struct {
	server *Server
	addr   string
}

// newTestTURNServer creates a TURN server for testing.
func newTestTURNServer(t *testing.T, network, address string) *testTURNServer {
	t.Helper()

	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.DefaultLogLevel = logging.LogLevelWarn

	authKey := GenerateAuthKey(testUsername, testRealm, testPassword)

	ip, _, _ := net.SplitHostPort(address)
	relayGen := &RelayAddressGeneratorStatic{
		RelayAddress: net.ParseIP(ip),
		Address:      ip,
	}

	var server *Server
	var addr string

	if isUDP(network) {
		udpConn, listenErr := net.ListenPacket(network, address) //nolint:noctx
		require.NoError(t, listenErr)
		addr = udpConn.LocalAddr().String()

		var serverErr error
		server, serverErr = NewServer(ServerConfig{
			Realm:         testRealm,
			LoggerFactory: loggerFactory,
			AuthHandler: func(ra *RequestAttributes) (string, []byte, bool) {
				if ra.Username == testUsername {
					return ra.Username, authKey, true
				}

				return "", nil, false
			},
			PacketConnConfigs: []PacketConnConfig{{
				PacketConn:            udpConn,
				RelayAddressGenerator: relayGen,
			}},
		})
		require.NoError(t, serverErr)
	} else {
		tcpListener, listenErr := net.Listen(network, address) //nolint:noctx
		require.NoError(t, listenErr)
		addr = tcpListener.Addr().String()

		var serverErr error
		server, serverErr = NewServer(ServerConfig{
			Realm:         testRealm,
			LoggerFactory: loggerFactory,
			AuthHandler: func(ra *RequestAttributes) (string, []byte, bool) {
				if ra.Username == testUsername {
					return ra.Username, authKey, true
				}

				return "", nil, false
			},
			ListenerConfigs: []ListenerConfig{{
				Listener:              tcpListener,
				RelayAddressGenerator: relayGen,
			}},
		})
		require.NoError(t, serverErr)
	}

	return &testTURNServer{server: server, addr: addr}
}

func (s *testTURNServer) Close() error {
	return s.server.Close()
}

// echoServer is a simple server that echoes back data with a prefix.
type echoServer struct {
	listener net.Listener
	pconn    net.PacketConn
	prefix   string
	wg       sync.WaitGroup
}

func newEchoServer(t *testing.T, network, address string) *echoServer {
	t.Helper()

	server := &echoServer{prefix: "echo:"}

	if isUDP(network) {
		pc, err := net.ListenPacket(network, address) //nolint:noctx
		require.NoError(t, err)
		server.pconn = pc
		server.wg.Add(1)
		go server.serveUDP()
	} else {
		ln, err := net.Listen(network, address) //nolint:noctx
		require.NoError(t, err)
		server.listener = ln
		server.wg.Add(1)
		go server.serveTCP()
	}

	return server
}

func (s *echoServer) serveTCP() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close() //nolint:errcheck,gosec

			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				reply := append([]byte(s.prefix), buf[:n]...)
				if _, err = c.Write(reply); err != nil {
					return
				}
			}
		}(conn)
	}
}

func (s *echoServer) serveUDP() {
	defer s.wg.Done()

	buf := make([]byte, 4096)
	for {
		n, addr, err := s.pconn.ReadFrom(buf)
		if err != nil {
			return
		}
		reply := append([]byte(s.prefix), buf[:n]...)
		_, _ = s.pconn.WriteTo(reply, addr)
	}
}

func (s *echoServer) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}

	return s.pconn.LocalAddr()
}

func (s *echoServer) Close() {
	if s.listener != nil {
		s.listener.Close() //nolint:errcheck,gosec
	}
	if s.pconn != nil {
		s.pconn.Close() //nolint:errcheck,gosec
	}
	s.wg.Wait()
}

// createTestListener creates a TCP or UDP listener based on network type.
func createTestListener(t *testing.T, network, address string) net.Listener {
	t.Helper()

	if isUDP(network) {
		addr, err := net.ResolveUDPAddr(network, address)
		require.NoError(t, err)

		l, err := udp.Listen(network, addr)
		require.NoError(t, err)

		return l
	}

	l, err := net.Listen(network, address) //nolint:noctx
	require.NoError(t, err)

	return l
}

// dialTestListener dials to a listener, handling both TCP and UDP.
func dialTestListener(t *testing.T, network string, addr net.Addr) net.Conn {
	t.Helper()

	conn, err := net.Dial(network, addr.String()) //nolint:noctx
	require.NoError(t, err)

	return conn
}

func TestForwardProxy(t *testing.T) {
	tests := []struct { //nolint:dupl
		name         string
		listenerNet  string
		listenerAddr string
		peerNet      string
		peerAddr     string
		skipIPv6     bool
	}{
		// TCP listener to UDP peer (IPv4).
		{
			name:         "TCP4Listener/UDP4Peer",
			listenerNet:  "tcp4",
			listenerAddr: "127.0.0.1:0",
			peerNet:      "udp4",
			peerAddr:     "127.0.0.1:0",
		},
		// TCP listener to UDP peer (IPv6).
		{
			name:         "TCP6Listener/UDP6Peer",
			listenerNet:  "tcp6",
			listenerAddr: "[::1]:0",
			peerNet:      "udp6",
			peerAddr:     "[::1]:0",
			skipIPv6:     true,
		},
		// UDP listener to UDP peer (IPv4).
		{
			name:         "UDP4Listener/UDP4Peer",
			listenerNet:  "udp4",
			listenerAddr: "127.0.0.1:0",
			peerNet:      "udp4",
			peerAddr:     "127.0.0.1:0",
		},
		// UDP listener to UDP peer (IPv6).
		{
			name:         "UDP6Listener/UDP6Peer",
			listenerNet:  "udp6",
			listenerAddr: "[::1]:0",
			peerNet:      "udp6",
			peerAddr:     "[::1]:0",
			skipIPv6:     true,
		},
		// Cross-family: TCP4 listener to UDP6 peer.
		{
			name:         "TCP4Listener/UDP6Peer",
			listenerNet:  "tcp4",
			listenerAddr: "127.0.0.1:0",
			peerNet:      "udp6",
			peerAddr:     "[::1]:0",
			skipIPv6:     true,
		},
		// Cross-family: TCP6 listener to UDP4 peer.
		{
			name:         "TCP6Listener/UDP4Peer",
			listenerNet:  "tcp6",
			listenerAddr: "[::1]:0",
			peerNet:      "udp4",
			peerAddr:     "127.0.0.1:0",
			skipIPv6:     true,
		},
		// Cross-family: UDP4 listener to UDP6 peer.
		{
			name:         "UDP4Listener/UDP6Peer",
			listenerNet:  "udp4",
			listenerAddr: "127.0.0.1:0",
			peerNet:      "udp6",
			peerAddr:     "[::1]:0",
			skipIPv6:     true,
		},
		// Cross-family: UDP6 listener to UDP4 peer.
		{
			name:         "UDP6Listener/UDP4Peer",
			listenerNet:  "udp6",
			listenerAddr: "[::1]:0",
			peerNet:      "udp4",
			peerAddr:     "127.0.0.1:0",
			skipIPv6:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipIPv6 && !hasIPv6() {
				t.Skip("IPv6 not available")
			}

			// Start TURN server.
			turnServer := newTestTURNServer(t, tc.peerNet, tc.peerAddr)
			defer turnServer.Close() //nolint:errcheck,gosec

			// Start peer echo server.
			peerServer := newEchoServer(t, tc.peerNet, tc.peerAddr)
			defer peerServer.Close()

			// Create connection to TURN server.
			turnConn, err := net.ListenPacket(tc.peerNet, tc.peerAddr) //nolint:noctx
			require.NoError(t, err)
			defer turnConn.Close() //nolint:errcheck,gosec

			// Create local listener (TCP or UDP).
			listener := createTestListener(t, tc.listenerNet, tc.listenerAddr)
			defer listener.Close() //nolint:errcheck,gosec

			// Create logger factory.
			loggerFactory := logging.NewDefaultLoggerFactory()
			loggerFactory.DefaultLogLevel = logging.LogLevelWarn

			// Create forward proxy (RAII - starts immediately).
			fp, err := NewForwardProxy(listener, tc.peerNet, &ClientConfig{
				TURNServerAddr: turnServer.addr,
				Conn:           turnConn,
				Username:       testUsername,
				Password:       testPassword,
				Realm:          testRealm,
				LoggerFactory:  loggerFactory,
			}, loggerFactory)
			require.NoError(t, err)
			defer fp.Close() //nolint:errcheck,gosec

			// Add the peer.
			err = fp.AddPeer(tc.peerNet, peerServer.Addr().String())
			require.NoError(t, err)

			// Give proxy time to be ready.
			time.Sleep(100 * time.Millisecond)

			// Dial to the listener.
			conn := dialTestListener(t, tc.listenerNet, listener.Addr())
			conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck,gosec
			defer conn.Close()                                //nolint:errcheck,gosec

			// Send data.
			testData := []byte("hello forward")
			_, err = conn.Write(testData)
			require.NoError(t, err)

			// Read echoed response.
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			require.NoError(t, err)

			expected := "echo:" + string(testData)
			assert.Equal(t, expected, string(buf[:n]))
		})
	}
}

func TestReverseProxy(t *testing.T) {
	tests := []struct { //nolint:dupl
		name       string
		peerNet    string
		peerAddr   string
		clientNet  string
		clientAddr string
		skipIPv6   bool
	}{
		// UDP peer to TCP client (IPv4).
		{
			name:       "UDP4Peer/TCP4Client",
			peerNet:    "udp4",
			peerAddr:   "127.0.0.1:0",
			clientNet:  "tcp4",
			clientAddr: "127.0.0.1:0",
		},
		// UDP peer to TCP client (IPv6).
		{
			name:       "UDP6Peer/TCP6Client",
			peerNet:    "udp6",
			peerAddr:   "[::1]:0",
			clientNet:  "tcp6",
			clientAddr: "[::1]:0",
			skipIPv6:   true,
		},
		// UDP peer to UDP client (IPv4).
		{
			name:       "UDP4Peer/UDP4Client",
			peerNet:    "udp4",
			peerAddr:   "127.0.0.1:0",
			clientNet:  "udp4",
			clientAddr: "127.0.0.1:0",
		},
		// UDP peer to UDP client (IPv6).
		{
			name:       "UDP6Peer/UDP6Client",
			peerNet:    "udp6",
			peerAddr:   "[::1]:0",
			clientNet:  "udp6",
			clientAddr: "[::1]:0",
			skipIPv6:   true,
		},
		// Cross-family: UDP4 peer to TCP6 client.
		{
			name:       "UDP4Peer/TCP6Client",
			peerNet:    "udp4",
			peerAddr:   "127.0.0.1:0",
			clientNet:  "tcp6",
			clientAddr: "[::1]:0",
			skipIPv6:   true,
		},
		// Cross-family: UDP6 peer to TCP4 client.
		{
			name:       "UDP6Peer/TCP4Client",
			peerNet:    "udp6",
			peerAddr:   "[::1]:0",
			clientNet:  "tcp4",
			clientAddr: "127.0.0.1:0",
			skipIPv6:   true,
		},
		// Cross-family: UDP4 peer to UDP6 client.
		{
			name:       "UDP4Peer/UDP6Client",
			peerNet:    "udp4",
			peerAddr:   "127.0.0.1:0",
			clientNet:  "udp6",
			clientAddr: "[::1]:0",
			skipIPv6:   true,
		},
		// Cross-family: UDP6 peer to UDP4 client.
		{
			name:       "UDP6Peer/UDP4Client",
			peerNet:    "udp6",
			peerAddr:   "[::1]:0",
			clientNet:  "udp4",
			clientAddr: "127.0.0.1:0",
			skipIPv6:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipIPv6 && !hasIPv6() {
				t.Skip("IPv6 not available")
			}

			// Start TURN server.
			turnServer := newTestTURNServer(t, tc.peerNet, tc.peerAddr)
			defer turnServer.Close() //nolint:errcheck,gosec

			// Create connection to TURN server for the proxy.
			turnConn, err := net.ListenPacket(tc.peerNet, tc.peerAddr) //nolint:noctx
			require.NoError(t, err)
			defer turnConn.Close() //nolint:errcheck,gosec

			// Create logger factory.
			loggerFactory := logging.NewDefaultLoggerFactory()
			loggerFactory.DefaultLogLevel = logging.LogLevelWarn

			// Create a separate allocation to act as the peer.
			peerTurnConn, err := net.ListenPacket(tc.peerNet, tc.peerAddr) //nolint:noctx
			require.NoError(t, err)
			defer peerTurnConn.Close() //nolint:errcheck,gosec

			peerAllocation, err := NewAllocation(tc.peerNet, &ClientConfig{
				TURNServerAddr: turnServer.addr,
				Conn:           peerTurnConn,
				Username:       testUsername,
				Password:       testPassword,
				Realm:          testRealm,
				LoggerFactory:  loggerFactory,
			})
			require.NoError(t, err)
			defer peerAllocation.Close() //nolint:errcheck,gosec

			// Start client echo server.
			clientServer := newEchoServer(t, tc.clientNet, tc.clientAddr)
			defer clientServer.Close()

			// Create reverse proxy (RAII - starts immediately).
			rp, err := NewReverseProxy(&net.Dialer{}, tc.clientNet, clientServer.Addr().String(), tc.peerNet, &ClientConfig{
				TURNServerAddr: turnServer.addr,
				Conn:           turnConn,
				Username:       testUsername,
				Password:       testPassword,
				Realm:          testRealm,
				LoggerFactory:  loggerFactory,
			}, loggerFactory)
			require.NoError(t, err)
			defer rp.Close() //nolint:errcheck,gosec

			// Add the peer.
			err = rp.AddPeer(tc.peerNet, peerAllocation.Addr().String())
			require.NoError(t, err)

			// Give proxy time to be ready.
			time.Sleep(100 * time.Millisecond)

			// Get proxy relay address.
			proxyRelayAddr := rp.RelayAddr()

			// Peer dials to proxy's relay.
			peerConn, err := peerAllocation.Dial(tc.peerNet, proxyRelayAddr.String())
			require.NoError(t, err)
			defer peerConn.Close() //nolint:errcheck,gosec

			peerConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck,gosec

			// Send data from peer.
			testData := []byte("hello reverse")
			_, err = peerConn.Write(testData)
			require.NoError(t, err)

			// Read echoed response.
			buf := make([]byte, 4096)
			n, err := peerConn.Read(buf)
			require.NoError(t, err)

			expected := "echo:" + string(testData)
			assert.Equal(t, expected, string(buf[:n]))
		})
	}
}

func isUDP(network string) bool {
	return network == "udp" || network == "udp4" || network == "udp6"
}

func hasIPv6() bool {
	ln, err := net.Listen("tcp6", "[::1]:0") //nolint:noctx
	if err != nil {
		return false
	}
	ln.Close() //nolint:errcheck,gosec

	return true
}
