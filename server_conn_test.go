// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package turn

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5/udp"
	"github.com/pion/turn/v5/internal/proto"
	"github.com/stretchr/testify/require"
)

// unpaddedConn is a TURN client transport over a connected datagram conn (UDP or DTLS) that sends
// ChannelData without the 4-byte padding, which RFC 8656 requires only over TCP and TLS.
type unpaddedConn struct {
	net.Conn
}

func (c *unpaddedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)

	return n, c.RemoteAddr(), err
}

func (c *unpaddedConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) >= 4 && proto.ChannelNumber(binary.BigEndian.Uint16(p[0:2])).Valid() {
		if unpadded := 4 + int(binary.BigEndian.Uint16(p[2:4])); unpadded < len(p) {
			if _, err := c.Write(p[:unpadded]); err != nil {
				return 0, err
			}

			return len(p), nil
		}
	}

	return c.Write(p)
}

// trackedConn records whether the server closed it.
type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)

	return c.Conn.Close()
}

// trackingListener hands every accepted conn to the test as a trackedConn.
type trackingListener struct {
	net.Listener
	conns chan *trackedConn
}

func (l *trackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tracked := &trackedConn{Conn: conn}
	l.conns <- tracked

	return tracked, nil
}

type channelFinder interface {
	FindChannelNumberByAddr(addr net.Addr) (uint16, bool)
	IsChannelActive(chNum uint16) bool
}

// testDatagramListener runs a TURN session over a datagram listener served through
// ListenerConfigs: the client relays unpadded ChannelData to a peer and back, and closing the
// allocation closes the server's conn.
func testDatagramListener(t *testing.T, ln net.Listener, dial func() (net.Conn, error)) {
	t.Helper()

	loggerFactory := logging.NewDefaultLoggerFactory()
	tracker := &trackingListener{Listener: ln, conns: make(chan *trackedConn, 8)}
	server, err := NewServer(ServerConfig{
		AuthHandler: func(ra *RequestAttributes) (string, []byte, bool) {
			return ra.Username, GenerateAuthKey(ra.Username, ra.Realm, "pass"), true
		},
		ListenerConfigs: []ListenerConfig{{
			Listener: tracker,
			RelayAddressGenerator: &RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
		Realm:         "pion.ly",
		LoggerFactory: loggerFactory,
	})
	require.NoError(t, err)
	defer server.Close() //nolint:errcheck

	peer, err := net.ListenPacket("udp4", "127.0.0.1:0") // nolint: noctx
	require.NoError(t, err)
	defer peer.Close() //nolint:errcheck

	conn, err := dial()
	require.NoError(t, err)
	// the client does not own its transport: close it after the client, ending the read loop
	defer conn.Close() //nolint:errcheck
	client, err := NewClient(&ClientConfig{
		STUNServerAddr: conn.RemoteAddr().String(),
		TURNServerAddr: conn.RemoteAddr().String(),
		Conn:           &unpaddedConn{Conn: conn},
		Username:       testUser,
		Password:       "pass",
		Realm:          "pion.ly",
		LoggerFactory:  loggerFactory,
	})
	require.NoError(t, err)
	require.NoError(t, client.Listen())
	defer client.Close()

	relayConn, err := client.Allocate()
	require.NoError(t, err)

	var serverConn *trackedConn
	select {
	case serverConn = <-tracker.conns:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "server accepted no conn")
	}

	// The first write installs the permission and starts the channel binding; wait until the
	// client frames its writes as ChannelData.
	finder, ok := relayConn.(channelFinder)
	require.True(t, ok)
	payload := []byte("hello") // 5 bytes: ChannelData would need 3 bytes of padding
	require.Eventually(t, func() bool {
		_, _ = relayConn.WriteTo(payload, peer.LocalAddr())
		num, found := finder.FindChannelNumberByAddr(peer.LocalAddr())

		return found && finder.IsChannelActive(num)
	}, 5*time.Second, 50*time.Millisecond)

	// Drain what reached the peer so far, then check that unpadded ChannelData is relayed.
	buf := make([]byte, 1500)
	for {
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		if _, _, err = peer.ReadFrom(buf); err != nil {
			break
		}
	}
	_, err = relayConn.WriteTo(payload, peer.LocalAddr())
	require.NoError(t, err)
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, relayAddr, err := peer.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:n])

	// And the way back, from the peer to the client over the channel.
	_, err = peer.WriteTo([]byte("world"), relayAddr)
	require.NoError(t, err)
	require.NoError(t, relayConn.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, _, err = relayConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("world"), buf[:n])

	// Deleting the allocation closes the client conn it was made on.
	require.False(t, serverConn.closed.Load())
	require.NoError(t, relayConn.Close())
	require.Eventually(t, serverConn.closed.Load, 5*time.Second, 20*time.Millisecond)
}

func TestServerDatagramConnUDP(t *testing.T) {
	ln, err := (&udp.ListenConfig{}).Listen("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)

	testDatagramListener(t, ln, func() (net.Conn, error) {
		return net.Dial("udp", ln.Addr().String()) // nolint: noctx
	})
}

func TestServerDatagramConnDTLS(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	ln, err := dtls.ListenWithOptions("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		dtls.WithCertificates(cert))
	require.NoError(t, err)

	testDatagramListener(t, ln, func() (net.Conn, error) {
		raddr, err := net.ResolveUDPAddr("udp", ln.Addr().String())
		if err != nil {
			return nil, err
		}
		clientCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		// An IPv4 client socket: dtls.Dial binds the IPv6 wildcard, from which the TURN client
		// would infer an IPv6 allocation.
		sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			return nil, err
		}

		return dtls.ClientWithOptions(sock, raddr, dtls.WithCertificates(clientCert),
			dtls.WithInsecureSkipVerify(true))
	})
}

// Deleting an allocation made over a stream conn closes that conn too.
func TestServerStreamConnClosedOnDelete(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()
	ln, err := net.Listen("tcp4", "127.0.0.1:0") // nolint: noctx
	require.NoError(t, err)
	tracker := &trackingListener{Listener: NewSTUNListener(ln), conns: make(chan *trackedConn, 8)}
	server, err := NewServer(ServerConfig{
		AuthHandler: func(ra *RequestAttributes) (string, []byte, bool) {
			return ra.Username, GenerateAuthKey(ra.Username, ra.Realm, "pass"), true
		},
		ListenerConfigs: []ListenerConfig{{
			Listener: tracker,
			RelayAddressGenerator: &RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
		Realm:         "pion.ly",
		LoggerFactory: loggerFactory,
	})
	require.NoError(t, err)
	defer server.Close() //nolint:errcheck

	conn, err := net.Dial("tcp4", ln.Addr().String()) // nolint: noctx
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck
	client, err := NewClient(&ClientConfig{
		STUNServerAddr: ln.Addr().String(),
		TURNServerAddr: ln.Addr().String(),
		Conn:           NewSTUNConn(conn),
		Username:       testUser,
		Password:       "pass",
		Realm:          "pion.ly",
		LoggerFactory:  loggerFactory,
	})
	require.NoError(t, err)
	require.NoError(t, client.Listen())
	defer client.Close()

	relayConn, err := client.Allocate()
	require.NoError(t, err)
	serverConn := <-tracker.conns
	require.False(t, serverConn.closed.Load())

	require.NoError(t, relayConn.Close())
	require.Eventually(t, serverConn.closed.Load, 5*time.Second, 20*time.Millisecond)
}

// A Refresh with lifetime 0 is answered before the allocation, and the conn it was made on, is
// deleted. The test runs over TCP: a pion udp.Conn still writes after Close, a TCP conn does not.
func TestServerRefreshZeroAnswered(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()
	ln, err := net.Listen("tcp4", "127.0.0.1:0") // nolint: noctx
	require.NoError(t, err)
	tracker := &trackingListener{Listener: NewSTUNListener(ln), conns: make(chan *trackedConn, 8)}
	server, err := NewServer(ServerConfig{
		AuthHandler: func(ra *RequestAttributes) (string, []byte, bool) {
			return ra.Username, GenerateAuthKey(ra.Username, ra.Realm, "pass"), true
		},
		ListenerConfigs: []ListenerConfig{{
			Listener: tracker,
			RelayAddressGenerator: &RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
		Realm:         "pion.ly",
		LoggerFactory: loggerFactory,
	})
	require.NoError(t, err)
	defer server.Close() //nolint:errcheck

	conn, err := net.Dial("tcp4", ln.Addr().String()) // nolint: noctx
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck
	client, err := NewClient(&ClientConfig{
		STUNServerAddr: ln.Addr().String(),
		TURNServerAddr: ln.Addr().String(),
		Conn:           NewSTUNConn(conn),
		Username:       testUser,
		Password:       "pass",
		Realm:          "pion.ly",
		LoggerFactory:  loggerFactory,
	})
	require.NoError(t, err)
	require.NoError(t, client.Listen())
	defer client.Close()

	relayConn, err := client.Allocate()
	require.NoError(t, err)
	// stops the client's refresh timers; its own Refresh(0) goes nowhere by then
	defer relayConn.Close() //nolint:errcheck
	serverConn := <-tracker.conns

	// an unauthenticated Refresh fetches the nonce, the authenticated one deletes the
	// allocation and must be answered
	nonceRes, err := client.PerformTransaction(stun.MustBuild(stun.TransactionID,
		stun.NewType(stun.MethodRefresh, stun.ClassRequest), proto.Lifetime{},
		stun.Fingerprint), ln.Addr(), false)
	require.NoError(t, err)
	var nonce stun.Nonce
	require.NoError(t, nonce.GetFrom(nonceRes.Msg))

	res, err := client.PerformTransaction(stun.MustBuild(stun.TransactionID,
		stun.NewType(stun.MethodRefresh, stun.ClassRequest), proto.Lifetime{},
		stun.NewUsername(testUser), stun.NewRealm("pion.ly"), nonce,
		stun.NewLongTermIntegrity(testUser, "pion.ly", "pass"), stun.Fingerprint),
		ln.Addr(), false)
	require.NoError(t, err, "the Refresh(0) is answered")
	require.Equal(t, stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse), res.Msg.Type)
	require.Eventually(t, serverConn.closed.Load, 5*time.Second, 20*time.Millisecond)
}
