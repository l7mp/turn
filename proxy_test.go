// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package turn

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v3/test"
	"github.com/pion/transport/v3/udp"
	"github.com/stretchr/testify/assert"
)

type testCase struct {
	name, proto, uri string
	listener         net.Listener
	sink             net.PacketConn
	loggerFactory    logging.LoggerFactory
}

func TestProxy(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logging.NewDefaultLoggerFactory()
	// loggerFactory.DefaultLogLevel = logging.LogLevelTrace
	log := loggerFactory.NewLogger("test")

	log.Debug("creating a sink")
	sink, err := net.ListenPacket("udp", "0.0.0.0:5001") //nolint:gosec
	assert.NoError(t, err)

	log.Debug("creating a server")
	udpServer, err := net.ListenPacket("udp", "0.0.0.0:3478") //nolint:gosec
	assert.NoError(t, err)

	tcpServer, err := net.Listen("tcp", "0.0.0.0:3478") //nolint:gosec
	assert.NoError(t, err)

	server, err := NewServer(ServerConfig{
		AuthHandler: func(username, realm string, srcAddr net.Addr) (key []byte, ok bool) {
			if username == "user1" {
				key := GenerateAuthKey(username, "pion.ly", "pass1")
				return key, true
			}
			return nil, false
		},
		Realm: "pion.ly",
		PacketConnConfigs: []PacketConnConfig{
			{
				PacketConn: udpServer,
				RelayAddressGenerator: &RelayAddressGeneratorNone{
					Address: "127.0.0.1",
				},
			},
		},
		ListenerConfigs: []ListenerConfig{
			{
				Listener: tcpServer,
				RelayAddressGenerator: &RelayAddressGeneratorNone{
					Address: "127.0.0.1",
				},
			},
		},
		LoggerFactory: loggerFactory,
	})
	assert.NoError(t, err)

	t.Run("TestProxyUDPOverUDP", func(t *testing.T) {
		addr, _ := net.ResolveUDPAddr("udp", "0.0.0.0:5000") //nolint:errcheck
		listener, err := udp.Listen("udp", addr)
		assert.NoError(t, err)

		testProxyTransport(t, testCase{
			name:          "udp-udp-proxy-test",
			proto:         "udp",
			uri:           "turn:127.0.0.1:3478?transport=udp",
			listener:      listener,
			sink:          sink,
			loggerFactory: loggerFactory,
		})

		assert.NoError(t, listener.Close())
	})

	t.Run("TestProxyTCPOverUDP", func(t *testing.T) {
		listener, err := net.Listen("tcp", "0.0.0.0:5000") //nolint:gosec
		assert.NoError(t, err)

		testProxyTransport(t, testCase{
			name:          "tcp-udp-proxy-test",
			proto:         "tcp",
			uri:           "turn:127.0.0.1:3478?transport=udp",
			listener:      listener,
			sink:          sink,
			loggerFactory: loggerFactory,
		})

		assert.NoError(t, listener.Close())
	})

	t.Run("TestProxyUDPOverTCP", func(t *testing.T) {
		addr, _ := net.ResolveUDPAddr("udp", "0.0.0.0:5000") //nolint:errcheck,gosec
		listener, err := udp.Listen("udp", addr)
		assert.NoError(t, err)

		testProxyTransport(t, testCase{
			name:          "udp-tcp-proxy-test",
			proto:         "udp",
			uri:           "turn:127.0.0.1:3478?transport=tcp",
			listener:      listener,
			sink:          sink,
			loggerFactory: loggerFactory,
		})

		assert.NoError(t, listener.Close())
	})

	t.Run("TestProxyTCPOverTCP", func(t *testing.T) {
		listener, err := net.Listen("tcp", "0.0.0.0:5000") //nolint:gosec
		assert.NoError(t, err)

		testProxyTransport(t, testCase{
			name:          "tcp-udp-proxy-test",
			proto:         "tcp",
			uri:           "turn:127.0.0.1:3478?transport=tcp",
			listener:      listener,
			sink:          sink,
			loggerFactory: loggerFactory,
		})

		assert.NoError(t, listener.Close())
	})

	assertNoErrorOrNetClosed(t, server.Close(), "server close error")
	assertNoErrorOrNetClosed(t, udpServer.Close(), "UDP server listener close error")
	assertNoErrorOrNetClosed(t, tcpServer.Close(), "TCP server listener close error")
	assertNoErrorOrNetClosed(t, sink.Close(), "sink close error")
}

func testProxyTransport(t *testing.T, c testCase) {
	log := c.loggerFactory.NewLogger(c.name)

	log.Debug("creating a proxy")
	proxy, err := NewProxy(ProxyConfig{
		TURNServerURI: c.uri,
		Listeners:     []net.Listener{c.listener},
		PeerAddr:      "127.0.0.1:5001",
		AuthGen:       func() (string, string, error) { return "user1", "pass1", nil },
		LoggerFactory: c.loggerFactory,
	})
	assert.NoError(t, err, "should succeed")

	log.Debug("creating a client")
	client, err := net.Dial(c.proto, "127.0.0.1:5000")
	assert.NoError(t, err)

	testBuffer := []byte("dummy-string")
	go func() {
		_, err = client.Write(testBuffer)
		assertNoErrorOrNetClosed(t, err, "close error")
	}()

	// test content
	buf := make([]byte, 1600)

	n, _, err := c.sink.ReadFrom(buf)
	assertNoErrorOrNetClosed(t, err, "close error")
	assert.Equal(t, testBuffer, buf[0:n], "packet content")

	assertNoErrorOrNetClosed(t, client.Close(), "client connection close error")
	proxy.Close()
}

func assertNoErrorOrNetClosed(t *testing.T, err error, msg string) {
	assert.True(t, err == nil || errors.Is(err, net.ErrClosed), msg)
}
