// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a TURN proxy and a test app using UDP
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v3/udp"
	"github.com/pion/turn/v3"
)

func localRelayConnGen(insecure bool) turn.RelayConnGen {
	return func(proto, addr string) (net.PacketConn, error) {
		if proto == "udp" {
			t, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			return t, nil
		}
		return turn.DefaultRelayConnGen(insecure)(proto, addr)
	}
}

func main() {
	host := flag.String("host", "", "TURN server address")
	port := flag.Int("port", 3478, "TURN server port (default: 3478)")
	user := flag.String("user", "", "A pair of username and password (e.g. \"user=pass\")")
	ping := flag.Bool("ping", false, "Run ping test")
	xdp := flag.Bool("xdp", false, "Use XDP offload")
	flag.Parse()

	if len(*host) == 0 {
		log.Fatalf("'host' is required")
	}

	if len(*user) == 0 {
		log.Fatalf("'user' is required")
	}

	cred := strings.SplitN(*user, "=", 2)

	// UDP client used for testing.
	clientAddr := "127.0.0.1:50001"
	conn, err := net.ListenPacket("udp4", clientAddr)
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Panicf("Failed to close connection: %s", closeErr)
		}
	}()

	// UDP listener the TURN proxy will use
	proxyAddr := "127.0.0.1:50000"
	proxyUDPAddr, err := net.ResolveUDPAddr("udp", proxyAddr)
	if err != nil {
		log.Panicf("Failed to resolve proxy address: %s", err)
	}
	listener, err := udp.Listen("udp", proxyUDPAddr)
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			log.Panicf("Failed to close connection: %s", closeErr)
		}
	}()

	proxy, err := turn.NewProxy(turn.ProxyConfig{
		TURNServerURI: fmt.Sprintf("turn:%s:%d?transport=udp", *host, *port),
		Listeners:     []net.Listener{listener},
		PeerAddr:      clientAddr,
		RelayConnGen:  localRelayConnGen(true),
		AuthGen:       func() (string, string, error) { return cred[0], cred[1], nil },
	})
	if err != nil {
		log.Panicf("Failed to create proxy: %s", err)
	}
	defer proxy.Close()

	// If you provided `-xdp`, use the XDP offload engine
	if *xdp {
		loggerFactory := logging.NewDefaultLoggerFactory()
		err = turn.InitOffload(turn.OffloadConfig{Log: loggerFactory.NewLogger("offload")})
		if err != nil {
			log.Panicf("Failed to init offload engine: %s", err)
		}
		defer turn.ShutdownOffload()
	}

	// If you provided `-ping`, perform a ping test against the proxy.
	if *ping {
		err = doPingTest(conn, proxyUDPAddr)
		if err != nil {
			log.Panicf("Failed to ping: %s", err)
		}
	}
}

func doPingTest(client net.PacketConn, proxyUDPAddr net.Addr) error {
	// Start read-loop on client
	go func() {
		buf := make([]byte, 1600)
		for i := 1; i <= 10; i++ {
			n, from, pingerErr := client.ReadFrom(buf)
			if pingerErr != nil {
				break
			}

			msg := string(buf[:n])
			if sentAt, pingerErr := time.Parse(time.RFC3339Nano, msg); pingerErr == nil {
				rtt := time.Since(sentAt)
				log.Printf("pkt %d: %d bytes from %s time=%d ms\n",
					i, n, from.String(), int(rtt.Seconds()*1000))
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Send 10 packets from relayConn to the echo server
	for i := 0; i < 10; i++ {
		msg := time.Now().Format(time.RFC3339Nano)
		_, err := client.WriteTo([]byte(msg), proxyUDPAddr)
		if err != nil {
			return err
		}

		// For simplicity, this example does not wait for the pong (reply).
		// Instead, sleep 1 second.
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}
