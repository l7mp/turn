// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package proto

import (
	"net"
)

// ClientConn is a conn a client is served on: it adapts a connected conn that delivers exactly
// one STUN or ChannelData message per Read to the net.PacketConn API the server works with. A
// datagram conn (UDP, DTLS) does so as is; a stream conn (TCP, TLS) does once wrapped in a
// STUNConn. WriteTo ignores the address: the conn is connected, so every write goes to its
// remote end.
type ClientConn struct {
	net.Conn
}

// ReadFrom reads one message and reports the conn's remote address as its source.
func (c *ClientConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	n, err := c.Read(payload)

	return n, c.RemoteAddr(), err
}

// WriteTo writes one message to the conn's remote end, ignoring addr.
func (c *ClientConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return c.Write(payload)
}
