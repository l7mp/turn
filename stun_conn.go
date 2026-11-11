// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package turn

import (
	"net"

	"github.com/pion/turn/v5/internal/proto"
)

type STUNConn = proto.STUNConn

// NewSTUNConn creates a STUNConn.
func NewSTUNConn(nextConn net.Conn) *STUNConn {
	return proto.NewSTUNConn(nextConn)
}

// NewSTUNStreamConn frames a stream conn (TCP, TLS) for a server: every Read returns exactly one
// STUN or ChannelData message. The server serves the conns it accepts as they are, so a stream
// conn must be framed by the caller, either one by one with this function or all at once with
// NewSTUNListener. Datagram conns (UDP, DTLS) need no framing.
func NewSTUNStreamConn(conn net.Conn) net.Conn {
	return proto.NewSTUNConn(conn)
}

// NewSTUNListener frames every conn accepted on a stream listener (TCP, TLS) with
// NewSTUNStreamConn.
func NewSTUNListener(l net.Listener) net.Listener {
	return stunListener{l}
}

type stunListener struct {
	net.Listener
}

func (l stunListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return NewSTUNStreamConn(conn), nil
}
