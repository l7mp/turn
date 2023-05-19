// Package offload implements a kernel-offload engine to speed up transporting ChannelData messages
//
//nolint:gochecknoinits
package offload

import (
	"encoding/binary"
	"net"

	"github.com/pion/logging"
)

// Engine represents the network offloading engine
//
//nolint:gochecknoglobals
var Engine OffloadEngine

// OffloadEngine provides a general interface for offloading techniques (e.g., XDP)
//
//nolint:revive
type OffloadEngine interface {
	Logger() logging.LeveledLogger
	Init() error
	Shutdown()
	Upsert(peer, client Connection, metrics []string) error
	Remove(peer, client Connection) error
}

// Connection combines offload engine identifiers required for uinquely identifying Allocation channel bindings. Depending of the used offload engine, values might be nulled. For example, the SockFd has no role for an XDP offload.
type Connection struct {
	RemoteIP   uint32
	LocalIP    uint32
	RemotePort uint16
	LocalPort  uint16
	Protocol   uint32
	SocketFd   uintptr
	ChannelID  uint32
}

// NewConnection is the internal representation of a five-tuple with a channel ID
func NewConnection(remote, local *net.UDPAddr, channel uint32) Connection {
	var localIP uint32
	if local.IP.To4() != nil {
		localIP = binary.BigEndian.Uint32(local.IP.To4())
	}
	var remoteIP uint32
	if remote.IP.To4() != nil {
		remoteIP = binary.BigEndian.Uint32(remote.IP.To4())
	}
	return Connection{
		LocalIP:    localIP,
		RemoteIP:   remoteIP,
		LocalPort:  uint16(local.Port),
		RemotePort: uint16(remote.Port),
		Protocol:   17,
		ChannelID:  channel,
	}
}
