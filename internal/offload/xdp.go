// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package offload

import (
	"encoding/binary"
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pion/logging"
	"github.com/pion/turn/v3/internal/offload/xdp"
	"github.com/pion/turn/v3/internal/proto"
)

// XdpEngine represents an XDP offload engine; implements OffloadEngine
type XdpEngine struct {
	SetupDone     bool
	interfaces    []net.Interface
	upstreamMap   *ebpf.Map
	downstreamMap *ebpf.Map
	ipaddrsMap    *ebpf.Map
	statsMap      *ebpf.Map
	objs          xdp.BpfObjects
	links         []link.Link
	log           logging.LeveledLogger
}

// NewXdpEngine creates an uninitialized XDP offload engine
func NewXdpEngine(ifs []net.Interface, log logging.LeveledLogger, setup bool) (*XdpEngine, error) {
	return &XdpEngine{
		SetupDone:  setup,
		interfaces: ifs,
		log:        log,
	}, nil
}

func (o *XdpEngine) unpinMaps() error {
	// unlink maps
	if o.downstreamMap != nil {
		if err := o.downstreamMap.Unpin(); err != nil {
			return err
		}
	}
	if o.upstreamMap != nil {
		if err := o.upstreamMap.Unpin(); err != nil {
			return err
		}
	}
	if o.statsMap != nil {
		if err := o.statsMap.Unpin(); err != nil {
			return err
		}
	}

	if o.ipaddrsMap != nil {
		if err := o.ipaddrsMap.Unpin(); err != nil {
			return err
		}
	}

	return nil
}

// Init sets up the environment for the XDP program: enables IPv4
// forwarding in the kernel; links maps of the XDP program; and,
// starts the XDP program on network interfaces.
// Based on https://github.com/l7mp/l7mp/blob/master/udp-offload.js#L232
func (o *XdpEngine) Init() error {
	if o.SetupDone {
		return nil
	}

	// enable ipv4 forwarding
	f := "/proc/sys/net/ipv4/conf/all/forwarding"
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	val, err := strconv.Atoi(string(data[:len(data)-1]))
	if err != nil {
		return err
	}
	if val != 1 {
		//nolint:gosec
		if e := os.WriteFile(f, []byte("1"), 0o644); e != nil {
			return e
		}
	}

	// unlink maps if they exist
	if err = o.unpinMaps(); err != nil {
		return err
	}

	// Load pre-compiled programs into the kernel
	o.objs = xdp.BpfObjects{}
	bpfMapPinPath := "/sys/fs/bpf"
	opts := ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: bpfMapPinPath}}
	if err = xdp.LoadBpfObjects(&o.objs, &opts); err != nil {
		return err
	}
	o.downstreamMap = o.objs.TurnServerDownstreamMap
	o.upstreamMap = o.objs.TurnServerUpstreamMap
	o.ipaddrsMap = o.objs.TurnServerInterfaceIpAddressesMap
	o.statsMap = o.objs.TurnServerStatsMap

	ifNames := []string{}
	// Attach program to interfaces
	for _, iface := range o.interfaces {
		l, linkErr := link.AttachXDP(link.XDPOptions{
			Program:   o.objs.XdpProgFunc,
			Interface: iface.Index,
		})
		if linkErr != nil {
			return linkErr
		}
		o.links = append(o.links, l)
		ifNames = append(ifNames, iface.Name)
	}

	// populate interface IP addresses map
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, netIf := range ifs {
		ifIdx := netIf.Index
		addrs, err := netIf.Addrs()
		if err == nil && len(addrs) > 0 {
			a, ok := addrs[0].(*net.IPNet)
			if addr := a.IP.To4(); addr != nil && ok {
				ifAddr := binary.LittleEndian.Uint32(addr)
				err := o.ipaddrsMap.Put(uint32(ifIdx), ifAddr)
				if err != nil {
					return err
				}
			}
		}
	}

	o.SetupDone = true

	o.log.Infof("Init done on interfaces: %s", ifNames)
	return nil
}

// Shutdown stops the XDP offloading engine
func (o *XdpEngine) Shutdown() {
	if !o.SetupDone {
		return
	}

	// close objects
	if err := o.objs.Close(); err != nil {
		o.log.Errorf("Error during shutdown: %s", err.Error())
		return
	}

	// close links
	for _, l := range o.links {
		if err := l.Close(); err != nil {
			o.log.Errorf("Error during shutdown: %s", err.Error())
			return
		}
	}

	// unlink maps
	if err := o.unpinMaps(); err != nil {
		o.log.Errorf("Error during shutdown: %s", err.Error())
		return
	}

	o.SetupDone = false

	o.log.Info("Shutdown done")
}

// Upsert creates a new XDP offload between a client and a peer
func (o *XdpEngine) Upsert(client, peer Connection) error {
	p, err := bpfFourTuple(peer)
	if err != nil {
		return err
	}
	cft, err := bpfFourTuple(client)
	if err != nil {
		return err
	}
	c := xdp.BpfFourTupleWithChannelId{
		FourTuple: *cft,
		ChannelId: client.ChannelID,
	}

	if err := o.downstreamMap.Put(p, c); err != nil {
		o.log.Errorf("Error in upsert (downstream map): %s", err.Error())
		return err
	}
	if err := o.upstreamMap.Put(c, p); err != nil {
		o.log.Errorf("Error in upsert (upstream map): %s", err.Error())
		return err
	}

	o.log.Infof("Create offload between client: %+v and peer: %+v", client, peer)
	return nil
}

// Remove removes an XDP offload between a client and a peer
func (o *XdpEngine) Remove(client, peer Connection) error {
	p, err := bpfFourTuple(peer)
	if err != nil {
		return err
	}
	cft, err := bpfFourTuple(client)
	if err != nil {
		return err
	}
	c := xdp.BpfFourTupleWithChannelId{
		FourTuple: *cft,
		ChannelId: client.ChannelID,
	}

	if err := o.downstreamMap.Delete(p); err != nil {
		return err
	}

	if err := o.upstreamMap.Delete(c); err != nil {
		return err
	}

	o.log.Infof("Remove offload between client: %+v and peer: %+v", client, peer)
	return nil
}

// GetStat queries statistics about an offloaded connection
func (o *XdpEngine) GetStat(con Connection) (*Stat, error) {
	c, err := bpfFourTuple(con)
	if err != nil {
		return nil, err
	}
	bs := xdp.BpfFourTupleStat{}
	if err := o.statsMap.Lookup(c, &bs); err != nil {
		return nil, err
	}

	s := Stat{}
	s.Pkts = bs.Pkts
	s.Bytes = bs.Bytes
	s.TimeStamp = bs.TimestampLast

	return &s, nil
}

func hostToNetShort(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// bpfFourTuple creates an xdp.BpfFourTuple struct that can be used in the XDP offload maps
func bpfFourTuple(c Connection) (*xdp.BpfFourTuple, error) {
	if c.Protocol != proto.ProtoUDP {
		return nil, errUnsupportedProtocol
	}
	l, lok := c.LocalAddr.(*net.UDPAddr)
	r, rok := c.RemoteAddr.(*net.UDPAddr)
	if !lok || !rok {
		return nil, errUnsupportedProtocol
	}
	var localIP uint32
	if l.IP.To4() != nil {
		localIP = binary.LittleEndian.Uint32(l.IP.To4())
	}
	var remoteIP uint32
	if r.IP.To4() != nil {
		remoteIP = binary.LittleEndian.Uint32(r.IP.To4())
	}

	t := xdp.BpfFourTuple{
		RemoteIp:   remoteIP,
		LocalIp:    localIP,
		RemotePort: hostToNetShort(uint16(r.Port)),
		LocalPort:  hostToNetShort(uint16(l.Port)),
	}
	return &t, nil
}
