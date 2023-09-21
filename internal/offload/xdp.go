package offload

import (
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pion/logging"
	"github.com/pion/turn/v3/internal/offload/xdp"
)

// XdpEngine represents an XDP offload engine; implements OffloadEngine
type XdpEngine struct {
	SetupDone     bool
	interfaces    []net.Interface
	upstreamMap   *ebpf.Map
	downstreamMap *ebpf.Map
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

	return nil
}

// Logger returns the offload engine's logger
func (o *XdpEngine) Logger() logging.LeveledLogger {
	return o.log
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
	if err := xdp.LoadBpfObjects(&o.objs, &opts); err != nil {
		return err
	}
	o.downstreamMap = o.objs.TurnServerDownstreamMap
	o.upstreamMap = o.objs.TurnServerUpstreamMap
	o.statsMap = o.objs.TurnServerStatsMap

	ifNames := []string{}
	// Attach program to interfaces
	for _, iface := range o.interfaces {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   o.objs.XdpProgFunc,
			Interface: iface.Index,
		})
		if err != nil {
			return err
		}
		o.links = append(o.links, l)
		ifNames = append(ifNames, iface.Name)
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
	p := xdp.BpfFourTuple{
		RemoteIp:   HostToNetLong(peer.RemoteIP),
		LocalIp:    HostToNetLong(peer.LocalIP),
		LocalPort:  HostToNetShort(peer.LocalPort),
		RemotePort: HostToNetShort(peer.RemotePort),
	}
	c := xdp.BpfFourTupleWithChannelId{
		FourTuple: xdp.BpfFourTuple{
			RemoteIp:   HostToNetLong(client.RemoteIP),
			LocalIp:    HostToNetLong(client.LocalIP),
			LocalPort:  HostToNetShort(client.LocalPort),
			RemotePort: HostToNetShort(client.RemotePort),
		},
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

	o.log.Debugf("Create offload between client: %+v and peer: %+v", client, peer)
	return nil
}

// Remove removes an XDP offload between a client and a peer
func (o *XdpEngine) Remove(client, peer Connection) error {
	p := xdp.BpfFourTuple{
		RemoteIp:   HostToNetLong(peer.RemoteIP),
		LocalIp:    HostToNetLong(peer.LocalIP),
		LocalPort:  HostToNetShort(peer.LocalPort),
		RemotePort: HostToNetShort(peer.RemotePort),
	}
	c := xdp.BpfFourTupleWithChannelId{
		FourTuple: xdp.BpfFourTuple{
			RemoteIp:   HostToNetLong(client.RemoteIP),
			LocalIp:    HostToNetLong(client.LocalIP),
			LocalPort:  HostToNetShort(client.LocalPort),
			RemotePort: HostToNetShort(client.RemotePort),
		},
		ChannelId: client.ChannelID,
	}

	if err := o.downstreamMap.Delete(p); err != nil {
		return err
	}

	if err := o.upstreamMap.Delete(c); err != nil {
		return err
	}

	o.log.Debugf("Remove offload between client: %+v and peer: %+v", client, peer)
	return nil
}

// GetStat queries statistics about an offloaded connection
func (o *XdpEngine) GetStat(con Connection) (*Stat, error) {
	c := xdp.BpfFourTuple{
		RemoteIp:   HostToNetLong(con.RemoteIP),
		LocalIp:    HostToNetLong(con.LocalIP),
		LocalPort:  HostToNetShort(con.LocalPort),
		RemotePort: HostToNetShort(con.RemotePort),
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
