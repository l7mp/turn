// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package xdp

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfFourTuple struct {
	RemoteIp   uint32
	LocalIp    uint32
	RemotePort uint16
	LocalPort  uint16
}

type bpfFourTupleStat struct {
	Pkts          uint64
	Bytes         uint64
	TimestampLast uint64
}

type bpfFourTupleWithChannelId struct {
	FourTuple bpfFourTuple
	ChannelId uint32
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	XdpProgFunc *ebpf.ProgramSpec `ebpf:"xdp_prog_func"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	TurnServerDownstreamMap           *ebpf.MapSpec `ebpf:"turn_server_downstream_map"`
	TurnServerInterfaceIpAddressesMap *ebpf.MapSpec `ebpf:"turn_server_interface_ip_addresses_map"`
	TurnServerStatsMap                *ebpf.MapSpec `ebpf:"turn_server_stats_map"`
	TurnServerUpstreamMap             *ebpf.MapSpec `ebpf:"turn_server_upstream_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	TurnServerDownstreamMap           *ebpf.Map `ebpf:"turn_server_downstream_map"`
	TurnServerInterfaceIpAddressesMap *ebpf.Map `ebpf:"turn_server_interface_ip_addresses_map"`
	TurnServerStatsMap                *ebpf.Map `ebpf:"turn_server_stats_map"`
	TurnServerUpstreamMap             *ebpf.Map `ebpf:"turn_server_upstream_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.TurnServerDownstreamMap,
		m.TurnServerInterfaceIpAddressesMap,
		m.TurnServerStatsMap,
		m.TurnServerUpstreamMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	XdpProgFunc *ebpf.Program `ebpf:"xdp_prog_func"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.XdpProgFunc,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel.o
var _BpfBytes []byte
