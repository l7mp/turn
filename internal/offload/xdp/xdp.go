//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-Wall -O2" bpf xdp.c -- -I./headers

package xdp

import "github.com/cilium/ebpf"

type BpfObjects = bpfObjects

func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadBpfObjects(obj, opts)
}

type BpfFourTuple = bpfFourTuple
type BpfFourTupleWithChannelId = bpfFourTupleWithChannelId
type BpfFourTupleStat = bpfFourTupleStat
