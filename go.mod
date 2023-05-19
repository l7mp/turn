module github.com/pion/turn/v2

go 1.16

require (
	github.com/pion/logging v0.2.2
	github.com/pion/randutil v0.1.0
	github.com/pion/stun v0.5.2
	github.com/pion/transport/v2 v2.2.1
	github.com/stretchr/testify v1.8.3
	golang.org/x/sys v0.7.0
)

// ebpf/xdp offload
require github.com/cilium/ebpf v0.10.0
