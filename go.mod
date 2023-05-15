module github.com/pion/turn/v2

go 1.19

require (
	github.com/pion/logging v0.2.2
	github.com/pion/randutil v0.1.0
	github.com/pion/stun v0.5.2
	github.com/pion/transport/v2 v2.2.1
	github.com/stretchr/testify v1.8.3
	golang.org/x/sys v0.7.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pion/dtls/v2 v2.2.6 // indirect
	github.com/pion/udp/v2 v2.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// ebpf/xdp offload
require github.com/cilium/ebpf v0.10.0
