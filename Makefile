GO=go
GOFMT=gofmt
CLANG_FORMAT=clang-format

default: build

build: generate

generate:
	cd internal/offload/xdp/ && \
	$(GO) generate

format-offload:
	$(CLANG_FORMAT) -i --style=file internal/offload/xdp/xdp.c

clean-offload:
	rm -vf internal/offload/xdp/bpf_bpfe*.o
	rm -vf internal/offload/xdp/bpf_bpfe*.go

purge-offload: clean

test:
	go test -v

bench: build
	go test -bench=.
