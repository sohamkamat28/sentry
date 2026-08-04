# SENTRY agent build.
#
# The BPF object and the Go binary compile independently: the object is loaded
# from disk at runtime rather than embedded, so a Go build does not require
# clang and a BPF build does not require Go.

CLANG    ?= clang
STRIP    ?= llvm-strip
ARCH     ?= arm64
VERSION  ?= dev

# Homebrew LLVM on macOS; Apple's clang has no bpf target.
ifeq ($(shell uname -s),Darwin)
CLANG := /opt/homebrew/opt/llvm/bin/clang
STRIP := /opt/homebrew/opt/llvm/bin/llvm-strip
endif

BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g -Wall \
              -Wno-unused-function -Wno-pass-failed -I bpf/include

.PHONY: all bpf go test verify clean

all: bpf go

bpf: bin/tls.bpf.o

bin/tls.bpf.o: bpf/tls.bpf.c bpf/vmlinux.h
	@mkdir -p bin
	$(CLANG) $(BPF_CFLAGS) -c bpf/tls.bpf.c -o $@
	@echo "built $@"

# Cross-compiles from any host. cilium/ebpf is Linux-only, so darwin is not a
# valid target and is not offered.
go:
	@mkdir -p bin
	GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION) -s -w" \
		-o bin/sentry-agent-linux-arm64 ./cmd/sentry-agent
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION) -s -w" \
		-o bin/sentry-agent-linux-amd64 ./cmd/sentry-agent
	@echo "built bin/sentry-agent-linux-{arm64,amd64}"

# vet targets linux because the agent is Linux-only; the contract test is pure
# ELF parsing and runs on the build host.
test: bpf
	GOOS=linux go vet ./...
	go test ./internal/bpfcontract ./internal/ship ./internal/identity ./internal/elfsym -v

# The full check. `verify` requires the object to exist, so a Go change that
# renames a map or program fails here rather than at load time on the host.
verify: bpf
	go test ./internal/bpfcontract ./internal/ship ./internal/identity ./internal/elfsym -v

clean:
	rm -rf bin

# Loads the object into the running kernel and reports the verifier's verdict.
# Requires Docker; this is the check that separates "clang accepted it" from
# "the kernel will run it", and the two are not the same bar.
KERNEL_TEST_IMAGE ?= debian:bookworm-slim
.PHONY: kernel-test
kernel-test: bpf
	@GOOS=linux GOARCH=$(shell docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/;s/x86_64/amd64/') \
		CGO_ENABLED=0 go build -o bin/bpfload ./tools
	docker run --rm --privileged --pid=host \
		-v "$(PWD)/bin/bpfload:/bpfload:ro" \
		-v "$(PWD)/bin/tls.bpf.o:/tls.bpf.o:ro" \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		-v /sys/fs/bpf:/sys/fs/bpf \
		--ulimit memlock=-1:-1 \
		$(KERNEL_TEST_IMAGE) /bpfload /tls.bpf.o
