# SENTRY kernel sensor.
#
# Two independent compile steps: clang produces the BPF object, Go produces the
# userspace binary. Neither needs the other's toolchain, which is why the object
# is loaded from disk at runtime rather than embedded.

# ── BPF object ───────────────────────────────────────────────────────────────
# trixie, not bookworm, for clang 19.
#
# The compiler version is a load-bearing dependency here, not a preference.
# Bookworm's clang 14 compiles this source without complaint and produces an
# object the kernel then refuses: the classifier's inner loop expands into a
# state space the verifier walks past its one-million-instruction ceiling. The
# same source through clang 19 loads in 163k. A BPF object is only correct with
# respect to the verifier that has to accept it, so the toolchain is pinned and
# checked rather than left to whatever the base image happens to carry.
FROM debian:trixie-slim AS bpf
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev make \
    && rm -rf /var/lib/apt/lists/*
RUN MAJOR=$(clang --version | sed -n 's/.*clang version \([0-9]*\).*/\1/p') && \
    if [ "$MAJOR" -lt 16 ]; then \
      echo "clang $MAJOR is too old; the object it emits exceeds the BPF verifier's instruction limit. Need 16 or newer." >&2; \
      exit 1; \
    fi
WORKDIR /src
COPY agent/bpf ./bpf
ARG TARGETARCH
RUN ARCH=$(case "$TARGETARCH" in arm64) echo arm64;; *) echo x86;; esac) && \
    clang -target bpf -D__TARGET_ARCH_${ARCH} -O2 -g -Wall -Wno-pass-failed \
          -I bpf/include -c bpf/tls.bpf.c -o /tls.bpf.o

# ── userspace binary ─────────────────────────────────────────────────────────
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ ./
ARG VERSION=dev
ARG TARGETARCH
RUN GOOS=linux GOARCH=${TARGETARCH} CGO_ENABLED=0 \
    go build -ldflags "-X main.version=${VERSION} -s -w" \
    -o /sentry-agent ./cmd/sentry-agent

# ── runtime ──────────────────────────────────────────────────────────────────
# Not distroless: the agent is the one component that must run privileged, and a
# shell is worth having when diagnosing a kernel that refuses to load a probe.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libelf1 zlib1g ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /sentry-agent /usr/local/bin/sentry-agent
COPY --from=bpf   /tls.bpf.o    /opt/sentry/bpf/tls.bpf.o

# Vendored BTF for kernels that do not expose /sys/kernel/btf/vmlinux — notably
# the LinuxKit kernel in Docker Desktop, which does not enable BTF by default.
# Generated at image build with `pahole -J` against the matching kernel-dev image.
COPY agent/btf/ /opt/sentry/btf/

ENV BPF_OBJECT_PATH=/opt/sentry/bpf/tls.bpf.o

# Runs as root by necessity: bpf(), perf_event_open() and cross-namespace uprobe
# attach all require privilege. It has no listener and exactly one egress target.
ENTRYPOINT ["/usr/local/bin/sentry-agent"]
