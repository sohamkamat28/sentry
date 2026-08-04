FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libelf1 zlib1g && rm -rf /var/lib/apt/lists/*
COPY sentry-agent-linux-arm64 /usr/local/bin/sentry-agent
COPY tls.bpf.o /opt/sentry/bpf/tls.bpf.o
ENV BPF_OBJECT_PATH=/opt/sentry/bpf/tls.bpf.o
ENTRYPOINT ["/usr/local/bin/sentry-agent"]
