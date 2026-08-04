# Vendored BTF

Blobs for kernels that do not expose `/sys/kernel/btf/vmlinux`.

The LinuxKit kernel shipped with Docker Desktop does not enable BTF by default,
so CO-RE relocation has nothing to resolve against and the agent refuses to
start. Supplying a blob here is the fix.

Generate one against the matching kernel:

```
docker run --rm -v "$PWD:/out" linuxkit/kernel:<version> \
  sh -c 'cp /kernel-dev/vmlinux.btf /out/<kernel-release>.btf'
```

The agent looks for `/opt/sentry/btf/<kernel-release>.btf`, where the release is
read from `/proc/sys/kernel/osrelease`.
