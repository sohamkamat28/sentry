# Stage 01 — Sensor Grid

Four collectors feed one observation stream. One of them is a kernel probe, and it is the only one that can see an endpoint nobody registered.

---

## 1. Scope

**Owns:** capture of every HTTP/SOAP request crossing the estate, from four independent sources; data-class tagging of payloads in kernel memory; delivery of validated observations into `observation`.

**Does not own:** endpoint identity, deduplication, ownership, or classification. This stage emits raw observations with `endpoint_id = NULL`. Stage 03 resolves them.

---

## 2. Deployment units

| Component | Language | Runs as |
|---|---|---|
| `agent/` | Go 1.23 + `cilium/ebpf` | Privileged container, `--pid=host`, one per node |
| `ingest/` | Go 1.23 | Deployment, N replicas behind gRPC LB |
| `worker/app/collectors/` | Python | Celery beat tasks |

Agent resource profile: 256 Mi memory limit, 0.5 CPU. Ring buffers are 4 MiB per CPU and count against the memory limit; `RINGBUF_SIZE_KB` must be lowered on nodes with high CPU counts.

---

## 3. Platform requirements

The agent refuses to start unless all of these hold. Each failure names its own remediation; none is silently worked around.

| Requirement | Check at startup | On failure |
|---|---|---|
| Linux ≥ 5.8 | `uname` | `FATAL: ring buffer requires kernel 5.8+, found %s` |
| BTF available | `/sys/kernel/btf/vmlinux` readable, else `BTF_PATH` | `FATAL: no BTF. Mount /sys/kernel/btf or supply BTF_PATH=/opt/sentinel/btf/<kver>.btf` |
| `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_PTRACE` | `capget` | `FATAL: missing capability %s — run privileged` |
| Host PID namespace | `/proc/self/ns/pid` differs from `/proc/1/ns/pid` → not host | `FATAL: --pid=host required to attach uprobes in peer containers` |
| `debugfs` mounted | `/sys/kernel/debug` | `FATAL: mount -t debugfs none /sys/kernel/debug` |
| RLIMIT_MEMLOCK | raised or `MEMLOCK_UNLIMITED` | Auto-raises; fatal if refused |

### BTF on Docker Desktop

The LinuxKit kernel shipped with Docker Desktop does **not** enable BTF by default. The agent resolves BTF in this order:

1. `/sys/kernel/btf/vmlinux` — present on most distribution kernels and on recent LinuxKit builds.
2. `$BTF_PATH` — an explicitly supplied `.btf` file.
3. `/opt/sentinel/btf/<kernel-release>.btf` — vendored blobs baked into the agent image for the pinned Docker Desktop kernel releases, generated at image build with `pahole -J` against the matching LinuxKit `kernel-dev` image.

If none resolves, the agent exits non-zero with the mount command needed to fix it. It does not fall back to a non-CO-RE build, and it does not fall back to a userspace proxy tap — this deployment is kernel capture or nothing.

### Scope of visibility on macOS

The agent runs inside the Docker Desktop LinuxKit VM and observes processes in that VM — that is, the estate containers. macOS host processes are outside the kernel it is attached to and are not visible. This is a real limit of running Linux tracing on a Darwin host, and it is stated rather than engineered around. The reference estate ([90](90-REFERENCE-ESTATE.md)) is containerised, so every workload under analysis is in scope.

---

## 4. BPF programs

`agent/bpf/tls.bpf.c`, compiled CO-RE with `clang -target bpf -g -O2`, embedded via `bpf2go`.

### 4.1 Maps

```c
struct ssl_args {
    __u64 ssl_ptr;
    __u64 buf_ptr;
    __u32 num;
    __u32 fd;
};

/* entry→exit correlation, keyed by pid_tgid */
struct { __uint(type, BPF_MAP_TYPE_HASH);
         __uint(max_entries, 16384);
         __type(key, __u64); __type(value, struct ssl_args); } active_ssl SEC(".maps");

/* stage 1 filter: ports we care about. Populated from APPROVER_PORTS. */
struct { __uint(type, BPF_MAP_TYPE_HASH);
         __uint(max_entries, 256);
         __type(key, __u16); __type(value, __u8); } approver_ports SEC(".maps");

/* stage 1 filter: cgroups in scope */
struct { __uint(type, BPF_MAP_TYPE_HASH);
         __uint(max_entries, 4096);
         __type(key, __u64); __type(value, __u8); } approver_cgroups SEC(".maps");

/* stage 2 filter: signatures proven to be noise. LRU so it self-trims. */
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH);
         __uint(max_entries, 65536);
         __type(key, __u64); __type(value, __u64); } discarders SEC(".maps");

/* per-pid-fd socket tuple, maintained by the companion kprobes */
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH);
         __uint(max_entries, 65536);
         __type(key, __u64); __type(value, struct sock_tuple); } sock_info SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_RINGBUF);
         __uint(max_entries, 4 * 1024 * 1024); } events SEC(".maps");

/* counters, read by the agent for /metrics */
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
         __uint(max_entries, 4);
         __type(key, __u32); __type(value, __u64); } stats SEC(".maps");
```

### 4.2 Two-stage in-kernel filtering

This is the mechanism that makes the CPU claim true. Both stages run **before** any data is copied to the ring buffer.

**Stage 1 — approvers.** Static allow-lists loaded at startup. An event survives only if its cgroup is in `approver_cgroups` and its destination port is in `approver_ports`. Both are hash lookups, O(1), and reject the overwhelming majority of TLS traffic on a busy host (package managers, telemetry agents, log shippers).

**Stage 2 — discarders.** A dynamic LRU keyed by a 64-bit signature of `(cgroup_id, dst_port, method_hash, path_prefix_hash)`. Userspace writes a signature here when it has classified a flow as known-safe noise — health checks, metrics scrapes, service-mesh probes. The kernel then drops matching events without a ring-buffer write. Being an LRU, a signature that stops appearing ages out, so the filter cannot permanently blind the sensor.

```c
static __always_inline int should_emit(__u64 cgid, __u16 port, __u64 sig) {
    if (!bpf_map_lookup_elem(&approver_cgroups, &cgid)) { bump(STAT_FILTERED_APPROVER); return 0; }
    if (!bpf_map_lookup_elem(&approver_ports,   &port)) { bump(STAT_FILTERED_APPROVER); return 0; }
    if (bpf_map_lookup_elem(&discarders, &sig))         { bump(STAT_FILTERED_DISCARDER); return 0; }
    return 1;
}
```

`sentinel_agent_events_filtered_total{stage}` exports both counters, so the reduction ratio is a measured number rather than an assertion.

### 4.3 OpenSSL probes

`SSL_read` cannot be read at entry — the buffer is empty until the call returns. Both directions therefore use an entry probe to stash arguments and a return probe to read the data.

```c
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_enter, void *ssl, const void *buf, int num) {
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args a = { .ssl_ptr = (__u64)ssl, .buf_ptr = (__u64)buf, .num = num };
    a.fd = ssl_fd_from(ssl);                    /* version-specific BIO offsets */
    bpf_map_update_elem(&active_ssl, &id, &a, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ssl_write_exit, int ret) {
    if (ret <= 0) return 0;
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args *a = bpf_map_lookup_elem(&active_ssl, &id);
    if (!a) return 0;
    handle_plaintext(a, ret, DIR_EGRESS);
    bpf_map_delete_elem(&active_ssl, &id);
    return 0;
}
```

`SSL_read` mirrors this with `DIR_INGRESS`. The plaintext is read with `bpf_probe_read_user` into a per-CPU scratch buffer, capped at `SCAN_BYTES` (512) — enough for a request line and headers.

**Bounding that length needs a compiler barrier.** A clamp alone does not satisfy the verifier, and neither does a clamp plus a mask: the compiler keeps a copy of the pre-clamp value in another register and passes *that* to the helper, so the verifier still sees an unbounded scalar and refuses with `R2 unbounded memory access`. The working form is:

```c
__u32 len = (__u32)ret;
if (len > SCAN_BYTES) len = SCAN_BYTES;
asm volatile("" : "+r"(len));   // force the clamped value to be materialised
```

Two further constraints, both discovered at load time:

- **No variable-length `__builtin_memcpy`.** BPF has no memcpy with a runtime length. The ring-buffer record is fixed size and `data_len` tells userspace how much of it is real.
- **`bpf_ringbuf_reserve` needs a compile-time constant size**, for the same reason.

**Struct offsets.** `ssl_fd_from()` needs `ssl_st → rbio → num`, whose offsets differ across OpenSSL 1.1.1, 3.0, 3.2 and across BoringSSL. The agent carries an offset table in `agent/internal/offsets/`, keyed by the library's GNU build ID, with a fallback keyed on the `OPENSSL_VERSION_NUMBER` string read from the `.rodata` section. An unknown library is attached with `fd = 0`; the observation still carries method, path, host and timing, and peer resolution falls back to the `sock_info` map. Unknown build IDs increment `sentinel_agent_unknown_libssl_total` and are logged once each — the agent degrades a field, never the whole capture.

### 4.4 Go TLS probes

Go binaries statically link `crypto/tls` and never call `libssl`. They need a separate path:

- Symbols `crypto/tls.(*Conn).Read` and `crypto/tls.(*Conn).Write`, resolved from the ELF symbol table (or `.gopclntab` when stripped).
- Go's register ABI (`GOARCH=arm64`/`amd64`, Go ≥ 1.17) passes arguments in registers, and Go's runtime moves goroutine stacks, so a uretprobe cannot rely on the entry stack pointer. The agent instead attaches **uprobes at each RET instruction** in the function body, located by decoding the function's instruction range — the standard workaround, used by Pixie and Speedscale.
- Go version is read from the `.go.buildinfo` section to select the correct argument-register layout.

### 4.5 Socket tuple resolution

Two kprobes maintain `sock_info` so egress events can name their peer without a userspace `/proc` walk per event:

```c
SEC("kprobe/security_socket_connect") /* client side */
SEC("kretprobe/inet_csk_accept")      /* server side */
```

Both write `{saddr, daddr, sport, dport}` keyed by `(pid_tgid << 32) | fd`. Entries are LRU and expire naturally. When lookup misses, `peer_ip` is null and stage 03 resolves the caller from the cgroup instead.

### 4.6 HTTP inference

Performed in kernel on the scratch buffer, bounded, no backtracking.

- **Request**: first token matched against a fixed set (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`). Second token is the path, taken to the first space or `?`. `Host:` and `Authorization:` headers found by a bounded header scan (max 32 headers, max 256 bytes each).
- **Response**: `HTTP/1.x ` prefix then a three-digit status.
- **SOAP**: `POST` with `Content-Type: text/xml` or `application/soap+xml`; `SOAPAction` header captured into `path_raw` as `<path>#<action>` so distinct SOAP operations on one URL remain distinct endpoints.
- **HTTP/2**: frame headers are recognised and HPACK-compressed headers are **not** decoded in kernel. The event is emitted with `path_raw = ""` and a `needs_h2_decode` flag; the agent's userspace side maintains the HPACK dynamic table per connection and completes the record. Getting this wrong silently would undercount, so unresolved H2 events increment `sentinel_agent_h2_undecoded_total`.

Anything not inferable as HTTP or SOAP is dropped in kernel.

---

## 5. Data-class detection

The 0.20 data-exposure weight in CDRI depends on knowing an endpoint returns an Aadhaar number. That determination happens here, in kernel, and the number itself is never retained.

Implemented with `bpf_loop()` (kernel ≥ 5.17) over at most `CLASSIFY_BYTES` (256), using character-class state machines. No regex engine, no backtracking.

**`bpf_loop()` is mandatory here, not stylistic.** Three verifier rejections established the constraints, and all three are load-time failures rather than compile-time ones — clang accepts every version below:

| Attempt | Verifier said | Cause |
|---|---|---|
| `#pragma unroll` over 4096 bytes | *Branch target out of insn range* (assembler) | BPF branch offsets are 16-bit; the unrolled body exceeded them |
| Rolled `for` loop, 256 iterations | *Processed 1000001 insn (limit 1000000)* | The verifier walks every path; a branchy loop body explodes the state space |
| `bpf_loop()`, unbounded counters | *Processed 1000001 insn* again | The verifier tracks each counter's **concrete value** and forks a state per increment — visible in the log as `alpha_run=15, 16, 17…` |
| `bpf_loop()` + clamped counters | **accepted** | 163k instructions processed |

So the rules the implementation must follow:

- Iterate with `bpf_loop()`, so the callback is verified once regardless of iteration count.
- **Clamp every accumulator** (`digit_run ≤ 20`, `alpha_run ≤ 8`). An unbounded counter is a state-space explosion even inside a `bpf_loop` callback.
- Mask buffer indices (`i & (CLASSIFY_BYTES-1)`) rather than comparing, giving a provable bound without a branch.
- Verify Verhoeff and Luhn **in userspace** against the same window that is copied out. Their tables cost more verifier budget than the check is worth in kernel, and run length alone is a strong enough signal to tag.

| Class | Rule |
|---|---|
| `PAN` | `[A-Z]{5}[0-9]{4}[A-Z]` at a token boundary |
| `AADHAAR` | 12 consecutive digits, optionally space/hyphen grouped 4-4-4, passing the Verhoeff checksum |
| `IFSC` | `[A-Z]{4}0[A-Z0-9]{6}` |
| `ACCOUNT_NO` | 9–18 digit run adjacent to a key matching `acct`, `account`, `beneficiary` |
| `CARD` | 13–19 digit run passing Luhn |
| `CVV` | 3–4 digit run adjacent to a key matching `cvv`, `cvc`, `security_code` |
| `DOB` | ISO or `DD/MM/YYYY` date adjacent to a key matching `dob`, `birth` |

Verhoeff and Luhn are implemented as unrolled table lookups — both are fixed-iteration over a bounded digit run.

**The privacy property.** The match result is a bitmask. The scratch buffer holding the plaintext is per-CPU and is overwritten by the next event. The ring-buffer record contains the bitmask and never the matched bytes. The protobuf has no field for a payload ([01 §13](01-DATA-MODEL.md)), and `observation` has no payload column. Retaining a customer identifier is not prevented by policy here — it is prevented by there being nowhere to put one.

---

## 6. Userspace agent

```
agent/internal/
├── btf/        resolution chain, vendored blob loading
├── offsets/    build-id → struct offset tables, .rodata version fallback
├── attach/     process discovery, cross-namespace uprobe attach, reconciliation
├── ringbuf/    consumer, per-CPU drain, loss accounting
├── h2/         HPACK dynamic table per connection
├── classify/   cgroup → service name resolution
└── ship/       batching, gRPC stream, bounded disk queue
```

### 6.1 Cross-mount-namespace attach

The target `libssl.so` lives in another container's filesystem. With `--pid=host`, the agent resolves it through `/proc`:

1. Walk `/proc/*/`; filter by `cgroup` against `TARGET_CGROUP_PREFIX`.
2. Parse `/proc/<pid>/maps` for a mapping whose path matches `libssl.so*`, `libgnutls.so*`, or for statically linked Go, the executable itself.
3. Open the library at **`/proc/<pid>/root/<path>`**, which crosses the mount namespace from the host PID namespace without entering it.
4. Read the ELF, compute the symbol offset for `SSL_write` / `SSL_read`, read the GNU build ID.
5. Attach `link.OpenExecutable(hostPath).Uprobe(sym, prog, &link.UprobeOptions{Offset: off})`.
6. Record `(build_id, inode)` — a second process mapping the same library file is already covered by that uprobe and is not attached twice.

This is the mechanism bpfman and Pixie use for container uprobe attach.

### 6.2 Reconciliation

A 10-second reconcile loop diffs desired attachments against live ones: new containers get probes, exited ones have links closed. Attach failures are retried with backoff and counted in `sentinel_agent_attach_failures_total{reason}`. `sentinel_agent_uprobes_attached` is a gauge, so a silent detach is visible on a dashboard.

### 6.3 Shipping

Events drain from the per-CPU ring buffers into a channel, batch at `BATCH_SIZE` (512) or `BATCH_INTERVAL_MS` (500), whichever comes first, and stream over gRPC. On stream failure, batches spill to a bounded on-disk queue (`AGENT_QUEUE_MB`, default 256) and replay on reconnect. Overflow drops oldest and increments `sentinel_agent_queue_dropped_total`.

Ring-buffer loss is read from the kernel's own counter and exported as `sentinel_agent_ringbuf_lost_total`. The console renders capture as degraded when it is non-zero rather than presenting an undercount as a complete picture.

---

## 7. The other three collectors

Celery beat tasks in `worker/app/collectors/`. Each writes `endpoint_source` rows and, where it observes traffic, `observation` rows.

### 7.1 Gateway — `gateway.py`

Kong Admin API, read-only. `GET /services`, `GET /routes`, `GET /plugins`, paginated by `offset`. Polls every `GATEWAY_POLL_VMINUTES` (15).

Extracts: declared routes, `service.tags` (source of `criticality` when tagged `crit:PAYMENT`), configured plugins → `auth`, `rate_limited`, and TLS policy. Writes `endpoint_source(source='gateway')`.

Kong's own request log is consumed via the `http-log` plugin pointed at `POST /api/v1/ingest/gateway-log`, giving north-south observations with status and latency without polling.

Timeout 5 s, 3 retries, exponential backoff. Unreachable → `readyz` degraded, stage continues on the other three sources.

### 7.2 Code — `code.py`

`GitPython` clones or fetches each repository in `CODE_REPOS`; `tree-sitter` parses ASTs with grammars for Python, Java, Go, JavaScript.

Route extraction is per-framework, declared in `worker/app/collectors/patterns.py`:

| Framework | Node pattern |
|---|---|
| Flask / FastAPI | decorator `@app.route`, `@app.<method>`, `@router.<method>` |
| Spring | annotation `@RequestMapping`, `@GetMapping`, … |
| Go net/http, chi, gin | call to `HandleFunc`, `r.<Method>`, `router.<Method>` |
| Express | `app.<method>(path, …)` |

For each route it also records `git blame` on the defining line — author, email, commit date — which is rung 2 of the ownership ladder at stage 03. Writes `endpoint_source(source='code')` with `detail = {repo, path, line, last_author, last_commit_vday}`.

An endpoint found only in code has never been called and is not a zombie — it is unreleased. Stage 04 distinguishes them by `last_call_vday IS NULL`.

### 7.3 Legacy — `legacy.py`

`zeep` parses WSDL documents at `LEGACY_WSDL_URLS`. Each `wsdl:operation` becomes an endpoint with `method='POST'` and `path_template='<service-path>#<operation>'`, matching the SOAPAction convention the kernel probe emits, so the two sources correlate on identity rather than by heuristic.

Also reads Finacle-format registry exports from `LEGACY_REGISTRY_PATH` (CSV/XML), which is how a core banking platform publishes its interface inventory. Writes `endpoint_source(source='legacy')`.

---

## 8. Ingest service

gRPC bidirectional stream. Per batch:

1. **Validate** — reject a batch whose `agent_version` major differs from the server's contract version (`FAILED_PRECONDITION`). Reject items failing field constraints; count, do not fail the batch.
2. **Stamp** — `vday = current_vday()`. Never taken from the agent, so clock skew on a node cannot corrupt the analysis time base.
3. **Resolve peer** — `cgroup_id` → service name via the `service` table cache; unknown cgroups pass through as null.
4. **Write** — `COPY` into `observation` in batches of 5000. `endpoint_id` is left null.
5. **Count** — increment Redis live counters (`live:obs:<vday>`, `live:src:<source>`) with a 2×`scale_seconds` TTL, feeding the console's capture stream without querying Postgres.
6. **Ack** — `{accepted, rejected, reason}`.

Backpressure: when the write queue exceeds `INGEST_QUEUE_HIGH` (50 000), ingest stops reading from the stream. gRPC flow control propagates this to the agent, which spills to its disk queue. The system slows down rather than losing data silently.

---

## 9. Data model delta

Writes `observation` (all columns except `endpoint_id`), `endpoint_source`, and `endpoint.{auth, tls_version, rate_limited, data_classes}` for endpoints already resolved. Creates no `endpoint` rows — that is stage 03's responsibility.

---

## 10. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/discovery` | `viewer` | Per-source counts, coverage, filter ratio, agent health |
| `GET /api/v1/discovery/stream` | `viewer` | SSE of live captures (from Redis, capped 200/s) |
| `GET /api/v1/discovery/agents` | `viewer` | Per-agent: node, version, uprobes attached, ringbuf loss, queue depth |
| `POST /api/v1/ingest/gateway-log` | service `kong-log` | Kong `http-log` sink |
| `POST /api/v1/collectors/{name}/run` | `analyst` | Force a collector cycle; `202` + task id |
| `POST /api/v1/discovery/discarders` | `admin` | Add a noise signature to the in-kernel discarder map |

`GET /api/v1/discovery` response:

```json
{
  "vday": 47,
  "sources": [
    {"source":"ebpf","endpoints":126,"observations_24v":184203,"exclusive":7,"healthy":true},
    {"source":"gateway","endpoints":119,"observations_24v":98120,"exclusive":0,"healthy":true},
    {"source":"code","endpoints":131,"observations_24v":0,"exclusive":12,"healthy":true},
    {"source":"legacy","endpoints":14,"observations_24v":0,"exclusive":2,"healthy":true}
  ],
  "filter": {"captured": 9812004, "approver_dropped": 9204118, "discarder_dropped": 421883, "emitted": 186003},
  "capture_degraded": false
}
```

`exclusive` is the count of endpoints only that source found. For `ebpf` it is the shadow count, and it is the number that demonstrates why the kernel sensor exists.

---

## 11. Configuration

| Variable | Default | Range |
|---|---|---|
| `INGEST_ENDPOINT` | — | required |
| `BTF_PATH` | `/sys/kernel/btf/vmlinux` | |
| `TARGET_CGROUP_PREFIX` | `/docker` | |
| `APPROVER_PORTS` | `443,8443,8080,9443` | |
| `SCAN_BYTES` | `4096` | 512–8192 |
| `RINGBUF_SIZE_KB` | `4096` | 64–16384, power of two |
| `BATCH_SIZE` / `BATCH_INTERVAL_MS` | `512` / `500` | |
| `AGENT_QUEUE_MB` | `256` | 0 disables spill |
| `RECONCILE_INTERVAL_S` | `10` | |
| `GATEWAY_POLL_VMINUTES` | `15` | |
| `CODE_REPOS` | — | Comma-separated URLs or paths |
| `CODE_SCAN_VHOURS` | `24` | |
| `LEGACY_WSDL_URLS` / `LEGACY_REGISTRY_PATH` | — | |
| `INGEST_QUEUE_HIGH` | `50000` | |

---

## 12. Failure modes

| Condition | Behaviour |
|---|---|
| No BTF | Agent exits non-zero with the mount command. Never starts degraded |
| Unknown `libssl` build ID | Attaches anyway; `fd` unresolved, peer falls back to `sock_info`/cgroup. Counter + single log line |
| Go binary stripped, no `.gopclntab` | That process is skipped, logged once, counted. Other processes unaffected |
| Ring buffer full | Kernel drops; loss counter rises; console marks capture degraded |
| Ingest unreachable | Disk-queue spill, replay on reconnect, oldest dropped on overflow |
| Kong Admin unreachable | Gateway collector marks unhealthy; other sources continue. Shadow detection becomes unreliable and the API reports `gateway.healthy=false` so nothing is inferred from a missing gateway record |
| Repo clone fails | That repo skipped, others proceed, `detail.error` recorded |
| Malformed WSDL | Operation skipped with a logged parse error |

The Kong-unreachable case matters: shadow status is defined by absence from the gateway registry. If the gateway collector is down, absence is not evidence. Stage 03 refuses to assign `SHADOW` while `gateway.healthy` is false.

---

## 13. Security and compliance

- **RBAC**: all discovery routes `viewer`; discarder writes `admin` (a bad discarder signature blinds the sensor, so it is an administrative act and is audited).
- **Audit events**: `discovery.discarder.added`, `collector.forced`.
- **Privilege**: the agent is the only privileged component. It has no network listener, no inbound path, and one egress target. It cannot be reached from the console or the API.
- **Frameworks**: PCI-DSS v4.0 Req 6.4 (runtime encryption validated by observing TLS version per call); DPDP Act §8 (data minimisation — classes recorded, values discarded in kernel); DORA Art 9 (shadow surface discovery).

---

## 14. Tests

**Unit (Go)**
- Offset table selection for each known build ID; unknown ID falls back and flags.
- HTTP request-line and header parsing across malformed, truncated, and pipelined inputs.
- Verhoeff and Luhn against published vectors, including known-invalid numbers.
- HPACK dynamic table across a multi-request connection.

**BPF (privileged Linux container)**
- Every program loads and passes the verifier on the pinned kernel. This test gates the build.
- `should_emit` truth table across approver hit/miss and discarder hit/miss.
- Data-class state machines against a fixture buffer containing one of each class plus near-misses (11-digit number, PAN-shaped string failing the letter pattern, Luhn-failing card).
- Ring-buffer loss is reported, not swallowed, when the consumer is deliberately stalled.

**Integration (testcontainers)**
- A TLS server in one container, a client in another, agent attached: an observation with correct method, path, host, status and `tls_version` reaches Postgres.
- OpenSSL 1.1.1 and 3.x images both produce observations.
- A Go TLS client produces observations.
- A container started **after** the agent is attached within one reconcile interval.
- A request carrying an Aadhaar-shaped value yields `data_classes = {AADHAAR}` and no digits anywhere in the database: `SELECT * FROM observation` dumped and grepped for the value returns nothing.
- Killing ingest mid-stream, then restoring it, loses no observations while under the queue bound.

**E2E**
- `shadow-fx-rate` ([90](90-REFERENCE-ESTATE.md)), which is absent from Kong and from every scanned repo, appears in `endpoint_source` with `source='ebpf'` only.

---

## 15. Acceptance criteria

- [ ] Agent starts on the target kernel, or exits with a specific, actionable message naming the unmet requirement.
- [ ] `sentinel_agent_uprobes_attached` is non-zero for OpenSSL and for Go TLS.
- [ ] Observations from all four sources land in `observation` with correct `vday`.
- [ ] `GET /api/v1/discovery` shows a non-zero `exclusive` count for `ebpf`.
- [ ] `filter.approver_dropped + filter.discarder_dropped` is a measured value, and the reduction ratio is reported rather than asserted.
- [ ] No payload bytes exist anywhere in the database — verified by the grep test above.
- [ ] Agent CPU stays under 1 % of one core at 1000 req/s sustained across the estate, measured with `docker stats` and recorded in the verification run.
- [ ] Stopping and restarting a target container leaves the agent attached to the replacement within `RECONCILE_INTERVAL_S`.
- [ ] Ring-buffer loss under induced stall is visible in `/metrics` and in the console.
