# 92 — Deployment

Compose is the primary path. Kubernetes manifests exist and are honest about what they require.

---

## 1. Topology

Two compose projects on a shared external network. The estate is separate so it can be torn down and rebuilt without touching the platform, and so its isolation from the platform database is structural rather than conventional.

```
deploy/compose/
├── compose.yaml              platform
├── compose.observability.yaml
├── servicenow-stub/
└── .env.example
estate/compose.yaml           reference workloads
```

```bash
docker network create sentinel-net
docker compose -f estate/compose.yaml up -d
docker compose -f deploy/compose/compose.yaml up -d
```

---

## 2. Services

| Service | Image | Ports | Depends on |
|---|---|---|---|
| `postgres` | `postgres:16-alpine` | 5432 | — |
| `redis` | `redis:7-alpine` | 6379 | — |
| `keycloak` | `quay.io/keycloak/keycloak:26` | 8081 | postgres |
| `kong` | `kong:3.8` | 8000, 8443, 8001 | postgres |
| `minio` | `minio/minio` | 9000, 9001 | — |
| `rsyslog` | `rsyslog/syslog_appliance_alpine` | 514/tcp | — |
| `sentinel-api` | build `api/` | 8000 | postgres, redis, keycloak |
| `sentinel-ingest` | build `ingest/` | 9090 (gRPC) | postgres, redis |
| `sentinel-worker` | build `worker/` | — | postgres, redis, kong, minio |
| `sentinel-beat` | build `worker/` | — | redis |
| `sentinel-agent` | build `agent/` | — | ingest |
| `sentinel-honeypot` | build `honeypot/` | 8088 | postgres |
| `sentinel-console` | build `console/` | 5173 | api |
| `prometheus` / `grafana` | official | 9091 / 3000 | — |

---

## 3. The agent

The only privileged container, and the only one with unusual requirements.

```yaml
sentinel-agent:
  build: ../../agent
  privileged: true
  pid: host
  network_mode: host
  volumes:
    - /sys/kernel/debug:/sys/kernel/debug:rw
    - /sys/kernel/btf:/sys/kernel/btf:ro
    - /sys/fs/bpf:/sys/fs/bpf:rw
    - /proc:/host/proc:ro
    - agent-queue:/var/lib/sentinel/queue
  environment:
    INGEST_ENDPOINT: sentinel-ingest:9090
    TARGET_CGROUP_PREFIX: /docker
  ulimits:
    memlock: -1
```

| Requirement | Reason |
|---|---|
| `privileged` | `bpf()`, `perf_event_open`, uprobe attach |
| `pid: host` | Resolve target processes and cross mount namespaces via `/proc/<pid>/root` |
| `/sys/kernel/debug` | uprobe registration |
| `/sys/kernel/btf` | CO-RE relocation |
| `memlock: -1` | BPF map allocation |

### Docker Desktop on macOS

The agent runs inside the LinuxKit VM and observes containers in that VM. macOS host processes are not visible — see [10 §3](10-STAGE-01-SENSOR-GRID.md).

**BTF is not enabled by default in the LinuxKit kernel.** If `/sys/kernel/btf/vmlinux` is absent, supply a vendored blob:

```bash
docker run --rm -v "$PWD/agent/btf:/out" \
  linuxkit/kernel:$(docker run --rm alpine uname -r | cut -d- -f1) \
  sh -c 'cp /kernel-dev/vmlinux.btf /out/'
```

Then set `BTF_PATH=/opt/sentinel/btf/<kernel-release>.btf`. The agent image already carries blobs for the pinned Docker Desktop releases; this step is for a kernel outside that set.

The agent exits non-zero with the required command if BTF cannot be resolved. It does not start degraded.

---

## 4. Bootstrap ordering

Some initialisation cannot be expressed as a healthcheck dependency and runs as one-shot init containers:

| Order | Job | Does |
|---|---|---|
| 1 | `db-migrate` | `alembic upgrade head`; seeds `vclock`, default `policy_weights`, `policy_setting` |
| 2 | `keycloak-realm` | Imports `deploy/keycloak/sentinel-realm.json` — clients, four roles, dev users |
| 3 | `minio-init` | Creates `sentinel-worm` **with `ObjectLockEnabledForBucket=true`**, sets the default retention |
| 4 | `kong-init` | Applies `deploy/kong/platform.yaml` — the http-log plugin pointing at the ingest route |

Step 3 is not optional. A bucket created without Object Lock cannot have it enabled afterwards, and stage 11 would then archive to storage that permits deletion. `sentinel-worker` fails `readyz` if the bucket lacks Object Lock, so the misconfiguration surfaces immediately rather than at the first retirement.

---

## 5. Health and dependencies

Every service defines a healthcheck; `depends_on` uses `condition: service_healthy`.

```yaml
postgres:
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U sentinel -d sentinel"]
    interval: 5s
    timeout: 3s
    retries: 12

sentinel-api:
  healthcheck:
    test: ["CMD", "curl", "-fsS", "http://localhost:8000/readyz"]
    interval: 10s
    start_period: 30s
```

`start_period` matters on `api`: it runs full audit-chain verification at boot, which takes longer on a populated database than a liveness probe would allow.

---

## 6. Secrets

`.env.example` carries placeholders and is the only committed environment artefact. Real values go in `.env`, gitignored.

```
POSTGRES_PASSWORD=change-me
KONG_ADMIN_TOKEN=change-me
MINIO_ROOT_PASSWORD=change-me
KEYCLOAK_ADMIN_PASSWORD=change-me
SERVICENOW_PASSWORD=
ANTHROPIC_API_KEY=
```

With `SENTINEL_ENV=prod`, services refuse to start on any value matching `change-me`. A prototype that silently runs production with default credentials is a worse outcome than one that fails to start.

`ANTHROPIC_API_KEY` and `SERVICENOW_PASSWORD` may be empty — those integrations degrade as documented in [02 §6](02-PLATFORM-SERVICES.md).

---

## 7. Kubernetes

`deploy/k8s/`. Kustomize base plus `dev` and `prod` overlays. Not the primary path, and complete enough to be run rather than pointed at.

| Resource | Notes |
|---|---|
| `agent-daemonset.yaml` | `hostPID: true`, `privileged`, host mounts as in §3. **One agent per node** — this is why it is a DaemonSet and not a Deployment |
| `api-deployment.yaml` | 2 replicas, HPA on CPU, PDB minAvailable 1 |
| `ingest-deployment.yaml` | 3 replicas, gRPC service with `sessionAffinity: None` |
| `worker-deployment.yaml` | 2 replicas |
| `beat-deployment.yaml` | **Exactly 1 replica**, `strategy: Recreate`. Two schedulers would double-run every stage |
| `honeypot-deployment.yaml` | 2 replicas |
| `console-deployment.yaml` | nginx, 2 replicas |
| `postgres-statefulset.yaml` | Single writer. HA is out of scope ([00 §12](00-ARCHITECTURE.md)) |
| `networkpolicy.yaml` | See below |
| `secrets.yaml` | `ExternalSecret` stubs; no committed values |

### Network policy

Three rules that carry security weight:

- **Honeypot egress**: to Postgres only. It receives attacker traffic; it must not be able to reach the estate.
- **Agent ingress**: none. The agent has no listener and accepts no connection.
- **Kong Admin (8001)**: reachable only from `sentinel-worker`. The control plane is not exposed beyond the one component that writes to it.

### Resource requests

| Service | Request | Limit |
|---|---|---|
| `agent` | 100m / 128Mi | 500m / 256Mi |
| `ingest` | 200m / 256Mi | 1000m / 512Mi |
| `api` | 200m / 512Mi | 1000m / 1Gi |
| `worker` | 500m / 1Gi | 2000m / 2Gi |
| `honeypot` | 50m / 64Mi | 200m / 128Mi |

The worker limit accommodates the Isolation Forest fit and the shadow-container Judge run, which are the two memory peaks in the system.

---

## 8. Images

Multi-stage, non-root, minimal base.

| Service | Base | User |
|---|---|---|
| Go services | `gcr.io/distroless/static` | 65532 |
| `agent` | `debian:bookworm-slim` | root — required for BPF |
| Python services | `python:3.12-slim` | 1000 |
| `console` | `nginxinc/nginx-unprivileged` | 101 |

The agent is the one root container, and it is the one that needs kernel privileges. Everything else drops privileges.

Images are tagged with the git SHA. `latest` is not used in any compose file or manifest.

---

## 9. CI

`.github/workflows/ci.yaml`:

1. `buf lint` + `buf breaking` against `main`.
2. `go vet`, `golangci-lint`, `go test ./...`.
3. `ruff`, `mypy --strict` on `api/` and `worker/`, `pytest` with coverage gate.
4. `tsc --noEmit`, `vitest`, the console prose lint.
5. **BPF verifier test** in a privileged Ubuntu container — every program must load. This gates the build.
6. Alembic `upgrade → downgrade → upgrade` schema-hash equality.
7. Integration tests with testcontainers (Postgres, Redis, Kong, MinIO).
8. E2E against `ESTATE_PROFILE=minimal` with `VCLOCK_SCALE=1`.
9. Build and push images on `main`.

Step 5 is non-negotiable. A BPF program that fails the verifier fails at load time on the target machine, and finding that during a demonstration is the worst possible moment.

---

## 10. Operations

**Backup**: `pg_dump` on a schedule; MinIO archive is already immutable and does not need backing up — that is what Object Lock is for.

**Upgrade**: migrations run before the new image rolls. Engine version bumps invalidate affected derived rows per [01 §14](01-DATA-MODEL.md); the pipeline recomputes them on the next cycle.

**Partition maintenance**: `worker` creates partitions 7 vdays ahead and archives-then-drops past retention. A missing future partition blocks ingest, so the job runs hourly regardless of vclock scale.

**Clock**: `POST /api/v1/clock/pause` freezes analysis while capture continues. Used to hold a state during a demonstration without stopping the sensor.

---

## 11. Acceptance criteria

- [ ] `docker network create` + two `compose up` commands bring the whole system to `readyz`-green with no further manual steps.
- [ ] The agent starts and attaches uprobes, or exits with a specific actionable message.
- [ ] `minio-init` creates the bucket with Object Lock enabled, and `worker` fails `readyz` if it did not.
- [ ] `SENTINEL_ENV=prod` with a default password refuses to start.
- [ ] Kong Admin is unreachable from any container except `sentinel-worker`.
- [ ] The honeypot cannot reach any estate service, verified from inside its container.
- [ ] Kubernetes manifests apply cleanly to a local cluster and the agent DaemonSet reaches Ready.
- [ ] `beat` runs exactly one replica.
- [ ] CI fails on a BPF program that does not pass the verifier.
- [ ] No image is tagged `latest`.
