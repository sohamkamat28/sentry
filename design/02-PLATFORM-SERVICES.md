# 02 — Platform Services

Cross-cutting machinery every service depends on: configuration, identity, the audit ledger, observability, and the API conventions.

---

## 1. Configuration

Twelve-factor. Environment variables only; no config files in images. Python services use `pydantic-settings`, Go services use `envconfig`. Both fail fast on a missing required value — a service never starts with a defaulted secret.

### Shared

| Variable | Default | Notes |
|---|---|---|
| `SENTINEL_ENV` | `dev` | `dev`\|`staging`\|`prod`. `prod` refuses to start with any default secret |
| `LOG_LEVEL` | `info` | |
| `LOG_FORMAT` | `json` | `console` for local |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | Tracing disabled when unset |
| `DATABASE_URL` | — | **required** `postgresql+psycopg://…` |
| `REDIS_URL` | — | **required** |

### `api`

| Variable | Default | Notes |
|---|---|---|
| `OIDC_ISSUER` | — | **required**. Keycloak realm URL |
| `OIDC_AUDIENCE` | `sentinel-api` | |
| `OIDC_JWKS_CACHE_S` | `300` | |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated |
| `AUDIT_VERIFY_ON_BOOT` | `true` | Full chain verification at startup |

### `agent`

| Variable | Default | Notes |
|---|---|---|
| `INGEST_ENDPOINT` | — | **required** gRPC target |
| `BTF_PATH` | `/sys/kernel/btf/vmlinux` | Fallback `/opt/sentinel/btf/<kver>.btf` |
| `TARGET_CGROUP_PREFIX` | `/docker` | Restricts attach scope |
| `RINGBUF_SIZE_KB` | `4096` | Per-CPU |
| `BATCH_SIZE` / `BATCH_INTERVAL_MS` | `512` / `500` | Egress batching |
| `APPROVER_PORTS` | `443,8443,8080,9443` | Seeds the in-kernel approver map |

### `worker`

| Variable | Default | Notes |
|---|---|---|
| `KONG_ADMIN_URL` | — | **required** for stages 10/11/13 |
| `KONG_ADMIN_TOKEN` | — | |
| `MINIO_ENDPOINT` / `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | — | WORM archive |
| `WORM_BUCKET` | `sentinel-worm` | Object Lock enabled at creation |
| `WORM_RETAIN_YEARS` | `7` | COMPLIANCE mode |
| `SERVICENOW_URL` / `SERVICENOW_USER` / `SERVICENOW_PASSWORD` | — | Stage 10 |
| `SIEM_HOST` / `SIEM_PORT` / `SIEM_FORMAT` | — / `514` / `cef` | `cef`\|`leef` |
| `ANTHROPIC_API_KEY` | — | Absent → template generator, labelled |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-5` | |
| `SCAN_INTERVAL_VHOURS` | `6` | |

**Secrets** are injected from Docker secrets or Kubernetes `Secret` volumes, never baked into images or compose files. `deploy/compose/.env.example` ships with placeholder values and is the only committed env artefact.

---

## 2. Identity

Keycloak realm `sentinel`, OIDC authorisation code flow with PKCE for the console, client credentials for service-to-service.

### Roles

| Role | Grants |
|---|---|
| `viewer` | Read every analytical surface. No mutation |
| `analyst` | Everything in `viewer`, plus run pipeline stages, trace impact, run API Judge, propose controls, tune CDRI weights |
| `approver` | Everything in `analyst`, plus apply controls to Kong, advance decommission phases, issue certificates, approve change requests |
| `admin` | Everything, plus virtual clock control, policy settings, partition maintenance, audit export |

The `analyst`/`approver` split is the technical expression of the governance requirement: the person who proposes a production change is not automatically the person who authorises it. An `analyst` can prepare a fully evidenced control and cannot apply it.

### Enforcement

A single dependency, applied per route:

```python
# api/app/security.py
def require(*roles: str) -> Callable:
    async def _dep(claims: Claims = Depends(verify_token)) -> Claims:
        if not set(roles) & set(claims.realm_roles):
            raise PermissionError(code="ROLE_REQUIRED", detail={"required": list(roles)})
        return claims
    return _dep
```

Route-level matrix:

| Route pattern | Role |
|---|---|
| `GET /api/v1/**` | `viewer` |
| `POST /api/v1/pipeline/**` | `analyst` |
| `POST /api/v1/impact/*/trace` | `analyst` |
| `POST /api/v1/remediation/*/judge` | `analyst` |
| `POST /api/v1/policy/weights` | `analyst` |
| `POST /api/v1/remediation/*/apply` | `approver` |
| `POST /api/v1/remediation/cr/*/approve` | `approver` |
| `POST /api/v1/decommission/**` | `approver` |
| `POST /api/v1/zerotrust/*/harden` | `approver` |
| `POST /api/v1/clock/**`, `/api/v1/policy/settings` | `admin` |
| `POST /api/v1/ingest/gate` | service token `ci-gate` |

Token verification: RS256 against cached JWKS, `iss`/`aud`/`exp` validated, 60 s clock skew allowance. `claims.sub` becomes `audit_entry.actor`.

---

## 3. API conventions

- Base path `/api/v1`. JSON only.
- **Pagination**: `?limit=` (default 50, max 500) and `?cursor=`. Responses carry `{"items": [...], "next_cursor": "..."}`. No offset pagination on `observation` or `probe`.
- **Filtering**: explicit query params per route. No generic query language.
- **Mutations are idempotent** where the operation is naturally repeatable. `POST /remediation/{id}/apply` with an already-applied control returns `409 conflict` with the existing `control.id` rather than creating a duplicate Kong plugin.
- **Long operations** return `202 Accepted` with `{"task_id": "..."}`. Progress at `GET /api/v1/tasks/{task_id}`. Pipeline runs, judge runs, and repo scans use this; nothing blocks an HTTP request for more than 10 s.
- **Live updates**: `GET /api/v1/stream` is a Server-Sent Events channel emitting `estate.changed`, `stage.completed`, `probe.captured`, `alert.raised`. The console subscribes once and invalidates local caches by event type. No polling loops.

---

## 4. Audit ledger

Append-only and tamper-evident. Hash chained so that altering or removing any historical entry invalidates every entry after it.

```python
# api/app/audit/ledger.py
def _entry_hash(prev: bytes, e: AuditEntry) -> bytes:
    payload = canonical_json({
        "seq": e.seq, "wall_ts": e.wall_ts.isoformat(), "vday": e.vday,
        "actor": e.actor, "action": e.action, "target": e.target, "detail": e.detail,
    })
    return hashlib.blake2b(prev + payload.encode(), digest_size=32).digest()
```

- `canonical_json` sorts keys and uses fixed separators, so the hash is stable across serialiser versions.
- Genesis entry has `prev_hash = b"\x00" * 32`.
- Writes go through a single `SELECT … FOR UPDATE` on the tail row, making concurrent appends serialisable. Throughput is bounded and adequate: audit entries are governance events, not telemetry.
- `GET /api/v1/audit/verify` (admin) walks the chain and returns `{"ok": true, "entries": N}` or the `seq` of the first break.
- `AUDIT_VERIFY_ON_BOOT=true` runs this at startup and refuses to serve on a broken chain.

**What is audited.** Every state change reachable from an `approver` or `admin` route, plus every automated action with production effect: control apply/revert, decommission phase transitions, certificate issuance, weight changes, clock changes, CR submission and approval, honeypot activation, gateway hardening, WORM writes. Read operations are not audited — they are traced.

**What is not in the ledger.** Analytical results. A CDRI score is not an audit event; the weight change that altered it is.

---

## 5. Observability

### Logging

Structured JSON to stdout. Required fields on every line: `ts`, `level`, `service`, `msg`, `trace_id`, `span_id`. Domain fields go in a `fields` object; nothing is interpolated into `msg`.

Never logged: request or response bodies, `Authorization` header values, `ANTHROPIC_API_KEY`, Kong admin token, database URL password component. A redacting filter enforces this at the handler level rather than relying on call sites.

### Metrics

Prometheus at `/metrics` on every service.

| Metric | Type | Labels |
|---|---|---|
| `sentinel_observations_ingested_total` | counter | `source`, `node` |
| `sentinel_ingest_batch_seconds` | histogram | |
| `sentinel_agent_events_captured_total` | counter | `library`, `node` |
| `sentinel_agent_events_filtered_total` | counter | `stage` (`approver`\|`discarder`) |
| `sentinel_agent_ringbuf_lost_total` | counter | `node` |
| `sentinel_agent_uprobes_attached` | gauge | `library`, `node` |
| `sentinel_stage_duration_seconds` | histogram | `stage` |
| `sentinel_stage_records` | gauge | `stage` |
| `sentinel_endpoints_total` | gauge | `lifecycle`, `governance` |
| `sentinel_cdri_tier_total` | gauge | `tier` |
| `sentinel_control_apply_total` | counter | `kind`, `result` |
| `sentinel_external_call_seconds` | histogram | `system`, `result` |
| `sentinel_probe_captured_total` | counter | `endpoint_id` |

`sentinel_agent_ringbuf_lost_total` is the honest one. If the kernel drops events because userspace is too slow, that number rises and the console shows degraded capture rather than presenting an undercount as fact.

### Tracing

OpenTelemetry. Spans propagate from the console through `api` into Celery tasks via headers. Span names are stable identifiers (`stage.06.cdri`, `kong.plugin.create`), never interpolated strings.

### Health

Every service exposes:

- `GET /healthz` — process alive. Never touches a dependency.
- `GET /readyz` — dependencies reachable. Returns `503` with a per-dependency map when not.

```json
{"ready": false, "checks": {"postgres": "ok", "redis": "ok", "kong": "unreachable"}}
```

Kubernetes liveness uses `/healthz`, readiness uses `/readyz`. Conflating them causes restart loops when a downstream is merely slow.

---

## 6. Degradation policy

The system has one rule for unavailable dependencies: **produce less, never produce fiction.**

| Dependency down | Behaviour |
|---|---|
| `agent` → `ingest` | Agent buffers to a bounded on-disk queue (`AGENT_QUEUE_MB`, default 256), drops oldest on overflow, and increments `sentinel_agent_queue_dropped_total`. Console shows capture as degraded |
| Postgres | `api` returns `503 dependency`. Workers retry with exponential backoff. No cached-value fallback |
| Redis | Live counters and SSE degrade; analytical routes unaffected. Celery is unavailable, so pipeline runs queue at the API and return `503` |
| Kong | Control application fails with `503 dependency`, `control.state='FAILED'`, audit event recorded. **No control is ever marked `APPLIED` without a 2xx from Kong carrying a plugin id** |
| MinIO | Phase D blocks. An endpoint cannot reach `RETIRED` without a WORM object and a retention date. Certificate issuance fails |
| ServiceNow | Change request stored `state='FAILED'` with the payload retained; retried by beat. The virtual patch is unaffected — that is the entire point of splitting them |
| Anthropic | Narrative generated by template, `finding.generator='template'`, surfaced in the console as such |
| SIEM | Events spool to a bounded Redis list and drain on recovery. Overflow drops oldest and counts it |

---

## 7. Data protection

- **In kernel**: payloads are pattern-matched and discarded in the same BPF program. No payload leaves the kernel. Enforced by the wire format having no payload field.
- **In transit**: agent→ingest is gRPC over mTLS in `prod`. Console→api is HTTPS. Kong Admin API is reached over the internal network with a token, never exposed publicly.
- **At rest**: Postgres volume encryption is a deployment concern and documented in [92](92-DEPLOYMENT.md). Secrets live in Docker/Kubernetes secret stores.
- **Data classes** are stored as labels (`{'AADHAAR'}`) with no count and no value. Reconstruction of a customer identifier from the database is impossible because the value never entered it.
- **Probe bodies** are hashed, not stored.

---

## 8. Testing baseline

Applies to every service; per-stage specifics live in the stage documents.

| Layer | Tool | Requirement |
|---|---|---|
| Unit | `pytest` / `go test` | Every engine is a pure function tested against fixtures. ≥85% on `worker/app/engines` |
| Contract | `buf breaking`, `schemathesis` | Proto changes checked against `main`; REST responses validated against OpenAPI |
| Integration | `testcontainers` | Real Postgres, Redis, Kong, MinIO. No mocked clients for systems we ship against |
| E2E | `pytest` + compose | The full acceptance run in [93](93-VERIFICATION.md) |
| BPF | `go test` in a privileged Linux container | Verifier-load test for every program; map behaviour tested against synthetic events |

External systems with no local runtime (ServiceNow, Anthropic) are tested against recorded-cassette fixtures for shape and against live credentials in a manual pre-release check. The cassette is generated from a real response, never hand-written.

---

## 9. Acceptance criteria

- [ ] `docker compose up` yields all services `readyz`-green with no manual step.
- [ ] A request without a token gets `401`; with `viewer` to an `approver` route gets `403` and no state change.
- [ ] `GET /api/v1/audit/verify` returns `ok: true` on a populated database.
- [ ] Manually updating one `audit_entry.detail` row makes `verify` return the correct breaking `seq`.
- [ ] Every service exposes `/metrics`, `/healthz`, `/readyz`; `readyz` returns `503` with a named failing check when Kong is stopped.
- [ ] Stopping Kong and attempting a control apply yields `503 dependency`, `control.state='FAILED'`, and an audit entry — and no Kong plugin exists.
- [ ] Unsetting `ANTHROPIC_API_KEY` produces findings with `generator='template'`, visibly labelled in the console.
- [ ] `grep -rE '"(Authorization|api[_-]?key|password)"' ` over captured log output returns no values.
- [ ] Alembic `upgrade → downgrade → upgrade` reaches an identical schema hash in CI.
