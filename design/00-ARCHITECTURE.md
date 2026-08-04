# 00 — Architecture

System topology, build order, and the conventions every other document depends on.

---

## 1. What the system does

SENTINEL discovers every HTTP/SOAP endpoint in a service estate — including endpoints that traverse no gateway and appear in no repository — classifies each on lifecycle and governance axes, scores its risk, proves what breaks before anything is removed, applies gateway-level controls, retires dead endpoints through a phased sunset, and serves retired routes as instrumented traps.

**Everything is observed.** No component in this system invents an endpoint, a call count, or a risk input. If a figure appears in the console, a sensor produced it or an engine computed it from sensor output.

---

## 2. Deployment units

Six services. Go on the hot path (single static binary, no runtime, no GIL); Python where the analysis libraries live (scikit-learn, NetworkX, datasketch, zeep, tree-sitter).

| Unit | Language | Runs as | Responsibility |
|---|---|---|---|
| `agent/` | Go 1.23 + `cilium/ebpf` | Privileged DaemonSet / container | Kernel sensor. uprobes on TLS libraries, two-stage in-kernel filtering, data-class tagging, batched gRPC egress |
| `ingest/` | Go 1.23 | Deployment, N replicas | gRPC receiver → validation → `COPY` into partitioned tables; Redis live counters |
| `api/` | Python 3.12 / FastAPI | Deployment, N replicas | REST control plane, OIDC/RBAC, orchestration, audit ledger writes |
| `worker/` | Python 3.12 / Celery | Deployment + beat | Stages 02–14 engines, non-kernel collectors, API Judge, Kong actuator, SIEM emitter, WORM writer |
| `honeypot/` | Go 1.23 | Deployment | Serves retired routes, watermarked synthetic responses, probe capture |
| `console/` | React 18 + TS + Vite | Static, nginx | Operator UI |

**Shared contracts** live in `contracts/` — protobuf for the agent→ingest wire format, JSON Schema for the REST surface, generated into Go and Python packages. Neither side hand-writes the other's types.

### Infrastructure

| Component | Version | Purpose |
|---|---|---|
| PostgreSQL | 16 | System of record. Partitioned observation tables |
| Redis | 7 | Live counters, Celery broker, LSH index cache, rate limiting |
| Kong Gateway | 3.8 (OSS) | Real data plane. Virtual patches, sunset headers, 410, canary weights, mTLS |
| MinIO | RELEASE.2024-10+ | WORM archive, S3 Object Lock COMPLIANCE mode |
| Keycloak | 26 | OIDC issuer, four realm roles |
| rsyslog + HEC receiver | — | CEF/LEEF SIEM sink |
| Prometheus + Grafana | — | Metrics, dashboards |

---

## 3. Repository layout

```
sentinel/
├── contracts/
│   ├── proto/sentinel/v1/{observation,control}.proto
│   ├── openapi/sentinel-api.yaml
│   └── gen/{go,python}/              generated, committed
├── agent/
│   ├── bpf/{tls.bpf.c,filter.bpf.c,vmlinux.h}
│   ├── internal/{attach,btf,offsets,ringbuf,classify,ship}/
│   └── cmd/sentinel-agent/main.go
├── ingest/
│   ├── internal/{grpc,batch,store,counters}/
│   └── cmd/sentinel-ingest/main.go
├── api/
│   ├── app/{main,config,deps,security}.py
│   ├── app/routers/*.py
│   ├── app/audit/ledger.py
│   └── migrations/                   alembic
├── worker/
│   ├── app/collectors/{gateway,code,legacy}.py
│   ├── app/engines/*.py              stages 02–14
│   ├── app/actuators/{kong,servicenow,siem,worm}.py
│   ├── app/judge/{replay,diff,score}.py
│   └── app/tasks.py                  celery entrypoints
├── honeypot/
│   ├── internal/{routes,synth,watermark,capture}/
│   └── cmd/sentinel-honeypot/main.go
├── console/src/{views,components,lib}/
├── estate/                           reference workloads — see 90
├── deploy/{compose,k8s}/
└── design/                           this folder
```

---

## 4. Stage → service map

The fourteen stages are analytical stages, not services. This is where each executes.

| Stage | Name | Executes in | Trigger |
|---|---|---|---|
| 01 | Sensor Grid | `agent` + `ingest` + `worker` (3 collectors) | Continuous / poll |
| 02 | Baseline & Confidence | `worker` | Beat, every vday |
| 03 | Correlation | `worker` | Beat, 6 vhours |
| 04 | Classification | `worker` | After 03 |
| 05 | Behavioural Intelligence | `worker` | After 04 |
| 06 | CDRI | `worker` | After 05 |
| 07 | Pre-Zombie Forecast | `worker` | After 04; writes back to 04 record |
| 08 | Findings & Explainability | `worker` + Anthropic | After 06, 07, 09 |
| 09 | Blast Radius | `worker` | After 03 |
| 10 | Remediation | `worker` + `judge` + Kong + ServiceNow | Operator-initiated |
| 11 | Decommission | `worker` + Kong + MinIO | Operator-initiated, phase timer |
| 12 | Honeypot & Resurrection | `honeypot` + `worker` | Continuous / on registration |
| 13 | Zero-Trust | `worker` + Kong | After 06; operator-applied |
| 14 | Operations | `worker` beat + `api` webhooks | Every 6 vhours |

---

## 5. The pipeline DAG

Stage order is enforced in code, not documentation. `worker/app/pipeline.py` declares:

```python
STAGE_DEPS: dict[int, frozenset[int]] = {
    1:  frozenset(),
    2:  frozenset({1}),
    3:  frozenset({1, 2}),
    4:  frozenset({3}),
    5:  frozenset({4}),      # behaviour needs lifecycle context
    6:  frozenset({5}),      # CDRI consumes r6 from behaviour
    7:  frozenset({4}),      # writes pre_zombie back onto the stage-4 record
    9:  frozenset({3}),
    8:  frozenset({6, 7, 9}),
    13: frozenset({6}),
    14: frozenset({6}),
}
```

Two properties this encodes, both of which were defects in the source architecture:

- **05 precedes 06.** CDRI's formula takes a behavioural-anomaly term r₆. A pipeline where CDRI ran first would read an input from its own future.
- **07 writes back to 04.** The pre-zombie flag is computed at forecast time and stamped onto the classification record. Stage 04 displays it; it does not produce it. This is the one legal back-edge in the graph and it is explicit.

A stage invoked with an unsatisfied dependency raises `StageDependencyError` and records a `pipeline.stage.blocked` audit event. There is no implicit ordering by task submission time.

---

## 6. Time — the virtual clock

Every window in this system (30-day baseline, 90-day correlation window, 90-day sunset) is computed on **virtual days**, not wall clock.

```
vday(t) = floor((t - vclock.epoch_wall) / vclock.scale_seconds)
```

`scale_seconds` is configuration. **In production it is 86400 and `vday` is a calendar day.** For demonstration it is 30, and a 90-day lifecycle completes in 45 minutes.

This is not a simulation layer bolted on. It is the system's only time base, and the same code path serves both settings. Traffic, capture, and classification are real at any scale; only elapsed wall time differs.

Consequences, binding on every stage:

- `observation` is **partitioned by `vday`**, so window queries prune partitions identically at either scale.
- No engine calls `datetime.now()` for analysis. Engines take `vday` from `worker.app.clock.current_vday(session)`.
- Wall timestamps are retained on every row for forensics and for SIEM correlation, and are never used for windowing.

---

## 7. Identifier scheme

Deterministic, content-derived, stable across restarts and re-discovery.

| Entity | Form | Derivation |
|---|---|---|
| Service | `svc_<12hex>` | blake2s(`name`) |
| Endpoint | `ep_<16hex>` | blake2s(`method` ⋮ `path_template` ⋮ `service_id`) |
| Observation | `bigserial` | — |
| Finding | `fnd_<16hex>` | blake2s(`endpoint_id` ⋮ `vday` ⋮ `engine_version`) |
| Change request | ServiceNow `sys_id` | assigned by ServiceNow |
| Audit entry | `bigserial` + chain hash | see [02](02-PLATFORM-SERVICES.md) |

`path_template` is the normalised path — numeric and UUID segments collapse to `{id}`, so `/accounts/8814/balance` and `/accounts/9902/balance` are one endpoint. Normalisation rules are owned by stage 03 and specified in [12-STAGE-03](12-STAGE-03-CORRELATION.md).

---

## 8. Error taxonomy

All services emit one error envelope. HTTP status is set from `class`.

```json
{
  "error": {
    "class": "validation|not_found|conflict|dependency|permission|internal",
    "code": "STAGE_DEPENDENCY_UNSATISFIED",
    "message": "stage 6 requires stage 5",
    "detail": {"stage": 6, "missing": [5]},
    "trace_id": "0af7651916cd43dd8448eb211c80319c"
  }
}
```

| class | HTTP | Retryable |
|---|---|---|
| `validation` | 422 | no |
| `not_found` | 404 | no |
| `conflict` | 409 | no |
| `permission` | 403 | no |
| `dependency` | 503 | yes, with backoff |
| `internal` | 500 | yes |

`dependency` is reserved for a named external system being unavailable (Kong, MinIO, ServiceNow, Anthropic). It always names the system in `detail.system`. A dependency failure never silently degrades a result — see each stage's *Failure modes* section.

---

## 9. Versioning

- **REST**: path-prefixed `/api/v1`. Breaking changes mint `/api/v2`; both served during a deprecation window, with `Sunset` headers on v1. The platform applies to itself the convention it enforces on others.
- **Protobuf**: `sentinel.v1`. Field numbers are never reused. The agent sends its build version in stream metadata; ingest rejects a major mismatch with `FAILED_PRECONDITION`.
- **Engines**: every engine module exports `VERSION: str`. It is written onto every row the engine produces, so a score can always be traced to the code that computed it. Changing an algorithm requires bumping it; a migration backfills or invalidates prior rows.

---

## 10. Build order

Each step is independently runnable and testable. Do not begin a step before its predecessor passes its acceptance criteria.

1. **`contracts/`** — proto + OpenAPI, code generation wired into the build.
2. **Foundation** — Postgres schema and Alembic migrations ([01](01-DATA-MODEL.md)), config, Keycloak realm, audit ledger, health/metrics ([02](02-PLATFORM-SERVICES.md)).
3. **`estate/`** ([90](90-REFERENCE-ESTATE.md)) — the workloads must exist before there is anything to discover. Build this before the agent.
4. **`agent/` + `ingest/`** ([10](10-STAGE-01-SENSOR-GRID.md)) — the highest-risk component. Prove endpoints appear in `observation` from kernel capture alone before writing any engine.
5. **Collectors** — gateway, code, legacy ([10](10-STAGE-01-SENSOR-GRID.md)).
6. **Engines 02–09** — pure functions over the observation store, in DAG order.
7. **Actuators** — Kong, ServiceNow, SIEM, WORM ([19](19-STAGE-10-REMEDIATION.md), [20](20-STAGE-11-DECOMMISSION.md), [23](23-STAGE-14-OPERATIONS.md)).
8. **`honeypot/`** ([21](21-STAGE-12-THREAT.md)).
9. **`console/`** ([91](91-CONSOLE.md)).
10. **Deployment and verification** ([92](92-DEPLOYMENT.md), [93](93-VERIFICATION.md)).

Step 4 is where this project succeeds or fails. If kernel capture does not work, no amount of downstream engineering makes the system real. Prove it first.

---

## 11. Cited work

Two papers are load-bearing and are cited where the algorithm is implemented:

- **Liu, Ting & Zhou, *Isolation-Based Anomaly Detection*, ACM TKDD 2012** — the Isolation Forest construction used at stage 05. Cited in [14-STAGE-05](14-STAGE-05-BEHAVIOUR.md).
- **Springer 2021, monitoring cadence analysis** — the basis for the 6-hour scan interval at stage 14. Cited in [23-STAGE-14](23-STAGE-14-OPERATIONS.md).

> **Open item.** The supporting material claims four peer-reviewed papers. Only these two are cited anywhere in it. The other two must be named or the claim amended. No citation has been invented to close the gap.

---

## 12. Explicitly out of scope

Named here so absence reads as a decision rather than an omission.

| Not built | Why |
|---|---|
| Multi-tenant isolation | Single-institution deployment. Tenancy would change every table's primary key |
| HA Postgres / failover | Single-writer topology. The prototype demonstrates function, not availability engineering |
| Kernel-level enforcement (blocking in BPF) | The agent observes only. Enforcement happens at the gateway, where it is auditable and reversible |
| Automatic code-fix commits | FFIEC DA&M requires human authorisation for production change. The system generates and evidences; it does not merge |
| Windows / non-Linux workload capture | uprobes require Linux. Stated as a platform requirement, not worked around |
| PII value storage | Data classes are recorded; values never leave kernel memory. See [10-STAGE-01 §7](10-STAGE-01-SENSOR-GRID.md) |
