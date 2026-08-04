# 93 — Verification

How to prove the system computes rather than displays.

---

## 1. What is being verified

Not "does it run". The question is whether every figure the console shows was derived from something observed. A system that reads well and asserts its numbers is exactly what this build exists to replace, so verification is built around falsifiability: each check below can fail, and the failure means something specific.

---

## 2. Test pyramid

| Layer | Scope | Gate |
|---|---|---|
| Unit | Pure functions, engines, parsers | ≥ 85 % on `worker/app/engines`, ≥ 75 % overall |
| BPF verifier | Every program loads on the pinned kernel | 100 %, blocking |
| Contract | Proto compatibility, OpenAPI conformance | No breaking change without a version bump |
| Integration | Real Postgres, Redis, Kong, MinIO via testcontainers | All pass |
| E2E | Full stack + reference estate | The acceptance run in §4 |

**No mocked clients for systems we ship against.** Kong, MinIO, Postgres and Redis run for real in integration tests. Only ServiceNow and Anthropic use recorded cassettes, because neither has a local runtime — and both cassettes are generated from real responses, never hand-written.

---

## 3. Closure checks

Automated structural checks over the design and the code. These catch the class of defect that unit tests do not.

### 3.1 Contract closure

Every stage's declared inputs are produced by a named upstream stage's declared outputs.

```bash
python tools/check_contracts.py design/
```

Parses the *Inputs* and *Outputs* sections of each stage document, builds a bipartite graph, and fails on any input with no producer. Catches the class of defect that put CDRI before the engine producing its input in the source architecture.

### 3.2 Schema closure

Every column in `01-DATA-MODEL.md` has exactly one writing stage.

```bash
python tools/check_schema_writers.py design/ api/migrations/
```

Fails on a column with zero writers (dead) or two (ambiguous). `classification.pre_zombie` is the one deliberate cross-stage write and is declared as an exception with its rationale; the checker requires the exception to be explicit.

### 3.3 Claim closure

Every capability asserted in the source documents maps to a design section or an explicit out-of-scope entry.

```bash
python tools/check_claims.py design/ ../finalSol.html ../14stages.html
```

Extracts capability claims and requires each to resolve. Prevents a feature quietly disappearing between architecture and implementation.

### 3.4 Prose lint

```bash
grep -rEn '(is a |stands for|think of it as|in other words|why this matters)' console/src --include='*.tsx' | grep -v '^\s*//'
```

Must return nothing in rendered strings. The console does not teach.

---

## 4. The acceptance run

One scripted end-to-end run. `make verify` executes it and writes `verification-report.md`.

### Phase 0 — Clean start

```bash
docker compose down -v
docker network create sentinel-net
docker compose -f estate/compose.yaml up -d
docker compose -f deploy/compose/compose.yaml up -d
```

| Assert | |
|---|---|
| All services `readyz` green | |
| `SELECT count(*) FROM endpoint` | `0` |
| Agent log shows uprobes attached | non-zero for OpenSSL and Go |

An empty endpoint table at start is the precondition for everything below. If anything seeds it, the run is void.

### Phase 1 — Discovery from nothing

Advance to vday 5.

| Assert | Expected |
|---|---|
| `observation` rows | > 0, all four sources |
| `endpoint` rows | > 0 |
| `shadow-fx-rate` in `endpoint_source` | `ebpf` only |
| Data classes on `kyc-service` | includes `AADHAAR` |
| **Grep the whole database for a live Aadhaar value from a response** | **no match** |
| `classification` rows | `0` — below baseline |

The grep is the privacy proof. The value was in the response body, was matched in kernel, and must exist nowhere in Postgres.

### Phase 2 — Confidence ramp

Advance to vday 45.

| Assert | Expected |
|---|---|
| `classification` rows | > 0, all `PROVISIONAL` |
| Enrol a zombie in decommission | `409 PROVISIONAL_VERDICT` |
| `recon-quarterly` lifecycle | `ACTIVE` |

### Phase 3 — Full analysis

Advance to vday 140.

| Assert | Expected |
|---|---|
| `legacy-balance`, `nostro-sync` | `ZOMBIE` |
| `shadow-fx-rate` governance | `SHADOW` |
| `recon-quarterly` | still `ACTIVE` — never `ZOMBIE` |
| `payments-upi` `pre_zombie` | `false` — rising traffic never flagged |
| Pre-zombie flagged | < 25 % of active endpoints |
| Blast tier distribution | ≥ 3 distinct tiers |
| CDRI parts | re-sum to score for every row |
| Weight sum | exactly 1.00 |
| Ownership | `legacy-balance` `reachable=false` with named escalation |

Two of these encode regressions from the predecessor build: the pre-zombie proportion (which was 51 of 86 before deseasonalisation), and the blast distribution (which was 108 of 125 CRITICAL before the hop cap). Both would fail here.

### Phase 4 — Remediation, for real

Target `nostro-sync`, CDRI CRITICAL.

```
POST /remediation/{id}/generate   → control PROPOSED
POST /remediation/{id}/judge      → verdict PASS, measured latency delta
POST /remediation/{id}/apply      → as approver
```

| Assert | Expected |
|---|---|
| **`curl $KONG_ADMIN/plugins/{id}`** | **200 — plugin exists in Kong's own API** |
| `control.state` | `APPLIED` with `kong_plugin_id` |
| CDRI after | dropped by exactly the `no_auth` contribution |
| Tier | changed |
| Zero-trust posture | improved |
| Status-bar critical count | decreased |
| `change_request.number` | present |
| Apply as `analyst` | `403`, **no new plugin in Kong** |
| Revert | plugin gone from Kong, CDRI restored |

The Kong assertions are made against Kong's Admin API directly, not through SENTINEL. A system reporting its own success is not evidence.

### Phase 5 — Decommission and WORM

Enrol `legacy-balance`, advance through all phases.

| Assert | Expected |
|---|---|
| Phase A | rate-limit plugin present in Kong |
| Phase B | `Sunset` and `Deprecation` headers on a live response |
| Phase C | a call raises an alert and records a hidden caller |
| Phase D | WORM object exists with `ObjectLockMode=COMPLIANCE` |
| **`aws s3api delete-object` on it** | **`AccessDenied`** |
| 410 on the retired route | yes |
| Certificate | issued; `content_hash` present in `audit_entry` |
| MinIO stopped before Phase D | phase blocks, endpoint not retired |

The delete attempt is the immutability proof. A configuration flag is a claim; a refused delete is evidence.

### Phase 6 — Threat

Advance to vday 215.

| Assert | Expected |
|---|---|
| Probe from the scanner container | `probe` row with real source IP and watermark |
| Response body | synthetic, reserved-range account number |
| Honeypot's DB reachability to estate | none |
| vday-200 redeployment | resurrection alert, similarity ≥ 0.85 |
| Alert names | the original retired path |
| Redis flushed, rescan | same alert, rebuilt from Postgres |

### Phase 7 — Operations and audit

| Assert | Expected |
|---|---|
| CEF event in the rsyslog container log | present and parseable |
| SIEM stopped → spooled → restored | drains in order, no loss |
| CI gate against an unauthenticated-route PR fixture | fails with file and line |
| `GET /audit/verify` | `ok: true` |
| Tamper one `audit_entry.detail`, re-verify | reports the correct breaking `seq` |
| Leaderboard | reflects the Phase 4 remediation |

### Phase 8 — Determinism and honesty

| Assert | Expected |
|---|---|
| Two full runs | results within the [90 §8](90-REFERENCE-ESTATE.md) ranges, **not identical** |
| Unset `ANTHROPIC_API_KEY`, regenerate | `generator='template'`, labelled in the console |
| Stop the agent, check console | `CAPTURE DEGRADED` shown |
| Induce ring-buffer loss | loss counter non-zero, degradation surfaced |

Non-identical results across runs is a positive assertion. Identical results would mean the estate is not real software under a real scheduler.

---

## 5. Performance

Measured during the acceptance run, recorded in the report.

| Metric | Target | Method |
|---|---|---|
| Agent CPU at 1000 req/s | < 1 % of one core | `docker stats` sampled over 5 min |
| Agent memory | < 256 Mi | `docker stats` |
| Ring-buffer loss at target load | 0 | `sentinel_agent_ringbuf_lost_total` |
| Ingest throughput | ≥ 5000 obs/s | Load harness |
| Full pipeline, 500 endpoints | < 60 s | `stage_run.duration_ms` sum |
| Estate re-score on weight change | < 2 s | API timing |
| Console first paint | < 1.5 s | Lighthouse |

The agent CPU figure is the one that carries the architectural claim. It is measured under load and reported as a measurement, with the filter ratio alongside it.

---

## 6. The report

`make verify` emits `verification-report.md` containing, for every assertion: the check, expected, observed, pass/fail, and the command that produced it. Failures do not stop the run — the full picture is more useful than the first failure.

Each figure carries its provenance: which table, which query, which vday. A number in the report can be re-derived by anyone with a psql prompt.

---

## 7. Known limitations, stated

Carried into the report so they are never discovered by a reviewer first.

| Limitation | Detail |
|---|---|
| macOS visibility | The agent observes containers in the Docker Desktop VM, not macOS host processes |
| Replay fidelity | Request bodies were never captured, so the Judge replays exact paths with schema-synthesised or absent bodies. Coverage is reported per run. Privacy was chosen over replay fidelity, deliberately |
| Time-to-breach | A heuristic. No CVE or exploit-intelligence feed is wired. Labelled `basis: heuristic` everywhere it appears |
| Prophet | Named in the source architecture; Holt is what runs. Documented in [16](16-STAGE-07-FORECAST.md) and the README |
| ServiceNow | Tested against a schema-accurate stub and recorded cassettes. Labelled `STUB` in the console when the stub is in use |
| HTTP/2 | HPACK decoded in userspace, not kernel. Undecoded events counted and reported |
| Postgres HA | Single writer. Out of scope per [00 §12](00-ARCHITECTURE.md) |

---

## 8. Open item

The supporting research claims **four peer-reviewed papers**. Two are cited anywhere in the source material — ACM TKDD 2012 (Isolation Forest, stage 05) and Springer 2021 (monitoring cadence, stage 14). Both are cited where the algorithm is implemented.

The other two must be named or the claim amended before presenting. No citation has been invented to close the gap, and the verification report reproduces this item verbatim so it cannot be lost.

---

## 9. Acceptance criteria

- [ ] `make verify` runs end to end and produces the report.
- [ ] Every closure check passes.
- [ ] The prose lint returns nothing.
- [ ] Every Kong and MinIO assertion is made against those systems directly, not through SENTINEL.
- [ ] The privacy grep finds no customer identifier anywhere in the database.
- [ ] The WORM delete attempt is refused.
- [ ] Two runs differ in detail and agree in shape.
- [ ] The known-limitations table is in the report.
- [ ] Every figure in the report names the query that produced it.
