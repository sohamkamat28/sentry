# Stage 14 — Continuous Operations

The loop that closes: scheduled re-analysis, auto-enrolment, a CI gate that fails builds, a SIEM feed, and per-team accountability.

---

## 1. Scope

**Owns:** the scan scheduler, new-endpoint auto-enrolment, the CI pre-merge gate (`gate_event`), the SIEM emitter, and the Security Debt Leaderboard.

---

## 2. Deployment unit

`worker/app/engines/operations.py`, `worker/app/actuators/siem.py`, plus `api` webhook routes and a published GitHub Action.

---

## 3. Scan cycle

APScheduler / Celery beat, every `SCAN_INTERVAL_VHOURS` (6).

```python
@beat(interval=scan_interval())
def scan_cycle():
    run = start_pipeline_run(trigger="scheduled")
    for stage in topological_order(STAGE_DEPS):
        execute_stage(stage, run)
    emit_siem(new_findings_since(run.started_at))
    refresh_leaderboard()
```

> The 6-hour cadence follows the Springer 2021 analysis of monitoring frequency for banking API estates. It is configurable; the default is cited rather than asserted.

Runs are serialised by a Redis lock. An overrunning cycle causes the next to be skipped and counted (`sentinel_scan_skipped_total`) rather than overlapping and corrupting stage ordering.

---

## 4. Auto-enrolment

When the sensor observes an endpoint absent from the registry, stage 03 creates it. Within one scan cycle it is correlated, classified, scored, forecast and fingerprint-scanned.

A newly created endpoint receives:

- Immediate stage 12 resurrection scan — a redeployed zombie should not wait six hours to be caught.
- `confidence = NONE` until it accumulates baseline history, so it appears in the registry without a verdict.
- A `SHADOW` governance verdict if it is in no registry and no repository — the highest-urgency cell in the matrix, surfaced without delay.

---

## 5. CI pre-merge gate

Prevents the next generation of zombies at the point they are written.

### 5.1 The Action

`sentinel-gate` runs on pull requests, extracts route definitions from the diff with the same tree-sitter parsers the code collector uses, and posts them to SENTINEL.

```yaml
- uses: sentinel/gate-action@v1
  with:
    endpoint: ${{ secrets.SENTINEL_URL }}
    token:    ${{ secrets.SENTINEL_CI_TOKEN }}
    fail-on:  error
```

### 5.2 Checks

| Check | Fails when |
|---|---|
| `owner-tag` | New route has no resolvable owner via CODEOWNERS or an `@api-owner` annotation |
| `auth-middleware` | Route handler has no authentication middleware in its chain |
| `catalogue-registration` | Route is absent from the service's OpenAPI/catalogue definition |
| `no-resurrection` | The route's declared shape matches a retired endpoint's fingerprint above threshold |
| `tls-policy` | Service listener config permits below `ZT_TLS_FLOOR` |

`no-resurrection` is the check that closes the loop: a developer recreating a decommissioned endpoint under a new path is caught at the pull request rather than six months later by the sensor.

### 5.3 Response

```json
{
  "passed": false,
  "checks": [
    {"name":"owner-tag","passed":true},
    {"name":"auth-middleware","passed":false,
     "detail":"POST /api/v3/transfer has no auth middleware",
     "file":"src/routes/transfer.py","line":48},
    {"name":"no-resurrection","passed":false,
     "detail":"matches retired /api/v1/legacy-balance at 0.91"}
  ]
}
```

The Action renders these as annotations on the diff and exits non-zero. `POST /api/v1/gate/check` authenticates with a service token scoped to that route only — CI credentials cannot read the estate.

---

## 6. SIEM feed

Events serialised as CEF over syslog, or LEEF for QRadar.

```
CEF:0|SENTINEL|APILifecycle|1.0|ZOMBIE_CRITICAL|Zombie endpoint with no authentication|9|
 src=10.0.0.14 dst=svc-core-accounts requestMethod=GET
 request=/api/v1/legacy-balance cs1Label=CDRI cs1=0.93
 cs2Label=Frameworks cs2=RBI-4.2;DPDP-8;FFIEC-DAM
 cs3Label=Endpoint cs3=ep_9f2c8a1b cn1Label=TimeToBreachDays cn1=2
```

| Event | Severity |
|---|---|
| `ZOMBIE_CRITICAL` | 9 |
| `SHADOW_DETECTED` | 8 |
| `RESURRECTION_ALERT` | 9 |
| `HONEYPOT_PROBE` | 7 |
| `QUARANTINE_HIT` | 8 |
| `CONTROL_APPLIED` | 4 |
| `DECOMMISSION_PHASE` | 3 |

Delivery over TCP syslog with a bounded Redis spool on failure, draining on recovery. Splunk HEC is supported as an alternative sink where the institution prefers it.

The security team sees SENTINEL alerts in the console they already use. That is the integration requirement — a tool that demands a new console gets checked on Mondays.

---

## 7. Security Debt Leaderboard

Per team, refreshed each cycle.

```python
debt = (2.0 * zombie_count
      + 1.5 * sum(cdri.score for e in eps if cdri.tier == "CRITICAL")
      + 1.0 * orphaned_count
      + 0.5 * pre_zombie_count) * ownership_confidence_factor
```

`ownership_confidence_factor` is the mean `ownership.confidence` across the team's endpoints. A team is not charged for endpoints attributed to it by a 0.40-confidence null metadata field — otherwise the leaderboard becomes a dispute about attribution rather than a prompt to act.

Trend over the last 30 vdays is shown alongside the absolute figure, because a team reducing debt from 90 to 60 is doing better than one static at 55, and only the trend shows it.

---

## 8. Data model delta

Writes `gate_event`. Reads everything else. Leaderboard is a materialised view refreshed per cycle:

```sql
CREATE MATERIALIZED VIEW team_debt AS
SELECT s.team,
       count(*) FILTER (WHERE c.lifecycle = 'ZOMBIE')            AS zombies,
       count(*) FILTER (WHERE c.governance = 'ORPHANED')         AS orphaned,
       count(*) FILTER (WHERE c.pre_zombie)                      AS pre_zombie,
       coalesce(sum(d.score) FILTER (WHERE d.tier = 'CRITICAL'), 0) AS critical_score,
       avg(o.confidence)                                          AS conf
FROM endpoint e
JOIN service s        ON s.id = e.service_id
LEFT JOIN classification c ON c.endpoint_id = e.id
LEFT JOIN cdri d           ON d.endpoint_id = e.id
LEFT JOIN ownership o      ON o.endpoint_id = e.id
WHERE NOT e.retired
GROUP BY s.team;
```

---

## 9. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/operations` | `viewer` | Scan status, next run, cycle history |
| `GET /api/v1/operations/leaderboard` | `viewer` | Team debt with trend |
| `GET /api/v1/operations/siem` | `viewer` | Recent emitted events, delivery status |
| `POST /api/v1/operations/scan` | `analyst` | Trigger a cycle; `202` |
| `POST /api/v1/gate/check` | service `ci-gate` | Pre-merge gate |
| `GET /api/v1/gate/events` | `viewer` | Gate history |
| `GET /api/v1/audit` | `viewer` | Ledger, filterable |
| `GET /api/v1/audit/verify` | `admin` | Chain verification |

---

## 10. Configuration

| Variable | Default | Notes |
|---|---|---|
| `SCAN_INTERVAL_VHOURS` | `6` | Springer 2021 cadence |
| `SCHEDULER_ENABLED` | `true` | |
| `SIEM_HOST` / `_PORT` / `_FORMAT` | — / `514` / `cef` | `cef`\|`leef`\|`hec` |
| `SIEM_SPOOL_MAX` | `10000` | Bounded spool |
| `GATE_FAIL_ON` | `error` | `error`\|`warn`\|`never` |
| `LEADERBOARD_TREND_VDAYS` | `30` | |

---

## 11. Failure modes

| Condition | Behaviour |
|---|---|
| Cycle overruns | Next skipped and counted. No overlap |
| A stage fails | Recorded in `stage_run` with the error; dependent stages skip; the cycle completes and reports partial |
| SIEM unreachable | Spool to Redis, drain on recovery, oldest dropped on overflow and counted |
| Gate endpoint unreachable from CI | Action fails closed or open per `GATE_FAIL_ON`. Default `error` fails the build — a security gate that fails open is not a gate |
| Leaderboard refresh fails | Previous view served with a staleness timestamp shown |

---

## 12. Security and compliance

- **RBAC**: reads `viewer`; scan `analyst`; audit verify `admin`; gate uses a dedicated service token that can write gate events and read nothing else.
- **Audit**: `scan.triggered`, `gate.checked`, `siem.delivery_failed`.
- **Frameworks**: RBI §continuous monitoring; FS AI RMF (decision log surfaced here); NYDFS Part 500 §500.06; DORA Art 9; FFIEC DA&M (the gate is change control at the point of authorship).

---

## 13. Tests

**Unit**
- CEF serialisation matches the specification, including escaping of `=` and `|` in values.
- LEEF serialisation for QRadar.
- Debt formula against a fixture team; confidence factor reduces debt as expected.
- Each gate check, positive and negative.

**Integration**
- Cycle executes stages in DAG order; a deliberately failed stage skips dependants and the run reports partial.
- Overlapping trigger is skipped, not run concurrently.
- SIEM events arrive at a real rsyslog container and appear in its log file.
- SIEM stopped → spool grows → restored → events drain in order.
- Gate rejects a PR fixture with an unauthenticated route and returns file and line.
- `no-resurrection` fires against a retired fingerprint.

**E2E**
- A new endpoint appearing in the estate is fully analysed within one cycle.
- Opening a PR with an ownerless route fails the build with a readable annotation.
- Leaderboard reflects a change after a control is applied.

---

## 14. Acceptance criteria

- [ ] Cycles run on schedule, in DAG order, without overlap.
- [ ] A new endpoint is discovered, classified and scored within one cycle.
- [ ] A redeployed retired endpoint is resurrection-scanned immediately, not on the next cycle.
- [ ] CEF events reach a real syslog receiver and are readable there.
- [ ] The SIEM spool survives an outage without reordering or silent loss.
- [ ] The CI gate fails a real pull request and annotates the offending line.
- [ ] The gate fails closed by default.
- [ ] The leaderboard weights by ownership confidence and shows trend.
- [ ] `GET /api/v1/audit/verify` passes on a fully exercised database.
