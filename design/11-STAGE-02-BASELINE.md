# Stage 02 — Baseline & Confidence

Rolls raw observations into a daily series, and governs when the system is allowed to have an opinion.

---

## 1. Scope

**Owns:** the `endpoint_daily` rollup; `endpoint.last_call_vday` and `total_calls`; the confidence level that gates every downstream verdict.

**Does not own:** classification. It decides whether a verdict is *permitted*, not what the verdict is.

---

## 2. Deployment unit

`worker/app/engines/baseline.py`. Celery beat, once per vday plus on demand. Runtime is O(observations in vday); at estate scale, seconds.

---

## 3. Inputs

| Source | Contract |
|---|---|
| `observation` | Rows for the target vday with `endpoint_id IS NOT NULL` |
| `vclock` | `current_vday()` |
| `policy_setting` | `baseline_vdays` (30), `window_vdays` (90) |

Observations still unresolved (`endpoint_id IS NULL`) are not counted. Stage 03 resolves them, then the rollup for that vday is recomputed — the task is idempotent by design and safe to re-run.

---

## 4. Outputs

| Target | Columns |
|---|---|
| `endpoint_daily` | Full row per `(endpoint_id, vday)` |
| `endpoint` | `last_call_vday`, `total_calls` |
| `stage_run` | Records processed, duration |

Confidence is computed, not stored on this table — it is a pure function of `vday` and `first_vday`, consumed directly by stage 04. Storing it would create a second source of truth that could drift.

---

## 5. Algorithm

### 5.1 Rollup

```sql
INSERT INTO endpoint_daily (endpoint_id, vday, calls, distinct_peers, err_calls,
                            p50_latency_us, p95_latency_us, mean_resp_bytes,
                            auth_missing, hour_histogram)
SELECT
  endpoint_id, :vday,
  count(*),
  count(DISTINCT peer_service),
  count(*) FILTER (WHERE status >= 400),
  percentile_disc(0.5)  WITHIN GROUP (ORDER BY latency_us),
  percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_us),
  avg(resp_bytes)::int,
  count(*) FILTER (WHERE NOT auth_present),
  <24-element histogram from wall_ts hour>
FROM observation
WHERE vday = :vday AND endpoint_id IS NOT NULL
GROUP BY endpoint_id
ON CONFLICT (endpoint_id, vday) DO UPDATE SET
  calls = EXCLUDED.calls, distinct_peers = EXCLUDED.distinct_peers, ...;
```

The `ON CONFLICT` clause is what makes re-running after stage 03 backfill correct rather than additive.

**Zero-call days are materialised.** An endpoint observed at least once has a row for every vday from `first_vday` to `current_vday`, with `calls = 0` where there was no traffic. This matters: the forecast at stage 07 fits a time series, and a series with missing days produces a different slope from one with explicit zeros. Gap-filling happens here, once, rather than being re-derived by every consumer.

### 5.2 Aggregate update

```sql
UPDATE endpoint e SET
  last_call_vday = (SELECT max(vday) FROM endpoint_daily d
                     WHERE d.endpoint_id = e.id AND d.calls > 0),
  total_calls    = (SELECT coalesce(sum(calls),0) FROM endpoint_daily d
                     WHERE d.endpoint_id = e.id);
```

`last_call_vday` stays `NULL` for an endpoint discovered in code but never called. That is not a zombie; it is unreleased, and stage 04 separates the two.

### 5.3 Confidence ramp

The source architecture specifies a 30-day baseline while stages 03, 09 and 11 reason over 90 days. At go-live that data cannot exist. Rather than pretending otherwise, observation age determines what the system is allowed to conclude.

```python
def confidence(vday: int, first_vday: int, backfilled_vdays: int = 0) -> Confidence:
    observed = vday - first_vday + backfilled_vdays
    if observed <= BASELINE_VDAYS:      return Confidence.NONE          # ≤ 30
    if observed < WINDOW_VDAYS:         return Confidence.PROVISIONAL   # 31–89
    return Confidence.CONFIRMED                                          # ≥ 90
```

| Level | Observed | Effect |
|---|---|---|
| `NONE` | ≤ 30 vdays | Registry is built. No lifecycle verdict, no CDRI, no alerts. Stage 04 writes nothing |
| `PROVISIONAL` | 31–89 vdays | Verdicts computed and shown, stamped `PROVISIONAL`. **Cannot enter the decommissioning workflow** — enforced at stage 11, not by convention |
| `CONFIRMED` | ≥ 90 vdays | Full verdicts. Decommissioning permitted |

`backfilled_vdays` accounts for historical gateway or SIEM logs imported at onboarding. `POST /api/v1/baseline/backfill` accepts a Kong log export or CEF archive, writes `observation` rows with `source='gateway'` and historical `vday` values, and credits the endpoint with that history. Backfill can carry an estate to `CONFIRMED` on day one where the bank retained logs — which most have, and which is the difference between a 90-day pilot and a same-week result.

Backfilled observations are marked `detail->>'backfill' = true` so a verdict resting on imported rather than directly observed data is distinguishable in audit.

---

## 6. Data model delta

Writes `endpoint_daily` (all columns), `endpoint.last_call_vday`, `endpoint.total_calls`.

Index supporting the window scans:

```sql
CREATE INDEX endpoint_daily_window_idx ON endpoint_daily (endpoint_id, vday DESC) INCLUDE (calls);
```

---

## 7. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/baseline` | `viewer` | Estate-wide confidence distribution, registry growth curve, day counter |
| `GET /api/v1/baseline/{endpoint_id}/series` | `viewer` | Daily call series with zero days materialised |
| `POST /api/v1/baseline/backfill` | `admin` | Import historical gateway/SIEM logs; `202` + task id |
| `GET /api/v1/baseline/export` | `viewer` | The registry as CSV — the day-30 pilot deliverable |

```json
{
  "vday": 47,
  "confidence": {"NONE": 12, "PROVISIONAL": 98, "CONFIRMED": 16},
  "registry_size": 126,
  "growth": [{"vday": 0, "n": 0}, {"vday": 1, "n": 31}, ...],
  "verdicts_permitted": true,
  "decommission_permitted": 16
}
```

---

## 8. Configuration

| Variable | Default | Notes |
|---|---|---|
| `BASELINE_VDAYS` | `30` | Below this, no verdicts at all |
| `WINDOW_VDAYS` | `90` | Analysis window; also the `CONFIRMED` threshold |
| `ROLLUP_BATCH_VDAYS` | `7` | Vdays per rollup transaction on catch-up |

`WINDOW_VDAYS = 90` is a banking constraint, not a tuning parameter. Statutory returns, settlement reconciliation and dividend runs are quarterly; a 30-day window classifies those endpoints as dead. Lowering it below 90 is permitted by the config but the API returns a warning on `GET /api/v1/policy/settings` because it changes what the word "zombie" means.

---

## 9. Failure modes

| Condition | Behaviour |
|---|---|
| Rollup runs before stage 03 resolution | Unresolved observations excluded; rollup re-runs idempotently after correlation |
| Missed vdays (worker down) | Catch-up loop processes each missing vday in order, `ROLLUP_BATCH_VDAYS` per transaction |
| Observation partition missing | Maintenance task creates it; rollup for that vday returns zero and is retried |
| Backfill overlaps live data | `ON CONFLICT` on `observation` natural key discards duplicates; count reported in the task result |

---

## 10. Security and compliance

- **RBAC**: reads `viewer`; backfill `admin` (it changes what the system is entitled to conclude).
- **Audit**: `baseline.backfill` with source, row count, vday range.
- **Frameworks**: RBI API Security §continuous monitoring; DORA Art 9 (resilience testing needs a real baseline).

---

## 11. Tests

**Unit**
- `confidence()` at boundaries: 30 → `NONE`, 31 → `PROVISIONAL`, 89 → `PROVISIONAL`, 90 → `CONFIRMED`.
- Backfill credit moves an endpoint across a boundary correctly.
- Zero-day materialisation produces a contiguous series with no gaps.
- Percentile computation against a known distribution.

**Integration**
- Rollup then stage-03 backfill then rollup re-run: `calls` is correct, not doubled.
- An endpoint in code only has `last_call_vday IS NULL` and `total_calls = 0`.
- Catch-up after a 5-vday worker outage produces the same `endpoint_daily` as an uninterrupted run.

**E2E**
- At `vday ≤ 30` no `classification` rows exist and `GET /api/v1/risk` returns an empty register.
- At `vday = 45` classification rows exist, all `PROVISIONAL`, and stage 11 enrolment is refused.

---

## 12. Acceptance criteria

- [ ] `endpoint_daily` has a contiguous row per vday per endpoint from `first_vday`, zero days included.
- [ ] Re-running the rollup for a vday changes no value.
- [ ] No verdict of any kind exists while the estate is under `BASELINE_VDAYS`.
- [ ] Every verdict between 31 and 89 vdays is stamped `PROVISIONAL`.
- [ ] Stage 11 enrolment of a `PROVISIONAL` endpoint is refused with `409 conflict`.
- [ ] Backfilling a gateway log export advances confidence and marks the affected observations as backfilled.
- [ ] `GET /api/v1/baseline/export` produces a registry CSV that opens cleanly in a spreadsheet.
