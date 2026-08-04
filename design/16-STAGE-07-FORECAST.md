# Stage 07 — Pre-Zombie Forecast

Projects call volume forward and flags endpoints on a trajectory to zero, 18–30 vdays before they get there.

---

## 1. Scope

**Owns:** `forecast` (all columns) and `classification.pre_zombie` — the one legal back-edge in the pipeline DAG.

**Does not own:** lifecycle status. An endpoint predicted to become a zombie is still `ACTIVE` today, and the flag is an early warning, not a verdict.

---

## 2. Deployment unit

`worker/app/engines/forecast.py`. Runs after stage 04. Fits per endpoint over a 90-point series — cheap, and parallelised across the estate.

---

## 3. The write-back

Stage 04 evaluates lifecycle from observed history. The pre-zombie flag requires a projection stage 04 has no access to. The source document had stage 4 claiming to set it; it cannot.

```python
# forecast.py — the only writer of this column
session.execute(
    update(Classification)
    .where(Classification.endpoint_id == ep_id)
    .values(pre_zombie=flag)
)
```

Stage 04's upsert deliberately omits `pre_zombie` from its `SET` list ([13 §7](13-STAGE-04-CLASSIFICATION.md)), so a re-classification does not clear it. A test asserts this in both directions.

---

## 4. Inputs

| Source | Field |
|---|---|
| `endpoint_daily` | `calls` per vday over `WINDOW_VDAYS`, zero days materialised by stage 02 |
| `endpoint_source` | `detail.last_commit_vday` from the code collector |
| `ownership` | `reachable`, `confidence` |
| `classification` | `lifecycle` — only `ACTIVE` and `DORMANT` are candidates |

`ZOMBIE` endpoints are excluded. Forecasting the death of something already dead produces a flag nobody can act on.

---

## 5. Algorithm

### 5.1 Deseasonalise first

Banking traffic has a hard weekly cycle — weekday volume, weekend trough. Fitting a trend to the raw daily series makes the answer depend on which day the window happens to end.

This is not hypothetical. In an earlier build, fitting raw daily volume produced *declining* verdicts for endpoints whose volume was rising, and flagged 51 of 86 active endpoints as pre-zombie. The window ending on a Sunday was doing the work.

```python
def deseasonalise(series: list[float], period: int = 7) -> list[float]:
    """Remove the weekly component by centred moving average over exactly one period."""
    if len(series) < period * 2:
        return list(series)
    idx = np.arange(len(series))
    # centred MA over one full period — the trend-cycle estimate
    trend = pd.Series(series).rolling(period, center=True, min_periods=period).mean()
    ratio = np.where(trend > 0, series / trend, 1.0)
    # average seasonal index per weekday position, normalised to mean 1.0
    seasonal = np.array([np.nanmean(ratio[i::period]) for i in range(period)])
    seasonal = np.nan_to_num(seasonal, nan=1.0)
    seasonal /= seasonal.mean() or 1.0
    return list(np.asarray(series) / seasonal[idx % period])
```

Smoothing over *exactly* one period is what removes the cycle without eating the trend. A longer window flattens genuine decline; a shorter one leaves the cycle in.

### 5.2 Holt linear trend

```python
def project(series: list[float], horizon: int = 30) -> Projection:
    y = deseasonalise(series)
    level, trend = y[0], y[1] - y[0]
    for t in range(1, len(y)):
        prev = level
        level = ALPHA * y[t] + (1 - ALPHA) * (level + trend)
        trend = BETA  * (level - prev) + (1 - BETA) * trend
    forward = [max(0.0, level + (h + 1) * trend) for h in range(horizon)]
    return Projection(level=level, slope=trend, points=forward)
```

α = 0.3, β = 0.1. Both exposed as policy.

**Prophet is named in the architecture document; Holt is what runs.** Holt captures the trend component this decision needs, adds no heavy compiled dependency, and is fully inspectable — an operator can be shown the level and slope. The seasonality Prophet would model is removed upstream in §5.1, and the 90-day window handles the rest. `project_series` is a single function with a stable signature, so substituting Prophet is a drop-in change if the estate later needs multiplicative seasonality or holiday effects. This is documented rather than left for someone to discover mid-presentation.

### 5.3 Days to zombie

```python
def days_to_zombie(proj, current_silence: int) -> int | None:
    if proj.slope >= 0:
        return None                                  # not declining
    for h, v in enumerate(proj.points, start=1):
        if v < ZOMBIE_FLOOR_CALLS:                   # effectively zero
            return h + (ZOMBIE_VDAYS - current_silence)
    return None                                      # doesn't reach zero within horizon
```

The returned figure is *days until it qualifies as a zombie*, not *days until traffic stops* — it adds the 90-vday silence requirement that follows the last call. That is the number an owner can act on.

### 5.4 Three weighted signals

Declining volume alone over-flags. An endpoint can be quiet and actively maintained.

| Signal | Weight | Derivation |
|---|---|---|
| Call-volume trajectory | 0.50 | Normalised negative slope, clipped to [0,1] |
| Commit recency | 0.30 | `1 - exp(-days_since_commit / 180)` |
| Owner activity | 0.20 | `0.0` reachable owner with high confidence → `1.0` unresolved |

```python
risk = 0.50 * volume + 0.30 * commit + 0.20 * owner
pre_zombie = (days_to_zombie is not None
              and days_to_zombie <= PRE_ZOMBIE_HORIZON     # 30
              and risk >= PRE_ZOMBIE_RISK_FLOOR)           # 0.45
```

Requiring both a projection *and* a composite risk floor is what keeps the flag actionable. An endpoint declining because a migration is deliberately draining it has recent commits and a reachable owner, scores low on signals two and three, and is not flagged.

### 5.5 Owner notification

`POST /api/v1/forecast/notify` sends to resolved owners, or to the escalation contact where ownership is unresolved. Emits a `forecast.notified` audit event with the recipient list. Notification is operator-initiated, not automatic — an unrequested mail to 40 engineers is how a security tool gets switched off.

---

## 6. Data model delta

Writes `forecast` (full row) and `classification.pre_zombie` (only writer).

---

## 7. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/forecast` | `viewer` | Pre-zombie queue sorted by days-to-zombie, signal breakdown |
| `GET /api/v1/forecast/{endpoint_id}` | `viewer` | Observed series, deseasonalised series, projection, signals |
| `POST /api/v1/forecast/notify` | `analyst` | Notify owners; body selects endpoints |
| `POST /api/v1/forecast/run` | `analyst` | Force; `202` |

```json
{
  "endpoint_id": "ep_4a1b…",
  "days_to_zombie": 18,
  "slope": -2.41, "level": 43.2,
  "deseasonalised": true,
  "signals": {"call_volume": 0.81, "commit_recency": 0.64, "owner_activity": 0.0, "composite": 0.60},
  "observed": [...90 points...],
  "adjusted": [...90 points...],
  "projection": [...30 points...]
}
```

Returning observed and deseasonalised series together lets the console show both lines, which is how an operator sees that the weekly cycle was removed rather than being told it was.

---

## 8. Configuration

| Variable | Default | Range |
|---|---|---|
| `FORECAST_ALPHA` | `0.3` | 0.05–0.95 |
| `FORECAST_BETA` | `0.1` | 0.01–0.5 |
| `FORECAST_HORIZON` | `30` | 7–90 |
| `SEASONAL_PERIOD` | `7` | Fixed at 7 unless the estate has a different cycle |
| `ZOMBIE_FLOOR_CALLS` | `0.5` | Below this, effectively zero |
| `PRE_ZOMBIE_HORIZON` | `30` | Flag if zombie within this many vdays |
| `PRE_ZOMBIE_RISK_FLOOR` | `0.45` | Composite signal minimum |

---

## 9. Failure modes

| Condition | Behaviour |
|---|---|
| Series shorter than `2 × SEASONAL_PERIOD` | Deseasonalisation skipped, `deseasonalised=false` recorded on the row, Holt fits raw. Consumer can see the caveat |
| Series all zeros | Already silent; excluded as `ZOMBIE` or `DORMANT` with no trend |
| Slope ≥ 0 | `days_to_zombie = null`, `pre_zombie = false`. Rising traffic is never flagged |
| No commit data | Commit signal defaults to 0.5 and is marked `estimated` in `signals` |
| Stage 04 not run | `StageDependencyError` |

---

## 10. Security and compliance

- **RBAC**: reads `viewer`; notify and forced run `analyst`.
- **Audit**: `forecast.notified` with recipients and endpoint list.
- **FS AI RMF**: statistical forecast, in scope. Model parameters, seed-free determinism, and both series are stored, so a projection is reproducible.
- **Frameworks**: DORA Art 9 (proactive resilience); RBI §continuous monitoring.

---

## 11. Tests

**Unit**
- **The regression that motivated §5.1**: a synthetic series with a rising trend and a strong weekly cycle, windowed to end on a low day, yields a positive slope after deseasonalisation and a negative slope without it. This test is the reason the function exists and is named accordingly.
- Deseasonalisation of a pure sine of period 7 returns a near-flat series.
- Holt on a linear ramp recovers the slope within 5 %.
- `days_to_zombie` adds the silence requirement; returns `None` for a non-negative slope.
- Composite signal weights sum to 1.00.

**Integration**
- Stage 07 sets `pre_zombie`; a subsequent stage 04 run leaves it set.
- Clearing the flag requires stage 07 to compute `false` — nothing else clears it.
- Endpoints classified `ZOMBIE` are excluded from the forecast population.

**E2E**
- On the reference estate, the count of pre-zombie flags is a small fraction of the active population, not a majority. A run flagging over `PRE_ZOMBIE_SANITY_RATIO` (0.25) of active endpoints fails the acceptance check — the earlier build's 51-of-86 result would fail here.

---

## 12. Acceptance criteria

- [ ] Deseasonalisation runs over exactly one weekly period before any trend fit.
- [ ] An endpoint with rising traffic is never flagged pre-zombie, whichever weekday the window ends on.
- [ ] `days_to_zombie` includes the 90-vday silence requirement.
- [ ] Both observed and deseasonalised series are returned so the correction is visible.
- [ ] `pre_zombie` survives a stage 04 re-run.
- [ ] Stage 07 is the only writer of `classification.pre_zombie`, verified by grep in the schema-closure check.
- [ ] Flagged proportion of the active estate stays below the sanity ratio.
- [ ] The Prophet-versus-Holt decision is stated in the README, not only here.
