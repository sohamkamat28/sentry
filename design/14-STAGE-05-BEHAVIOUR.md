# Stage 05 — Behavioural Intelligence

Isolation Forest over per-endpoint call features. Produces r₆, the sixth CDRI input.

---

## 1. Scope

**Owns:** `anomaly` — the binary flag, the raw isolation score, isolation depth, named patterns, and the feature vector.

**Does not own:** the CDRI score. It produces one input to it.

**Runs before stage 06.** CDRI's formula takes a behavioural-anomaly term. In the source architecture CDRI sat at stage 5 and consumed an input stage 6 produced — a linear pipeline reading from its own future. The order is enforced by `STAGE_DEPS` in [00 §5](00-ARCHITECTURE.md), not by convention.

---

## 2. Deployment unit

`worker/app/engines/behaviour.py`. Runs after stage 04. One `IsolationForest` fit across the whole estate per run; per-endpoint scoring is a vectorised predict. Fit cost is O(n · ψ · log ψ) with subsample size ψ = 256.

---

## 3. Inputs

| Source | Field |
|---|---|
| `endpoint_daily` | Last `WINDOW_VDAYS` rows per endpoint |
| `classification` | `lifecycle` — context for pattern naming |
| `observation` | `auth_present`, `resp_bytes`, `peer_ip` for entropy over the last 7 vdays |
| `policy_setting` | `anomaly_contamination` (0.05) |

Endpoints with fewer than `MIN_SERIES_VDAYS` (14) of history are excluded from the fit and scored `flag=false, score=0.0` with `patterns=['INSUFFICIENT_HISTORY']`. Fitting a forest on three points and reporting the result as an anomaly verdict would be fabrication.

---

## 4. Outputs

`anomaly` — one row per endpoint. `flag` is r₆ ∈ {0,1}, consumed by stage 06 at weight 0.07.

---

## 5. Algorithm

### 5.1 Features

Six dimensions per endpoint, computed over the analysis window:

| Feature | Derivation |
|---|---|
| `call_frequency_hourly` | Mean calls per hour from `hour_histogram` summed across window vdays |
| `payload_size_mean` | `mean_resp_bytes` averaged over the window |
| `payload_size_cv` | Coefficient of variation of `mean_resp_bytes` — captures shape change independent of magnitude |
| `auth_missing_ratio` | `sum(auth_missing) / sum(calls)` |
| `source_ip_entropy` | Shannon entropy of the `peer_ip` distribution over the last 7 vdays |
| `error_ratio` | `sum(err_calls) / sum(calls)` |
| `tod_concentration` | Gini coefficient of the 24-bin hour histogram — distinguishes a steady service from a nightly batch |

Seven columns; the source document names six dimensions and `payload_size` is split into magnitude and variability because a zombie returning the same volume in a different shape is the exfiltration signal and one moment cannot express it.

### 5.2 Scaling

`RobustScaler` (median and IQR), not `StandardScaler`. Banking traffic distributions are heavily skewed — a handful of endpoints carry orders of magnitude more calls than the rest — and mean/variance scaling lets those dominate every axis. The scaler is fit on the same population as the forest and persisted alongside it.

### 5.3 Fit and score

```python
from sklearn.ensemble import IsolationForest

forest = IsolationForest(
    n_estimators=200,
    max_samples=256,          # ψ from the ACM 2012 paper
    contamination=CONTAMINATION,
    random_state=SEED,        # reproducible verdicts
    n_jobs=-1,
)
forest.fit(X_scaled)

raw   = forest.score_samples(X_scaled)      # higher = more normal
flags = forest.predict(X_scaled) == -1
depth = -np.log2(np.clip(-raw, 1e-9, None)) # presentation-only isolation depth
```

`random_state` is fixed. The same estate scores identically on two runs, which is what makes a verdict defensible when an owner disputes it a week later.

`contamination` is policy, exposed at `POST /api/v1/policy/settings`. It sets the expected anomalous proportion, and changing it re-scores the estate — a governance act, and audited.

> Isolation Forest construction and the ψ = 256 subsample follow Liu, Ting & Zhou, *Isolation-Based Anomaly Detection*, ACM TKDD 6(1), 2012.

### 5.4 Named patterns

The forest says *how* anomalous, not *why*. Three rules run alongside it and attach names, so the console shows a reason rather than a number:

```python
def patterns(ep, series, feats) -> list[str]:
    out = []
    # zombie traffic spike — targeted reconnaissance
    silent = trailing_zero_vdays(series, before=7)
    if silent >= 60 and sum(series[-7:]) >= SPIKE_MIN_CALLS:
        out.append("ZOMBIE_TRAFFIC_SPIKE")
    # auth sequence anomaly — accepting what it should refuse
    if feats.auth_missing_ratio > AUTH_ANOMALY_RATIO and ep.auth != "none":
        out.append("AUTH_SEQUENCE")
    # payload deviation — possible exfiltration
    if feats.payload_size_cv > PAYLOAD_CV_THRESHOLD and recent_mean(series) > baseline_mean(series) * 3:
        out.append("PAYLOAD_DEVIATION")
    return out
```

`AUTH_SEQUENCE` requires `ep.auth != 'none'`. An endpoint with no auth configured is not anomalous for serving unauthenticated requests — that is its documented behaviour, and CDRI already charges 0.28 for it. Flagging it here would double-count the same defect.

### 5.5 Flag composition

```python
flag = bool(forest_flag or patterns)
```

A named pattern raises the flag even when the forest does not, because the three patterns encode domain knowledge the forest cannot learn from seven features. The forest raises it on shapes nobody enumerated. `anomaly.features` stores the vector so a disputed verdict can be reproduced exactly.

---

## 6. Data model delta

Writes `anomaly`, full row, upsert on `endpoint_id`. The fitted forest and scaler are persisted to `MODEL_DIR/behaviour-<engine_version>-<vday>.joblib` and referenced in `stage_run.detail`, so the exact model that produced a verdict can be reloaded.

---

## 7. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/behaviour` | `viewer` | Flagged endpoints, score distribution, pattern counts, model metadata |
| `GET /api/v1/behaviour/{endpoint_id}` | `viewer` | Feature vector, score, depth, patterns, per-feature percentile |
| `POST /api/v1/behaviour/run` | `analyst` | Refit and re-score; `202` |

```json
{
  "vday": 147,
  "model": {"n_estimators": 200, "max_samples": 256, "contamination": 0.05,
            "fitted_on": 108, "excluded_insufficient_history": 18},
  "flagged": 9,
  "patterns": {"ZOMBIE_TRAFFIC_SPIKE": 3, "AUTH_SEQUENCE": 2, "PAYLOAD_DEVIATION": 1},
  "score_distribution": [...]
}
```

`excluded_insufficient_history` is reported rather than hidden — 18 endpoints not scored is a fact an operator needs.

---

## 8. Configuration

| Variable | Default | Range |
|---|---|---|
| `ANOMALY_CONTAMINATION` | `0.05` | 0.001–0.5 |
| `ANOMALY_N_ESTIMATORS` | `200` | 50–1000 |
| `ANOMALY_MAX_SAMPLES` | `256` | 64–1024 |
| `ANOMALY_SEED` | `20260726` | Fixed for reproducibility |
| `MIN_SERIES_VDAYS` | `14` | Below this, not scored |
| `SPIKE_MIN_CALLS` | `50` | 7-vday total to count as a spike |
| `AUTH_ANOMALY_RATIO` | `0.02` | |
| `PAYLOAD_CV_THRESHOLD` | `1.5` | |
| `MODEL_DIR` | `/var/lib/sentinel/models` | Persisted fits |

---

## 9. Failure modes

| Condition | Behaviour |
|---|---|
| Fewer than `MIN_FIT_ENDPOINTS` (30) eligible | Forest not fitted. Pattern rules still run; `flag` set from patterns alone; `model.fitted=false` reported. A forest on 12 points is noise, and the API says so |
| Endpoint below `MIN_SERIES_VDAYS` | Not scored; `patterns=['INSUFFICIENT_HISTORY']`, `flag=false` |
| All features identical | `RobustScaler` IQR of zero → fall back to unit scale for that column, logged |
| Stage 04 not run | `StageDependencyError` |
| Model dir unwritable | Fit proceeds in memory; persistence failure logged and reported in `stage_run.detail`. Verdicts are still produced |

---

## 10. Security and compliance

- **RBAC**: reads `viewer`; refit `analyst`; `contamination` change `admin` (it re-scores the estate).
- **Audit**: `policy.anomaly_contamination.changed`.
- **FS AI RMF**: this is a model-derived decision and is in scope. Every run writes `ai_decision`-equivalent provenance via `stage_run.detail`: model hyperparameters, seed, fit population size, and the model artefact path. The verdict is reproducible from stored inputs, which is the framework's actual requirement.
- **Frameworks**: RBI §continuous monitoring; NYDFS Part 500 (reconnaissance detection on zombie endpoints).

---

## 11. Tests

**Unit**
- Feature extraction against a fixture series with a known Gini and known entropy.
- `ZOMBIE_TRAFFIC_SPIKE` fires on 60 silent vdays followed by 400 calls in one; does not fire on 60 silent vdays followed by 3 calls.
- `AUTH_SEQUENCE` does not fire when `ep.auth == 'none'`.
- `PAYLOAD_DEVIATION` fires on a 3× volume jump with high CV; not on a smooth 3× ramp.
- Two fits with the same seed and input produce identical scores.

**Integration**
- Estate with an injected outlier: that endpoint is flagged, and `features` reproduces its vector.
- Below `MIN_FIT_ENDPOINTS`, the API reports `fitted=false` and pattern-only flags.
- `flag` values land in `anomaly` and stage 06 reads them as r₆ — asserted by checking `cdri.parts` contains a non-zero anomaly contribution for flagged endpoints only.

**E2E**
- A burst of traffic against a long-silent estate endpoint produces `ZOMBIE_TRAFFIC_SPIKE` and moves its CDRI by exactly 0.07 × weight-normalised contribution.

---

## 12. Acceptance criteria

- [ ] Every endpoint with sufficient history has an `anomaly` row.
- [ ] Endpoints with insufficient history are reported as excluded, not scored as normal.
- [ ] Identical inputs produce identical scores across runs.
- [ ] The feature vector is stored and a disputed verdict can be recomputed from it.
- [ ] `AUTH_SEQUENCE` never fires on an endpoint with no configured auth.
- [ ] Stage 06 consumes `flag` as r₆ and the contribution appears in `cdri.parts`.
- [ ] `GET /api/v1/behaviour` reports whether the forest was actually fitted.
