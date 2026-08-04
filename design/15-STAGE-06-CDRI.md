# Stage 06 — CDRI

Composite Damage Risk Index. Six weighted indicators, summing to exactly 1.00.

---

## 1. Scope

**Owns:** `cdri.score`, `tier`, `parts`, `weights_version`, `time_to_breach_d`.

**Does not own:** any of the six indicators. Every r value is read from a table another stage wrote. This engine is arithmetic over facts, which is why its output is defensible.

---

## 2. Deployment unit

`worker/app/engines/cdri.py`. Runs after stage 05. Pure and vectorised; a full estate re-score is sub-second, which is what makes the console's live weight tuner possible.

---

## 3. Inputs

| Indicator | Weight | Source | Rule |
|---|---|---|---|
| `no_auth` | 0.28 | `endpoint.auth` | `1.0` if `auth = 'none'`, `0.5` if `basic`/`apikey`, else `0.0` |
| `zombie` | 0.22 | `classification.lifecycle` | `1.0` `ZOMBIE`, `0.6` `DORMANT`, `0.3` `DEPRECATED`, `0.0` `ACTIVE` |
| `data_exposure` | 0.20 | `endpoint.data_classes` | `1.0` if any of PAN/AADHAAR/CARD/CVV, `0.6` if ACCOUNT_NO/DOB, `0.3` if IFSC only, `0.0` if empty |
| `weak_tls` | 0.15 | `endpoint.tls_version` | `1.0` for none/1.0/1.1, `0.5` for 1.2, `0.0` for 1.3 |
| `no_rate_limit` | 0.08 | `endpoint.rate_limited` | `1.0` if false |
| `anomaly` | 0.07 | `anomaly.flag` | r₆ ∈ {0,1} from stage 05 |

Weights come from `policy_weights`, not from code. Defaults above; the sum-to-one constraint is enforced by the schema ([01 §8](01-DATA-MODEL.md)).

Indicators are graded rather than binary where a middle state genuinely exists. `basic` auth is not as bad as none and not as good as OAuth; scoring it 0.5 says so. The source document treats most indicators as binary; grading them changes no maximum and makes the ordering within a tier meaningful.

---

## 4. Outputs

`cdri` — one row per endpoint. Also the primary sort key of the Risk Register and the trigger for stage 10's queue.

---

## 5. Algorithm

### 5.1 Score

```python
def score(ep, cls, anom, weights) -> CdriResult:
    r = {
        "no_auth":       auth_risk(ep.auth),
        "zombie":        lifecycle_risk(cls.lifecycle),
        "data_exposure": data_risk(ep.data_classes),
        "weak_tls":      tls_risk(ep.tls_version),
        "no_rate_limit": 1.0 if not ep.rate_limited else 0.0,
        "anomaly":       1.0 if anom and anom.flag else 0.0,
    }
    parts = [{"key": k, "r": r[k], "w": weights[k], "contribution": r[k] * weights[k]}
             for k in weights]
    total = sum(p["contribution"] for p in parts)
    return CdriResult(round(total, 4), tier_for(total), parts)
```

The anomaly term is one of the six weights. It is not applied again after the sum. Applying it twice would double-count it and break the property that the maximum is exactly 1.00 and that any two scores are comparable.

### 5.2 Tiers

| Tier | Range | Action |
|---|---|---|
| `CRITICAL` | ≥ 0.75 | Page on-call; eligible for the virtual-patch queue |
| `HIGH` | 0.50–0.74 | Daily digest; action within 48 vhours |
| `MEDIUM` | 0.25–0.49 | Weekly review queue; owner notified |
| `LOW` | < 0.25 | Register only |

Bounds live in `policy_setting.tier_bounds`.

### 5.3 Live re-scoring

`POST /api/v1/policy/weights` writes a new `policy_weights` version and re-scores the whole estate in one transaction. The console's weight sliders drive this, so an operator sees the estate's tier distribution move as they change policy.

Two guards:

- The schema constraint rejects any weight set not summing to 1.00. The API surfaces this as `422` with the actual sum, so the UI can show the residual while dragging.
- The prior version is never deleted. Every `cdri` row references the `weights_version` that produced it, so a score is always interpretable against the policy in force at the time.

### 5.4 Time-to-breach

A CDRI of 0.92 is a debate. A countdown is a deadline, and deadlines move budget.

```python
def time_to_breach(ep, cls, anom, cdri_score) -> int | None:
    if cdri_score < TTB_MIN_SCORE:            # below HIGH, not meaningful
        return None
    base = TTB_BASE_DAYS                       # 180
    base *= (1.0 - 0.85 * cdri_score)          # composite exposure
    if ep.auth == "none":            base *= 0.45
    if data_risk(ep.data_classes) >= 0.6: base *= 0.60
    if cls.governance == "SHADOW":   base *= 0.50
    if anom and "ZOMBIE_TRAFFIC_SPIKE" in anom.patterns:
        base *= 0.25                           # already under reconnaissance
    if ep.internet_reachable:        base *= 0.50
    return max(1, round(base))
```

**This is a heuristic and is labelled as one.** The API returns `time_to_breach: {days: 2, basis: "heuristic", factors: [...]}` with every multiplier that applied, so the number is inspectable rather than oracular. The source material describes it as combining public exploit-database activity with historical breach timing; no such feed is wired here, and claiming otherwise would be a fabrication. Integrating a real CVE/exploit-intelligence source is the documented path to replacing the heuristic, and the `factors` array is the seam.

`ep.internet_reachable` is derived by stage 03 from the Kong route's configured hosts and listener, not guessed.

---

## 6. Data model delta

Writes `cdri`, full row. Indexes on `score DESC` and `tier` support the register.

---

## 7. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/risk` | `viewer` | Register: sortable, filterable, paginated |
| `GET /api/v1/risk/{endpoint_id}` | `viewer` | Score with per-part breakdown |
| `GET /api/v1/policy/weights` | `viewer` | Current + history |
| `POST /api/v1/policy/weights` | `analyst` | New version, re-score estate |
| `POST /api/v1/policy/weights/reset` | `analyst` | Restore defaults |

```json
{
  "endpoint_id": "ep_9f2c…", "score": 0.93, "tier": "CRITICAL",
  "weights_version": 3,
  "parts": [
    {"key":"no_auth","label":"No authentication","r":1.0,"w":0.28,"contribution":0.28},
    {"key":"zombie","label":"Zombie status","r":1.0,"w":0.22,"contribution":0.22},
    {"key":"data_exposure","label":"PII / financial data","r":1.0,"w":0.20,"contribution":0.20},
    {"key":"weak_tls","label":"TLS below 1.3","r":1.0,"w":0.15,"contribution":0.15},
    {"key":"no_rate_limit","label":"No rate limiting","r":1.0,"w":0.08,"contribution":0.08},
    {"key":"anomaly","label":"Behavioural anomaly","r":0.0,"w":0.07,"contribution":0.0}
  ],
  "weight_sum": 1.0,
  "time_to_breach": {"days": 2, "basis": "heuristic",
                     "factors": ["no_auth ×0.45","data ×0.60","shadow ×0.50"]}
}
```

---

## 8. Configuration

| Variable | Default | Notes |
|---|---|---|
| `TTB_BASE_DAYS` | `180` | Unmodified exposure horizon |
| `TTB_MIN_SCORE` | `0.50` | Below HIGH, no estimate offered |
| `CDRI_ROUND_DP` | `4` | Storage precision |

Weights and tier bounds are database policy, not environment configuration — they are governed, versioned and audited, which environment variables are not.

---

## 9. Failure modes

| Condition | Behaviour |
|---|---|
| `anomaly` row missing | r₆ = 0. Recorded in `parts` as `{"r":0.0,"source":"absent"}` — an unmeasured input reads as zero, and the record says it was unmeasured rather than measured-zero |
| `classification` row missing | Endpoint skipped entirely. No score without a lifecycle verdict |
| Weights do not sum to 1.00 | Rejected at the schema; `422` with actual sum |
| Stage 05 not run | `StageDependencyError` |

---

## 10. Security and compliance

- **RBAC**: reads `viewer`; weight changes `analyst`, audited with before/after and note.
- **Audit**: `policy.weights.changed`.
- **Frameworks**: RBI §4.2 (auth term), PCI-DSS 6.3 (data-exposure term), DPDP §8 (data-exposure term), NYDFS Part 500 (auth on zombie endpoints).

---

## 11. Tests

**Unit**
- All six indicators at 1.0 → score exactly 1.0.
- All at 0.0 → 0.0.
- Weights summing to 0.99 or 1.01 rejected.
- Tier boundaries: 0.7499 → HIGH, 0.75 → CRITICAL, 0.4999 → MEDIUM.
- Anomaly contributes exactly `w_anomaly`, once, never twice.
- Graded indicators: `basic` auth yields 0.5 × 0.28.
- `time_to_breach` returns `None` below `TTB_MIN_SCORE` and never returns 0.

**Integration**
- Weight change re-scores the estate; every `cdri.weights_version` advances; tier distribution changes accordingly.
- Missing `anomaly` row yields a part marked `source: absent`.
- Two endpoints with identical inputs score identically.

**E2E**
- Applying an auth control at stage 10 drops the endpoint's score by exactly the `no_auth` contribution and moves its tier.

---

## 12. Acceptance criteria

- [ ] Weights sum to exactly 1.00, enforced at the schema, and maximum score is 1.00.
- [ ] Every score has a six-part breakdown that re-sums to the score.
- [ ] The anomaly term appears exactly once.
- [ ] A weight change re-scores the whole estate live and is audited.
- [ ] Every `cdri` row names the `weights_version` that produced it.
- [ ] `time_to_breach` is labelled `heuristic` and lists its factors.
- [ ] An absent anomaly input is recorded as absent, not as zero-risk.
