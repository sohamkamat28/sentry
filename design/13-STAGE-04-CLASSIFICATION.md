# Stage 04 — Classification

Two independent axes, five deterministic questions, no machine learning.

---

## 1. Scope

**Owns:** `classification.lifecycle`, `governance`, `confidence`, `severity_bump`, and the rule trace.

**Does not own:** `classification.pre_zombie`. That column lives on this table but is written by stage 07, which computes it from a forecast this stage has no access to. Stage 04 displays it.

---

## 2. Deployment unit

`worker/app/engines/classification.py`. Runs after stage 03. Pure function of one endpoint's facts — no cross-endpoint state, so it parallelises trivially and is exhaustively testable.

---

## 3. Why this is rule-based

A bank must defend every verdict to a regulator, and "the model decided" is not a defence. A rule tree can be re-run by hand by an examiner and reach the same answer. The deliberate choice not to use ML here is the reason the output is admissible, and it is a design constraint rather than an implementation shortcut.

---

## 4. Inputs

| Source | Field |
|---|---|
| `endpoint` | `last_call_vday`, `first_vday`, `deprecated` |
| `endpoint_source` | Presence per source |
| `endpoint_shadow` view | Shadow evidence |
| `ownership` | `owner_email`, `reachable`, `confidence` |
| Stage 02 | `confidence(vday, first_vday, backfilled)` |
| Stage 03 | `shadow_reliable` flag |

---

## 5. Algorithm

### 5.1 The five questions

Evaluated in order, each answer recorded in `trace`:

| # | Question | Source |
|---|---|---|
| Q1 | Days since last call? | `vday - last_call_vday`, or `NULL` if never called |
| Q2 | Registered in the gateway? | `endpoint_source` has `gateway` |
| Q3 | Does it have a reachable owner? | `ownership.owner_email IS NOT NULL AND reachable` |
| Q4 | Formally deprecated? | `endpoint.deprecated` |
| Q5 | Present in code? | `endpoint_source` has `code` |

### 5.2 Lifecycle axis

```python
def lifecycle(q1: int | None, q4: bool) -> Lifecycle:
    if q1 is None:      return Lifecycle.ACTIVE   # discovered in code, never called — unreleased
    if q4:              return Lifecycle.DEPRECATED
    if q1 <= 30:        return Lifecycle.ACTIVE
    if q1 < 90:         return Lifecycle.DORMANT
    return Lifecycle.ZOMBIE
```

Two corrections to the source model are encoded here:

- **`DORMANT` covers days 31–89.** The original had `ACTIVE ≤ 30` and `ZOMBIE ≥ 90`, leaving days 31–89 matching no status at all.
- **Ownership is not part of this test.** The original required "no active owner" for `ZOMBIE`, so a 200-day-silent endpoint *with* an owner matched nothing. Missing ownership raises severity; it does not decide status.

`DEPRECATED` outranks the day count because a formally sunsetting endpoint that is still serving traffic is not `ACTIVE` — it is on a retirement path, and treating it as healthy would hide the work in progress.

An endpoint never called is `ACTIVE`, not `ZOMBIE`. It has no traffic history to be silent against. `ZOMBIE` means *was alive, now is not*; unreleased code is a different condition and stage 08 narrates it differently.

### 5.3 Governance axis

```python
def governance(q2: bool, q3: bool, q5: bool, shadow_reliable: bool) -> Governance:
    if not q2 and not q5:
        if not shadow_reliable:
            return Governance.ORPHANED if not q3 else Governance.OWNED  # withhold SHADOW
        return Governance.SHADOW
    return Governance.OWNED if q3 else Governance.ORPHANED
```

`SHADOW` requires traffic present, gateway absent, **and** code absent. When the gateway collector is unhealthy, absence is not evidence, and the verdict is withheld rather than manufactured.

`SHADOW` outranks `ORPHANED`: an endpoint in no registry and no repository has no owner by construction, and reporting it as merely ownerless understates it.

### 5.4 Severity modifier

```python
severity_bump = (not q3) or (ownership.confidence < OWNERSHIP_CONFIDENCE_FLOOR)
```

Consumed by stage 06 for tier presentation and by stage 14 for leaderboard weighting. It does not alter the CDRI score — the score is the weighted formula and nothing else, so it stays comparable across the estate.

### 5.5 Confidence gate

```python
if confidence(vday, first_vday, backfilled) is Confidence.NONE:
    return  # no row written at all
```

Below the baseline threshold the engine writes nothing. An absent row is unambiguous; a row stamped "not confident" invites being read as a verdict.

---

## 6. The matrix

Four lifecycle × three governance = twelve cells, all reachable and all meaningful.

|  | OWNED | ORPHANED | SHADOW |
|---|---|---|---|
| **ACTIVE** | Normal | Live, no owner — escalate | Ungoverned live traffic — highest urgency |
| **DORMANT** | Watch | Watch, no owner | Ungoverned and fading |
| **DEPRECATED** | Sunsetting normally | Sunsetting, no owner to confirm | Undocumented and sunsetting |
| **ZOMBIE** | Dead, owner accountable | Dead, nobody accountable | Dead, ungoverned, unrecorded |

`ACTIVE`/`SHADOW` is the most urgent cell in the estate: traffic is flowing right now through an endpoint no registry knows exists. `ZOMBIE`/`SHADOW` is the classic finding. The console's matrix is clickable and filters the register.

---

## 7. Data model delta

Writes `classification` — every column except `pre_zombie`.

```sql
INSERT INTO classification (endpoint_id, lifecycle, governance, confidence,
                            severity_bump, trace, vday, engine_version)
VALUES (...)
ON CONFLICT (endpoint_id) DO UPDATE SET
  lifecycle=EXCLUDED.lifecycle, governance=EXCLUDED.governance,
  confidence=EXCLUDED.confidence, severity_bump=EXCLUDED.severity_bump,
  trace=EXCLUDED.trace, vday=EXCLUDED.vday, engine_version=EXCLUDED.engine_version;
  -- pre_zombie deliberately absent from the SET list
```

The omission is load-bearing: a classification re-run must not clear a flag stage 07 wrote. A test asserts this.

`trace` shape:

```json
[
  {"q": 1, "question": "days since last call", "answer": 147, "source": "endpoint.last_call_vday"},
  {"q": 2, "question": "registered in gateway",  "answer": false, "source": "endpoint_source"},
  {"q": 3, "question": "reachable owner",        "answer": false, "source": "ownership.reachable"},
  {"q": 4, "question": "formally deprecated",    "answer": false, "source": "endpoint.deprecated"},
  {"q": 5, "question": "present in code",        "answer": false, "source": "endpoint_source"},
  {"rule": "lifecycle", "applied": "q1 >= 90 → ZOMBIE"},
  {"rule": "governance","applied": "not q2 and not q5 → SHADOW"},
  {"rule": "severity",  "applied": "not q3 → severity_bump"}
]
```

An examiner can replay this by hand. That is the requirement the trace exists to satisfy.

---

## 8. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/classification` | `viewer` | Matrix counts, per-cell endpoint ids |
| `GET /api/v1/classification/{endpoint_id}` | `viewer` | Verdict plus full trace |
| `GET /api/v1/estate` | `viewer` | Filterable register: `?lifecycle=&governance=&confidence=&team=&tier=` |
| `POST /api/v1/classification/run` | `analyst` | Force; `202` |

```json
{
  "vday": 147,
  "matrix": [
    {"lifecycle":"ACTIVE","governance":"OWNED","n":68},
    {"lifecycle":"ACTIVE","governance":"SHADOW","n":3},
    {"lifecycle":"ZOMBIE","governance":"ORPHANED","n":11},
    ...
  ],
  "confidence": {"PROVISIONAL": 98, "CONFIRMED": 28},
  "shadow_reliable": true
}
```

---

## 9. Configuration

| Variable | Default | Notes |
|---|---|---|
| `ACTIVE_VDAYS` | `30` | Upper bound of `ACTIVE` |
| `ZOMBIE_VDAYS` | `90` | Lower bound of `ZOMBIE`; equals `WINDOW_VDAYS` |
| `OWNERSHIP_CONFIDENCE_FLOOR` | `0.5` | Below this, severity bump even with a name |

`ACTIVE_VDAYS` and `ZOMBIE_VDAYS` are exposed but changing them changes what the words mean estate-wide. Both are recorded on every `classification` row via `engine_version`, so a historical verdict is always interpretable against the thresholds in force when it was made.

---

## 10. Failure modes

| Condition | Behaviour |
|---|---|
| Confidence `NONE` | No row written |
| `shadow_reliable=false` | `SHADOW` withheld; falls back to owner test |
| Ownership row missing | Treated as unreachable → `ORPHANED` + severity bump; ladder shows why |
| Stage 03 not run | `StageDependencyError`, `pipeline.stage.blocked` audit event |
| Endpoint retired | Skipped; retired endpoints leave the live matrix |

---

## 11. Security and compliance

- **RBAC**: reads `viewer`; forced run `analyst`.
- **Audit**: not audited per verdict — verdicts are analytical output, not governance events. Threshold changes are audited by stage 02/policy.
- **Frameworks**: FS AI RMF — this stage is explicitly *not* an AI decision and is recorded as rule-derived, which is what keeps it outside the 230 control objectives; RBI §4.2 (auth state is an input); DORA Art 9.

---

## 12. Tests

**Unit** — the full truth table. 5 boolean/ordinal inputs, all reachable combinations, asserted against an explicit expectation table:
- `q1=147, q2=F, q3=F, q4=F, q5=F` → `ZOMBIE`/`SHADOW`, severity bump.
- `q1=200, q3=T` → `ZOMBIE`/`OWNED` — the case the original model could not express.
- `q1=45` → `DORMANT` — the gap the original model left.
- `q1=None` → `ACTIVE`, never `ZOMBIE`.
- `q4=T, q1=5` → `DEPRECATED`, not `ACTIVE`.
- `shadow_reliable=F` with gateway and code both absent → not `SHADOW`.

**Integration**
- Re-running classification does not clear `pre_zombie` set by stage 07. Asserted explicitly.
- An endpoint at confidence `NONE` has no row; crossing to `PROVISIONAL` creates one.
- Trace replay: a helper re-evaluates the recorded trace and reproduces the stored verdict for every row in the estate.

**E2E**
- `legacy-balance` reaches `ZOMBIE`/`ORPHANED` after 90 vdays of silence.
- `recon-quarterly` never reaches `ZOMBIE` despite 89-vday gaps.
- `shadow-fx-rate` is `ACTIVE`/`SHADOW`.

---

## 13. Acceptance criteria

- [ ] Every endpoint above baseline confidence has exactly one lifecycle and one governance value.
- [ ] No endpoint matches zero statuses. The truth-table test proves total coverage.
- [ ] A 200-vday-silent endpoint with an owner classifies `ZOMBIE`/`OWNED`.
- [ ] A 45-vday-silent endpoint classifies `DORMANT`.
- [ ] Trace replay reproduces the stored verdict for 100 % of rows.
- [ ] Classification re-run preserves `pre_zombie`.
- [ ] `SHADOW` never appears while `shadow_reliable` is false.
