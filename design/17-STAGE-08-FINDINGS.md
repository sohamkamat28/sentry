# Stage 08 — Findings & Regulatory Mapping

Turns a score into a document a compliance officer can hand to an examiner unmodified.

---

## 1. Scope

**Owns:** `finding` (narrative, generator, regulations) and `ai_decision` rows for narrative generation.

**Does not own:** the risk score, the blast radius, or the time-to-breach figure. It composes them into prose and maps them to clauses.

---

## 2. Deployment unit

`worker/app/engines/findings.py` plus `worker/app/ai/client.py`. Runs after stages 06, 07 and 09 — it needs the score, the projection and the impact before it can describe consequences.

---

## 3. Inputs

| Source | Field |
|---|---|
| `cdri` | `score`, `tier`, `parts`, `time_to_breach_d` |
| `classification` | `lifecycle`, `governance`, `trace`, `pre_zombie` |
| `anomaly` | `patterns` |
| `blast` | `tier`, `affected`, `touches_critical` |
| `ownership` | `owner_email`, `reachable`, `escalation` |
| `endpoint` | `auth`, `tls_version`, `data_classes`, `last_call_vday` |

Generated for `CRITICAL` and `HIGH` tiers by default (`FINDINGS_MIN_TIER`). Lower tiers on demand.

---

## 4. Generation

Two generators behind one interface. The output records which ran.

```python
class NarrativeGenerator(Protocol):
    name: str
    def generate(self, ctx: FindingContext) -> Narrative: ...
```

### 4.1 Anthropic generator

Used when `ANTHROPIC_API_KEY` is set.

- **Context assembled as structured JSON**, never free text: endpoint identity, CDRI breakdown, classification trace, anomaly patterns, blast summary, ownership state, data classes, last-call vday.
- **No customer data is in the context.** Data classes are labels (`AADHAAR`), not values — the values were discarded in kernel at stage 01 and have no representation anywhere in the system.
- System prompt requires four parts: executive summary (non-technical), technical finding, regulatory violations with exact clauses, recommended immediate action.
- Response requested as JSON with a fixed schema; validated against it. A malformed response is retried once, then falls through to the template generator with `generator='template'`.
- `max_tokens` 1500, `temperature` 0.2. Low temperature because two runs over the same evidence should not produce materially different findings.

Every call writes `ai_decision`: model id, prompt SHA-256, output SHA-256, token counts, latency, and the model's own stated confidence. With `AI_ARCHIVE_PROMPTS=true` the full prompt and response go to WORM under `ai/<vday>/<finding_id>.json`.

### 4.2 Template generator

Deterministic, dependency-free, and the fallback whenever the API key is absent or the call fails.

```python
def render(ctx) -> str:
    parts = []
    parts.append(f"{ctx.method} {ctx.path} has not been called in {ctx.silent_days} days "
                 f"and remains registered and reachable.")
    if ctx.auth == "none":
        parts.append("It enforces no authentication.")
    if ctx.data_classes:
        parts.append(f"Responses have been observed to carry {humanise(ctx.data_classes)}.")
    ...
```

The template is not a placeholder. It produces a correct, complete, citable finding — the model version reads better and adapts to unusual combinations. The distinction matters because `finding.generator` is surfaced in the API and in the console: a template narrative is never presented as model-generated. The system does not claim an LLM ran when one did not.

---

## 5. Regulatory mapping

Rule-based, not model-generated. A clause citation must be exactly right, and this is not a place for generation.

`worker/app/engines/frameworks.py` holds the mapping table; a finding's citations are the union of every rule whose predicate matches.

| Framework | Clause | Predicate |
|---|---|---|
| RBI API Security 2023 | §4.2 authentication | `auth == 'none'` or `auth == 'basic'` |
| RBI API Security 2023 | §5.1 encryption | `tls_version` in (none, 1.0, 1.1) |
| RBI API Security 2023 | §continuous monitoring | `lifecycle == 'ZOMBIE'` |
| PCI-DSS v4.0 | Req 6.3 secure development | `CARD` or `CVV` in data classes |
| PCI-DSS v4.0 | Req 6.4 public-facing protection | `internet_reachable and not rate_limited` |
| DPDP Act 2023 | §8 data minimisation | any of PAN/AADHAAR/ACCOUNT_NO/DOB |
| FFIEC DA&M | Development, Acquisition & Maintenance | `governance in ('ORPHANED','SHADOW')` |
| NYDFS Part 500 | §500.12 MFA / privileged access | `auth == 'none' and lifecycle == 'ZOMBIE'` |
| NYDFS Part 500 | §500.06 audit trail | always — the audit ledger is the evidence |
| DORA (EU) | Art 9 protection & prevention | `governance == 'SHADOW'` or `blast.tier == 'CRITICAL'` |
| FS AI RMF | AI decision logging | `finding.generator == 'anthropic'` |

**Seven frameworks.** FFIEC DA&M is in the grid because it is the entire stated rationale for human-in-the-loop remediation at stage 10; the source document cited it in prose while omitting it from the framework list and claiming six.

Each citation carries `{framework, clause, requirement, status, evidence}` where `evidence` names the field that triggered it — so a compliance officer can check the finding rather than trust it.

---

## 6. Time-to-breach presentation

Stage 06 computes it; this stage presents it as the headline. The finding leads with the countdown and carries the score as supporting detail, because a deadline moves budget and a score does not. The `basis: heuristic` label travels with it into the finding text — the document does not present a heuristic as a measurement.

---

## 7. Data model delta

Writes `finding` and `ai_decision`. Findings accumulate — a new one per vday per endpoint, never an update. The history is the record of how a risk was described over time.

---

## 8. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/findings` | `viewer` | Latest finding per endpoint, filterable by tier and framework |
| `GET /api/v1/findings/{endpoint_id}` | `viewer` | Current finding with full citation set |
| `GET /api/v1/findings/{endpoint_id}/history` | `viewer` | All findings for the endpoint |
| `POST /api/v1/findings/{endpoint_id}` | `analyst` | Regenerate; `202` |
| `GET /api/v1/findings/frameworks` | `viewer` | Coverage matrix: violations per framework across the estate |
| `GET /api/v1/findings/{endpoint_id}/export` | `viewer` | PDF/Markdown compliance brief |
| `GET /api/v1/ai/decisions` | `admin` | FS AI RMF decision log, paginated |

```json
{
  "id": "fnd_7c2a…", "endpoint_id": "ep_9f2c…", "vday": 147,
  "generator": "anthropic",
  "model": "claude-sonnet-4-5",
  "narrative": {
    "summary": "…", "technical": "…", "action": "…"
  },
  "time_to_breach": {"days": 2, "basis": "heuristic"},
  "regulations": [
    {"framework":"DPDP Act 2023","clause":"Section 8","requirement":"Data minimisation",
     "status":"VIOLATED","evidence":"data_classes contains AADHAAR"},
    {"framework":"FFIEC DA&M","clause":"Development, Acquisition & Maintenance",
     "requirement":"Ownership and change control","status":"VIOLATED",
     "evidence":"governance = ORPHANED"}
  ]
}
```

---

## 9. Configuration

| Variable | Default | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Absent → template generator |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-5` | |
| `ANTHROPIC_TIMEOUT_S` | `30` | |
| `ANTHROPIC_MAX_RETRIES` | `1` | Then template fallback |
| `AI_ARCHIVE_PROMPTS` | `false` | Full prompt/response to WORM |
| `FINDINGS_MIN_TIER` | `HIGH` | Auto-generation threshold |
| `FINDINGS_BATCH` | `20` | Concurrent generations |

---

## 10. Failure modes

| Condition | Behaviour |
|---|---|
| No API key | Template generator, `generator='template'`, surfaced in API and console |
| API timeout or 5xx | One retry, then template. `ai_decision` records the failure |
| Malformed model JSON | Validation fails → template. Never a partially parsed narrative |
| Rate limited (429) | Exponential backoff within the task; batch continues; unfinished endpoints retried next cycle |
| Blast radius missing | Finding generated without impact section, noted in the text as not yet analysed |
| Stage 06/07/09 incomplete | `StageDependencyError` |

Regulatory mapping never degrades — it is rule-based and runs regardless of generator availability. A finding always carries correct citations even when the prose is templated.

---

## 11. Security and compliance

- **RBAC**: reads `viewer`; regeneration `analyst`; AI decision log `admin`.
- **Audit**: `finding.generated` with generator and model.
- **FS AI RMF**: `ai_decision` is the compliance artefact — every model-influenced output reconstructable from prompt hash, model version, confidence and reasoning. The 230 control objectives require reconstructability, which digest-plus-summary satisfies without retaining prompts by default.
- **Data protection**: no customer data enters a prompt, structurally — the values do not exist in the database.
- **Deployment note**: `ANTHROPIC_BASE_URL` may point at a regional or on-premise gateway where data-residency rules require it. The client is endpoint-agnostic.

---

## 12. Tests

**Unit**
- Every framework predicate: positive and negative case each.
- FFIEC DA&M cited whenever governance is `ORPHANED` or `SHADOW`.
- Template generator produces a complete narrative for all four tiers.
- Malformed model JSON falls back to template and records the failure.
- No prompt contains a value from `data_classes` — only labels.

**Integration**
- With a key set, `generator='anthropic'` and an `ai_decision` row exists with matching hashes.
- With the key unset, `generator='template'` and no `ai_decision` row.
- API returning 500 twice yields a template finding; the retry is recorded.
- Framework coverage matrix totals equal the sum of per-endpoint citations.

**E2E**
- A CRITICAL zombie produces a finding citing at least RBI §4.2, DPDP §8 and FFIEC DA&M.
- Export renders to PDF without layout errors.

---

## 13. Acceptance criteria

- [ ] Every `HIGH`/`CRITICAL` endpoint has a current finding.
- [ ] `generator` is accurate on every row; template output is never labelled as model output.
- [ ] All seven frameworks appear in the mapping table and FFIEC DA&M is reachable.
- [ ] Every citation carries the field that triggered it.
- [ ] `ai_decision` exists for every Anthropic call with prompt and output digests.
- [ ] Removing the API key mid-run produces valid findings with correct citations.
- [ ] No customer identifier appears in any stored prompt or narrative.
- [ ] Time-to-breach is presented with its `heuristic` basis intact.
