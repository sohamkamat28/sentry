# Stage 10 — Human-Augmented Remediation

Generate the fix, prove it is safe, apply it at the gateway in seconds, and file the change request the same minute.

---

## 1. Scope

**Owns:** `control`, `judge_run`, `change_request`. Real Kong Admin API writes. Real shadow differential testing. Real ServiceNow submission.

**Does not own:** application code changes. Nothing here modifies a service. Every control is gateway configuration, reversible by deleting a plugin.

---

## 2. The split

FFIEC DA&M, NYDFS Part 500 and DORA all require human authorisation for production change. Manual remediation takes weeks while the exposure stays open. The system does not compromise between those; it splits the problem.

| Track | Latency | Approval | Scope |
|---|---|---|---|
| Virtual patch | < 30 s | `approver` role, in-product | Gateway configuration only. Already covered by emergency-change procedure in most institutions |
| Permanent fix | Normal CAB cycle | Change Advisory Board via ServiceNow | Application code, with all evidence pre-assembled |

The exposure closes immediately. The governance record is complete. Neither is traded for the other.

**The autonomous self-healing design in the predecessor research cannot ship in a regulated bank** — that is not a reduction in ambition, it is the constraint that makes the product deployable.

---

## 3. Deployment units

`worker/app/engines/remediation.py`, `worker/app/judge/`, `worker/app/actuators/{kong,servicenow}.py`.

---

## 4. Phase 1 — Generate

Input: endpoint, its CDRI parts, the specific indicator being remediated.

Two generators behind one interface, exactly as at stage 08. `control.generator` records which ran.

| Defect | Kong plugin | Config |
|---|---|---|
| No rate limiting | `rate-limiting` | `{minute: N, policy: "local", limit_by: "consumer"}`, N from the endpoint's observed p95 × 1.5 |
| TLS below 1.3 | `pre-function` | Rejects `ngx.var.ssl_protocol` below the floor with 426 |
| Data exposure | `response-transformer` | `remove.json` for the offending fields, resolved from observed data-class positions |
| No authentication | `key-auth` or `oauth2` | Consumer provisioning included in the plan |
| mTLS required | `pre-function` | Validates `ngx.var.ssl_client_verify == "SUCCESS"`, else 496 |

**A note on mTLS.** Kong's `mtls-auth` plugin is Enterprise-only. On Kong OSS the equivalent enforcement is the proxy listener configured with `ssl_verify_client=optional` and a CA bundle, plus a per-route `pre-function` that rejects unverified connections. That is what this system generates and applies. The Enterprise plugin is a configuration swap where a licence exists, and the actuator supports both via `KONG_MTLS_MODE`.

The same applies to DPoP: no OSS plugin implements it. The generated control is a `pre-function` validating the DPoP proof header — signature, `htm`/`htu` claims, `jti` replay cache in Redis. This is real enforcement, and it is described as what it is rather than as a plugin that does not exist.

Generated config is stored in `control.plugin_config` as **exactly the JSON that will be POSTed** — no transformation between what is reviewed and what is applied.

---

## 5. Phase 2 — API Judge

A patch is never applied without being tested against real traffic shapes first.

### 5.1 Shadow environment

`worker/app/judge/replay.py` brings up an isolated pair via the Docker API on a dedicated network:

- **Control**: a Kong instance with the endpoint's current configuration.
- **Variant**: an identical Kong instance with the proposed plugin added.

Both proxy to the same upstream. Neither is reachable from the estate network.

### 5.2 What is replayed, and what is not

Requests are reconstructed from `observation` rows over the last `JUDGE_WINDOW_VHOURS` (24): exact `method`, exact `path_raw`, `auth_scheme`, and the recorded header *shape*.

**Request bodies are not replayed, because they were never captured.** Stage 01 discards payloads in kernel; there is no body to replay. Where the endpoint has a declared schema — an OpenAPI spec from the gateway collector or a WSDL from the legacy collector — the Judge synthesises a schema-valid body. Where it has neither, body-bearing methods are replayed without a body and counted.

Every judge run therefore reports coverage honestly:

```json
"replay": {"requests": 480, "exact": 402, "schema_synthesised": 61, "bodyless": 17,
           "coverage": "partial"}
```

This is a real tension and it was resolved deliberately: capturing payloads would make replay perfect and would put customer financial data in the system. The privacy property is worth more than replay fidelity, and the limitation is reported rather than concealed.

### 5.3 The four dimensions

Each scored 0–100. Any dimension below its floor rejects the patch.

| Dimension | Method | Floor |
|---|---|---|
| Schema compatibility | `deepdiff` over response JSON structure, control vs variant. Removed fields are breaking; added are not | 100 |
| Latency budget | p95 delta measured across paired requests, compared to the endpoint's class budget | 70 |
| Error-rate delta | Status-class distribution shift | 95 |
| Data exposure | Variant responses re-scanned for data classes; a patch must not introduce exposure and should reduce it | 100 |

### 5.4 Latency scoring

```python
def latency_score(delta_us: int, budget_us: int) -> int:
    if delta_us <= 0:           return 100          # no slower than control
    if delta_us >= budget_us:   return 0            # over budget — reject
    headroom = 1.0 - (delta_us / budget_us)
    return int(round(60 + 40 * headroom))
```

**Budget compliance is a threshold, not a gradient.** An earlier build scored latency as a smooth ratio, so a patch using 68 % of an available budget scored 32 and was rejected — a patch that was, by the bank's own stated policy, acceptable.

With the floor at 70, the pass boundary sits at **75 % of budget consumed**:

| Budget consumed | Score | Verdict |
|---|---|---|
| 25 % | 90 | pass |
| 68 % | 73 | pass — the regression case |
| 75 % | 70 | pass, exactly at the boundary |
| 90 % | 64 | reject |

Being merely *within* budget is not sufficient. A patch consuming 90 % of the allowance leaves nothing for load variance, and the remaining quarter is the margin that makes the budget meaningful rather than nominal.

Budgets are per endpoint class, from `policy_setting.latency_budget_us`:

| Class | Budget |
|---|---|
| `SETTLEMENT` | 5 000 µs |
| `PAYMENT` | 10 000 µs |
| `CUSTOMER` | 50 000 µs |
| `REGULATORY` | 200 000 µs |
| `INTERNAL` | 200 000 µs |

The source document cited a flat "5 ms SWIFT/FedNow SLA". That is not a real per-hop API SLA and would not survive a technical challenge. Per-class configurable budgets replace it, tightest on settlement paths.

### 5.5 Verdict

```python
verdict = "PASS" if (schema >= 100 and latency >= 70 and error >= 95 and exposure >= 100) else "REJECT"
```

A `REJECT` returns to Phase 1 with the failing dimension and its diff as generation context. After `JUDGE_MAX_ATTEMPTS` (3) the control is marked `FAILED` and escalated to the operator with the full evidence.

---

## 6. Phase 3 — Apply

Only after a `PASS`, and only by an `approver`.

```python
resp = kong.post(f"/services/{svc}/plugins", json=control.plugin_config, timeout=10)
resp.raise_for_status()
control.kong_plugin_id = resp.json()["id"]
control.state = ControlState.APPLIED
control.applied_at = now()
```

**`APPLIED` is set only on a 2xx carrying a plugin id.** There is no path where a control is recorded as applied without Kong having confirmed it. A failure sets `FAILED`, records the response, emits a `dependency` error, and leaves the endpoint unchanged.

Post-apply, the endpoint's affected fields are updated (`auth`, `rate_limited`, `tls_version`) and **stages 04, 06, 07 and 13 re-run for that endpoint alone**. This is the shared-state property: the register, the matrix, the forecast and the zero-trust posture all move within one refresh cycle because they read from the same tables the actuator just wrote.

### Rollback

`DELETE /plugins/{id}`, `state = REVERTED`, dependent stages re-run. Every control is reversible, and reversibility is what makes a sub-30-second apply defensible.

### Idempotency

`POST /remediation/{id}/apply` on an already-`APPLIED` control returns `409` with the existing `control.id`. Kong is never given a duplicate plugin.

---

## 7. Phase 4 — Change Request

Submitted in parallel with the apply, not after it.

```python
payload = {
  "short_description": f"SENTINEL: remediate {ep.method} {ep.path_template}",
  "description":       finding.narrative.technical,
  "justification":     finding.narrative.summary,
  "risk":              cdri_tier_to_snow_risk(cdri.tier),
  "impact":            blast_tier_to_snow_impact(blast.tier),
  "implementation_plan": render_plan(control),
  "backout_plan":      f"DELETE /plugins/{{id}} at the gateway; no code change to revert.",
  "test_plan":         render_judge_evidence(judge_run),
  "u_regulatory_citations": "; ".join(f"{r.framework} {r.clause}" for r in finding.regulations),
  "assignment_group":  SERVICENOW_GROUP,
}
r = httpx.post(f"{SERVICENOW_URL}/api/now/table/change_request",
               json=payload, auth=(user, password), timeout=15)
```

Stores `sys_id` and `number`. State is polled every `SERVICENOW_POLL_VMINUTES` (30) and reflected in the console.

`u_regulatory_citations` is a custom field; where the target instance lacks it, the actuator falls back to appending citations to `description` — the client probes the table schema once at startup and adapts, rather than failing on a field that may not exist.

**Testing without a live instance.** ServiceNow has no local runtime. The client is tested against recorded cassettes generated from a real developer instance, plus a schema-accurate stub served in compose (`deploy/compose/servicenow-stub/`) implementing `POST/GET /api/now/table/change_request`. The stub is labelled a stub in the console's integration status panel; nothing presents it as a live ITSM connection.

---

## 8. Data model delta

Writes `control`, `judge_run`, `change_request`. Updates `endpoint.{auth,rate_limited,tls_version}` on successful apply.

---

## 9. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/remediation` | `viewer` | Queue sorted by CDRI, with control state per endpoint |
| `GET /api/v1/remediation/{endpoint_id}` | `viewer` | Proposed controls, judge history, CR state |
| `POST /api/v1/remediation/{endpoint_id}/generate` | `analyst` | Phase 1; `202` |
| `POST /api/v1/remediation/{endpoint_id}/judge` | `analyst` | Phase 2; `202` |
| `POST /api/v1/remediation/{endpoint_id}/apply` | **`approver`** | Phase 3 + 4 |
| `POST /api/v1/remediation/control/{id}/revert` | **`approver`** | Rollback |
| `GET /api/v1/remediation/cr/{id}` | `viewer` | CR state from ServiceNow |
| `POST /api/v1/remediation/cr/{id}/approve` | **`approver`** | Mark approved |

The `analyst`/`approver` boundary sits exactly at the Kong write. An analyst can generate and prove a control and cannot apply it.

```json
{
  "endpoint_id": "ep_9f2c…",
  "controls": [{
    "id": 41, "kind": "key-auth", "state": "JUDGED", "generator": "anthropic",
    "plugin_config": {"name":"key-auth","config":{"key_names":["apikey"]}},
    "judge": {
      "verdict": "PASS",
      "replay": {"requests":480,"exact":402,"schema_synthesised":61,"bodyless":17,"coverage":"partial"},
      "scores": {"schema":100,"latency":88,"error":99,"exposure":100},
      "latency_delta_us": 3400, "budget_us": 10000, "headroom_pct": 66
    }
  }],
  "change_request": {"number":"CHG0030041","state":"SUBMITTED","sys_id":"…"}
}
```

---

## 10. Configuration

| Variable | Default | Notes |
|---|---|---|
| `KONG_ADMIN_URL` / `KONG_ADMIN_TOKEN` | — | Required |
| `KONG_MTLS_MODE` | `pre-function` | or `mtls-auth` with Enterprise |
| `JUDGE_WINDOW_VHOURS` | `24` | Replay window |
| `JUDGE_MAX_REQUESTS` | `2000` | Cap per run |
| `JUDGE_MAX_ATTEMPTS` | `3` | Regeneration cycles before escalation |
| `JUDGE_NETWORK` | `sentinel-shadow` | Isolated Docker network |
| `SERVICENOW_URL` / `_USER` / `_PASSWORD` / `_GROUP` | — | |
| `SERVICENOW_POLL_VMINUTES` | `30` | |

---

## 11. Failure modes

| Condition | Behaviour |
|---|---|
| Kong unreachable | `503 dependency`, `state=FAILED`, audited. **No plugin created, nothing marked applied** |
| Kong returns 4xx | `state=FAILED`, response body stored, surfaced verbatim to the operator |
| Shadow containers fail to start | Judge run `FAILED` with the Docker error. Apply is blocked — no untested patch reaches production |
| No traffic in the replay window | `judge_run.requests = 0`, verdict `REJECT`, reason `insufficient_traffic`. A patch is never passed on zero evidence |
| ServiceNow unreachable | CR `state=FAILED`, payload retained, retried by beat. **The virtual patch is unaffected** — the split is the point |
| Anthropic unavailable | Template generator; `control.generator='template'` |
| Revert fails | `state` stays `APPLIED`, alert raised. The system does not claim a revert it could not perform |

---

## 12. Security and compliance

- **RBAC**: generate/judge `analyst`; apply/revert/approve `approver`. Enforced at the route, tested by asserting an `analyst` token gets `403` on apply and no Kong plugin appears.
- **Audit**: `control.generated`, `control.judged`, `control.applied` (with plugin id and config hash), `control.reverted`, `cr.submitted`, `cr.approved`. Every production-affecting action, with actor.
- **Frameworks**: FFIEC DA&M (human authorisation — the governing rationale for this entire design); NYDFS Part 500 §500.03; DORA Art 9; PCI-DSS 6.3.
- **Secrets**: Kong admin token and ServiceNow credentials from the secret store, never logged, redacted from stored payloads.

---

## 13. Tests

**Unit**
- Config generation per defect matches the expected plugin JSON exactly.
- `latency_score`: 0 delta → 100; at budget → 0; 68 % of budget → ≥ 70 with headroom reported. **This is the regression test for the over-strict scoring that rejected acceptable patches.**
- Verdict logic across all floor combinations.
- ServiceNow risk/impact mapping for every tier pair.

**Integration (testcontainers, real Kong)**
- Apply creates a real plugin; `GET /plugins/{id}` confirms it; `control.kong_plugin_id` matches.
- Revert deletes it; a subsequent `GET` returns 404.
- Kong stopped mid-apply → `FAILED`, no plugin, audit entry present.
- Duplicate apply returns `409` and creates no second plugin.
- Applying an auth control re-runs stages 04/06/07/13 and the endpoint's CDRI drops by the `no_auth` contribution.
- Judge against real shadow containers produces non-zero measured latency delta.
- Zero-traffic endpoint yields `REJECT` with `insufficient_traffic`.

**E2E**
- Full path on a CRITICAL zombie: generate → judge PASS → apply → CDRI falls → tier changes → register re-sorts → CR appears with a number.
- `analyst` token is refused at apply with `403` and no state change.

---

## 14. Acceptance criteria

- [ ] A control reaches `APPLIED` only after a 2xx from Kong carrying a plugin id.
- [ ] The applied plugin is verifiable through Kong's own Admin API, independently of SENTINEL.
- [ ] Revert removes it and the removal is verifiable the same way.
- [ ] Judge measurements come from real requests against two real gateway instances.
- [ ] Replay coverage is reported honestly, including bodyless and synthesised counts.
- [ ] A patch within its latency budget passes and reports headroom.
- [ ] A patch that removes a response field fails schema compatibility.
- [ ] Applying a control moves CDRI, the matrix, the forecast and the zero-trust posture in the same refresh.
- [ ] `analyst` cannot apply; `approver` can. Verified by test, not by inspection.
- [ ] ServiceNow unavailability blocks nothing on the virtual-patch track.
- [ ] The ServiceNow stub is labelled as a stub wherever its state is displayed.
