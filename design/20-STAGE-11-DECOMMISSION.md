# Stage 11 — Phased Decommission

Four phases, real gateway state changes at each, and a WORM archive before anything goes dark.

---

## 1. Scope

**Owns:** `decommission`, `certificate`, `endpoint.retired`. Gateway state transitions for throttle, sunset headers, quarantine alerting, 410, and canary weights. WORM archival.

**Does not own:** honeypot behaviour. Phase D activates it; stage 12 runs it.

---

## 2. Eligibility

Enforced in code before an endpoint can be enrolled:

```python
def eligible(ep, cls, blast) -> None:
    if cls.confidence is not Confidence.CONFIRMED:
        raise Conflict("PROVISIONAL_VERDICT", "requires 90 vdays of observation")
    if cls.lifecycle is not Lifecycle.ZOMBIE and not ep.deprecated:
        raise Conflict("NOT_ELIGIBLE", "lifecycle must be ZOMBIE or formally deprecated")
    if blast is None:
        raise Conflict("NO_IMPACT_ANALYSIS", "run stage 09 first")
    if ep.retired:
        raise Conflict("ALREADY_RETIRED", ...)
```

A `PROVISIONAL` verdict cannot enter the workflow. That is the confidence ramp from stage 02 having a real consequence rather than being a label.

---

## 3. Path selection

```python
express = blast.tier is BlastTier.ZERO and blast.in_graph
canary  = blast.touches_critical
```

| Path | Condition | Phases | Duration |
|---|---|---|---|
| Standard | Default | A → B → C → D | 90 vdays |
| Express | `ZERO` blast, present in graph | B → C → D | 30 vdays |
| Canary | Blast touches payment/settlement/regulatory | A(canary) → B → C → D | 90 vdays |

**Express skips throttling, not the quarantine.** Ninety days of silence cannot rule out an annual job. `blast.in_graph` is required: an endpoint never observed in the graph has not been proven to have zero callers, it has merely never been seen, and that is not the same evidence.

**Canary never throttles.** Deliberately degrading a payment path is itself an incident. The source design applied a 75 % throttle uniformly, which would have done exactly that.

---

## 4. Phases

### Phase A — Throttle *or* canary (vdays 1–30)

**Ordinary endpoints.** Kong `rate-limiting` plugin at 25 % of observed p95, and migration guidance generated for every caller team named in the blast radius.

```json
{"name":"rate-limiting","config":{"minute":N,"policy":"local","limit_by":"service"}}
```

**Critical endpoints.** Canary migration instead. `canary_split` starts at 0.10 and advances 0.10 → 0.01 → 0.00 as error rates hold. Implemented with Kong upstream targets and weights:

```
PUT /upstreams/{name}/targets  {"target":"replacement:8443","weight":90}
PUT /upstreams/{name}/targets  {"target":"legacy:8443","weight":10}
```

Error rate is measured from `endpoint_daily.err_calls` across the shift. A rise beyond `CANARY_ERROR_CEILING` (2 % absolute over baseline) reverts weights to 100/0 old immediately, sets `phase = REVERTED`, records `reverted_reason`, and alerts. Reverting is automatic because waiting for a human while a payment path degrades is the wrong trade — and unlike a code change, a weight revert is safe to automate.

### Phase B — Sunset headers (vdays 31–60)

Kong `response-transformer`:

```json
{"name":"response-transformer","config":{"add":{"headers":[
  "Sunset: Wed, 21 Oct 2026 07:28:00 GMT",
  "Deprecation: true",
  "Link: <https://sentinel.internal/sunset/ep_9f2c>; rel=\"sunset\""
]}}}
```

`Sunset` is RFC 8594 and machine-parseable, so client tooling picks it up without anyone reading a memo. The date is computed from `entered_vday` plus the remaining path length, converted to wall time through the vclock.

### Phase C — Quarantine (vdays 61–90)

The endpoint stays fully operational. Every call raises a CRITICAL alert and is recorded as a hidden caller.

```python
def record_hidden_caller(ep_id, obs):
    # any call during quarantine is by definition an undiscovered dependency
    upsert(decommission.hidden_callers, {"service": obs.peer_service, "ip": str(obs.peer_ip),
                                          "first_vday": obs.vday, "calls": 1})
    alert(CRITICAL, f"quarantined endpoint called by {obs.peer_service}")
```

This is the forcing function. Quarterly batch jobs and third-party integrations that no registry knew about surface here, while the endpoint still works. Surfacing a dependency during quarantine is a success, not a failure — the console labels it that way.

A hidden caller does not automatically halt the process; it raises an alert and the operator decides. `POST /decommission/{id}/hold` pauses the phase clock with a mandatory reason.

### Phase D — Archive, 410, honeypot

Order matters and is enforced:

1. **WORM archive first.** All `observation` and `endpoint_daily` history for the endpoint, plus its full analytical record, serialised to MinIO with Object Lock.

```python
s3.put_object(Bucket=WORM_BUCKET, Key=f"decommission/{ep.id}/{vday}.json.gz",
              Body=payload, ObjectLockMode="COMPLIANCE",
              ObjectLockRetainUntilDate=now() + timedelta(days=365 * WORM_RETAIN_YEARS))
```

2. **410 Gone at the gateway** — not 404. `410` means this existed and was intentionally removed, which is information a client should have.

```json
{"name":"request-termination","config":{"status_code":410,"message":"Endpoint retired"}}
```

3. **Fingerprint captured** by stage 12 before the route stops behaving normally.
4. **Honeypot activated** — the 410 termination is replaced by a route to the honeypot service.
5. **Certificate issued.**

**Phase D cannot complete without a WORM object and a retention date.** If MinIO is unavailable the phase blocks. Retiring an endpoint whose history was not archived would destroy the evidence the archive exists to preserve.

---

## 5. WORM verification

Object Lock in `COMPLIANCE` mode cannot be shortened or removed by any user, including root. The system proves this rather than asserting it:

`GET /api/v1/decommission/{id}/worm/verify` attempts a delete against the archived object and reports the resulting `AccessDenied`. A demonstrable immutability check is worth more than a configuration screenshot.

The bucket is created with `ObjectLockEnabledForBucket=True` at first startup; a bucket without it is a fatal misconfiguration and `readyz` fails.

---

## 6. Certificate

Issued at Phase D completion, signed by an `approver`.

```json
{
  "id": "cert_…", "endpoint": {"method":"GET","path":"/api/v1/legacy-balance","service":"…"},
  "retired_vday": 237,
  "evidence": {
    "silent_vdays": 147, "confidence": "CONFIRMED",
    "blast": {"tier":"ZERO","direct_callers":0,"in_graph":true},
    "hidden_callers_found": 1,
    "phases": [{"phase":"B","entered_vday":207},{"phase":"C","entered_vday":222},{"phase":"D","entered_vday":237}],
    "cdri_at_retirement": 0.93,
    "worm_object": "s3://sentinel-worm/decommission/ep_9f2c/237.json.gz",
    "worm_retain_until": "2033-07-27T00:00:00Z",
    "honeypot_activated": true,
    "honeypot_legal_signoff": "policy:LEGAL-2026-004"
  },
  "approved_by": "…", "content_hash": "…"
}
```

`content_hash` is written to the audit ledger, so the certificate is tamper-evident independently of the database row. `honeypot_legal_signoff` references the one-time policy record — activation is recorded here rather than approved per endpoint, which is what makes it operable at estate scale.

---

## 7. Phase advancement

Beat task each vday:

```python
for d in active_decommissions():
    if d.hold: continue
    if current_vday() - d.phase_vday >= phase_length(d):
        advance(d)
```

`POST /decommission/{id}/advance` lets an `approver` advance early with a recorded reason. There is no automatic advance *into* Phase D — archival and 410 are irreversible in effect, so the final transition requires a human. Phases A→B and B→C advance on the clock.

---

## 8. Data model delta

Writes `decommission`, `certificate`, `endpoint.{retired, honeypot_active}`.

**Gateway changes are delegated to the stage 10 actuator**, exactly as stage 13 delegates. Every throttle, sunset header, canary weight and 410 termination is created as a `control` row by `worker/app/actuators/kong.py` and owned by stage 10. This stage never writes `control` directly.

One writer for gateway state means one audit trail, one place where `APPLIED` can become true, and one rollback path. A phase transition that bypassed the actuator would be a gateway change with no `control` row to revert.

---

## 9. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/decommission` | `viewer` | Queue by phase, hidden callers, canary state |
| `GET /api/v1/decommission/{endpoint_id}` | `viewer` | Full phase history and evidence |
| `POST /api/v1/decommission/{endpoint_id}/enrol` | `approver` | Eligibility-checked enrolment |
| `POST /api/v1/decommission/{endpoint_id}/advance` | `approver` | Advance with reason |
| `POST /api/v1/decommission/{endpoint_id}/hold` | `approver` | Pause with mandatory reason |
| `POST /api/v1/decommission/{endpoint_id}/canary` | `approver` | Set split |
| `POST /api/v1/decommission/{endpoint_id}/revert` | `approver` | Roll back to operational |
| `POST /api/v1/decommission/{endpoint_id}/certificate` | `approver` | Issue |
| `GET /api/v1/decommission/{endpoint_id}/worm/verify` | `viewer` | Prove immutability |

---

## 10. Configuration

| Variable | Default | Notes |
|---|---|---|
| `PHASE_A_VDAYS` / `B` / `C` | `30` / `30` / `30` | Standard path |
| `EXPRESS_QUARANTINE_VDAYS` | `30` | Express still quarantines |
| `THROTTLE_PCT` | `25` | Of observed p95 |
| `CANARY_STEPS` | `0.10,0.01,0.00` | |
| `CANARY_ERROR_CEILING` | `0.02` | Absolute rise over baseline |
| `WORM_RETAIN_YEARS` | `7` | SEC/FINRA |

---

## 11. Failure modes

| Condition | Behaviour |
|---|---|
| MinIO unavailable at Phase D | Phase blocks. No 410, no retirement, no certificate. Retried |
| Bucket lacks Object Lock | Fatal at startup; `readyz` fails |
| Kong unavailable | Phase transition fails, state unchanged, audited, retried |
| Canary error spike | Automatic revert to 100 % old, `phase=REVERTED`, alert |
| Hidden caller in quarantine | Alert; process continues unless the operator holds it |
| Certificate before Phase D | `409 conflict` |
| Enrolling a `PROVISIONAL` endpoint | `409 conflict` with the vdays remaining |

---

## 12. Security and compliance

- **RBAC**: every mutation `approver`.
- **Audit**: `decommission.enrolled`, `.advanced`, `.held`, `.canary_set`, `.reverted`, `worm.archived`, `certificate.issued` — all with actor and reason.
- **Frameworks**: SEC/FINRA retention (WORM); FFIEC DA&M (controlled change); DORA Art 9 (graduated, reversible); NYDFS Part 500 §500.06 (audit trail).

---

## 13. Tests

**Unit**
- Path selection across the tier × criticality matrix.
- Express requires `in_graph`.
- Phase length per path.
- Canary revert triggers exactly at the ceiling.
- `Sunset` header formats as RFC 8594 from a vday.

**Integration (real Kong + real MinIO)**
- Each phase creates the expected Kong plugin, verified through Kong's own API.
- Phase D writes an object with `ObjectLockMode=COMPLIANCE` and a retention date.
- Deleting that object fails with `AccessDenied`. **This test is the immutability proof.**
- MinIO stopped → Phase D blocks, endpoint not retired, no 410 applied.
- Canary weight changes are visible on the Kong upstream.
- A `PROVISIONAL` endpoint is refused enrolment.

**E2E**
- Full 90-vday path under the compressed clock: enrol → A → B → C (hidden caller surfaces) → D → certificate.
- Express path completes in 30 vdays with a quarantine window.
- A payment-adjacent endpoint routes to canary and is never throttled.

---

## 14. Acceptance criteria

- [ ] `PROVISIONAL` endpoints cannot be enrolled.
- [ ] Every phase transition produces a verifiable Kong configuration change.
- [ ] Express skips Phase A and still quarantines for 30 vdays.
- [ ] Endpoints whose blast radius touches payment/settlement/regulatory are never throttled.
- [ ] Canary reverts automatically on an error spike and records why.
- [ ] Hidden callers are surfaced during quarantine and named.
- [ ] Phase D cannot complete without a WORM object and retention date.
- [ ] The archived object cannot be deleted, demonstrated by the verify endpoint.
- [ ] The certificate hash is in the audit ledger.
- [ ] Advance into Phase D requires a human.
