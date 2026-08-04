# Stage 13 — Zero-Trust Posture

Control-by-control gap analysis, and gateway hardening that needs no backend change.

---

## 1. Scope

**Owns:** the posture assessment — five controls per endpoint, scored and gap-listed — and the hardening plan.

**Does not own:** applying controls. Hardening delegates to the stage 10 actuator, so every gateway write goes through one audited path with one judge gate.

---

## 2. Deployment unit

`worker/app/engines/zerotrust.py`. Runs after stage 06. Assessment is a pure function of observed posture.

---

## 3. The five controls

| # | Control | Satisfied when | Weight |
|---|---|---|---|
| 1 | Strong authentication | `auth in ('oauth2','mtls')` | 1 |
| 2 | Transport integrity | `tls_version == '1.3'` | 1 |
| 3 | Sender-constrained tokens | DPoP or mTLS binding present | 1 |
| 4 | Rate limiting | `rate_limited` | 1 |
| 5 | Least-privilege response | No PAN/AADHAAR/CARD/CVV in responses, or masked | 1 |

Score is `n/5`, reported as a count rather than a percentage — an operator acts on "2 of 5 controls missing", not on 40 %.

Control 3 is the one competitors rarely address. A bearer token that leaks is usable by anyone; a sender-constrained token is bound to the key that requested it and is useless elsewhere. For an endpoint carrying settlement instructions that difference is material, and the assessment treats it as a first-class control rather than a footnote to authentication.

---

## 4. Assessment

```python
def assess(ep, cdri) -> Posture:
    controls = [
        Control("auth",   ep.auth in ("oauth2", "mtls"),
                remedy="oauth2" if ep.criticality != "SETTLEMENT" else "mtls"),
        Control("tls",    ep.tls_version == "1.3", remedy="tls-min"),
        Control("binding", has_binding(ep),        remedy="dpop"),
        Control("ratelimit", ep.rate_limited,      remedy="rate-limit"),
        Control("response", not exposes_sensitive(ep), remedy="response-mask"),
    ]
    return Posture(satisfied=sum(c.ok for c in controls), of=5, controls=controls,
                   priority=cdri.score)
```

The remedy for control 1 depends on criticality: settlement paths get mTLS, everything else OAuth 2.0. Recommending mTLS estate-wide would generate a certificate-distribution programme nobody will run, and a recommendation nobody executes is worth nothing.

`has_binding` checks for a `pre-function` DPoP validator or an mTLS enforcement control in `control` with `state='APPLIED'` — the assessment reads applied reality, not intent.

---

## 5. Hardening

`POST /api/v1/zerotrust/{endpoint_id}/harden` builds the control set for every unsatisfied control and submits them through the stage 10 pipeline: generate → judge → apply. Same Kong actuator, same judge gate, same audit events, same `approver` requirement.

There is no separate hardening path that bypasses the judge. A control applied from this screen has been differentially tested exactly like one applied from the remediation screen.

Ordering is deliberate — least disruptive first, so a failure at a later step leaves the endpoint better off than before:

1. `rate-limit` — additive, no client change
2. `tls-min` — rejects only clients already below policy
3. `response-mask` — removes fields, potentially breaking; judge catches it
4. `auth` — requires consumer provisioning, so it is staged with a migration window
5. `binding` — after auth exists

Applying auth to a live endpoint breaks every unprovisioned caller. The plan includes the blast-radius caller list and a provisioning checklist, and the API returns `requires_migration: true` so the console can require acknowledgement before it proceeds.

---

## 6. The outcome worth stating

An endpoint remediated through this pipeline ends up more secure than it was before it became a zombie. It started with basic auth and TLS 1.2; it ends with OAuth 2.0, DPoP binding, TLS 1.3, rate limiting and masked responses. The zombie lifecycle becomes the occasion for the upgrade rather than merely a cleanup.

---

## 7. Data model delta

Owns no table. Reads `endpoint`, `cdri`, `control`. Writes only through the stage 10 actuator, which owns `control`.

This is deliberate: one writer for gateway state means one audit trail and one place where "applied" can become true.

---

## 8. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/zerotrust` | `viewer` | Estate posture distribution, per-control gap counts |
| `GET /api/v1/zerotrust/{endpoint_id}` | `viewer` | Five controls with satisfied state and remedy |
| `POST /api/v1/zerotrust/{endpoint_id}/harden` | `approver` | Generate → judge → apply the gap set |
| `POST /api/v1/zerotrust/harden-preview` | `analyst` | Dry run: controls that would be generated, no writes |

```json
{
  "endpoint_id": "ep_9f2c…", "satisfied": 1, "of": 5, "priority": 0.93,
  "controls": [
    {"key":"auth","ok":false,"current":"none","remedy":"oauth2","requires_migration":true},
    {"key":"tls","ok":false,"current":"1.0","remedy":"tls-min","requires_migration":false},
    {"key":"binding","ok":false,"current":null,"remedy":"dpop","requires_migration":true},
    {"key":"ratelimit","ok":true,"current":true,"remedy":null},
    {"key":"response","ok":false,"current":["AADHAAR"],"remedy":"response-mask","requires_migration":false}
  ]
}
```

---

## 9. Configuration

| Variable | Default | Notes |
|---|---|---|
| `ZT_TLS_FLOOR` | `1.3` | Control 2 threshold |
| `ZT_SETTLEMENT_AUTH` | `mtls` | Remedy for settlement class |
| `ZT_DEFAULT_AUTH` | `oauth2` | Remedy elsewhere |
| `ZT_SENSITIVE_CLASSES` | `PAN,AADHAAR,CARD,CVV` | Control 5 trigger set |

---

## 10. Failure modes

| Condition | Behaviour |
|---|---|
| Judge rejects a control | That control is skipped, remaining ones proceed, result reports partial hardening with the reason |
| Kong unavailable | Delegates to stage 10's handling — `FAILED`, nothing marked applied |
| Endpoint retired | Excluded from assessment; retired endpoints have no posture to improve |
| Stage 06 not run | `StageDependencyError` |

Partial hardening is reported as partial. Three of five controls applied is stated as three of five, never rounded up to "hardened".

---

## 11. Security and compliance

- **RBAC**: reads `viewer`; preview `analyst`; harden `approver`.
- **Audit**: inherited from stage 10 — each control produces its own `control.applied` entry.
- **Frameworks**: RBI §4.2 and §5.1; NYDFS Part 500 §500.12 (MFA/privileged access); PCI-DSS 6.4; DORA Art 9.

---

## 12. Tests

**Unit**
- Each control's satisfaction predicate, positive and negative.
- Settlement endpoints get `mtls`; others get `oauth2`.
- `has_binding` requires an `APPLIED` control, not a `PROPOSED` one.
- Ordering places `rate-limit` first and `binding` last.

**Integration**
- Hardening an endpoint with 0/5 issues controls in order through the stage 10 pipeline, each with a judge run.
- A judge rejection skips one control and applies the rest; the result reports partial.
- Applied controls change the assessment on re-run: 0/5 → 4/5.
- `analyst` gets `403` on harden.

**E2E**
- Hardening a CRITICAL zombie moves its posture, drops its CDRI, and both changes appear in the register within one refresh.

---

## 13. Acceptance criteria

- [ ] Every non-retired endpoint has a five-control assessment.
- [ ] Assessment reflects applied controls, not proposed ones.
- [ ] Hardening delegates entirely to stage 10 — no separate gateway write path exists.
- [ ] Every hardening control passes the judge before application.
- [ ] Settlement endpoints receive mTLS; others OAuth 2.0.
- [ ] Controls requiring consumer migration are flagged before application.
- [ ] Partial hardening is reported as partial.
- [ ] Score is presented as a count out of five, not a percentage.
