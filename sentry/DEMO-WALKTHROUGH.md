# One endpoint, the whole workflow

## The endpoint

**`POST /finacle/customerservice`** — id `ep_7bf33b50216c3d57`, service `finacle-bridge`, team `core-banking`.

It was chosen by scoring every endpoint in the estate against how many pipeline
stages actually hold evidence for it. Four reasons it wins:

1. **It is SOAP.** It came from the legacy collector, not the gateway — and it has
   operation-level siblings (`#GetNostroPosition`, `#GetCustomerBalance`,
   `#GetCustomerKyc`). Most API tools cannot see inside a single SOAP POST at all.
2. **It is REGULATORY** and carries four regulated identifiers — AADHAAR,
   ACCOUNT_NO, IFSC, **PAN** — detected in the response body in kernel space.
3. **It is still live.** Every action control on it is usable on stage. The
   retired endpoints cannot demonstrate the response half of the workflow.
4. **It scores 0.93 CRITICAL** with a full six-term breakdown, and it has a real
   control history including failures — not a clean synthetic path.

A second endpoint closes the demo, because this one is only at Phase C and
therefore cannot show retirement, honeypots or resurrection. See **Act 9**.

---

## Before you start

```bash
docker compose -f deploy/compose/compose.yaml up -d
```

Give it **~10 minutes**. The virtual clock needs to accumulate traffic before the
work queue is populated. Console at `http://localhost:5173`, role selector top
right — leave it on **admin** until Act 8.

Numbers below that are **stable**: CDRI 0.93, the six weights, the seven
regulatory citations, posture 1/5, the control-state counts. Numbers that
**drift every run**: vday, "days since last call", the queue length. Do not
memorise the drifting ones.

---

## Act 1 — Discovery: where it came from

**Sensor Grid** (left nav).

Four independent sources, each with what only it saw:

| source | endpoints | exclusive |
|---|---|---|
| eBPF | 44 | 28 |
| gateway | 14 | 2 |
| code | 6 | 0 |
| legacy | 5 | 1 |

> "Twenty-eight endpoints were seen by the kernel agent and by nothing else. They
> are in no gateway registry and no code repository. That is the gap this product
> exists to close — and the SOAP endpoint we are about to follow came from the
> legacy collector, which is the only source that can read inside a SOAP envelope."

---

## Act 2 — The queue: why this one

**Triage** (left nav, top).

The queue has **no search box** and runs to ~94 rows, so do not hunt for the
endpoint. Click the **`sunset`** and **`resurrection`** chips to switch them off.
The queue drops to 47 risk-only rows, highest score first, and
**`POST /finacle/customerservice` is row 4 — on screen without scrolling.**

Select it. Three panes: queue, evidence, action.

> "Nobody ranked this by hand. It is a merge of four independent signals —
> risk score, sunset state, resurrection alerts — ordered by one weight."

---

## Act 3 — Classification: the verdict, and how it was reached

Evidence pane, **"how it was classified"**. Nine rows: five questions, four rules.

```
1  days since last call        229      endpoint.last_call_vday
2  registered in gateway       true     endpoint_source
3  reachable owner             false    ownership.reachable
4  formally deprecated         false    endpoint.deprecated
5  present in code             false    endpoint_source
→  lifecycle    q1 >= 90 -> ZOMBIE              ZOMBIE
→  governance   not q3 -> ORPHANED              ORPHANED
→  severity     no reachable owner -> bump      true
→  confidence   observed 5213 vdays             CONFIRMED
```

> "The verdict is ZOMBIE × ORPHANED, and this is the whole derivation. Five facts,
> each with the field it came from, then the rules that fired. No model, no
> opinion. There is a `replay()` function in the classifier that re-derives the
> verdict from this stored trace — so the reasoning is auditable after the fact."

**Two axes, not one.** ZOMBIE is lifecycle: nobody calls it. ORPHANED is
governance: nobody owns it. An endpoint can be actively used and unowned, or
dead and well-governed. Collapsing them into one "risk" label loses the
distinction that decides what you actually do about it.

---

## Act 4 — CDRI: the score, decomposed

Same pane, **"what the score is made of"**. The bars are contributions, ordered
so the eye ranks causes in the same order the score does.

| term | contribution | weight |
|---|---|---|
| No authentication | 0.280 | ×0.28 |
| Zombie status | 0.220 | ×0.22 |
| PII / financial data | 0.200 | ×0.20 |
| TLS below 1.3 | 0.150 | ×0.15 |
| No rate limiting | 0.080 | ×0.08 |
| Behavioural anomaly | 0.000 | ×0.07 |

**They sum to exactly 0.93.** Add them up on stage if you want the room to trust it.

> "Six weighted terms summing to one. Nothing here is a black box — you can point
> at any number and ask where it came from. Behavioural anomaly contributes zero:
> the model scored this endpoint and found nothing unusual. A zero that was
> *measured* is different from a zero that was never checked, and the console
> shows which."

**Time to breach: 10 days**, basis `heuristic`, factors `composite exposure ×0.21,
no_auth ×0.45, sensitive data ×0.60`. Say "heuristic" out loud — it is labelled
that way in the payload, not dressed up as a prediction.

---

## Act 5 — Ownership and blast radius

Same pane, lower.

- **Owner: unresolved.** Resolved by `unresolved`, confidence 0.00, reachable `false`
  → **escalates to `elena.rossi@bank.example`**
- **Blast radius: ZERO** — 0 direct callers, 0 second-hop, no datastores

> "The ownership ladder has four rungs — CODEOWNERS, git blame, deploy metadata,
> directory. All four missed, so it escalates. That failure is *why* it is
> ORPHANED — the classification and the ownership resolution are the same fact
> seen twice."

Blast radius ZERO is **good news, and say so**: nothing calls it, so acting on it
breaks nothing. That is the difference between a finding and an actionable finding.

---

## Act 6 — Compliance: the regulatory mapping

**Findings** (left nav). Click the row.

Seven citations across five frameworks — **six VIOLATED, one SATISFIED**:

| framework | clause | status |
|---|---|---|
| RBI API Security 2023 | Section 4.2 | VIOLATED |
| RBI API Security 2023 | Section 5.1 | VIOLATED |
| RBI API Security 2023 | Continuous monitoring mandate | VIOLATED |
| DPDP Act 2023 | Section 8 | VIOLATED |
| FFIEC DA&M | Development, Acquisition & Maintenance | VIOLATED |
| NYDFS Part 500 | Section 500.12 | VIOLATED |
| NYDFS Part 500 | Section 500.06 | **SATISFIED** |

> "Each citation carries its requirement and the evidence for the verdict. Note the
> last one is SATISFIED — the mapping reports what is met as well as what is
> breached. A tool that only ever finds violations is not measuring anything."

---

## Act 7 — Zero-trust: the gaps, with remedies

**Zero-Trust** (left nav).

Top: the distribution bar — most of the estate holds 0 or 1 of 5 controls.
Find the endpoint: **posture 1/5, priority 0.93**.

| control | ok | current | remedy | needs caller migration |
|---|---|---|---|---|
| auth | ✅ | none | oauth2 | yes |
| tls | ❌ | — | tls-min | no |
| binding | ❌ | — | dpop | yes |
| ratelimit | ❌ | false | — | no |
| response | ❌ | **`['AADHAAR', 'PAN']`** | response-mask | no |

**Stop on the `response` row.** That is the strongest single fact in the demo:

> "The agent read Aadhaar and PAN numbers out of the response body — in kernel
> space, before TLS was applied, without touching the application. That is what
> the eBPF probe on `SSL_write` buys you. And notice: it captured the *field
> names*, never the values. The BPF program rewinds a token out of its buffer the
> moment it turns out to be a value."

Two controls are flagged `requires_migration` — they would break callers holding
no credential. That is a different decision from one that breaks the contract, so
the console keeps them apart.

---

## Act 8 — The live action, and the permission boundary

⚠️ **Use `preview` → `harden` on Zero-trust, NOT `apply` on Gateway controls.**

Right now **zero controls are in JUDGED state** (4,245 are PROPOSED), and `apply`
is disabled unless a control is JUDGED — so that button is correctly greyed out
across the whole estate. `preview → harden` is the path that generates, judges
and applies in one flow, and it is enabled on 44 endpoints.

1. Click **preview**. A drawer opens: *"proposed zero-trust controls — no changes
   have been made"*, listing what would be judged, with migration warnings.
2. **Before confirming, switch the role selector to `viewer`** and press harden.

> "Requires one of: approver, admin — hardening writes to the gateway and requires
> approver."

3. Switch back to **admin** and confirm.

> "The button was never hidden from the analyst. Hiding it teaches them the action
> does not exist; showing the refusal teaches them it is not theirs. That is
> separation of duties — the person who proposes a production change is not
> automatically the person who authorises it, and the API enforces it, not the UI."

Then **Remediation** and show the real history on this endpoint:

```
key-auth       APPLIED     ×1
key-auth       REVERTED    ×2
response-mask  FAILED      ×152
response-mask  REJECTED    ×1
tls-min        REJECTED    ×1
tls-min        SUPERSEDED  ×482
```

> "This is the honest record. 152 failed gateway writes, two controls the Judge
> refused on measured evidence, 482 superseded. Nothing was cleaned up for the
> demo. A REJECTED control is the Judge working — it replayed real traffic against
> the change and the latency or error budget failed."

---

## Act 9 — The closer: retirement, honeypot, resurrection

`POST /finacle/customerservice` is only at **Phase C** (2 hidden callers found
during quarantine), so it cannot show the end of the lifecycle. Switch to
**`GET /api/v1/legacy-balance`** — the one endpoint that went all the way.

**Decommission**, find it: phase **RETIRED**.

- WORM object `s3://sentry-worm/decommission/ep_6696d6f326fd4628/234.json.gz`
- **Retained until 2033-07-28** — MinIO Object Lock, COMPLIANCE mode
- Certificate `cert_508cde6d7aac908e`

> "Object Lock in COMPLIANCE mode means this cannot be deleted before 2033 — not
> by me, not by an administrator, not by root. That is what makes a retirement
> certificate worth anything."

**Threat** (left nav). One honeypot stands where the retired endpoint was.
**3 probes captured** from `172.19.0.18`, each with a unique watermark.

> "Something is still calling an endpoint we retired. Each probe gets a distinct
> watermark, so we can trace which caller."

Then the resurrection alerts — **this is the closing line of the demo**:

| resurrected as | matched | similarity | threshold |
|---|---|---|---|
| GET /api/v1/payments/upi/{id} | /api/v1/legacy-balance | **1.0000** | 0.85 |
| GET /api/v1/nostro/{id}/positions | /api/v1/legacy-balance | 0.9000 | 0.85 |
| GET /api/v1/nostro/deutdeff/positions | /api/v1/legacy-balance | 0.9000 | 0.85 |

> "We retired that endpoint. It came back under three different paths. MinHash
> over the request/response shape, LSH for the candidate lookup — the path changed,
> the shape didn't. A control you can defeat by renaming the route is not a control."

**Audit** (left nav). Every action in this demo is in a hash-chained ledger,
`control.revert.requested` then `control.reverted`, with the actor on each line.

---

## Three things that will go wrong, and what to say

**1. "The trace says 229 days but the finding says 17,330."**
Both are correct and both derive from the same `last_call_vday`. The classification
trace is the decision record **as it was made** — frozen, replayable, which is what
makes it auditable. The finding recomputes at generation time. Say:

> "The trace is the record of the decision at the moment it was taken; the finding
> is recomputed each pass. That's deliberate — an audit trail that silently updates
> itself isn't an audit trail."

If you would rather avoid the question entirely, don't put the two screens
side by side.

**2. `apply` is greyed out.** Correct behaviour — nothing is JUDGED. Use
`preview → harden` (Act 8). Do not try to talk around a disabled button on stage.

**3. The agent shows stale (`agent +Nv`) after a restart.** It has not captured
since the container came up. It clears once traffic accumulates — which is why the
stack needs its 10 minutes.

---

## The one-sentence version

> A SOAP endpoint nobody owns, that nobody has called in years, that is still
> reachable, still unauthenticated, and still returning Aadhaar and PAN numbers —
> found by the kernel, scored on six weighted terms, mapped to six regulatory
> violations, hardened at the gateway under an approver's signature, and when its
> retired sibling came back under a new path, caught by shape rather than by name.
