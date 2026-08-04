# 94 — Working Prototype Verification

This file records what the current self-contained proof of concept actually does. It is intentionally separate from [93-VERIFICATION](93-VERIFICATION.md), which describes the later bank-integrated acceptance environment with real eBPF, Kong, Postgres, MinIO, Redis, Keycloak, and SIEM infrastructure.

---

## 1. Honest boundary

The prototype is real application software built with Next.js 16, React 19, and TypeScript. Its buttons mutate a live in-browser session and recalculate dependent results.

The evidence source is synthetic by design. It creates realistic, deterministic observations for a 12-service reference bank estate through four adapter contracts: kernel, gateway, code graph, and legacy CMDB. No control is represented as a change to a real bank gateway. The interface says “synthetic gateway” wherever that boundary matters.

To connect a bank later, replace the source and actuator adapters. Stages 02–14 keep the same input and output contracts.

---

## 2. Fourteen-stage implementation map

| Stage | Design contract | Implemented proof |
|---|---|---|
| 01 | Sensor Grid | Builds 121 fresh sightings for 42 endpoints from four independent sources. |
| 02 | Baseline | Calculates evidence age, source coverage, confidence, and verdict eligibility. |
| 03 | Correlation | Normalises paths, merges sightings, resolves ownership, and builds the call graph. |
| 04 | Classification | Produces lifecycle and governance decisions with replayable rule traces. |
| 05 | Behaviour | Runs a seeded 200-tree Isolation Forest over robust-scaled behavioural features. |
| 06 | CDRI | Calculates the six-part weighted risk score with the documented weights. |
| 07 | Forecast | Deseasonalises traffic and applies Holt forecasting with the documented parameters. |
| 08 | Findings | Generates evidence-bound findings and framework mappings. |
| 09 | Blast Radius | Performs a two-hop dependency walk and assigns impact tiers. |
| 10 | Remediation | Builds judged controls, replay measurements, exact-effect confirmation, and a synthetic gateway instance. |
| 11 | Decommission | Enforces candidate → A → B → C → D → retired, with WORM evidence before HTTP 410. |
| 12 | Threat | Activates the retired-route trap and compares path-free fingerprints for resurrection. |
| 13 | Zero Trust | Scores five controls and recalculates posture after an applied control. |
| 14 | Operations | Runs the dependency DAG, CI gate, service health, team debt, SIEM status, and hash-chained audit ledger. |

The enforced dependency order is:

`01 → 02 → 03 → 04 → 05 → 06 → 07 → 09 → 08 → 10 → 11 → 12 → 13 → 14`

Stage 09 runs before Stage 08 because Findings consumes blast-radius evidence. The operator never sees this as a school-style wizard; stage identifiers appear only in Operations & audit.

---

## 3. Automated evidence

Run:

```bash
npm test
npm run lint
```

Final result on 29 July 2026:

- Production build: passed
- Engine and rendered-console tests: 10/10 passed
- ESLint: passed
- Whitespace/error check: passed

The tests prove:

- Stage 01 starts from fresh evidence across all four source types.
- A stage cannot run before its declared dependencies.
- The full analytical DAG completes without pre-applying an action.
- Reference-estate edge cases classify from evidence rather than endpoint names.
- Applying a judged control changes the endpoint and every dependent view.
- Retirement cannot skip its evidence-bearing phases.
- A fixed seed produces the same analytical result.
- Invalidating one stage removes only its real dependants.
- The server renders an honest reset state.
- Product language keeps synthetic actions distinct from bank production actions.

---

## 4. Browser acceptance run

A clean in-app browser session was tested at desktop size.

| Check | Observed result |
|---|---|
| First load | No live session, no cached evidence, navigation disabled |
| Start monitoring | Visible four-source connection state before results appear |
| Discovery result | 42 APIs, 121 source sightings, 12 services |
| Initial posture | 6 zombies, 3 shadow APIs, 6 critical decisions, 49% zero-trust |
| Lead API | `GET /api/v1/legacy-balance/{id}`, CDRI 100 |
| Risk explanation | Six contributions sum to 100 |
| Impact trace | Direct callers and second-hop systems are named |
| Judge result | 240 exact replays, PASS, 31,000 µs latency delta, 38% budget headroom |
| Confirmation | Exact gateway policy and before/after risk are shown inline |
| Apply result | Synthetic gateway instance created; CDRI 100 → 72 |
| Correlated posture | Critical decisions 6 → 5; zero-trust 49% → 50%; next lead API changes |
| Retirement | Candidate → A throttle → B sunset → C quarantine → D archive + 410 → retired |
| Archive order | WORM Object Lock evidence exists before route retirement |
| Threat result | One probe captured; renamed route matched at 100% behavioural similarity |
| Operations | 14/14 analytical checks healthy; 4/4 capture sources; audit chain valid |
| Reload | Returns to no live session and no computed evidence |
| Themes | Dark and light both render correctly |
| Browser errors | None |

---

## 5. What changes when a bank connects

The current `DiscoveryAdapter` is replaced by collectors that emit the same observation contract. The synthetic gateway actuator is replaced by the bank-approved gateway and change-management connectors. Identity moves from the role selector to the bank’s OIDC provider. The audit, storage, messaging, and monitoring interfaces move to the deployment described in the foundation and delivery documents.

The analytical engine and the operator journey do not need to be rewritten.
