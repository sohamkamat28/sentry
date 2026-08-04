# 91 — Operator Console

A tool for someone who already knows what a zombie API is.

---

## 1. The governing rule

**The console explains nothing.**

The predecessor build taught its viewer: panels defining eBPF, paragraphs justifying the 90-day window, a "Legal and ethical guardrails" explainer, narrative headers on every screen. That was correct for its purpose and is wrong here.

An operator opening this console is a security analyst or a compliance officer at the institution that deployed it. They do not need to be told what a blast radius is. They need to know which endpoint has one, how big, and what happens if they press the button.

Concretely prohibited in UI copy:

| Prohibited | Replace with |
|---|---|
| "eBPF is a technology that…" | The source is labelled `KERNEL`. Its coverage figure is shown |
| "The 90-day window catches quarterly jobs" | `window 90d` on the filter control |
| "Isolation Forest works by…" | `ANOMALY 0.83 · isolation depth 3.1` |
| "This is different from competitors because…" | Nothing. Not the console's job |
| "Legal and ethical guardrails" explainer panel | `legal sign-off: LEGAL-2026-004` on the certificate |
| Section intros, taglines, "why this matters" | Data |

Tooltips may carry a **definition of a specific field** where the term is ambiguous (`headroom: % of latency budget unused`). They may not carry rationale, justification, or comparison.

`93-VERIFICATION` includes a lint pass: `grep -rEi '(is a|stands for|think of it as|in other words|this means that|why this matters)' console/src` must return nothing in rendered string literals.

---

## 2. Stack

React 18, TypeScript strict, Vite, Tailwind. TanStack Query for server state, SSE for invalidation. No component library — the surfaces here are dense tables and small charts, and a generic library fights that.

```
console/src/
├── views/            one per surface
├── components/
│   ├── data/         Table, Metric, Bar, Sparkline, Diff, GraphCanvas
│   ├── control/      Button, Toggle, Slider, Filter, Confirm
│   └── shell/        Nav, StatusBar, Toast, ErrorBoundary
├── lib/
│   ├── api.ts        generated from OpenAPI
│   ├── stream.ts     SSE subscription and cache invalidation
│   ├── auth.ts       OIDC PKCE
│   └── format.ts     number, duration, vday formatting
└── routes.tsx
```

`lib/api.ts` is generated from `contracts/openapi/sentinel-api.yaml`. Request and response types are never hand-written.

---

## 3. Information architecture

Fourteen work surfaces plus a command centre, grouped by what an operator is trying to do rather than by pipeline stage number.

| Group | Surfaces |
|---|---|
| **Posture** | Command Centre · Estate Register · Classification Matrix |
| **Detection** | Sensor Grid · Baseline · Correlation · Behaviour |
| **Assessment** | Risk Register · Forecast · Findings · Impact |
| **Response** | Remediation · Decommission · Zero-Trust |
| **Assurance** | Threat · Operations · Audit |

Stage numbers appear only in the pipeline status readout, where they carry operational meaning (which stage failed). They are not the navigation.

### Command Centre

Landing surface. Answers "what needs me now".

- Status bar: endpoints, zombies, shadow, critical, retired, capture health, last scan, vday.
- **Action queue** — the only ranked list that matters: endpoints where CDRI is CRITICAL and no control is applied, sorted by time-to-breach ascending. Each row is one click from the surface that resolves it.
- Classification matrix, 4 × 3, clickable into a filtered register.
- Capture health: per-source coverage, ring-buffer loss, agent count. Red when degraded.
- Team debt, top five by trend.

---

## 4. Surface specifications

Each surface: the question it answers, its primary control, and its failure display.

| Surface | Question | Primary control |
|---|---|---|
| **Sensor Grid** | Is capture healthy and complete? | Per-agent detail; discarder management |
| **Baseline** | What are we entitled to conclude yet? | Backfill import |
| **Correlation** | Did we merge these correctly, and who owns it? | Ownership override with justification |
| **Classification** | Where does each endpoint sit on both axes? | Matrix cell → filtered register; per-endpoint rule trace |
| **Behaviour** | What is behaving abnormally? | Contamination policy; per-endpoint feature vector |
| **Risk Register** | What is most dangerous? | **Weight sliders — live estate re-score** |
| **Forecast** | What dies next? | Notify owners |
| **Findings** | What do I hand the examiner? | Regenerate; export |
| **Impact** | What breaks if I remove this? | Trace; send to decommission queue |
| **Remediation** | How do I close this now? | Generate → Judge → **Apply** |
| **Decommission** | Where is each retirement? | Enrol · Advance · Hold · Canary · Certificate |
| **Zero-Trust** | Which controls are missing? | Harden |
| **Threat** | Who is probing, and did anything come back? | Rescan |
| **Operations** | Is the loop running, and who owns the debt? | Trigger scan; gate history |
| **Audit** | Who did what? | Verify chain |

### Risk Register — the weight tuner

Six sliders bound to `policy_weights`. Dragging shows the resulting distribution live; the residual from 1.00 is displayed continuously and **Apply is disabled until it is zero**. The schema constraint would reject an invalid set anyway; showing the residual means the operator never submits one.

Applying writes a new version and re-scores the estate. The table re-sorts, tier badges change, the status bar updates. The previous version is retained and shown in a history list.

### Remediation — the two tracks

The screen is split because the product is split:

- **Immediate**: control, judge scores, `Apply` — enabled only for `approver`, only after a `PASS`.
- **Governed**: change request number, state, submitted time, live from ServiceNow.

Both tracks are visible simultaneously, with their own elapsed timers. An analyst sees `Apply` disabled with `requires approver` — the role boundary is shown, not hidden.

Judge results render as four scored bars with the measured latency delta, the budget, and headroom. Replay coverage (`exact / synthesised / bodyless`) is shown next to the request count, so an operator knows what the verdict rests on.

### Decommission — the phase board

Columns A, B, C, D, Retired. Cards move between them. Each card carries phase entry vday, days remaining, blast tier, and canary split where applicable.

Hidden callers surfaced during quarantine appear as a badge on the card and expand to the caller list. The badge is not styled as an error — surfacing a hidden dependency is the phase working correctly, and the colour says so.

Phase D shows the WORM object key, retention date, and a `Verify immutability` button that calls the delete-attempt endpoint and shows the resulting `AccessDenied`.

---

## 5. State handling

Three states, always distinct. Conflating them is the most common way a dashboard lies.

| State | Rendering |
|---|---|
| **Loading** | `—` in metric tiles, skeleton rows in tables, `scanning…` sub-label |
| **Empty** | Explicit: `No probes captured`. Never `0` where the value is unknown |
| **Error** | The error `code` and `message` from the envelope, plus a retry control |

**Never render `0` for a value that has not arrived.** A resurrection-alert tile showing `0` during a scan reads as "none found", which is a claim the system has not yet made. This was a real defect in the predecessor build, caught in verification, and the rule exists because of it.

Degraded capture propagates: when `sentinel_agent_ringbuf_lost_total` is non-zero or a collector is unhealthy, the status bar shows `CAPTURE DEGRADED` and every count derived from that source carries a marker. A number that might be an undercount is never presented as complete.

Template-generated findings are labelled `TEMPLATE` beside the narrative. Model-generated ones show the model id. The console never presents one as the other.

The ServiceNow stub, when in use, is labelled `STUB` in the integration status panel.

---

## 6. Live updates

One SSE subscription in `lib/stream.ts`. Events map to TanStack Query invalidations:

| Event | Invalidates |
|---|---|
| `estate.changed` | estate, classification, risk |
| `stage.completed` | that stage's surface, pipeline status |
| `control.applied` | remediation, risk, zero-trust, estate |
| `probe.captured` | threat |
| `alert.raised` | command centre, threat |

No polling intervals anywhere. A surface that has not received an event does not refetch.

---

## 7. Permissions in the interface

The console renders what the token permits, and disables rather than hides:

- A `viewer` sees every analytical surface with all mutating controls disabled.
- An `analyst` can generate, judge, trace, tune weights. `Apply`, `Advance`, `Harden`, `Certificate` show as disabled with `requires approver`.
- An `approver` has all of it.

Disabling with a stated reason is better than hiding, because hiding makes the workflow look shorter than it is and an analyst needs to know an approval step exists.

Every destructive or outward-facing action requires a confirmation dialog naming the exact effect: `Apply key-auth to GET /api/v1/nostro. Callers without a key will receive 401.` Not `Are you sure?`.

---

## 8. Visual design

Dark by default, light supported. Dense — this is a working tool, not a landing page.

| Token | Value |
|---|---|
| Background / panel / panel-2 | `#0d1117` / `#161b22` / `#1c2128` |
| Text / dim / dimmer | `#e6edf3` / `#8b949e` / `#6e7681` |
| Critical / high / medium / low / ok | `#f85149` / `#d29922` / `#58a6ff` / `#8b949e` / `#3fb950` |
| Accent | `#a371f7` |

Monospace for all identifiers, paths, scores and vdays. Proportional for labels only. Tabular figures everywhere numbers align in a column.

Charts follow `dataviz` conventions: no gridline noise, direct labelling over legends, colour carrying tier semantics consistently across every surface — the red in a CDRI bar is the same red as a CRITICAL badge.

---

## 9. Accessibility

- Keyboard reachable throughout; visible focus rings.
- Colour is never the only signal — tiers carry text labels alongside colour.
- Contrast ≥ 4.5:1 for text in both themes.
- Live regions announce alerts and job completion.
- Tables are real `<table>` elements with proper headers.

---

## 10. Testing

| Layer | Approach |
|---|---|
| Unit | Vitest for `format`, `stream` reducers, permission gating |
| Component | Testing Library: loading/empty/error rendered distinctly for every data component |
| Contract | Generated types compile against the OpenAPI schema; CI fails on drift |
| E2E | Playwright: the full operator path in [93](93-VERIFICATION.md) |
| Lint | The explanatory-prose grep in §1 |

Explicit component tests:

- A metric tile with `loading: true` renders `—`, never `0`.
- A metric tile with a real `0` renders `0` with its empty-state label.
- A `viewer` token renders `Apply` disabled with the reason visible.
- A finding with `generator: 'template'` renders the `TEMPLATE` label.
- Degraded capture renders the status-bar marker and per-count markers.

---

## 11. Acceptance criteria

- [ ] The prose lint returns nothing.
- [ ] No surface contains a paragraph explaining a concept.
- [ ] Loading, empty and error are visually distinct on every data surface.
- [ ] No tile renders `0` for an unarrived value.
- [ ] Degraded capture is visible in the status bar and on affected counts.
- [ ] Template findings are labelled; model findings show the model id.
- [ ] Role-gated controls are disabled with a stated reason, not hidden.
- [ ] Every mutating action confirms with its concrete effect named.
- [ ] Weight sliders re-score the estate live and block submission until weights sum to 1.00.
- [ ] Applying a control updates risk, classification, zero-trust and the status bar without a manual refresh.
- [ ] Keyboard-only operation completes the full path from command centre to applied control.
