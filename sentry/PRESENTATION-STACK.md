# The stack — why each piece, and how to show it

Companion to `PRESENTATION.md`. Three parts:

- **A** — why each choice, framed as the constraint that forced it
- **B** — every tool mapped to something visible on screen
- **C** — the click-by-click demo

The rule for the whole talk: **never list a tool without pointing at what it
does.** A slide of logos teaches nothing. "This number exists because of that
library" teaches everything.

---

# A · Why each choice

## The split: Go on the hot path, Python where the maths lives

This is the one architectural decision worth explaining properly, because it
looks arbitrary until you give the reason.

> "We used two languages, and the split isn't taste. It's about where the
> constraint is.
>
> Go handles anything that runs continuously and has to be deployed
> everywhere. Python handles anything that has to *think*.
>
> The reason is blunt: the algorithms we need exist in Python and don't exist
> in Go. Rewriting them would take months and produce something worse."

### Go — the agent, the ingest, the honeypot

| Why | Detail |
|---|---|
| **eBPF loading is a Go ecosystem** | `cilium/ebpf` is the library for loading BPF programs. It's what Cilium and Pixie use. |
| **Single static binary** | The agent runs on *every node*. A Python agent means an interpreter and a virtualenv on every host you want to observe. A Go binary is one file with no runtime. |
| **The ingest is a hot path** | Hundreds of observations a second. `pgx/v5` gives us `CopyFrom` — PostgreSQL's bulk COPY protocol, which is far faster than row-by-row INSERT. |
| **Concurrency is free** | Goroutines handle concurrent batches without a thread pool or an async framework. |

### Python — the API and the analysis worker

| Library | What it does here | Why not Go |
|---|---|---|
| **scikit-learn** | Isolation Forest — flags endpoints behaving unlike their peers | No equivalent in Go |
| **datasketch** | MinHash + LSH — finds a retired endpoint that has come back under a new name, without comparing every pair | No mature Go equivalent |
| **networkx** | Graph traversal — "if I remove this, what breaks", two hops out | Would be hand-rolled |
| **tree-sitter** | Parses Go, JavaScript and Java source to find route declarations | Bindings exist but the Python ones are the maintained path |
| **SQLAlchemy + Alembic** | ORM and versioned schema migrations | Nothing comparable in Go |
| **FastAPI + Pydantic** | The REST API — and, importantly, it **generates the OpenAPI schema for free** | — |

> "That last one is worth a sentence. Because FastAPI produces an OpenAPI
> document automatically, we generate the frontend's TypeScript types straight
> from it. So if the backend changes a field, the frontend stops compiling.
> The contract is enforced by the build, not by anyone remembering."

### C — the BPF program itself

> "The probe is written in C, because that's what the kernel's verifier
> accepts. It's about 700 lines and it's the most constrained code in the
> project — no unbounded loops, no arbitrary memory access, everything has to
> be provably safe before the kernel will load it."

---

## Infrastructure — every choice was forced by something

| Component | Why this one |
|---|---|
| **PostgreSQL 16** | One database shared by Go and Python. JSON columns hold engine output whose shape varies by stage. The observation table is partitioned by day so old data drops by partition rather than a slow `DELETE`. |
| **Redis 7** | Two unrelated jobs. **Live counters** — the ingest increments a counter per capture so the console can show a live rate without running `COUNT(*)` several hundred times a second. **A distributed lock** — two pipeline cycles running at once would interleave their writes, so a cycle takes the lock or skips. |
| **Kong 3.8, database-backed** | ⚠️ **The detail worth explaining.** Kong has a declarative mode where config comes from a file. In that mode **the Admin API is read-only**. This entire product works by writing plugins through the Admin API, so declarative mode makes the core feature impossible. Database-backed was forced, not preferred. |
| **MinIO with Object Lock** | S3-compatible, and supports Object Lock in COMPLIANCE mode — genuine write-once storage. Needed for the claim that a retirement certificate can't be deleted, *including by an administrator*. |
| **Keycloak 26** | A real OIDC provider. The role boundary is enforced on real signed JWTs, not a mock. It also gave us a real token issuer for judging OAuth2 controls. |
| **Celery + beat** | Scheduler. `beat` dispatches on a schedule, workers execute, Redis is the message broker — which is why Redis is already there. |
| **Docker Compose** | 20 services with health checks and ordered startup. Kubernetes manifests exist too, but Compose is the thing you can actually run on a laptop. |

---

## The frontend — deliberately small

> "Three runtime dependencies: React, ReactDOM, and TanStack Query. That's it.
> No component library, no chart library, no state manager."

| Choice | Reason |
|---|---|
| **TanStack Query** | Handles polling, caching and retry. It's what lets every surface refresh on one shared clock with a global pause. |
| **Tailwind + CSS variables** | The palette holds four colours and one rule: **colour encodes severity and nothing else**. A red cell means the same thing on every screen. Written as CSS variables so there's a single definition. |
| **No chart library** | The sparklines are about fifteen lines of inline SVG. A charting library is several hundred kilobytes to draw a line. |
| **Vite** | Build tool. The whole bundle is ~250 KB. |

> "The reason to mention the small dependency list: this is a security product.
> Every dependency is supply-chain surface. Three is a defensible number."

---

# B · Every tool → what it puts on the screen

**This is the table to keep open while you demo.** When you point at something,
name the tool that produced it.

| Point at this | Say this produced it |
|---|---|
| Any endpoint existing at all | **eBPF probe in C** — kernel-level capture |
| Agent log: `attached pid=904 lib=openssl build_id=...` | **cilium/ebpf** attaching a probe to a live process |
| `captured 143` and the live rate | **Redis counters**, written by **Go ingest** on the hot path |
| That number becoming `—` when you kill Redis | The design rule: unknown ≠ zero |
| 47 endpoints in the register | **PostgreSQL** — the correlated registry |
| `ebpf` / `gateway` / `code` / `legacy` source tags | The four collectors; `code` is **tree-sitter** |
| Data class labels: `PAN`, `CARD`, `AADHAAR` | Classification **inside the kernel** — value discarded |
| `scan 2/14` ticking in the top bar | **Celery beat** dispatching, worker executing |
| Behaviour: `fitted on 34 endpoints` | **scikit-learn** Isolation Forest |
| Threat: resurrection `0.88` | **datasketch** MinHash + LSH |
| Blast radius: direct + second-hop callers | **networkx** graph traversal |
| Remediation: `key-auth applied` | **Kong Admin API** write — needs DB-backed mode |
| The Judge verdict beside the apply button | The shadow-pair replay |
| Decommission: `worm_object`, retained to 2033 | **MinIO** Object Lock, COMPLIANCE |
| Role dropdown → `403` | **Keycloak** JWT with role claims |
| `/docs` — the interactive API page | **FastAPI + Pydantic**, generated from code |
| The console compiling at all | Types generated from that OpenAPI document |
| `0s ago` freshness, pause button | **TanStack Query** |
| Migration drift check passing | **Alembic** |

---

# C · The demo, click by click

**Before you start** (do this 10 minutes early — the virtual clock needs time
to build up traffic):

```bash
open -a Docker
cd sentry
VCLOCK_SCALE_SECONDS=10 docker compose -f deploy/compose/compose.yaml up -d
docker compose -f estate/compose.yaml up -d
```

Have two windows: browser at `http://localhost:5173`, and a terminal.

---

### Click 1 — Terminal first, before the browser

```bash
docker ps --format '{{.Names}}\t{{.Status}}' | sort
```

> "Twenty-six containers. Thirteen of them are a fake bank — real services
> speaking real TLS to each other. The other thirteen are the product.
>
> The important thing: those two halves share **no database and no volume**.
> The only channel between them is the Linux kernel. So discovery has to
> actually discover — it can't cheat by reading a config file."

---

### Click 2 — Prove the sensor is real

```bash
docker logs sentry-agent-1 2>&1 | grep attached | tail -3
```

> "That's the agent attaching a probe to a running process. It found the
> OpenSSL library inside another container's filesystem, resolved the symbol
> offset, and hooked it. `build_id` is there because OpenSSL's internal layout
> differs between versions — we key the offsets on the build.
>
> That's `cilium/ebpf` doing the loading, and a C program running in the
> kernel doing the capture."

---

### Click 3 — Open the console → **Triage**

`http://localhost:5173`

> "This is where an operator starts. One question: what needs me now."

Point to the **top bar**:
> "vday is a virtual clock — we compress ninety days into about half an hour so
> a lifecycle plays out in a demo. `captured` and the rate come from Redis
> counters that the Go ingest increments on the capture path.
>
> `0s ago` is how fresh that reading is. It goes amber at fifteen seconds and
> red at sixty. A number on an operations screen with no age attached can't be
> acted on."

Point to the **health strip**:
> "Every component, and each one is judged on **evidence it produced** — not on
> a heartbeat it sent. A sensor that reports healthy while capturing nothing is
> the exact failure this product exists to catch, so it doesn't get to grade
> its own homework."

---

### Click 4 — Press `j` three times

> "Keyboard-driven. At three in the morning during an incident you don't want
> to be hunting for a mouse."

---

### Click 5 — Click a CRITICAL row → look at the middle pane

> "Here's why this scores 0.93. Six factors, bars sized by contribution, so
> your eye ranks the causes in the same order the score does.
>
> Below it, the decision trace: five questions, the answer to each, and
> **which source answered it**. Then the rules that fired. You can audit the
> verdict — it isn't a black box."

---

### Click 6 — The right pane, the Judge verdict

> "Before this control goes anywhere near production, the Judge builds two
> temporary routes on the real gateway — one with the control, one without —
> replays real captured traffic through both, and compares.
>
> `schema 100, error 100, exposure 100` means the response is identical. The
> latency line is the one that matters: how much this control costs, against
> the budget for this class of endpoint.
>
> If it fails, it's **rejected on measurement**. Twenty-two were."

---

### Click 7 — Nav → **Correlation** (or Estate Register), find `/internal/fx/rate`

> "This is the punchline. One source tag: `ebpf`.
>
> The gateway has never heard of this endpoint. It's in no repository we scan.
> It is serving live traffic right now, and it's only ever called
> service-to-service — nothing external touches it.
>
> Two independent systems disagree about it, and that disagreement **is** the
> finding. Nobody flagged it. It's a query."

---

### Click 8 — Nav → **Remediation**

> "Green `applied` means a plugin ID came back from Kong's Admin API on a 2xx.
> Nothing is marked applied on hope.
>
> This is why we run Kong database-backed rather than declarative — in
> declarative mode the Admin API is read-only, and this whole column would be
> impossible."

*(If you see `failed ×N`, be honest — it's a known bug in the actuator retrying
a write that already landed. Volunteering that goes down well.)*

---

### Click 9 — Nav → **Threat**

> "Realistic failure: you retire an endpoint, and three months later a team
> stands the same handler back up under a new path. Every identifier your
> registry keys on has changed.
>
> So before we retire anything we take a behavioural fingerprint — response
> field names, data classes, callers, traffic rhythm — deliberately excluding
> the path, because the path is what changes.
>
> That similarity number is MinHash and LSH from `datasketch`. It's how you
> compare against every retired endpoint without comparing every pair."

---

### Click 10 — Nav → **Decommission**

> "Retirement is four phases, not a switch. Announce with RFC 8594 headers,
> quarantine while logging every caller, then `410 Gone` at the gateway — the
> origin is untouched, so it's reversible in seconds.
>
> Then a signed certificate to WORM storage."

Terminal:
```bash
docker exec sentry-postgres-1 psql -U sentry -d sentry -c \
  "select worm_object, worm_retain_until from decommission where worm_object is not null limit 1;"
```

> "We tried to delete one to prove it. Storage refused — `Object is WORM
> protected`, retained until 2033. Not even an administrator can remove it.
> That's what makes it an audit artefact instead of a log line."

---

### Click 11 — Role dropdown, top right → **analyst**, then try to apply

> "An analyst can generate a control and prove it. They cannot apply it.
> The refusal is *shown* rather than the button being hidden — hiding it would
> teach people the action doesn't exist rather than that it isn't theirs.
>
> That's a real signed token from Keycloak, and every action lands in a
> hash-chained ledger where each entry contains the hash of the one before, so
> history can't be quietly edited."

Switch back to **admin**.

---

### Click 12 — The honesty demo. Do this one.

```bash
docker stop sentry-redis-1
```

> "I've just killed the cache the live counters run on. Watch the top bar."

*(capture becomes `—`, the redis pill turns red, a message appears:
"capture cache unreadable — counts withheld, not zero")*

> "It shows an em dash, not a zero. Because zero is a measurement — 'we looked,
> nothing happened'. Unknown is not. If you render those the same way, **a
> sensor outage looks exactly like a quiet, healthy estate.**
>
> That's the single most dangerous thing a security dashboard can do: sit there
> calm and green while it's blind."

```bash
docker start sentry-redis-1
```

---

### Click 13 — Close on `/docs`

`http://localhost:8080/docs`

> "Last thing. FastAPI generates this from the Python type annotations — all
> fifty-three routes with their response schemas.
>
> And we generate the frontend's TypeScript types straight from this document.
> So if I change a field name in the backend, the frontend stops compiling.
> The contract between the two halves is enforced by the build.
>
> We learned that the hard way — twice — by hand-writing a type that
> contradicted the server. Both times nothing failed: the request returned 200,
> the type-checker was happy, and a panel just quietly showed nothing."

---

## If the demo breaks

| Symptom | Fix |
|---|---|
| Console blank / stale | Hard reload, or `curl -s localhost:5173 \| grep assets` to check the bundle |
| Everything `—`, health red | Estate stopped: `docker compose -f estate/compose.yaml up -d` |
| Nothing running at all | Docker Desktop asleep: `open -a Docker`, wait, bring both compose files up |
| Empty triage queue | Not enough traffic yet — wait a few minutes |

**If it fails live, say so and move on.** With this audience, "the sensor
stopped and the health strip caught it" is a *better* story than a clean run.
