# SENTRY — presentation script

**Audience:** technical IT people, no API-security or banking domain knowledge.
**Running time:** ~20 minutes talk + 10 minutes demo + questions.
**Setup before you start:**

```bash
open -a Docker
cd sentry && VCLOCK_SCALE_SECONDS=10 docker compose -f deploy/compose/compose.yaml up -d && docker compose -f estate/compose.yaml up -d
```

Console at `http://localhost:5173`, API at `http://localhost:8080`.
Give it five minutes to accumulate traffic before you present.

---

## 0 · Opening — the hook (90 seconds)

> "Quick question to start. Everyone here has worked somewhere with APIs.
> Put your hand up if you think your organisation has an accurate, current
> list of every API endpoint it serves."
>
> *(pause — almost nobody will)*
>
> "Right. And that's not incompetence, it's structural. The list lives in a
> gateway config, or a wiki page, or a spreadsheet. It's written by hand, and
> it goes stale the moment somebody ships without updating it — or retires
> something and forgets to delete the entry.
>
> So you get two problems, and they're mirror images of each other."

Write on the board / next slide:

- **Shadow API** — serving live traffic, in nobody's list. Unmonitored, often unauthenticated.
- **Zombie API** — still deployed, still reachable, nobody calls it. Nobody patches it either.

> "A zombie is the one that gets you. It's running an old library, it has no
> owner, and it's been forgotten by everyone except an attacker doing
> reconnaissance. It is a breach that hasn't happened yet.
>
> Now here's the catch. You cannot find either of these with a tool that reads
> the registry — because the registry is precisely the thing that's wrong."

---

## 1 · The core idea (60 seconds)

> "So SENTRY does the opposite. It doesn't ask what exists. It watches what
> actually happens, and then compares that against what everyone *claims*
> exists.
>
> One sentence: **the findings are the disagreements between what the estate
> does and what the institution says it does.**
>
> Everything else in this project is machinery to make that comparison
> trustworthy."

---

## 2 · How the sensor works — eBPF (4 minutes)

> "This is the part I think you'll find most interesting, because the obvious
> approach doesn't work.
>
> Obvious approach: sniff the network. Doesn't work — it's all TLS. You get
> ciphertext.
>
> Next idea: terminate TLS in the middle, decrypt, re-encrypt. That's a
> man-in-the-middle on your own production traffic. You need to distribute
> certificates, you become a single point of failure, and security will —
> correctly — say no."

**The actual approach:**

> "We attach probes to the *encryption library itself*.
>
> When an application sends an HTTPS response, it calls `SSL_write` in OpenSSL
> and hands over **plaintext**. OpenSSL encrypts it and puts it on the wire.
> On the way in, `SSL_read` returns **plaintext** after decryption.
>
> So there are two points where the data is readable, and they're both inside
> the process, before the network is involved. We hook those two functions.
>
> The mechanism is **eBPF** — you load a small program into the Linux kernel,
> the kernel verifies it's safe (bounded loops, no bad memory access), and it
> runs on that hook. It's the same technology behind modern observability
> tools like Cilium and Pixie."

**Why it matters — say each of these deliberately:**

- No TLS interception. No certificates. Nothing is decrypted that wasn't already being decrypted.
- **No change to the applications being watched.** They don't know it's there. No SDK, no sidecar, no redeploy.
- If a service serves a request, we see it. **You cannot hide from it by not registering.**

**Two things happen inside the kernel — this is the important bit:**

> "First, filtering. We only capture approved processes and ports, and the
> filter runs in-kernel — uninteresting traffic is dropped before it ever
> becomes an event. That's what keeps the CPU cost low enough to run in
> production.
>
> Second — and this is the one that matters for a bank — **classification
> happens in kernel memory**. The body gets scanned for identifier shapes:
> card numbers, national IDs, account numbers. What comes out is the
> **label**: 'a card number was present'. Never the number.
>
> The body is then discarded. It never leaves the kernel. So it's not that
> we promise not to store sensitive data — there is no code path by which it
> could arrive."

> *(if asked how you know)* "We dumped every text column in the database and
> searched for identifier-shaped values. Zero hits. It's a test that runs in CI."

---

## 3 · Four sources, one registry (3 minutes)

> "The sensor is one source. On its own it tells you what's running, not
> what's wrong. So we collect three more:"

| Source | Answers |
|---|---|
| **Kernel sensor** | What the estate actually *does* |
| **API gateway** (Kong Admin API) | What the institution *publishes* |
| **Source repositories** (parsed) | What somebody *wrote* |
| **Legacy contracts** (WSDL / OpenAPI) | What the mainframe *declares* |

> "All four write into one table, tagged with where they came from. And now
> the definitions become **queries**, not flags somebody sets:
>
> - Traffic present, gateway absent, code absent → **shadow**
> - In the registry, no traffic for ninety days → **zombie**
>
> Nobody labels anything. It falls out of the disagreement."

**The demo moment to set up here:**

> "In our test estate there's a service called `shadow-fx-rate`. It's real, it
> serves real traffic, and it is deliberately registered in no gateway and
> present in no repository we scan. It's only ever called service-to-service —
> nothing external touches it.
>
> The only way to find it is to have watched two other services call it. And
> that's exactly how it appears."

**Two honesty notes worth saying out loud** — they build credibility:

> "Two things we were careful about.
>
> One — if the gateway is *unreachable*, that's not the same as the gateway
> having *no route*. If we confused those, a Kong outage would brand the entire
> estate as shadow and generate a mountain of false work. So the collector
> reports its own health, and the verdict is **withheld** when a source can't
> be read.
>
> Two — quarterly batch jobs. There's an endpoint in our estate that's silent
> for eighty-nine days and then fires. A naive thirty-day window kills it. So
> the window is ninety days with a confidence ramp: no verdict at all before
> day thirty, *provisional* to day eighty-nine, *confirmed* from ninety."

---

## 4 · Scoring and the pipeline (2 minutes)

> "Once we have a registry, fourteen stages run on a schedule — baseline,
> correlation, classification, behavioural anomaly detection, risk, forecast,
> blast radius, remediation, and so on. Dependency-ordered; if one fails it's
> recorded and its dependants are skipped rather than running on stale input.
>
> The output an operator cares about is a single score per endpoint. We call
> it CDRI. Six weighted factors:"

| Factor | Weight |
|---|---|
| No authentication | 0.28 |
| Zombie status | 0.22 |
| Sensitive data exposed | 0.20 |
| TLS below 1.3 | 0.15 |
| No rate limiting | 0.08 |
| Behavioural anomaly | 0.07 |

> "Sums to 1.00, and it's tunable — a payments team can weight differently
> from a reporting team.
>
> The thing I'd point at: **every one of those traces to an observation.**
> 'No authentication' doesn't mean a config field was empty. It means the
> sensor watched requests succeed with no credential attached."

---

## 5 · Acting safely — the Judge (4 minutes)

> "Finding problems is the easy half. Any scanner does that. The hard half is
> fixing them in a bank without causing an outage — because if your security
> tool takes down payments, it gets switched off and never switched back on.
>
> So nothing is ever applied on the strength of a rule. Every proposed control
> has to be **proven not to break anything first.**"

**Walk through this slowly — it's the strongest part of the demo:**

> "We call it the API Judge. When it wants to add, say, a rate limit:
>
> 1. It creates **two temporary routes** on the real gateway, both pointing at
>    the real service.
> 2. It puts the proposed control on one. Leaves the other clean.
> 3. It **replays real captured traffic** through both.
> 4. It compares the two: same response structure? same error rate? is the
>    latency penalty inside the budget for this class of endpoint?
> 5. Only if it passes all four does the control go anywhere near a live route.
>    Then the temporary routes are torn down.
>
> A control that would break callers is **rejected on measurement**. In our
> run, twenty-two were rejected that way."

> *(good aside, shows the system isn't credulous)*
> "One nice detail. Early on, every authentication control was being rejected.
> The Judge was replaying traffic with no credentials against a control whose
> entire job is to reject callers with no credentials — so it saw a 401 and
> reported that the patch broke the endpoint. Which is true, and useless.
> Now the Judge holds a real credential and replays as a legitimate caller, so
> the measurement is 'does a valid caller still get the same response'."

**Retirement — same philosophy:**

> "Retiring an endpoint is four phases, not a switch:
>
> - **Announce** — the gateway starts serving RFC 8594 `Sunset` and
>   `Deprecation` headers. The endpoint still works.
> - **Quarantine** — still serving, but every caller is logged. This is where
>   you find the batch job nobody remembered.
> - **Terminate** — `410 Gone` at the gateway. The origin is untouched, so it's
>   reversible in seconds.
> - **Archive** — a signed certificate of retirement written to WORM storage.
>
> WORM means write-once. We tried to delete one to prove it: storage refused,
> `Object is WORM protected`, retained until 2033. Not even an administrator
> can remove it. That's what makes it an audit artefact rather than a log line."

---

## 6 · After retirement — the trap (90 seconds)

> "Two more things happen after an endpoint dies.
>
> First, the retired route gets replaced by a **honeypot**. It serves
> realistic-looking but entirely fake data — account numbers from a reserved
> range, invented names — and every response carries a unique watermark. If
> that watermark ever turns up somewhere else, you know exactly which probe
> leaked it. Anyone still knocking on that door gets logged with their source
> IP and a session fingerprint.
>
> Second — and this is my favourite part — **resurrection detection**."

> "Here's the realistic failure. You retire an endpoint. Three months later a
> team still needs it, so they stand the same handler back up under a new path.
> Every identifier your registry keys on has changed. As far as any
> conventional tool is concerned, it's a brand new endpoint.
>
> So before we retire anything, we take a **behavioural fingerprint** — the
> response field names, the data classes, who calls it, its traffic rhythm,
> its size profile. Deliberately *excluding* the path, because the path is the
> thing that changes.
>
> Then we watch for anything new that matches. On our estate the redeployment
> scores 0.88 similarity against its own predecessor, and the nearest unrelated
> endpoint scores 0.59. It gets caught."

---

## 7 · The design principle (90 seconds) — *do not skip this*

> "One principle runs through the whole thing, and it's the thing I'd want you
> to take away even if you forget everything else.
>
> **Nothing in this system invents a number.** There's no seed data, no demo
> mode. If a figure is on the screen, a sensor produced it or an engine
> computed it from sensor output.
>
> The sharpest expression of that is a formatting rule. When a value is
> unknown, the interface shows an **em dash** — never a zero."

*(let that sit for a beat, then explain)*

> "Because zero is a measurement. Zero means 'we looked, and nothing happened'.
> Unknown means 'we didn't look, or we couldn't'. Those are opposite facts
> about your estate, and if you render them the same way, **a sensor outage
> looks exactly like a quiet, healthy system.**
>
> That's the single most dangerous thing a security dashboard can do — sit
> there calm and green while it's blind."

**Demo it live — this lands better than saying it:**

```bash
docker stop sentry-redis-1
```

> "I've just killed the cache the live counters run on. Watch the top bar."

*(the capture figure becomes an em dash, the component goes red, and a message
appears: "capture cache unreadable — counts withheld, not zero")*

```bash
docker start sentry-redis-1
```

---

## 8 · Live demo (8–10 minutes)

Open `http://localhost:5173`.

### 8.1 · The operations view

> "This is where an operator starts. One question: what needs me now.
>
> The left column is a single prioritised queue — risk, retirements that are
> blocked, and resurrection alerts, all merged and ranked. Middle column is
> the evidence. Right column is the action."

Press `j` a few times.

> "Keyboard-driven, because at three in the morning during an incident you
> don't want to be hunting for a mouse."

### 8.2 · Why a score is what it is

Click a CRITICAL endpoint.

> "Here's why this one scores 0.93. These bars are the six factors, sized by
> contribution — so the eye ranks the causes in the same order the score does.
>
> Below that is the decision trace. Five questions the engine asked, the
> answer to each, and **which source answered it**. Then the rules it applied.
> Nothing here is a black box — you can audit the verdict."

### 8.3 · The shadow endpoint

Go to **Correlation** or **Estate Register**, find `/internal/fx/rate`.

> "This is the one I mentioned. It carries only one source tag: `ebpf`. The
> gateway has never heard of it, it's in no repository we scan, and it's
> serving live traffic right now.
>
> Two independent systems disagree about it. That disagreement *is* the
> finding."

### 8.4 · Health, honestly

Point at the strip under the top bar.

> "Every component, judged on evidence it produced — not on a heartbeat it
> sent. A sensor that reports 'healthy' while capturing nothing is the exact
> failure this product exists to catch, so it isn't allowed to grade its own
> homework."

### 8.5 · The permission boundary

Switch the role dropdown to **analyst**, try to apply a control.

> "An analyst can generate a control and prove it. They cannot apply it —
> that's an approver action, and the refusal is shown rather than the button
> being hidden. Hiding it would teach people the action doesn't exist rather
> than that it isn't theirs.
>
> And every one of these lands in a hash-chained audit ledger — each entry
> includes the hash of the previous one, so you can't quietly edit history."

### 8.6 · Close the loop

Go to **Operations**, show the build gate.

> "Last piece. This hooks into CI. When someone opens a pull request declaring
> a new endpoint, we check it against everything we've retired — by behaviour,
> not by name.
>
> We tested it with a PR declaring `/api/v2/balance-legacy`. It was blocked at
> 0.89 similarity against `/api/v1/legacy-balance` — the endpoint this system
> had retired an hour earlier, matched despite the rename that would have
> hidden it from anything comparing strings."

---

## 9 · Close (60 seconds)

> "So, to pull it together.
>
> We watch real traffic at the kernel, with no change to the applications and
> without decrypting anything that wasn't already being decrypted. We compare
> what we see against what four different systems claim. The gaps are the
> findings. Everything we propose is proven safe against replayed real traffic
> before it touches production. And nothing on the screen is a number we made
> up.
>
> It's a prototype, not a product — but every figure I've shown you came from
> a sensor watching a real service, not from a seed script."

---

## Numbers you can quote

All verified during the build:

| | |
|---|---|
| Endpoints discovered from live traffic | 47 |
| Reference estate | 12 containerised services, real TLS |
| Pipeline stages | 14, dependency-ordered |
| Database tables | 30 |
| Tests | 425 Python · 63 Go · 25 frontend |
| Rate limit proven enforcing | 60 of 70 through, 10 answered `429` |
| Controls rejected by the Judge on evidence | 22 |
| Resurrection detection | 0.88 true match vs 0.59 nearest false |
| WORM deletion attempt | refused, retained to 2033 |
| Privacy audit | every text column searched — **0** identifier-shaped values |

---

## Likely questions

**"What's the performance cost?"**
Filtering happens in-kernel, so uninteresting traffic is dropped before it becomes an event — that's the whole reason the design puts the filter there rather than in userspace. Honest answer: we haven't load-tested at production volume. That's a real gap.

**"Does this work on Windows / non-Linux?"**
No. eBPF is Linux-only. On macOS it runs inside Docker's Linux VM. For a bank that's usually fine — the estate is Linux containers.

**"What if the app doesn't use OpenSSL?"**
We handle OpenSSL, GnuTLS and Go's built-in `crypto/tls`, which covers the large majority. A statically-linked binary with a bespoke TLS stack would need its own probe.

**"How is this different from an API gateway's own analytics?"**
A gateway can only report traffic that goes *through* the gateway. The endpoints you most need to find are exactly the ones that don't. Shadow endpoints are invisible to it by definition.

**"Isn't reading decrypted traffic a security risk in itself?"**
Fair challenge. Three answers: the probe reads memory the process already has in plaintext, so no new exposure is created; classification happens in-kernel and only labels leave; and the agent needs privileged kernel access, which is a real deployment consideration and would need its own review.

**"What's not finished?"**
Say it plainly — it buys credibility:
- ServiceNow integration has never run against a live instance
- mTLS and DPoP controls can't be judged here — no client certs, no DPoP client
- One control fails on latency against its budget, measured on a single request against a cold route; we haven't separated first-request cost from steady-state, so that verdict isn't decidable yet
- The shadow count is currently inflated by test-estate wiring, not by real findings
