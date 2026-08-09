# SENTRY

API lifecycle security platform. Discovers every endpoint in a service estate — including the ones no gateway and no repository knows about — classifies each on lifecycle and governance axes, scores its risk, proves what breaks before anything is removed, applies gateway controls, retires dead endpoints through a phased sunset, and serves retired routes as instrumented traps.

Built from [`../design/`](../design). Every stage document there is the specification for the corresponding module here.

A twelve-page technical report on the running system — architecture, the kernel sensor, the pipeline, and results measured from one frozen capture — is at [`../report/REPORT.md`](../report/REPORT.md), with the PDF at [`../SENTRY-report.pdf`](../SENTRY-report.pdf) and the raw evidence in [`../report/evidence/`](../report/evidence). Its figures supersede the counts below where the two disagree: this file records what was true when each line was written, and the report re-measured everything on 2026-08-09.

---

## The property that matters

**Nothing in this system invents an endpoint, a call count, or a risk input.** There is no `seed.py`. If a figure appears in the console, a sensor produced it or an engine computed it from sensor output.

The estate under analysis is [`estate/`](estate) — containerised services that speak real TLS to each other, in two tiers so that some of them call the others. Each has its own repository directory declaring its own routes, and `shadow-fx-rate`'s is deliberately outside the set the code collector is pointed at. SENTRY starts against an empty database and discovers them. One of them, `shadow-fx-rate`, is registered in no gateway and present in no scanned repository; only the kernel sensor can find it, which makes the blind-spot claim a measurement rather than an assertion.

---

## Status

| Component | State | Verified how |
|---|---|---|
| `core/` — domain model, config, virtual clock | **Complete** | 30 tables build; clock arithmetic tested |
| `worker/engines/` — stages 02–14 | **Complete** | 350 tests, incl. regression suites for every defect below |
| `worker/runner.py` — all 14 stages | **All 14 execute** | Stage 12 is in the DAG and runs; `pipeline_run` records each stage's outcome |
| `worker/actuators/control_plane.py` — the single gateway writer | **Complete** | Stages 10, 11 and 13 all apply through it; two-way drift reconcile |
| `worker/actuators/siem.py` — CEF / LEEF / HEC | **Delivers over TCP syslog** | Real CEF received by a listener; bounded spool drains on recovery |
| `worker/judge/` — API Judge, shadow-pair replay | **Applies real patches** | Controls applied from stages 10, 11 and 13; 22 rejected on measured evidence; SOAP and JSON bodies synthesised from the contract |
| `api/` — control plane, RBAC, audit ledger | **Complete** | 36 tests; 53 live REST paths, every one declaring a response schema |
| `api/migrations/` — Alembic | **Complete** | 2 revisions, both dialects; drift check fails the build |
| `worker/actuators/` — Kong, WORM | **Exercised against both** | Plugin applied, enforced, reverted; WORM delete refused |
| `estate/` — profiles, traffic driver | **Complete** | 8 tests on the traffic shapes |
| `console/` — 16 operator surfaces | **A live operations console** | Triage three-pane queue at `/`; every surface on one 2s clock with a global pause and a freshness readout; types generated from the control plane's own schema; all 21 typed calls match the live payloads; prose lint clean |
| `agent/` — eBPF sensor | **Captures live TLS traffic** | 34,560 events from real `SSL_write`/`SSL_read`/`SSL_write_ex`/`SSL_read_ex` |
| `worker/collectors/gateway.py` — Kong registry | **Complete** | Polls the live Admin API each pass |
| `worker/collectors/code.py` — repositories | **Complete** | Python by `ast`, Go/JS/Java by tree-sitter; routes found across 5 estate repos |
| `worker/collectors/legacy.py` — WSDL + registry export | **Complete** | Parses a live contract over TLS; 5 SOAP operations, 5 datastore edges |
| `ingest/` — observation intake | **Runs against Postgres** | Observations land via `COPY`; validation and backpressure tested |
| `honeypot/` — retired-route responder | **Runs against Postgres** | Serves synthetic responses, captures probes, guardrail enforced |
| `estate/` — running workloads | **Up** | 12 TLS services in two tiers + traffic driver, OpenSSL 3.5.6 |
| `deploy/compose/` — 19 services | **Run end to end** | Postgres, Redis, Kong, MinIO, Keycloak, estate, agent, ingest, worker, beat, honeypot, console all up |
| `deploy/k8s/` — Kustomize base | **Builds** | 25 resources; agent DaemonSet, network policies, ExternalSecret stubs |
| `deploy/keycloak/` — realm | **Imported and exercised** | Four roles on real OIDC tokens; the analyst/approver boundary enforced |
| `.github/` — CI and the gate Action | **The gate runs** | Extracts routes from a diff, posts to the live control plane, fails the build |

**393 Python tests and 9 Go suites pass**, and the pipeline runs end to end on captured traffic — all fourteen stages, in dependency order, on a schedule:

| Proven against live infrastructure | |
|---|---|
| BPF verifier | All 11 programs load on Linux 6.12, under clang 19 and clang 22 alike |
| **Kernel capture** | **34,560 events from `SSL_write`/`SSL_read` and their `_ex` forms across five Python services and a curl driver** |
| **Data-class detection** | **PAN, Aadhaar, IFSC and account numbers detected in kernel from live response bodies; values discarded, labels stored** |
| **Call graph** | **Ten edges resolved from `peer_service`, which the agent reads out of the calling process at capture time** |
| **Shadow, as a comparison** | **Two independent sources — the kernel sensor and Kong's Admin API — disagree about exactly two endpoints, and those two are the shadow set** |
| **WORM immutability** | **MinIO refused to delete a COMPLIANCE-locked object: `InvalidRequest — Object is WORM protected`, retained to 2033** |
| **Virtual patch** | **A rate limit generated from observed throughput, measured by the Judge, POSTed to Kong, and enforcing: 60 of 70 requests through, 10 answered 429 — while an unpatched route passed all 70** |
| **Reversibility** | **Deleting the plugin restored the route to 70/70 in the same minute, with the patched sibling still throttling** |
| **A measured zombie** | **`/api/v1/legacy-balance` went silent for 95 captured vdays while five other endpoints kept the sensor demonstrably alive; classified ZOMBIE/CONFIRMED with a ZERO blast radius, on observation alone** |
| **Phased sunset** | **Enrolled on the express path, B → C → D. Kong served `Sunset` + `Deprecation` + an RFC 8594 `Link` in Phase B with the endpoint still answering 200, and answers `410 Gone` now. The origin still returns 200 directly — only the gateway is closed** |
| **Retirement evidence** | **WORM archive refused a versioned delete (`Object is WORM protected`, COMPLIANCE, retained to 2033); audit chain verifies over 7 entries; the certificate's `content_hash` recomputes to the stored value** |
| **The quarantine caught something** | **A caller appeared during Phase C — `traffic` @ 172.19.0.5, 3 calls — and is named on the certificate. Finding one is the workflow succeeding, not failing** |
| **Zero-trust hardening** | **0/5 → 1/5 on a live endpoint: the rate limit passed the Judge and enforces (59 of 70 through, 11 × 429); `dpop` was measured and rejected because it turns an unprovisioned caller into a 401; `oauth2` is judged against a real issuer now and is its own row below** |
| **A recorded scan cycle** | **All 14 stages in one `pipeline_run`, each with its own `stage_run` row, duration and detail. A stage that raises is recorded and skipped past, its dependants are skipped, and the cycle completes and reports partial** |
| **Cycles serialised across both entry points** | **23 consecutive scheduled cycles, all 14 stages each, zero errored `stage_run` rows — and a manual scan issued during one is refused `409 CYCLE_IN_PROGRESS` naming the run that holds the lock, rather than interleaving with it** |
| **SIEM feed** | **A real CEF record delivered over TCP syslog to a listener: `SHADOW_DETECTED` severity 8, carrying the endpoint, its CDRI and its time-to-breach** |
| **The loop closing** | **A pull request declaring `GET /api/v2/balance-legacy` was blocked by the pre-merge gate at 0.89 similarity against `/api/v1/legacy-balance` — the endpoint this system retired an hour earlier, matched on behaviour rather than on the path that was renamed to hide it** |
| **Migrations** | **`upgrade head` builds all 30 tables on an empty PostgreSQL and on SQLite; autogenerate then finds zero differences from the models. The live database was verified to match and stamped, keeping its 99,290 observations** |
| **Three-source agreement** | **Six endpoints now carry `code+ebpf+gateway`. `/internal/fx/rate` carries `ebpf` alone — so SHADOW rests on two independently verified absences rather than one, and stage 04 withholds it entirely unless both the gateway and the repository set were actually readable** |
| **SOAP, correlated on identity** | **A real WSDL fetched over TLS yields `POST /finacle/CustomerService#GetCustomerKyc` — character for character the string the kernel probe builds from a SOAPAction header. The two meet as one endpoint carrying `ebpf+legacy`, its Aadhaar and PAN classes, and `FINACLE.KYC_MASTER` as its backing store** |
| **The ownership ladder, all four rungs** | **CODEOWNERS at 1.00; `settlement-rtgs` at 0.75 by git blame because its repository declares no owner; and `/api/v1/legacy-balance` at 0.375 — its last author departed with no successor, so the record keeps him as the only lead, marks him unreachable, and escalates to the department head. `Governance.OWNED` was unreachable before this and six endpoints now hold it** |
| **Honeypot activation, guarded** | **A retired endpoint answers 200 with account numbers from the reserved `9999` range, fictional names, and a unique watermark per response — recorded on the probe row with the source IP and a session fingerprint linking three requests. The service refused to serve at all until the legal sign-off policy was signed, and logged the remedy each refresh while it waited** |
| **The gateway control stack, enforcing** | **On one endpoint: no credential → 401; a provisioned consumer key → 200; TLS 1.2 → `426 TLS 1.3 required`; TLS 1.3 → 200 with `aadhaar` and `pan` absent from a body the origin still returns them in. Posture 1/5 → 4/5** |
| **The scheduler, contended** | **Celery beat dispatching every 6 vhours, the worker executing, and `sentry_scan_skipped_total` at 40 — the Redis lock refusing overlapping cycles at an interval shorter than a cycle takes, which is the designed behaviour rather than a fault** |
| **RBAC on real OIDC tokens** | **Keycloak realm imported; no token → 401, viewer reads but cannot rescan (403), analyst rescans but cannot harden (403), approver hardens (202). The audit ledger records `analyst@sentry.local`, not a UUID** |
| **The pre-merge gate** | **A pull request declaring a route whose data classes match a retired endpoint fails at 1.00, naming `/api/v1/legacy-balance` as the origin. Run against this repository's own estate sources: 7 routes extracted, 35 checks returned, exit 1** |
| **A synthesised SOAP replay** | **The Judge replayed `POST /finacle/CustomerService#GetCustomerKyc` against the live bridge with an envelope and a quoted `SOAPAction` built from the WSDL — `replay_synthesised: 1, replay_bodyless: 0` — and the endpoint's posture moved 0/5 → 3/5 on evidence that a bodyless replay could not have produced, because the service answers a body-less POST with a fault** |
| **The canary, shifting live weight** | **Kong upstream weights moved across three steps — `{v2: 900, v1: 100}` → `{990, 10}` → `{1000, 0}` — and the kernel sensor measured the split independently: `payments-upi-v2` took 54 of 60 gateway requests at the 0.10 step, 90%. The migration was verified by capture, not by the weights SENTRY itself wrote** |
| **Response schema, in kernel** | **The classifier now carries the JSON key names out with the class mask: 75 distinct field names across the estate, and `accountnumber`/`ifsc`/`balance` on the endpoints that serve them. Every stored name searched for identifier-shaped values — 0 digits, 0 PAN-shaped, 0 runs of nine or more. A token that turns out to be a value is rewound out of the buffer before the next byte is read, so the privacy property is control flow rather than a promise** |
| **Stage 12 over its own threshold** | **The resurrection now scores 0.882 against a 0.85 threshold, with the nearest unrelated endpoint at 0.591. On the same captured traffic with the field shingles stripped — the fingerprint this system had before — it scores 0.800 and misses, with the nearest miss at 0.727. The margin went from +0.073 to +0.291. `tools/measure_fingerprint.py` computes both against a live database** |
| **CVV and DOB, detected at last** | **Both were `#define`d in the BPF program from the first commit and nothing ever set either — a three-digit run and a date match too much ordinary content to be found by shape. Keyed on the field name instead, they now fire on 72 observations each, and `DataClass.CVV` is reachable for the first time** |
| **A REST write, replayed with a body** | **The estate publishes OpenAPI, the collector reads five documents (25 operations, 6 request schemas), and the Judge synthesises from them: 16 replays in ten minutes, `replay_bodyless: 0`. `response-mask` and `tls-min` passed and applied on a `POST` — verdicts a body-less replay could not have produced, because the service answers an empty POST with a fault** |
| **oauth2, judged rather than refused** | **Kong's own `oauth2` plugin makes Kong the token issuer, which no bank with a Keycloak deployment wants; where an issuer is configured the control compiles to `jwt` instead, verified against the issuer's real signing key. The Judge obtains a client-credentials token from Keycloak and presents it: schema 100, error 100, exposure 100 — the authenticated replay returns exactly the control's response — and it now fails only on latency, 41.8 ms against a 10 ms payment budget. That is an engineering finding; the 401 it used to fail on was the harness** |
| **The isolation forest, fitted** | **Stage 05 reported `fitted: false` on every run this system had ever made — 18 endpoints against a 30-endpoint minimum. The estate now carries the design's full twelve workloads and 47 endpoints: `fitted_on: 34`, `scored: 39`, `flagged: 1`, and 4 correctly excluded for insufficient history. The one flagged is `GET /finacle/customerservice` — a plain GET against a SOAP endpoint every other caller POSTs to** |
| **A parse, not a pattern** | **Go, JavaScript and Java move to tree-sitter. `router.HandleFunc(` with its path on the next line and `r.Get(base+"/deposits/{id}")` were both invisible to the line-wise matcher, and `"POST /api/v1/transfer"` was read twice — once correctly and once as a GET on a path beginning `/POST`, putting an endpoint in the registry that does not exist. A route the collector cannot see is a route absent from the `code` source, which with the gateway absent is the definition of SHADOW** |
| **A generated console** | **All 53 operations now declare a response schema, and `console/src/lib/api-types.ts` is generated from it — 133 interfaces. The two contract defects found this session are now unwriteable: `Pipeline.run` is not `runs`, and `AuditVerify.reason` is not `message`. Attached with `responses={200: ...}` and never `response_model=`, because the latter filters a live response down to whatever the model happened to declare** |
| **A live capture stream** | **`ingest/internal/store/live.go` has incremented `live:src:<source>` on the capture hot path since it was written — its own comment calls them "the console's capture stream" — and nothing had ever read them. `GET /live` closes that: the console's count matches `redis-cli GET live:src:ebpf` exactly, and the pipeline readout shows a cycle in flight at stage 2 of 14** |
| **An outage that reads as an outage** | **Redis stopped: the capture figure renders as an em dash, not a zero; the health strip turns `redis down` red; the bar says "capture cache unreadable — counts withheld, not zero". The distinction `live_counts` documents — `None` means ask Postgres, `0` means nothing was captured — is carried all the way to the screen, so a blind estate cannot present as a quiet one** |
| **Severity, visible for the first time** | **`format.ts` returned `text-critical`, `text-high`, `text-medium`, `text-low`, `text-muted` and `text-ink`. Tailwind defines none of those, so all six compiled to no rule and every tier, lifecycle and governance value in every table rendered in body text. Colour — the one thing this palette is reserved for — was the one thing it was not communicating** |
| **Opacity that painted nothing** | **`bg-line/40` and `bg-bg/60` were absent from the compiled stylesheet entirely: Tailwind emits no rule when an opacity modifier is applied to a `var()` holding a hex. The selected row in a list had no highlight and the drawer and command-palette scrims dimmed nothing. The palette is channel triplets with `<alpha-value>` now, and `severity.test.ts` fails the build if either half regresses** |
| PostgreSQL | 30 tables; both Go services read and write it |
| Privacy property | Every stored text column dumped and searched for identifier-shaped values — **0 hits**, labels only |

The endpoint that matters is `shadow-fx-rate:8443/internal/fx/rate`. Nothing in the traffic driver calls it. It is reached only by `payments-upi` and `settlement-rtgs`, service to service, and it appears in the database because a kernel probe watched those two make the call. Kong has no route for it. Both halves of the shadow definition are therefore measurements.

Every Go service compiles to static `linux/arm64` and `linux/amd64` binaries; the BPF object carries 11 programs and 9 maps.

```bash
make verify     # everything that does not require Docker
```

Needs Go and an LLVM with a `bpf` target for the agent. Apple's clang has none; `brew install llvm` provides one and the Makefile finds it on Darwin.

| Suite | Runner | Tests |
|---|---|---|
| `worker/tests` — engines, regressions, the runner against a database, stages 10–14, all five collectors, both ownership sources, body synthesis, the canary, tree-sitter parsing | pytest | 350 |
| `api/tests` — RBAC, audit chain, policy, cycle serialisation, response contract, the live stream, migration drift | pytest | 43 |
| `agent/` — object contract, struct offsets, field-name decoding, stream reassembly, workload identity, ELF symbols | go test | 30 |
| `ingest/` — validation, backpressure, clock refusal | go test | 18 |
| `honeypot/` — guardrails, synthetic values | go test | 15 |
| `estate/driver` — traffic shapes | pytest | 8 |
| `console/` — loading contract, the severity palette | vitest | 24 |

The 393 is the first two rows: `pytest.ini` sets `testpaths` to `api/tests worker/tests`, so `estate/driver` is a separate invocation and is not inside that number. 63 Go tests across 9 packages.

Two source-parsing checks run alongside them, and both failed the first time they were run:

```bash
python tools/check_schema_writers.py   # one writer per column, declarations vs code
python tools/check_migrations.py       # migration history vs models
```

A third needs the stack up, because the thing it checks is not visible offline — a console declaration and the payload it describes only disagree once a server is answering:

```bash
python tools/check_console_contract.py    # 17 typed calls vs what the API sends
python tools/generate_console_types.py --check   # generated types vs the live schema
python tools/measure_fingerprint.py       # what the field shingles are worth, measured
```

Each exits 2 rather than 0 when the control plane is unreachable. A check that compared nothing must not report a pass.

---

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e ./core -e ./worker -r api/requirements.txt
```

```bash
.venv/bin/python -m pytest -q
```

Run the API against SQLite with auth in dev mode:

```bash
DATABASE_URL="sqlite:///./sentry.db" AUTH_DISABLED=true REDIS_URL="" .venv/bin/uvicorn app.main:app --app-dir api --port 8080
```

Then http://localhost:8080/docs — 8000 belongs to Kong's proxy listener. Dev tokens: `dev-viewer`, `dev-analyst`, `dev-approver`, `dev-admin`.

Full stack (needs a running Docker daemon):

```bash
docker network create sentry-net && docker compose -f estate/compose.yaml up -d && docker compose -f deploy/compose/compose.yaml up -d
```

---

## Schema changes

The models are the schema of record and Alembic moves a database to them. Nothing else does — `create_all` is refused outside `dev`, because it builds whatever the models currently say and records nothing about having done so.

```bash
alembic revision --autogenerate -m "what changed"
```

```bash
make migrations-check
```

That applies every migration to a throwaway database and asks Alembic what still differs from the models. A model changed without a migration fails there, and in `api/tests/test_migrations.py`, rather than at a deploy. `tools/check_migrations.py --url postgresql://…` runs the same comparison against PostgreSQL, where server defaults are compared too.

An existing database that `create_all` built is brought under control with `alembic stamp head` — but only after the check confirms it already matches. Stamping one that does not match records a lie about what it holds.

---

## Layout

```
core/sentry_core/     domain model, config, virtual clock   — shared, installable
worker/sentry_worker/ engines, collectors, actuators, judge
api/app/              FastAPI control plane, RBAC, audit ledger
agent/                Go + eBPF kernel sensor
ingest/  honeypot/    Go
console/              React + TypeScript operator UI — 15 surfaces
estate/               the reference bank under analysis, its repos and HR stub
deploy/               compose, kong, keycloak realm, k8s kustomize base
.github/              CI, and the pre-merge gate Action
tools/                the two checks that read the source and compare it to itself
contracts/            protobuf + OpenAPI
```

---

## Four decisions worth knowing

**Time is configurable, not simulated.** `vday` is the only analysis axis. `VCLOCK_SCALE_SECONDS=86400` makes it a calendar day; `30` compresses a 90-day lifecycle into 45 minutes. Same code path, same windows, same partitioning. Traffic, capture and classification are real at either setting — only the wall-clock interval differs.

**Stage 05 runs before stage 06.** CDRI's formula takes a behavioural-anomaly term r₆. In the source architecture CDRI sat at stage 5 and consumed an input stage 6 produced — a pipeline reading from its own future. `pipeline.STAGE_DEPS` enforces the corrected order and a test asserts it.

**Produce less, never produce fiction.** Kong unreachable means a control is `FAILED`, never `APPLIED` — `APPLIED` is set only on a 2xx carrying a plugin id. A Judge run that could not happen leaves the control `PROPOSED`, never `REJECTED`: a failed measurement is not a failed patch, and collapsing the two would let an infrastructure outage read as a safety finding. No Anthropic key means `generator='template'`, labelled as such in the API and console. Dropped kernel events mean the console shows degraded capture rather than presenting an undercount as complete.

**The console explains nothing.** An operator here is a security analyst at the institution that deployed it. `npm run lint:prose` fails the build on explanatory copy in rendered strings.

---

## Four regressions, encoded as tests

Each of these shipped in the predecessor build. Each is now a test that fails if the fix is removed.

| Defect | Fix | Test |
|---|---|---|
| Holt fitted the weekend dip as a trend; rising endpoints projected to zero, flagging 51 of 86 active endpoints | Deseasonalise over exactly one weekly period before fitting | `test_rising_endpoint_with_weekly_cycle_is_not_flagged_declining` |
| Blast radius rated 108 of 125 endpoints CRITICAL — a queue where everything is critical is not a queue | Cap traversal at two hops; tier keys on direct callers | `test_two_hop_cap_produces_a_usable_tier_distribution` |
| Latency scored as a gradient, so a patch using 68% of an available budget was rejected | Budget compliance is a threshold; pass boundary at 75% consumed | `test_pass_requires_a_quarter_of_the_budget_left_unused` |
| Fingerprints weighted path tokens — the one thing a rename changes. A redeployed endpoint scored 0.583 against a 0.85 threshold | Key on behaviour; path tokens excluded by construction | `test_renamed_redeployment_still_matches` |

---

## Bugs found by running it

Each of these passed every test that existed at the time. Each now has something standing behind it — a test where the fault is expressible in one, a check where it is only visible against a running system. Three are the latter, and are named as such: the two console contract defects are held by `tools/check_console_contract.py`, and the IPv6 healthcheck by the container reporting healthy, which nothing offline can assert.

**The sensor was configured to observe nothing, and reported success.** `attach.go` documents at length why `TARGET_CGROUP_PREFIX` cannot default to `/docker` — Docker Desktop reports `/../<id>`, systemd reports `/system.slice/docker-<id>.scope`, Kubernetes something else again — and the compose file set it to `/docker` anyway. The agent started, resolved BTF, attached cleanly, and captured zero events from an estate issuing three thousand calls a minute. The fix was configuration; the lesson is that a defect fixed in code can be reintroduced by the deployment that carries it.

**Capture was silently partial for a second reason.** With the cgroup filter corrected, the agent still dropped every event whose cgroup id it could not resolve — which was most of them, because it reads `/proc/<pid>/cgroup` and stats the result under `/sys/fs/cgroup`, and in its own cgroup namespace those paths do not exist. The only symptom was one warning per pid. `cgroup: host` fixed it and `dropped_cgroup` went to zero.

**SENTRY discovered its own package downloads and registered them as bank endpoints.** `APPROVER_PORTS` included 443, the worker container pulled its dependencies over TLS during `docker compose build`, and the sensor did what it is built to do: 277 endpoints on `files.pythonhosted.org`, templated, scored and counted in the estate. The estate serves 8443 and nothing else here legitimately uses 443.

**And its own measurement apparatus.** The Judge builds a shadow pair of Kong services to measure a patch; the sensor observed that traffic too, and `/__sentry_judge/c/{id}` became an endpoint — one that would have decayed into a zombie once the run ended. Stage 03 now excludes the Judge's own scaffolding by prefix.

**The Judge aimed its shadow pair at a port the estate does not serve.** Only the egress half of an exchange names the port it dialled; an endpoint seen exclusively from the server side had a null port, and `_upstream_url` fell back to 443. Both halves of the pair then failed identically and agreed perfectly — the same shape of defect as the router-not-ready case, arriving by a different route. The port is now backfilled from any sighting that carries one.

**A masking control could never pass its own judgement.** `schema_score` returned 0 if any response field was removed — and removing fields is precisely what a response mask does. The dimension that exists to catch breakage scored zero exactly when the control worked as specified, so no PAN or Aadhaar could ever be masked at the gateway. The Judge now reads the fields the control *declares* it will remove and penalises only the others.

**Every auth control was rejected on the evidence that it worked.** The Judge replayed anonymously against a `key-auth` plugin, observed 401, and reported that the patch broke the endpoint. True of anonymous callers and useless as a measurement: the question is whether a caller who *has* a credential still gets the same response. Consumers are provisioned, the Judge presents a credential, and `key-auth` now applies and enforces.

**The TLS control was judged over plaintext.** `ssl_protocol` is empty on Kong's HTTP listener, so a `tls-min` pre-function rejected every replayed request. Controls that read connection state are now replayed over the TLS listener, and `tls-min` passes and enforces: TLS 1.2 gets 426, TLS 1.3 gets through.

**The retirement certificate asserted a honeypot nobody had activated.** `_complete_phase_d` wrote `honeypot_activated: true` unconditionally and set `endpoint.honeypot_active` alongside it, while no route existed, no upstream was configured and the legal sign-off was never read. The certificate is the document that outlives the endpoint and is read when somebody asks why it was removed — and it was the one place in the system asserting something no code had checked. It now reports what was done, and the boolean is set only when a route actually exists.

**The honeypot was live, correctly configured, and unreachable.** Phase D created a second Kong route for the retired path and assumed the gateway would prefer it as more specific. Both routes carried the identical path, so the original kept matching and its `request-termination` plugin answered 410 before the upstream was ever consulted. Every probe got 410 and nothing reported a problem, because from SENTRY's side the route had been created successfully.

**Resurrection detection decided on an approximation of its own measurement.** `ResurrectionIndex.query` scored candidates with the MinHash estimate, whose standard error at 128 permutations is about 0.088 — and the threshold is 0.85. A genuine redeployment scoring 0.857 exactly was missed, and the same pair could alert on one run and not the next. LSH still generates the shortlist; exact Jaccard now decides.

**The rhythm feature was seventy per cent of the fingerprint by cardinality.** Twenty-four `hour:NN:band` shingles against one for method, one for auth and a handful for data classes. Jaccard counts members and has no notion of feature groups, so any two endpoints driven by the same traffic pattern shared twenty-plus shingles before anything discriminating was considered — and five unrelated endpoints scored above threshold against a retired one.

**And an unmeasured feature was counted as agreement.** `respsize:unknown` on both sides of a comparison reads as a match, when it records that neither side was measured. On an estate where the sensor captures no payload sizes that put two identical tokens into every pair, and two unrelated endpoints scored 0.9167. Unmeasured features are now omitted rather than emitted as `unknown` — the same rule the console renders by.

**A fingerprint could be captured from no observations at all.** Retention prunes on a vday window, and at a compressed clock scale that window elapses in about an hour of wall time — so an endpoint's history could be gone before its own retirement completed. The resulting signature described the default profile and matched every other endpoint with nothing to say. Capture now refuses, and Phase D blocks with a reason.

**The migration job's own dependencies were missing from its image.** `api/Dockerfile` installed `api/requirements.txt` while the control plane's action routes import the pipeline runner — so `/threat/rescan`, `/operations/scan` and the harden routes imported cleanly at startup and raised `ModuleNotFoundError: networkx` on their first caller.

**`docker compose up` failed the second time it was run.** `kong config db_import` raises a UNIQUE violation on a credential that already exists, so importing consumers declaratively made every subsequent start fail on a stack that was already in the desired state.

**The console shipped with every utility class inert.** `console/Dockerfile` did not copy `postcss.config.js` or `tailwind.config.js`. Vite still built, still emitted a stylesheet, and that stylesheet contained the literal `@tailwind base;` directives unprocessed. The page rendered, nothing in the build reported a problem, and the layout was gone.

**Real OIDC tokens were rejected as having an invalid issuer.** The issuer is an identity that must match the token's `iss` claim exactly; the JWKS endpoint is a network location. In containers these differ — the browser gets a token from `localhost:8081`, the API can only reach `keycloak:8081` — and deriving one from the other breaks whichever side you pick. They are now configured separately.

**An unfitted model reported a clean estate.** `/behaviour` returned `scored: 15, flagged: 0` while the isolation forest had never fitted, which reads as fifteen endpoints checked and none anomalous. It now returns `null` for both and says why.

**SENTRY was resetting the silence clock on the endpoints it was judging.** The API Judge replays real request shapes through the gateway to the real upstream, so the kernel sensor captured them exactly as it captures a caller — and stage 10 judges precisely the endpoints under scrutiny. A zombie stayed alive because the system kept examining it: `container:5c561836963a` (Kong, replaying) was the only caller of an endpoint nothing in the estate had touched for ninety vdays. Replay traffic now carries `X-Sentry-Synthetic`, the sensor records it, and stage 02 excludes it from usage while keeping the rows — an operator asking why a judged endpoint shows a spike deserves to see it.

**A sensor outage would have retired the whole estate.** The virtual clock advances on wall time whether or not anything is watching. After the host slept, every endpoint's last call was 1,433 clock vdays in the past and all seven would have classified ZOMBIE — a monitoring gap presented as a retirement queue. Silence is now counted only in vdays where the platform received an observation from something, so an unwatched vday makes no claim in either direction. Of 1,673 clock vdays, 418 were watched.

**The API imported a module that does not exist.** Four routes deferred their work to `sentry_worker.tasks` — apply a control, revert one, advance a decommission, harden an endpoint. There is no such module, so each was a 500 waiting for its first caller. Apply and revert now call the control-plane actuator directly and return the outcome in the response that carried the decision, rather than a task id for work whose result lives somewhere else. Advance records an approver's release for the stage 11 runner to act on. Hardening returns 501, because stage 13 genuinely has no runner and a task id for work nothing will perform reads as success.

**The `vclock` singleton had a sequence it could never use.** Its primary key is a SmallInteger with a `CHECK (id = 1)` — exactly one row, forever — and PostgreSQL had quietly made it a SERIAL, because an integer primary key becomes one by default. Nothing depended on the sequence, which is why nobody saw it in three months of running the schema. The migration drift check compared the declared schema against the generated one and named it on the first run.

**The leaderboard charged every team nothing.** The ownership-confidence factor exists so a team is not charged for endpoints attributed to it by a 0.40-confidence guess. But the ownership ladder had resolved nobody at all — confidence 0.0 across the estate — while the teams themselves came from declared gateway tags, which is not a guess. Multiplying by zero reported an estate with seven orphaned endpoints as owing no debt whatsoever, which is worse than a wrong number because it reads as good news. The factor now applies only where the ladder actually made an attribution.

**A third copy of the debt formula lived in the API,** and it had quietly diverged: it omitted the ownership-confidence factor entirely, so the console charged teams in full where the pipeline discounted them. Both it and the gate now delegate to the stage 14 engine. The same fault had already been found in the zero-trust posture assessment.

**One operation, recorded twice, with neither copy carrying the other's evidence.** Endpoint identity keys on method, path template *and* service — and the legacy collector was attributing SOAP operations to the WSDL's own `<service name>`, "CustomerService", while the kernel reported the host it had actually reached, "finacle-bridge". The same operation therefore became two endpoints: one with the observed Aadhaar and PAN classes, one with the declared backing store, and no way to see they were the same thing. The host now comes from the contract's `soap:address`, which is what the probe sees. A second instance of the same fault sat one line further on — the observation carried the contract name while the datastore edge used the host, so the source row landed on one endpoint and the datastore on the other.

**A duplicate key in the pipeline DAG was discarded without a word.** `STAGE_DEPS` is a dict literal, and adding `13: frozenset({6, 10})` above an existing `13: frozenset({6})` silently kept the second — so stage 13 went on being ordered *before* the stage whose applied controls it assesses, and would have reported the estate as unhardened whatever stage 10 had just done. By the time the dict exists the duplicate is gone, so the test parses the source.

**Stage 13 would have throttled the settlement path stage 10 refuses to.** The exemption for payment, settlement and regulatory endpoints belongs to the endpoint, not to the stage proposing the control, and an operator hardening from the posture screen could have applied exactly what the remediation queue had declined. The remedy is now withheld for those classes while the gap stays visible and still counts against the score — a weakness this system will not close at the gateway is still a weakness.

**The Judge scored two 404s as a perfect patch.** Kong rebuilds its router asynchronously after an Admin API write, so requests issued straight after creating the shadow pair were answered `no Route matched` — on both halves. Compared against each other those two failures agree perfectly: identical structure, identical error rate, no data classes anywhere. All four dimensions scored 100 and the patch passed, having never been exercised. The pair is now waited for, and separately the Judge refuses to return any verdict when the control half fails every request, which catches the whole class rather than the one instance.

**A crash between the gateway write and the database commit left plugins nobody owned.** Thirteen of them, enforcing policy on live estate services, with no `control` row recording that they existed. The two cannot be one transaction, so the ordering now decides which way an interruption fails: the control row is committed first, every applied plugin is tagged with the control id that owns it, and each run removes tagged plugins whose control is not APPLIED. Untagged plugins are never touched — anything an operator put there by hand is theirs.

**Controls were applied to the service, not the route.** A service usually fronts several endpoints and only one of them was judged, so a rate limit sized for `/api/v1/accounts/{id}` was being imposed on every endpoint `core-accounts` serves. Kong also allows one instance of a plugin name per service, so the second endpoint was refused with a 409 rather than patched. Controls are now route-scoped, and the two applied rate limits were verified to hold independent counters.

**The agent could not see Python.** CPython's `ssl` module links against `SSL_write_ex` and `SSL_read_ex`, not `SSL_write` and `SSL_read`. The agent probed only the classic entry points, so it attached cleanly to every Python service in the estate and captured nothing from any of them — the uprobes were live and simply never fired. All traffic in the database came from the one workload that happened to be `curl`. Four `_ex` programs now exist and `elfsym` decides which to attach by reading the library rather than assuming a version.

**Every observation was silently discarded.** The `vclock` row had not been seeded. `Store.Enqueue` returned `(0, len(items))` on an unreadable clock, before the lines that increment the counters — so the sensor reported capture, the shipper reported delivery, the ingest returned 202, all three metrics read zero, and the observation table stayed empty with nothing logged anywhere. The batch is now refused with a 503 so the agent redelivers, the refusal is counted, and `readyz` fails while the clock is unreadable.

**Five of the design's twelve estate workloads did not exist, and the traffic driver reported success anyway.** `cards-auth`, `core-deposits`, `nostro-sync`, `partner-gateway` and `recon-quarterly` were specified, profiled in `profiles.yaml`, and never built. The driver counted calls *attempted* — `CALLS=$((CALLS+6))`, incremented whether or not anything answered — so the log read "3000 calls issued" throughout. A driver that cannot tell a served request from a refused connection is not evidence of traffic, and everything downstream of it inherits that. It now counts delivered and failed separately and names what failed.

**`DC_CVV` and `DC_DOB` were defined in the BPF program from the first commit and nothing ever set either.** `DataClass.CVV` sat in the sensitive set, unreachable. Neither can be found by value shape — a CVV is three digits and a date of birth is a date, and both match prices, counts and timestamps — so they needed the field name, which the classifier did not extract. Recognised on the key now, and firing.

**A `__u8` before a `__u64` moved every field after it.** Adding `fields_len` to the event struct pushed `conn_key` from byte 40 to 48 and the payload from 48 to 56, because the compiler inserts seven bytes of padding to align the 64-bit member. The Go decoder reads that struct by hand-counted offsets, and a wrong one does not fail — it decodes neighbouring bytes into a plausible value, so a misread cgroup id attributes capture to the wrong workload. The offsets are now asserted against the object's own BTF.

**The pattern matcher invented an endpoint.** `mux.HandleFunc("POST /api/v1/transfer", h)` is Go 1.22's syntax for a method and a path in one string. Two regexes matched it: one read it correctly, and one read the whole thing as a path, registering `GET /POST /api/v1/transfer` — a route no line of the repository declares. It also missed `router.HandleFunc(` with its path on the next line entirely, and a missed route is what SHADOW is computed from.

**Kong rejected the authorisation server's own signing key as invalid.** The JWKS `x5c` entry is a DER X.509 *certificate* — the key wrapped in an identity, a validity window and a signature — and re-armouring those bytes as `BEGIN PUBLIC KEY` produces a file whose header claims one structure and whose body is another. Built from the JWK's `n` and `e` now, which is the key itself.

**A credential registered under the configured issuer is never consulted.** Kong's `jwt` plugin selects its verifying key by matching the token's own `iss` claim. `OIDC_ISSUER` is `http://localhost:8081/...`, the browser-facing address; Keycloak stamps `iss` with the host the token was requested through, which from inside the network is `keycloak:8081`. The same identity-versus-address split made the API reject its own tokens as "invalid issuer" earlier in this project's life.

**The console reported itself unhealthy for its entire lifetime while serving every request.** `localhost` inside the nginx image resolves to `::1` before `127.0.0.1`, and `listen 80;` binds IPv4 only — so the container's own healthcheck got `connection refused` on a service answering 200 to everyone reaching it through the published port. Nineteen consecutive failures, no effect, because nothing in compose waits on the console. Anything that did — a `depends_on: service_healthy`, a probe dialling by name — would have blocked forever on a service that was working. nginx now listens on both stacks and the check dials by address.

**A console tile waited forever on a request that had already succeeded.** The Operations view declared `/pipeline` as `runs: [...]`; the endpoint returns one run, under `run`. `runs?.[0]` was therefore permanently undefined, so Last-run sat on its loading dash — while the fetch returned 200, TanStack Query reported success, and `tsc` type-checked the assertion rather than the contract. The Audit view had the same fault, declaring `message` where the server sends `reason`, so a broken chain would have read "broken" with no reason underneath it. This is the cost of hand-writing `lib/api.ts` instead of generating it, which is why the divergence was already recorded below rather than discovered here. `tools/check_console_contract.py` now compares all 17 typed calls against the payloads a live control plane actually sends.

**And rendered every stage it had not reached yet as failed.** `s.ok ? "ok" : (s.error ?? "failed")` has two branches for three states: a stage the run has not started carries `ok === null` and fell into the failure branch. A cycle caught mid-flight — which, at a cadence shorter than a cycle takes, is most of the time — displayed as a pipeline collapsing.

**The lock that serialises cycles guarded one of the two ways in.** `sentry.scan_cycle` takes a Redis lock before running a pass, and the module that owns it explains at length why overlapping passes are the one concurrency the DAG cannot catch — each satisfies its own dependency checks and then interleaves its writes. `/operations/scan` ran the same pipeline synchronously in the API process and took nothing. Pressing *scan* while beat's tick was in flight put two cycles in the same estate, and stage 02 died on `endpoint_daily_pkey` writing a rollup the other pass had already committed. Both entry points now take the lock, a held lock is a 409 rather than a second cycle, and the TTL has one definition instead of one per caller.

**Every call was counted twice.** Between two instrumented workloads the caller's `SSL_write` and the callee's `SSL_read` are both genuine sightings of one exchange. Both are worth keeping — only the egress copy names the caller, only the ingress copy exists when the client is outside the estate — but nothing distinguished them, so every volume figure was doubled. `observation.direction` now records which half a row is, and stage 02 counts the larger side once.

**Object Lock was tested with the wrong operation.** `verify_immutable` issued an unversioned `DeleteObject`. On a versioned bucket that writes a delete marker and returns success whatever the retention policy says, so the check reported a correctly configured COMPLIANCE bucket as not enforcing retention. It now deletes the specific version, which MinIO refuses with `Object is WORM protected`.

**The BPF program loaded or not depending on the compiler.** Three counters read back out of a `bpf_loop` context are unbounded scalars to the verifier, however tightly they were clamped before being stored. The branch tree over them was large enough that clang 19 produced an object rejected at exactly 1,000,001 instructions while clang 22 produced one that loaded in 163k. Masking on load restores the bound in one instruction and makes acceptance a property of the program rather than of the toolchain.

**An endpoint's history began when the gateway first mentioned it.** Correlation set `first_vday` from whichever sighting the loop reached first. A gateway declaration emitted today for an endpoint with a month of kernel history reset the window to today, dropped it below the baseline, and made stage 04 withhold a verdict it had ample evidence for. It is now the minimum across sightings.

**Every payment reference was its own endpoint.** `UPI7781XK92` matches none of the id patterns — not all-digits, not a UUID, not hex, not base64. One endpoint row per transaction, an inventory that grows without bound, and nothing ever accumulating enough history to classify. The normaliser now recognises a mixed alphanumeric reference, with API version segments and encoding vocabulary explicitly excluded so it cannot merge distinct endpoints.

**A caller that serves nothing produced no edge.** Only hosts seen in a request got a service row, so a batch driver or a mobile backend contributed no node and its edges were dropped. Endpoints it was the sole consumer of reported zero dependants — the exact figure a recommendation to retire them is built on.

Three older ones, from the previous build:

**The audit chain broke on every restart.** Entry hashes covered `wall_ts.isoformat()`. Postgres returns tz-aware datetimes and SQLite returns naive ones, so a chain written under one driver failed verification under the other — the worst possible failure for the one structure whose purpose is to prove nothing changed. Hashes now cover integer microseconds since epoch, normalised to UTC.

**Eleven tables could not accept a row on SQLite.** `BigInteger` primary keys do not auto-increment there — SQLite aliases only `INTEGER PRIMARY KEY` to rowid. Fixed with a dialect variant that keeps 64-bit ids in production.

**A test compared single vdays across different weekday positions** and read a decaying endpoint as growing. The weekly cycle is larger than the decay over a short span — the same trap the forecast fix exists to avoid, in a test. It now compares whole weeks.

## What has not been run

Stated plainly so it is not discovered by a reviewer first.

- **ServiceNow is untouched.** The change-request client has never run against a live instance; the change requests raised so far are `stub=true`.
- **`mtls` and `dpop` remain unjudgeable here.** `key-auth` passes because a consumer and a credential exist, and `oauth2` now compiles to `jwt` and is measured against a real Keycloak token. The other two need client certificates and a DPoP-capable client this deployment does not provide, so they are still rejected — correctly, and for a reason about the harness rather than the control.
- **oauth2 fails on latency, and that number is one request on a cold route.** 41.8 ms against a 10 ms payment budget, measured on `requests: 1`. Signature verification is not free, but a single replay against a route Kong has just built its router for is not a steady-state figure either, and it has not been separated from the router warm-up. The verdict is reported as measured rather than tuned to pass.
- **The legacy collector diverges from its design.** The design specifies `zeep`. `zeep` is a SOAP *client*, and reading operations out of a contract needs an XML parser rather than one — the standard library's ElementTree is exact for this and adds no dependency. This collector never calls a SOAP service, so the rest of zeep would be unused.
- **The gate's resurrection check needs the diff to reveal a response shape.** It compares a declaration against the declarable projection of a fingerprint — method, response fields, data classes. A handler that delegates its body to a shared helper the diff does not touch reveals nothing, and the check abstains rather than passing quietly. Stage 12's runtime detection is what covers that case.
- **Transport is HTTP/JSON, not the gRPC the design specifies — and stays that way, deliberately.** The agent's shipper and the ingest receiver agree, which matters more than matching the document. Nothing this estate does is throughput-bound: the change buys no measurable property here and puts the one path that cannot be re-run — live kernel capture — through a rewrite of both ends plus Go protobuf codegen. `contracts/proto` remains the schema of record and the migration path if throughput ever demands it. Reviewed and declined rather than left open.

---

## Next, in order

1. Separate Kong's router warm-up from the latency the Judge attributes to a control. `oauth2` fails at 41.8 ms against a 10 ms budget on a single replay against a freshly built route, and until the first-request cost is measured apart from the steady-state cost that verdict is not decidable either way.
2. Run the change-request client against a live ServiceNow instance. Everything raised so far is `stub=true`.
3. Provision client certificates and a DPoP-capable client, so the last two zero-trust controls are judged on evidence rather than rejected for the harness.


---

## Running it

Build the scanned repositories first — they are real git repositories with real
history, created here rather than committed, because rung 2 of the ownership
ladder runs `git log` against them:

```bash
./estate/repos/build-repos.sh
```

```bash
docker network create sentry-net
```

Bring up the platform. Nineteen services; the agent's privileged and namespace
requirements are declared in the compose file rather than left to a `docker run`:

```bash
VCLOCK_SCALE_SECONDS=10 docker compose -f deploy/compose/compose.yaml up -d
```

```bash
docker compose -f estate/compose.yaml up -d
```

The console is at `http://localhost:5173`, the control plane at
`http://localhost:8080`. Beat drives a pipeline pass every 6 virtual hours; to
run one immediately:

```bash
curl -X POST http://localhost:8080/api/v1/operations/scan -H 'Authorization: Bearer dev-analyst'
```

To turn real authentication on and see the analyst/approver boundary enforced by
Keycloak rather than by a dev token:

```bash
AUTH_DISABLED=false docker compose -f deploy/compose/compose.yaml up -d api
```

`VCLOCK_SCALE_SECONDS` decides how long a virtual day lasts. 86400 makes it a calendar day; 20 compresses a 90-day lifecycle into half an hour. The analysis is identical either way — only the wall-clock interval between observations differs.

## Citations

**Two peer-reviewed papers, cited at the algorithms that use them:**

- Liu, Ting & Zhou, *Isolation-Based Anomaly Detection*, ACM TKDD 6(1), 2012 — the isolation forest in `worker/sentry_worker/engines/behaviour.py`.
- Springer, 2021 — monitoring cadence, informing the stage 14 scan interval.

The supporting material claimed **four**. Two were cited anywhere in it, and the other two were never named. The claim is amended to two rather than left open: an unnamed citation is not a citation, and inventing the missing pair to close the gap would be the one failure this project has no defence against. Anything else here that reads as research-backed rests on these two and on measurement, not on a count.
