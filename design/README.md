# SENTINEL — Production Prototype Design Set

Twenty-two documents. Each stage file is self-contained: a developer who has not read the source architecture can build that stage from its file alone.

---

## Working synthetic engine

The web console starts with no live session and no cached decisions. `Start monitoring` connects the synthetic evidence adapter, runs the 14 analytical stages internally in dependency order, and publishes the resulting bank posture to the command centre. The operator does not run analytical stages by hand.

After the first analysis, a synthetic event stream keeps producing API observations. A fresh full-estate analysis is calculated in the background every monitoring cycle, so capture volume, risk, forecasts, findings, and audit evidence stay derived from the latest evidence.

The user-facing product is organised by bank operator intent:

- **Posture:** what needs a decision now
- **Detection:** what the bank observed and how confidently it identified it
- **Assessment:** why an API is risky, what will decay, and what a change will break
- **Response:** which control is safe, where an API is in retirement, and which zero-trust gap remains
- **Assurance:** whether the analytical loop and audit chain are healthy

Stage identifiers appear only in Operations for technical diagnosis. They are not the product navigation.

The synthetic source implements the `DiscoveryAdapter` interface in `app/engine.ts`. To connect a bank later, replace that adapter with an eBPF, gateway, CMDB, or OpenAPI collector that emits the same observation contract. Stages 02–14 do not need to change. A production browser session should receive invalidations over SSE; the current prototype uses an in-process event adapter so it remains self-contained.

Operational buttons change product state instead of raising a toast. Applying a judged synthetic gateway control immediately updates residual risk, the command queue, zero-trust evidence, and the activity stream. Advancing retirement moves the API record into the next governed phase.

Reloading returns the console to no live session and no computed evidence.

---

## Read in this order

**Foundation** — read all three before writing any code.

| File | What it settles |
|---|---|
| [00-ARCHITECTURE](00-ARCHITECTURE.md) | Six services, the stage→service map, the enforced DAG, the virtual clock, build order |
| [01-DATA-MODEL](01-DATA-MODEL.md) | Complete Postgres DDL, the agent→ingest protobuf, retention, the writer registry |
| [02-PLATFORM-SERVICES](02-PLATFORM-SERVICES.md) | Config, OIDC + four roles, the hash-chained audit ledger, observability, degradation policy |

**Stages**

| Stage | File | Owns |
|---|---|---|
| 01 | [Sensor Grid](10-STAGE-01-SENSOR-GRID.md) | eBPF uprobes, in-kernel filtering, data-class tagging, three collectors, ingest |
| 02 | [Baseline](11-STAGE-02-BASELINE.md) | Daily rollup, the confidence ramp that gates every verdict |
| 03 | [Correlation](12-STAGE-03-CORRELATION.md) | Path normalisation, identity, call graph, the four-rung ownership ladder |
| 04 | [Classification](13-STAGE-04-CLASSIFICATION.md) | Two axes, five questions, replayable trace |
| 05 | [Behaviour](14-STAGE-05-BEHAVIOUR.md) | Isolation Forest → r₆, three named patterns |
| 06 | [CDRI](15-STAGE-06-CDRI.md) | Σ(wᵢ·rᵢ), live re-scoring, time-to-breach |
| 07 | [Forecast](16-STAGE-07-FORECAST.md) | Deseasonalise then Holt, pre-zombie write-back |
| 08 | [Findings](17-STAGE-08-FINDINGS.md) | Narrative generation, seven-framework mapping, FS AI RMF log |
| 09 | [Blast Radius](18-STAGE-09-BLAST-RADIUS.md) | Two-hop BFS, tiers, retirement path |
| 10 | [Remediation](19-STAGE-10-REMEDIATION.md) | Kong Admin API, the API Judge, ServiceNow |
| 11 | [Decommission](20-STAGE-11-DECOMMISSION.md) | Four phases, canary, WORM Object Lock, certificate |
| 12 | [Threat](21-STAGE-12-THREAT.md) | Honeypot service, watermarking, MinHash/LSH resurrection |
| 13 | [Zero-Trust](22-STAGE-13-ZERO-TRUST.md) | Five-control posture, ordered hardening |
| 14 | [Operations](23-STAGE-14-OPERATIONS.md) | Scan cycle, CI gate, SIEM feed, debt leaderboard |

**Delivery**

| File | What it settles |
|---|---|
| [90-REFERENCE-ESTATE](90-REFERENCE-ESTATE.md) | Twelve real containerised services. **Build this before the agent** |
| [91-CONSOLE](91-CONSOLE.md) | Operator UI. The rule: it explains nothing |
| [92-DEPLOYMENT](92-DEPLOYMENT.md) | Compose topology, agent privileges, BTF on Docker Desktop, k8s |
| [93-VERIFICATION](93-VERIFICATION.md) | Closure checks, the acceptance run, known limitations |

---

## Four decisions that shape everything

**The estate is observed, not seeded.** There is no `seed.py`. `estate/` runs twelve real services and SENTINEL discovers them from an empty database. Every downstream figure traces to a captured request.

**Real eBPF, no fallback.** The agent attaches uprobes to `SSL_write`/`SSL_read` and Go's `crypto/tls`. It refuses to start without BTF rather than degrading to a proxy tap. On macOS it runs inside the Docker Desktop VM and sees containers there — [10 §3](10-STAGE-01-SENSOR-GRID.md) states the limit plainly.

**Time is configurable, not simulated.** `vday` is the only time axis. `VCLOCK_SCALE=86400` makes it a calendar day; `30` compresses a 90-day lifecycle into 45 minutes. Same code path, same windows, same partitioning.

**Produce less, never produce fiction.** Kong down means a control is `FAILED`, never `APPLIED`. No API key means `generator='template'`, labelled. Dropped kernel events mean the console shows degraded capture. Every stage's *Failure modes* section is written to this rule.

---

## Build order

1. `contracts/` — proto + OpenAPI, generation wired into the build
2. Foundation — schema, migrations, config, Keycloak, audit ledger
3. **`estate/`** — there must be something to discover before there is a discoverer
4. **`agent/` + `ingest/`** — the highest-risk component. Prove kernel capture works before writing any engine
5. Collectors → engines 02–09 in DAG order → actuators → honeypot → console
6. Deployment and the acceptance run

Step 4 is where this succeeds or fails. If kernel capture does not work, nothing downstream makes the system real.

---

## Checks that gate the build

```bash
python tools/check_contracts.py design/          # every input has a producer
python tools/check_schema_writers.py design/     # every column has exactly one writer
python tools/check_claims.py design/ ../*.html   # every source claim maps somewhere
grep -rEn '(is a |stands for|think of it as)' console/src --include='*.tsx'   # must be empty
```

All four pass against this set as written: 30 tables with exactly one declared writer, 14 stages with closed input/output contracts, 40 source capability claims resolved, no explanatory prose specified for the console.

---

## Open item

The supporting research claims **four peer-reviewed papers**. Two are cited anywhere in the source material — ACM TKDD 2012 (Isolation Forest, [stage 05](14-STAGE-05-BEHAVIOUR.md)) and Springer 2021 (monitoring cadence, [stage 14](23-STAGE-14-OPERATIONS.md)). Both are cited where the algorithm is implemented.

Name the other two or amend the claim. No citation has been invented to close the gap.
