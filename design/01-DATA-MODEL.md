# 01 — Data Model

Complete PostgreSQL schema, wire contracts, and the rules governing who writes what.

---

## 1. Principles

1. **One writer per column.** Every column names exactly one stage that writes it. Cross-checked in [93](93-VERIFICATION.md). A stage that needs another stage's output reads it; it never recomputes and overwrites.
2. **Raw observations are immutable.** `observation` and `probe` are append-only. Engines derive; they never edit source data.
3. **Engine output is versioned and re-derivable.** Every derived row carries `engine_version` and the `vday` it was computed for. Deleting all derived rows and re-running the pipeline reproduces them exactly.
4. **`vday` is the time axis.** Wall timestamps are retained for forensics and SIEM correlation only. No engine windows on wall time.

---

## 2. Extensions and enums

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;      -- digest() for the audit chain
CREATE EXTENSION IF NOT EXISTS pg_trgm;       -- path search in the console

CREATE TYPE criticality_t  AS ENUM ('PAYMENT','SETTLEMENT','REGULATORY','CUSTOMER','INTERNAL');
CREATE TYPE source_t       AS ENUM ('ebpf','gateway','code','legacy');
CREATE TYPE lifecycle_t    AS ENUM ('ACTIVE','DORMANT','DEPRECATED','ZOMBIE');
CREATE TYPE governance_t   AS ENUM ('OWNED','ORPHANED','SHADOW');
CREATE TYPE confidence_t   AS ENUM ('NONE','PROVISIONAL','CONFIRMED');
CREATE TYPE tier_t         AS ENUM ('LOW','MEDIUM','HIGH','CRITICAL');
CREATE TYPE blast_t        AS ENUM ('ZERO','LOW','MEDIUM','CRITICAL');
CREATE TYPE auth_t         AS ENUM ('none','basic','apikey','bearer','oauth2','mtls');
CREATE TYPE phase_t        AS ENUM ('NONE','A','B','C','D','RETIRED','REVERTED');
CREATE TYPE control_state_t AS ENUM ('PROPOSED','JUDGED','APPLIED','REVERTED','FAILED');
```

`lifecycle_t` has four values because `DORMANT` covers days 31–89, which matched no status in the source model. `governance_t` is a separate axis because an endpoint can be alive and ownerless, or dead and properly owned — a single enum cannot express both.

---

## 3. Time base

```sql
CREATE TABLE vclock (
  id             smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  epoch_wall     timestamptz NOT NULL,
  scale_seconds  integer     NOT NULL CHECK (scale_seconds BETWEEN 1 AND 86400),
  paused_at      timestamptz,
  paused_vday    integer
);
```

```sql
CREATE FUNCTION current_vday() RETURNS integer LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN paused_at IS NOT NULL THEN paused_vday
    ELSE floor(extract(epoch FROM (now() - epoch_wall)) / scale_seconds)::integer
  END FROM vclock WHERE id = 1;
$$;
```

`scale_seconds = 86400` in production, making `vday` a calendar day. Pausing freezes analysis without stopping capture — observations continue to arrive and are stamped with `paused_vday`.

**Writer:** `api` (admin role only). **Readers:** all.

---

## 4. Estate

### `service`

```sql
CREATE TABLE service (
  id           text PRIMARY KEY,                 -- svc_<12hex>
  name         text NOT NULL UNIQUE,
  team         text,
  criticality  criticality_t NOT NULL DEFAULT 'INTERNAL',
  stack        text,
  first_vday   integer NOT NULL,
  last_vday    integer NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX service_team_idx ON service (team);
```

`criticality` is resolved by stage 03 from Kong tags, repository metadata, or an operator override in `policy`. It is never guessed from the path string.

**Writer:** stage 03.

### `endpoint`

The aggregate row. Identity and observed facts only — engine verdicts live in their own tables so they can be recomputed and audited independently.

```sql
CREATE TABLE endpoint (
  id              text PRIMARY KEY,              -- ep_<16hex>
  method          text NOT NULL,
  path_template   text NOT NULL,
  service_id      text NOT NULL REFERENCES service(id) ON DELETE CASCADE,
  host            text,
  port            integer,

  first_vday      integer NOT NULL,
  last_call_vday  integer,                       -- NULL = never observed serving
  total_calls     bigint  NOT NULL DEFAULT 0,

  auth            auth_t  NOT NULL DEFAULT 'none',
  tls_version     text,                          -- '1.0'|'1.2'|'1.3'|NULL for cleartext
  rate_limited    boolean NOT NULL DEFAULT false,
  data_classes    text[]  NOT NULL DEFAULT '{}', -- {'PAN','AADHAAR','IFSC','ACCOUNT_NO','CARD','CVV','DOB'}
  deprecated      boolean NOT NULL DEFAULT false,

  retired         boolean NOT NULL DEFAULT false,
  honeypot_active boolean NOT NULL DEFAULT false,

  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (method, path_template, service_id)
);
CREATE INDEX endpoint_service_idx    ON endpoint (service_id);
CREATE INDEX endpoint_lastcall_idx   ON endpoint (last_call_vday);
CREATE INDEX endpoint_path_trgm_idx  ON endpoint USING gin (path_template gin_trgm_ops);
```

| Column | Writer |
|---|---|
| identity, `host`, `port`, `first_vday` | stage 03 |
| `last_call_vday`, `total_calls` | stage 02 (rollup) |
| `auth`, `tls_version`, `rate_limited`, `data_classes` | stage 01 (observed) — overridden by stage 10/13 on control application |
| `deprecated` | stage 03 (from `Deprecation` header or code annotation) |
| `retired`, `honeypot_active` | stage 11 |

### `endpoint_source`

Discovery provenance. Shadow detection is a query over this table, not a stored flag.

```sql
CREATE TABLE endpoint_source (
  endpoint_id  text     NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  source       source_t NOT NULL,
  first_vday   integer  NOT NULL,
  last_vday    integer  NOT NULL,
  detail       jsonb    NOT NULL DEFAULT '{}',
  PRIMARY KEY (endpoint_id, source)
);
```

```sql
-- Shadow: observed serving traffic, absent from gateway registry AND absent from code.
CREATE VIEW endpoint_shadow AS
SELECT e.id FROM endpoint e
WHERE EXISTS (SELECT 1 FROM endpoint_source s WHERE s.endpoint_id = e.id AND s.source = 'ebpf')
  AND NOT EXISTS (SELECT 1 FROM endpoint_source s WHERE s.endpoint_id = e.id AND s.source = 'gateway')
  AND NOT EXISTS (SELECT 1 FROM endpoint_source s WHERE s.endpoint_id = e.id AND s.source = 'code');
```

**Writer:** stage 01 collectors.

---

## 5. Observations

### `observation` — partitioned, append-only

One row per captured request. This is the highest-volume table in the system.

```sql
CREATE TABLE observation (
  id             bigserial   NOT NULL,
  vday           integer     NOT NULL,
  wall_ts        timestamptz NOT NULL,
  endpoint_id    text,                        -- NULL until stage 03 resolves it
  source         source_t    NOT NULL,

  method         text        NOT NULL,
  path_raw       text        NOT NULL,
  host           text,
  port           integer,
  status         smallint,
  latency_us     integer,
  req_bytes      integer,
  resp_bytes     integer,

  auth_present   boolean     NOT NULL DEFAULT false,
  auth_scheme    text,
  tls_version    text,
  data_classes   text[]      NOT NULL DEFAULT '{}',

  peer_service   text,                        -- caller, resolved from cgroup/pid at capture
  peer_ip        inet,
  pid            integer,
  cgroup_id      bigint,

  PRIMARY KEY (vday, id)
) PARTITION BY RANGE (vday);

CREATE INDEX observation_ep_idx    ON observation (endpoint_id, vday);
CREATE INDEX observation_unres_idx ON observation (vday) WHERE endpoint_id IS NULL;
```

**No payload column exists.** Request and response bodies are matched against data-class patterns in kernel memory and discarded there. The class is recorded; the value is never written to disk, never crosses the network, and has no column to occupy. See [10-STAGE-01 §7](10-STAGE-01-SENSOR-GRID.md).

Partitions are created 7 vdays ahead by the `partition_maintain` beat task and detached past `OBSERVATION_RETENTION_VDAYS` (default 400). Detached partitions are archived to WORM before drop.

```sql
-- created at runtime by worker/app/maintenance.py, one partition per vday.
-- Illustrative only — partitions are not declared in migrations.
CREATE TABLE observation_v0042 PARTITION OF observation FOR VALUES FROM (42) TO (43);
```

**Writer:** `ingest` (bulk `COPY`), stage 03 (backfills `endpoint_id`).

### `endpoint_daily` — rollup

Engines window over this, never over raw `observation`. Rebuilt idempotently per vday.

```sql
CREATE TABLE endpoint_daily (
  endpoint_id     text    NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  vday            integer NOT NULL,
  calls           bigint  NOT NULL,
  distinct_peers  integer NOT NULL,
  err_calls       bigint  NOT NULL,
  p50_latency_us  integer,
  p95_latency_us  integer,
  mean_resp_bytes integer,
  auth_missing    bigint  NOT NULL DEFAULT 0,
  hour_histogram  smallint[24] NOT NULL,
  PRIMARY KEY (endpoint_id, vday)
);
CREATE INDEX endpoint_daily_vday_idx ON endpoint_daily (vday);
```

`hour_histogram` feeds the `time_of_day_distribution` feature at stage 05 and the weekly deseasonalisation at stage 07.

**Writer:** stage 02.

---

## 6. Graph and ownership

```sql
CREATE TABLE call_edge (
  caller_service_id text    NOT NULL REFERENCES service(id) ON DELETE CASCADE,
  endpoint_id       text    NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  first_vday        integer NOT NULL,
  last_vday         integer NOT NULL,
  calls             bigint  NOT NULL,
  PRIMARY KEY (caller_service_id, endpoint_id)
);
CREATE INDEX call_edge_ep_idx ON call_edge (endpoint_id);

CREATE TABLE datastore_edge (
  endpoint_id text NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  datastore   text NOT NULL,
  PRIMARY KEY (endpoint_id, datastore)
);

CREATE TABLE ownership (
  endpoint_id  text PRIMARY KEY REFERENCES endpoint(id) ON DELETE CASCADE,
  owner_email  text,
  owner_team   text,
  resolved_by  text    NOT NULL,   -- 'codeowners'|'git-blame'|'hr-directory'|'gateway-metadata'|'unresolved'
  confidence   real    NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  reachable    boolean NOT NULL,   -- HR directory says this person still works here
  escalation   text,               -- department head, when unresolved
  ladder       jsonb   NOT NULL,   -- per-step trace: what each rung returned
  resolved_at  timestamptz NOT NULL DEFAULT now()
);
```

`ladder` records every rung attempted and its result, so an ownership verdict is auditable rather than asserted.

**Writer:** stage 03.

---

## 7. Engine outputs

Each stage owns one table. All carry `vday` and `engine_version`.

```sql
CREATE TABLE classification (
  endpoint_id    text PRIMARY KEY REFERENCES endpoint(id) ON DELETE CASCADE,
  lifecycle      lifecycle_t  NOT NULL,
  governance     governance_t NOT NULL,
  confidence     confidence_t NOT NULL,
  severity_bump  boolean NOT NULL DEFAULT false,  -- ownership missing → severity, not status
  pre_zombie     boolean NOT NULL DEFAULT false,  -- WRITTEN BY STAGE 07
  trace          jsonb   NOT NULL,                -- five rule answers, in order
  vday           integer NOT NULL,
  engine_version text    NOT NULL
);
CREATE INDEX classification_life_idx ON classification (lifecycle, governance);

CREATE TABLE anomaly (
  endpoint_id     text PRIMARY KEY REFERENCES endpoint(id) ON DELETE CASCADE,
  flag            boolean NOT NULL,              -- r6 ∈ {0,1}
  score           real    NOT NULL,              -- raw isolation score
  isolation_depth real    NOT NULL,
  patterns        text[]  NOT NULL DEFAULT '{}', -- {'ZOMBIE_TRAFFIC_SPIKE','AUTH_SEQUENCE','PAYLOAD_DEVIATION'}
  features        jsonb   NOT NULL,
  vday            integer NOT NULL,
  engine_version  text    NOT NULL
);

CREATE TABLE cdri (
  endpoint_id      text PRIMARY KEY REFERENCES endpoint(id) ON DELETE CASCADE,
  score            real   NOT NULL CHECK (score BETWEEN 0 AND 1),
  tier             tier_t NOT NULL,
  parts            jsonb  NOT NULL,   -- [{key,label,r,w,contribution}] — six entries
  weights_version  integer NOT NULL REFERENCES policy_weights(version),
  time_to_breach_d integer,
  vday             integer NOT NULL,
  engine_version   text    NOT NULL
);
CREATE INDEX cdri_score_idx ON cdri (score DESC);
CREATE INDEX cdri_tier_idx  ON cdri (tier);

CREATE TABLE forecast (
  endpoint_id    text PRIMARY KEY REFERENCES endpoint(id) ON DELETE CASCADE,
  days_to_zombie integer,
  slope          real    NOT NULL,
  level          real    NOT NULL,
  signals        jsonb   NOT NULL,   -- {call_volume:.., commit_recency:.., owner_activity:..}
  projection     real[]  NOT NULL,   -- 30 forward points
  deseasonalised boolean NOT NULL DEFAULT true,
  vday           integer NOT NULL,
  engine_version text    NOT NULL
);

CREATE TABLE blast (
  endpoint_id      text PRIMARY KEY REFERENCES endpoint(id) ON DELETE CASCADE,
  tier             blast_t NOT NULL,
  direct_callers   integer NOT NULL,
  hop2_callers     integer NOT NULL,
  affected         jsonb   NOT NULL,  -- [{service_id,hop,calls,criticality}]
  datastores       text[]  NOT NULL DEFAULT '{}',
  touches_critical boolean NOT NULL,  -- payment/settlement/regulatory in radius → throttle-exempt
  vday             integer NOT NULL,
  engine_version   text    NOT NULL
);

CREATE TABLE finding (
  id             text PRIMARY KEY,
  endpoint_id    text NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  narrative      text NOT NULL,
  generator      text NOT NULL,      -- 'anthropic'|'template' — never conflated
  regulations    jsonb NOT NULL,     -- [{framework,clause,requirement,status}]
  vday           integer NOT NULL,
  engine_version text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX finding_ep_idx ON finding (endpoint_id, vday DESC);
```

`finding.generator` is a first-class column. A template-generated narrative is labelled as such in the API and in the console. The system does not present template output as model output.

---

## 8. Policy

Mutable, versioned, audited. The CDRI weight tuner in the console writes here; it does not patch code.

```sql
CREATE TABLE policy_weights (
  version    serial PRIMARY KEY,
  weights    jsonb NOT NULL,   -- {no_auth:0.28, zombie:0.22, data:0.20, tls:0.15, no_rate_limit:0.08, anomaly:0.07}
  note       text,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT weights_sum_one CHECK (
    abs((SELECT sum(v::numeric) FROM jsonb_each_text(weights) AS t(k,v)) - 1.0) < 1e-6
  )
);
```

The `weights_sum_one` constraint is the schema-level guarantee that CDRI's maximum is exactly 1.00 and that scores remain comparable. The anomaly term is one of the six weights; it is not applied a second time after scoring.

```sql
CREATE TABLE policy_setting (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL,
  updated_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
```

Seeded keys: `latency_budget_us` (per criticality class), `tier_bounds`, `resurrection_threshold` (0.85), `blast_hop_limit` (2), `scan_interval_vhours` (6), `express_sunset_vdays` (30).

---

## 9. Action and governance

```sql
CREATE TABLE control (
  id            bigserial PRIMARY KEY,
  endpoint_id   text NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  kind          text NOT NULL,       -- 'rate-limit'|'tls-min'|'response-mask'|'mtls-auth'|'oauth2'|'sunset-header'|'request-termination'
  plugin_config jsonb NOT NULL,      -- exactly what was POSTed to Kong
  kong_plugin_id text,               -- Kong's assigned id; NULL until applied
  state         control_state_t NOT NULL DEFAULT 'PROPOSED',
  generator     text NOT NULL,       -- 'anthropic'|'template'
  judge_run_id  bigint REFERENCES judge_run(id),
  applied_at    timestamptz,
  reverted_at   timestamptz,
  actor         text
);
CREATE INDEX control_ep_idx ON control (endpoint_id, state);

CREATE TABLE judge_run (
  id             bigserial PRIMARY KEY,
  endpoint_id    text NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  requests       integer NOT NULL,      -- replayed request count
  schema_score   smallint NOT NULL CHECK (schema_score BETWEEN 0 AND 100),
  latency_score  smallint NOT NULL,
  error_score    smallint NOT NULL,
  exposure_score smallint NOT NULL,
  verdict        text NOT NULL,         -- 'PASS'|'REJECT'
  latency_delta_us integer NOT NULL,
  budget_us      integer NOT NULL,
  diff_summary   jsonb NOT NULL,        -- deepdiff output, truncated
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE change_request (
  id            bigserial PRIMARY KEY,
  endpoint_id   text NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  control_id    bigint REFERENCES control(id),
  sys_id        text,                  -- ServiceNow sys_id
  number        text,                  -- CHG0030001
  state         text NOT NULL,         -- 'DRAFT'|'SUBMITTED'|'APPROVED'|'REJECTED'|'FAILED'
  payload       jsonb NOT NULL,        -- exactly what was sent
  response      jsonb,
  submitted_at  timestamptz,
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE decommission (
  endpoint_id     text PRIMARY KEY REFERENCES endpoint(id) ON DELETE CASCADE,
  phase           phase_t NOT NULL DEFAULT 'NONE',
  express         boolean NOT NULL DEFAULT false,   -- ZERO blast → 30-vday path
  canary          boolean NOT NULL DEFAULT false,   -- critical blast → canary, never throttle
  canary_split    real CHECK (canary_split BETWEEN 0 AND 1),
  entered_vday    integer,
  phase_vday      integer,
  hidden_callers  jsonb NOT NULL DEFAULT '[]',      -- surfaced during quarantine
  worm_object     text,                             -- s3://…  set at phase D
  worm_retain_until timestamptz,
  certificate_id  text,
  reverted_reason text
);

CREATE TABLE certificate (
  id            text PRIMARY KEY,
  endpoint_id   text NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  body          jsonb NOT NULL,
  content_hash  bytea NOT NULL,
  worm_object   text NOT NULL,
  approved_by   text NOT NULL,
  issued_at     timestamptz NOT NULL DEFAULT now()
);
```

---

## 10. Threat

```sql
CREATE TABLE fingerprint (
  endpoint_id  text PRIMARY KEY REFERENCES endpoint(id) ON DELETE CASCADE,
  minhash      bytea   NOT NULL,      -- 128 permutations, serialised
  features     jsonb   NOT NULL,      -- the behavioural shingle set, for audit
  captured_vday integer NOT NULL,
  origin_path  text    NOT NULL       -- retained after the endpoint row is retired
);

CREATE TABLE probe (
  id          bigserial   NOT NULL,
  vday        integer     NOT NULL,
  wall_ts     timestamptz NOT NULL,
  endpoint_id text        NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  source_ip   inet        NOT NULL,
  source_asn  text,
  geo         text,
  method      text        NOT NULL,
  path_raw    text        NOT NULL,
  headers     jsonb       NOT NULL,
  body_sha256 bytea,
  watermark   text        NOT NULL,
  session_fp  text,
  PRIMARY KEY (vday, id)
) PARTITION BY RANGE (vday);
CREATE INDEX probe_ep_idx  ON probe (endpoint_id, vday);
CREATE INDEX probe_src_idx ON probe (source_ip);

CREATE TABLE resurrection_alert (
  id             bigserial PRIMARY KEY,
  new_endpoint_id text NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  origin_endpoint_id text NOT NULL,
  similarity     real NOT NULL,
  threshold      real NOT NULL,
  lsh_hit        boolean NOT NULL,
  vday           integer NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (new_endpoint_id, origin_endpoint_id)
);
```

`probe.headers` stores what an attacker sent. It is not estate data and carries no customer information. `body_sha256` is a digest — probe bodies are never retained in cleartext.

---

## 11. Audit and AI decision log

```sql
CREATE TABLE audit_entry (
  seq        bigserial PRIMARY KEY,
  wall_ts    timestamptz NOT NULL DEFAULT now(),
  vday       integer NOT NULL,
  actor      text NOT NULL,          -- subject claim, or 'system:<service>'
  action     text NOT NULL,          -- 'control.apply', 'decommission.advance', …
  target     text,
  detail     jsonb NOT NULL DEFAULT '{}',
  prev_hash  bytea NOT NULL,
  entry_hash bytea NOT NULL
);
CREATE INDEX audit_target_idx ON audit_entry (target, seq DESC);
CREATE INDEX audit_actor_idx  ON audit_entry (actor, seq DESC);

CREATE TABLE ai_decision (
  id             bigserial PRIMARY KEY,
  endpoint_id    text REFERENCES endpoint(id) ON DELETE SET NULL,
  purpose        text NOT NULL,       -- 'finding.narrative'|'remediation.config'
  model          text NOT NULL,
  prompt_sha256  bytea NOT NULL,
  output_sha256  bytea NOT NULL,
  confidence     real,
  reasoning      text,
  input_tokens   integer,
  output_tokens  integer,
  latency_ms     integer,
  wall_ts        timestamptz NOT NULL DEFAULT now()
);
```

`ai_decision` satisfies the FS AI RMF requirement that every model-influenced decision be reconstructable. Prompt and output are stored as digests plus a reasoning summary; full prompts go to WORM under `ai/` when `AI_ARCHIVE_PROMPTS=true`.

Chain construction and verification: [02 §4](02-PLATFORM-SERVICES.md).

---

## 12. Orchestration

```sql
CREATE TABLE pipeline_run (
  id          bigserial PRIMARY KEY,
  trigger     text NOT NULL,          -- 'scheduled'|'manual'|'auto-enrol'
  actor       text,
  started_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  ok          boolean
);

CREATE TABLE stage_run (
  id           bigserial PRIMARY KEY,
  run_id       bigint NOT NULL REFERENCES pipeline_run(id) ON DELETE CASCADE,
  stage        smallint NOT NULL,
  vday         integer NOT NULL,
  records      integer NOT NULL DEFAULT 0,
  duration_ms  integer NOT NULL DEFAULT 0,
  ok           boolean NOT NULL DEFAULT false,
  error        text,
  UNIQUE (run_id, stage)
);

CREATE TABLE gate_event (
  id         bigserial PRIMARY KEY,
  repo       text NOT NULL,
  pr_number  integer NOT NULL,
  commit_sha text NOT NULL,
  checks     jsonb NOT NULL,       -- [{name, passed, detail}]
  passed     boolean NOT NULL,
  wall_ts    timestamptz NOT NULL DEFAULT now()
);
```

---

## 13. Wire contract — agent to ingest

`contracts/proto/sentinel/v1/observation.proto`

```protobuf
syntax = "proto3";
package sentinel.v1;
option go_package = "github.com/sentinel/contracts/gen/go/sentinel/v1;sentinelv1";

service ObservationIngest {
  rpc Stream(stream ObservationBatch) returns (stream IngestAck);
}

message ObservationBatch {
  string agent_id     = 1;
  string agent_version= 2;
  string node         = 3;
  repeated Observation items = 4;
}

message Observation {
  int64  wall_unix_ns = 1;
  string method       = 2;
  string path_raw     = 3;
  string host         = 4;
  uint32 port         = 5;
  uint32 status       = 6;
  uint32 latency_us   = 7;
  uint32 req_bytes    = 8;
  uint32 resp_bytes   = 9;

  bool   auth_present = 10;
  string auth_scheme  = 11;
  string tls_version  = 12;
  repeated DataClass data_classes = 13;

  string peer_service = 14;   // resolved from cgroup at capture
  string peer_ip      = 15;
  uint32 pid          = 16;
  uint64 cgroup_id    = 17;
}

enum DataClass {
  DATA_CLASS_UNSPECIFIED = 0;
  PAN        = 1;
  AADHAAR    = 2;
  IFSC       = 3;
  ACCOUNT_NO = 4;
  CARD       = 5;
  CVV        = 6;
  DOB        = 7;
}

message IngestAck {
  uint64 accepted = 1;
  uint64 rejected = 2;
  string reason   = 3;
}
```

There is no `body` or `payload` field. The wire format makes payload exfiltration structurally impossible, not merely disallowed by policy.

`vday` is **not** on the wire. `ingest` stamps it from `current_vday()` at write time, so a clock-skewed agent cannot corrupt the analysis time base.

---

## 14. Migrations

Alembic, in `api/migrations/`. Rules:

- One migration per logical change; never edit a merged migration.
- Every migration has a working `downgrade()`. CI asserts `upgrade → downgrade → upgrade` reaches the same schema hash.
- Partitioned tables: migrations alter the parent only. Partition creation and drop are runtime operations owned by `worker/app/maintenance.py`, not migrations.
- An engine algorithm change bumps `VERSION` **and** ships a data migration that either backfills or nulls affected derived rows. A score whose provenance is ambiguous is deleted, not kept.

Baseline revision `0001_initial` contains §2–§12 in full.

---

## 15. Retention

| Table | Retention | Then |
|---|---|---|
| `observation` | `OBSERVATION_RETENTION_VDAYS` (400) | Archived to WORM, partition dropped |
| `probe` | 2555 vdays (7y) | Retained — threat evidence |
| `audit_entry` | Never deleted | — |
| `ai_decision` | Never deleted | — |
| `certificate` | Never deleted | — |
| `endpoint_daily` | Never deleted | Small, and the basis of all history |
| Engine output tables | Current row only | Superseded rows overwritten; history via `audit_entry` |

Seven years on `probe` and `certificate` matches the SEC/FINRA retention the WORM archive is configured for. `audit_entry` is never deleted because a hash chain with a hole is not a hash chain.

---

## 16. Writer registry

The authoritative one-writer-per-table map. `tools/check_schema_writers.py` parses this table and fails the build if any stage document claims a write not declared here, or if any table has no writer.

| Table | Writer | Notes |
|---|---|---|
| `vclock` | `api` (admin routes) | Platform, not a stage |
| `service` | Stage 03 | |
| `endpoint` | **Split by column** — see §4 | The one table with multiple writers, resolved at column granularity |
| `endpoint_source` | Stage 01 | |
| `observation` | `ingest` (insert) · Stage 03 (`endpoint_id` backfill only) | Otherwise append-only |
| `endpoint_daily` | Stage 02 | |
| `call_edge`, `datastore_edge` | Stage 03 | |
| `ownership` | Stage 03 | |
| `classification` | Stage 04, **except `pre_zombie`** | |
| `classification.pre_zombie` | **Stage 07** | *Declared exception.* The one legal cross-stage write; the DAG back-edge in [00 §5](00-ARCHITECTURE.md). Stage 04's upsert omits this column from its `SET` list |
| `anomaly` | Stage 05 | |
| `cdri` | Stage 06 | Stages 13, 14 read only |
| `forecast` | Stage 07 | |
| `blast` | Stage 09 | |
| `finding` | Stage 08 | |
| `policy_weights` | `api` (analyst routes) | Versioned, never updated in place |
| `policy_setting` | `api` (admin routes) | Platform |
| `control` | **Stage 10 actuator only** | Stages 11 and 13 delegate here; neither writes directly |
| `judge_run` | Stage 10 | |
| `change_request` | Stage 10 | |
| `decommission` | Stage 11 | |
| `certificate` | Stage 11 | |
| `fingerprint` | Stage 12 | Captured at Phase D, before behaviour changes |
| `probe` | `honeypot` service | Append-only |
| `resurrection_alert` | Stage 12 | |
| `audit_entry` | `api` audit ledger | Append-only, hash chained. See [02 §4](02-PLATFORM-SERVICES.md) |
| `ai_decision` | Stages 08 and 10 | Both make model calls; both log to the same FS AI RMF ledger. Distinguished by `purpose` |
| `pipeline_run`, `stage_run` | `worker` orchestrator | Platform |
| `gate_event` | Stage 14 | |
| `team_debt` (matview) | Stage 14 | Refreshed per cycle |

Three entries carry design weight and are called out so they are not read as sloppiness:

- **`classification.pre_zombie`** is deliberately written by a stage that does not own its table. It is the only such case, and stage 04's upsert is written to preserve it.
- **`control`** has exactly one writer despite three stages causing gateway changes. Stages 11 and 13 route through stage 10's actuator, which is what keeps `APPLIED` meaning "Kong confirmed it" everywhere.
- **`ai_decision`** has two writers by design — every model-influenced decision in the system lands in one ledger, which is what the FS AI RMF audit requires.
