# Stage 03 — Correlation

Turns four independent streams of sightings into one registry: deduplicated endpoints, a call graph, and an owner with a confidence score.

---

## 1. Scope

**Owns:** endpoint identity and creation; path normalisation; deduplication across sources; the `service` table; the call graph (`call_edge`, `datastore_edge`); ownership resolution.

**Does not own:** lifecycle or governance verdicts. It produces the facts stage 04 reasons over. It does, however, own the *evidence* for `SHADOW` — the `endpoint_source` rows — because absence from a registry is a correlation result.

---

## 2. Deployment unit

`worker/app/engines/correlation.py`. Celery beat every `SCAN_INTERVAL_VHOURS` (6) and after any collector run. Runtime dominated by unresolved-observation resolution; NetworkX graph construction is in-memory and rebuilt each run.

---

## 3. Inputs

| Source | Contract |
|---|---|
| `observation` | Rows with `endpoint_id IS NULL` for the last `WINDOW_VDAYS` |
| `endpoint_source` | Existing provenance |
| `endpoint` | Existing registry for matching |
| Git repositories | `git blame` results cached by the code collector |
| HR directory | `HR_DIRECTORY_URL` — JSON or LDAP |
| Kong service tags | Criticality declarations |

---

## 4. Outputs

| Target | Columns |
|---|---|
| `service` | Full row |
| `endpoint` | Identity, `host`, `port`, `first_vday`, `deprecated` |
| `observation` | Backfills `endpoint_id` |
| `endpoint_source` | Per-source first/last vday and detail |
| `call_edge`, `datastore_edge` | Full rows |
| `ownership` | Full row including the ladder trace |

---

## 5. Algorithm

### 5.1 Path normalisation

The gateway reports `/api/v1/accounts/{id}/balance`. The kernel reports `/api/v1/accounts/8814/balance`. Code reports `/api/v1/accounts/<int:id>/balance`. These are one endpoint.

Applied in order to `path_raw`:

1. Strip query string and fragment (except the SOAP `#action` suffix, which is identity).
2. Lowercase the path; preserve case in the SOAP action.
3. Collapse repeated slashes; strip trailing slash except at root.
4. Replace each segment matching a parameter pattern with `{id}`:

| Pattern | Example |
|---|---|
| All digits, length ≥ 2 | `8814` |
| UUID (RFC 4122, any version) | `3f2b…` |
| Hex, length ≥ 16 | `9a3f2b1c8d4e5f60` |
| Base64url, length ≥ 22 | `dGhpcyBpcyBhIHRlc3Q` |
| Framework placeholder | `{id}`, `:id`, `<int:id>`, `[id]` |
| Date `YYYY-MM-DD` | `2026-07-27` |

5. Cap at 8 segments; deeper paths truncate with a trailing `/**` and are counted in `sentinel_path_truncated_total`.

**The over-collapse guard.** A path of all-numeric segments (`/8814/9902`) would normalise to `/{id}/{id}` and merge genuinely distinct endpoints. When a normalised template would absorb more than `NORMALISE_MAX_MERGE` (200) distinct raw paths *and* those raw paths have divergent response schemas, the template is split back out on the first differing segment and the event is logged. Silent over-merging would understate the estate, which is the failure mode that matters here.

### 5.2 Identity and deduplication

```python
endpoint_id = "ep_" + blake2s(f"{method}⋮{path_template}⋮{service_id}", digest_size=8).hexdigest()
```

Service resolution, in order:

1. `peer_service` from the observation (agent resolved it from cgroup at capture) — authoritative.
2. Kong `service.name` for gateway-sourced rows.
3. Repository name for code-sourced rows.
4. `host:port` reverse lookup against the `service` table.
5. Otherwise `svc_unknown_<host>`, flagged for operator attention.

Because the id is content-derived, the same endpoint seen by four sources produces four `endpoint_source` rows against one `endpoint` row. Deduplication is a property of the identity function, not a merge pass that could run twice and differ.

`GET /api/v1/correlation` reports per-source merge decisions — sightings in, endpoints out, and which source contributed each field — so the dedup is inspectable rather than asserted.

### 5.3 Call graph

```python
G = nx.DiGraph()
for svc in services:      G.add_node(svc.id, kind="service", criticality=svc.criticality)
for ep in endpoints:      G.add_node(ep.id,  kind="endpoint", service=ep.service_id)
for e in call_edges:      G.add_edge(e.caller_service_id, e.endpoint_id, calls=e.calls)
for ep in endpoints:      G.add_edge(ep.id, ep.service_id, kind="implements")
for d in datastore_edges: G.add_edge(ep.id, d.datastore, kind="reads")
```

Edges are built from `observation.peer_service` over the 90-vday window. An edge whose `last_vday` falls outside the window is retained in the table with its dates but excluded from the in-memory graph, so blast radius at stage 09 reflects current reality while history stays available for audit.

Datastore edges come from the legacy collector's WSDL bindings and from repository AST analysis of ORM/JDBC calls. Where neither is available, no edge is asserted — the graph does not guess.

The graph is serialised to Redis (`graph:<vday>`, node-link JSON) so stage 09 does not rebuild it per query.

### 5.4 Shadow evidence

Shadow is defined once: **live traffic observed, absent from the gateway registry, and absent from every code repository.** The `endpoint_shadow` view in [01 §4](01-DATA-MODEL.md) is that definition in SQL and is the only place it is expressed.

Correlation refuses to treat gateway absence as evidence when the gateway collector is unhealthy. `GET /api/v1/correlation` returns `shadow_reliable: false` in that case, and stage 04 withholds the `SHADOW` verdict rather than manufacturing one from a failed poll.

### 5.5 Ownership ladder

Four rungs, tried in order, each recording what it returned.

| Rung | Source | Confidence | Detail |
|---|---|---|---|
| 1 | `CODEOWNERS` | 1.00 | Glob-matched against the route's file path. Authoritative when present |
| 2 | `git blame` | 0.75 | Last author to touch the route definition line |
| 3 | HR directory | modifier | Confirms the person is still employed; finds the successor if not |
| 4 | Gateway/catalogue metadata | 0.40 | The declared owner field — frequently null on exactly the endpoints that matter |

```python
def resolve(ep) -> Ownership:
    ladder = []
    for rung in (codeowners, git_blame, gateway_metadata):
        r = rung(ep); ladder.append({"rung": rung.__name__, "result": r.summary})
        if r.email:
            hr = hr_directory(r.email); ladder.append({"rung": "hr_directory", "result": hr.summary})
            if hr.employed:
                return Ownership(r.email, r.team, rung.__name__, r.confidence, True, ladder=ladder)
            if hr.successor:
                return Ownership(hr.successor, r.team, rung.__name__, r.confidence * 0.8, True, ladder=ladder)
            # found a name, but that person has left
            return Ownership(r.email, r.team, rung.__name__, r.confidence * 0.5, False,
                             escalation=hr.department_head, ladder=ladder)
    return Ownership(None, None, "unresolved", 0.0, False,
                     escalation=department_head_for(ep.service_id), ladder=ladder)
```

Two properties worth stating because they change outcomes:

- **A departed owner is not the same as no owner.** `reachable = false` with a named `escalation` routes to a department head rather than emailing an inbox nobody reads. Stage 04 treats `reachable = false` as `ORPHANED`.
- **Confidence is retained, not thresholded away.** The Security Debt Leaderboard at stage 14 weights by confidence, so a team is not charged for an endpoint whose ownership rests on a 0.40-confidence null metadata field.

---

## 6. Data model delta

Creates `service` and `endpoint` rows. Backfills `observation.endpoint_id` in batches of 10 000:

```sql
UPDATE observation o SET endpoint_id = m.endpoint_id
FROM path_match m
WHERE o.vday = :vday AND o.endpoint_id IS NULL
  AND o.method = m.method AND normalise(o.path_raw) = m.path_template;
```

`normalise()` is implemented in Python, not SQL — the rules in §5.1 are too involved for a stable SQL function and must match the collector's behaviour exactly. Matching happens in application code against a prepared template map.

---

## 7. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/correlation` | `viewer` | Merge decisions per source, dedup ratio, window rationale, `shadow_reliable` |
| `GET /api/v1/correlation/graph` | `viewer` | Node-link graph; `?root=` and `?depth=` to scope |
| `GET /api/v1/correlation/{endpoint_id}/ownership` | `viewer` | Full ladder trace |
| `POST /api/v1/correlation/{endpoint_id}/ownership` | `analyst` | Operator override with mandatory justification; sets `resolved_by='manual'`, confidence 1.0 |
| `POST /api/v1/correlation/run` | `analyst` | Force a cycle; `202` + task id |

---

## 8. Configuration

| Variable | Default | Notes |
|---|---|---|
| `WINDOW_VDAYS` | `90` | Graph edge window |
| `NORMALISE_MAX_MERGE` | `200` | Over-collapse guard threshold |
| `HR_DIRECTORY_URL` | — | Absent → rung 3 skipped, confidence unmodified, recorded in ladder |
| `CODEOWNERS_PATHS` | `.github/CODEOWNERS,CODEOWNERS` | |
| `RESOLUTION_BATCH` | `10000` | Rows per backfill transaction |

---

## 9. Failure modes

| Condition | Behaviour |
|---|---|
| Gateway collector unhealthy | `shadow_reliable=false`; stage 04 withholds `SHADOW`; no inference from absence |
| HR directory unreachable | Rung 3 skipped, ladder records the failure, confidence not inflated. `readyz` unaffected |
| Repository unavailable | `git blame` rung skipped; ownership may fall to metadata with lower confidence |
| Observation matches no template | Remains `endpoint_id IS NULL`, counted in `sentinel_unresolved_observations`; a new endpoint is created on the next cycle if the pattern recurs |
| Two services expose an identical path | Distinct endpoints — `service_id` is in the identity hash |
| Graph exceeds memory | Bounded by estate size; a run over `GRAPH_MAX_NODES` (50 000) fails loudly rather than swapping |

---

## 10. Security and compliance

- **RBAC**: reads `viewer`; ownership override `analyst`, audited with the supplied justification.
- **Audit**: `ownership.overridden` (before, after, justification), `correlation.service.created`.
- **Frameworks**: NYDFS Part 500 (forensic trail — the ladder is the evidence for an accountability claim); RBI §continuous monitoring.

---

## 11. Tests

**Unit**
- Normalisation table: 40 raw paths → expected templates, including UUID, hex, base64url, date and framework placeholders.
- Over-collapse guard splits `/{id}/{id}` when schemas diverge and does not split when they match.
- Identity hash is stable across process restarts and insensitive to field ordering.
- Ladder: each rung reached in order; departed owner produces `reachable=false` with escalation; successor lookup applies the 0.8 factor.

**Integration**
- The same endpoint reported by all four collectors yields one `endpoint` row and four `endpoint_source` rows.
- Two services with an identical path yield two endpoints.
- Graph edges respect the 90-vday window; an edge last seen at vday−95 is stored but absent from the in-memory graph.
- Killing the gateway collector sets `shadow_reliable=false` and no endpoint gains `SHADOW` on the next classification run.

**E2E**
- `shadow-fx-rate` resolves to exactly one endpoint with `ebpf` as its only source.
- `recon-quarterly` produces one endpoint whose call edges span the full window despite 89 silent vdays.

---

## 12. Acceptance criteria

- [ ] Four sources reporting one endpoint produce one registry row.
- [ ] `GET /api/v1/correlation` shows the merge decision per source with field-level attribution.
- [ ] Every endpoint has an `ownership` row with a populated ladder trace, including unresolved ones.
- [ ] An endpoint whose owner has left shows `reachable=false` and a named escalation target.
- [ ] `shadow_reliable` is `false` whenever the gateway collector is unhealthy, and no `SHADOW` verdict is issued in that state.
- [ ] The graph endpoint returns a connected structure that renders in the console without post-processing.
- [ ] Re-running correlation changes no endpoint id.
