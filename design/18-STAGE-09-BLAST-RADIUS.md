# Stage 09 — Blast Radius

BFS over the call graph. Answers what breaks if this endpoint is removed, before anyone removes it.

---

## 1. Scope

**Owns:** `blast` — tier, direct and second-hop caller counts, the named affected set, datastores, and `touches_critical`.

**Does not own:** the decommission decision. It supplies the evidence; stage 11 acts on it, and `touches_critical` is the flag that routes an endpoint away from throttling.

---

## 2. Deployment unit

`worker/app/engines/blast.py`. Runs after stage 03. Reads the serialised graph from Redis (`graph:<vday>`) rather than rebuilding it.

---

## 3. Inputs

| Source | Field |
|---|---|
| Redis `graph:<vday>` | Node-link graph built by stage 03 |
| `call_edge` | `calls`, `last_vday` — edges within `WINDOW_VDAYS` only |
| `datastore_edge` | Downstream stores |
| `service.criticality` | Payment/settlement/regulatory detection |

---

## 4. Algorithm

### 4.1 Bounded traversal

```python
def radius(G, endpoint_id, hop_limit=BLAST_HOP_LIMIT) -> Blast:
    levels = {}
    for node, hop in nx.bfs_layers_limited(G.reverse(), endpoint_id, hop_limit):
        levels.setdefault(hop, []).append(node)
    direct = [n for n in levels.get(1, []) if G.nodes[n]["kind"] == "service"]
    hop2   = [n for n in levels.get(2, []) if G.nodes[n]["kind"] == "service"]
    stores = [s for _, s, d in G.out_edges(endpoint_id, data=True) if d.get("kind") == "reads"]
    return Blast(direct, hop2, stores)
```

**Two hops, not the transitive closure.** Removing an endpoint breaks the services that call it. Whether that breaks *their* callers depends on how each handles a dependency failure — timeouts, circuit breakers, cached fallbacks, degraded modes — which is second-order and unknowable from a call graph.

This is not a theoretical preference. Traversing the full closure on the reference estate rated 108 of 125 endpoints `CRITICAL`, which is the same as rating none of them: an operator given a queue where everything is critical has no queue. Capping at two hops produced a usable distribution — most zombies `ZERO` or `LOW`, a handful genuinely `CRITICAL`.

`BLAST_HOP_LIMIT` is configurable. Raising it is permitted and the API reports the limit in force with every result, so a tier is always interpretable.

### 4.2 Tiers

Keyed on **direct** callers, because those are the ones that break immediately.

```python
def tier(direct: list, affected_crit: bool) -> BlastTier:
    if affected_crit:          return BlastTier.CRITICAL   # overrides count
    if len(direct) == 0:       return BlastTier.ZERO
    if len(direct) <= 2:       return BlastTier.LOW
    if len(direct) <= 5:       return BlastTier.MEDIUM
    return BlastTier.CRITICAL
```

| Tier | Rule | Consequence at stage 11 |
|---|---|---|
| `ZERO` | No callers in the window | Unlocks the 30-vday express sunset — **never immediate deletion** |
| `LOW` | 1–2 non-critical services | Standard 90-vday path |
| `MEDIUM` | 3–5 services, or 1–2 critical | Standard path, planned migration window |
| `CRITICAL` | 6+ services, or any payment/settlement/regulatory system in the radius | Canary migration, exempt from Phase A throttling |

Second-hop callers are reported and shown but do not set the tier. They inform the migration plan.

### 4.3 ZERO is not "delete now"

Ninety days of silence cannot rule out an annual job — year-end close, annual regulatory filing, a yearly reconciliation. `ZERO` unlocks a compressed path: skip Phase A throttling, still publish retirement notices, still run a 30-vday quarantine before removal.

The source document contained both "zero callers = immediate Phase C" and "ZERO blast radius = decommission immediately". Neither survives here. Stage 11 has one fast path and it still has a quarantine window.

### 4.4 Critical detection

```python
touches_critical = any(
    G.nodes[s]["criticality"] in ("PAYMENT", "SETTLEMENT", "REGULATORY")
    for s in direct + hop2
)
```

Second-hop services count here even though they do not set the tier by count. An endpoint two hops from settlement should not be throttled.

`criticality` comes from `service.criticality`, resolved by stage 03 from Kong tags or repository metadata — never inferred from the path string. An endpoint named `/api/v1/payment-history` is a reporting endpoint; one named `/api/v1/xfr` may be settlement. Name-based inference would get both wrong.

---

## 5. Data model delta

Writes `blast`, full row.

```json
{
  "affected": [
    {"service_id":"svc_a1b2","name":"mobile-banking","hop":1,"calls":48210,"criticality":"CUSTOMER"},
    {"service_id":"svc_c3d4","name":"settlement","hop":2,"calls":312,"criticality":"SETTLEMENT"}
  ]
}
```

---

## 6. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/impact` | `viewer` | All analysed endpoints with tier and counts |
| `GET /api/v1/impact/{endpoint_id}` | `viewer` | Full radius, subgraph for rendering, retirement path |
| `POST /api/v1/impact/{endpoint_id}/trace` | `analyst` | Compute for one endpoint |
| `POST /api/v1/impact/trace-all` | `analyst` | Estate-wide; `202` |

```json
{
  "endpoint_id": "ep_9f2c…",
  "tier": "LOW",
  "hop_limit": 2,
  "direct_callers": 2,
  "hop2_callers": 5,
  "touches_critical": false,
  "datastores": ["core_accounts_db"],
  "affected": [...],
  "retirement_path": {
    "express": false, "canary": false,
    "phases": ["A","B","C","D"], "estimated_vdays": 90
  },
  "subgraph": {"nodes": [...], "links": [...]}
}
```

`retirement_path` is computed here and consumed by stage 11, so the impact screen tells an operator what will happen before they commit to it.

---

## 7. Configuration

| Variable | Default | Range |
|---|---|---|
| `BLAST_HOP_LIMIT` | `2` | 1–4 |
| `WINDOW_VDAYS` | `90` | Edge inclusion window |
| `GRAPH_CACHE_TTL_S` | `600` | Redis graph cache |

---

## 8. Failure modes

| Condition | Behaviour |
|---|---|
| Graph cache miss | Rebuilt from `call_edge` on demand; slower, same result |
| Endpoint absent from graph | `ZERO` with `direct_callers: 0` and `in_graph: false` — an endpoint never observed serving has no callers, and the flag distinguishes that from a measured zero |
| Cycle in the graph | BFS visits each node once; cycles terminate naturally |
| Stage 03 not run | `StageDependencyError` |
| Graph exceeds `GRAPH_MAX_NODES` | Fails loudly rather than degrading silently |

The `in_graph: false` distinction matters at stage 11: an endpoint that was never in the graph has not been *proven* safe to retire, it has merely never been seen. Stage 11 refuses express sunset in that state.

---

## 9. Security and compliance

- **RBAC**: reads `viewer`; trace `analyst`.
- **Audit**: not audited — analysis, not action. The retirement decision that consumes it is audited at stage 11.
- **Frameworks**: DORA Art 9 (dependency mapping is resilience evidence); FFIEC DA&M (impact analysis before change).

---

## 10. Tests

**Unit**
- Chain A→B→C→D from D: direct = {C}, hop2 = {B}, D absent from its own radius.
- Cycle A→B→A terminates.
- Tier boundaries: 0, 2, 3, 5, 6 direct callers.
- `touches_critical` set by a hop-2 settlement service, and that endpoint is `CRITICAL` despite one direct caller.
- Edges outside the window excluded.
- **Hop-limit regression**: on a dense fixture graph, `hop_limit=2` yields a mixed tier distribution while unbounded traversal yields near-universal `CRITICAL`. This test encodes the reason for the cap.

**Integration**
- Reference estate: zombie tier distribution is spread across `ZERO`/`LOW`/`MEDIUM`/`CRITICAL`, not concentrated.
- `retirement_path.express` is true only for `ZERO` with `in_graph: true`.

**E2E**
- Tracing a zombie from the console populates the affected list with real service names drawn from observed traffic.

---

## 11. Acceptance criteria

- [ ] Traversal stops at `BLAST_HOP_LIMIT`, and the limit is reported with every result.
- [ ] Tier is keyed on direct callers, with the critical-service override.
- [ ] `touches_critical` accounts for both hops.
- [ ] `ZERO` yields express sunset with a quarantine window, never immediate deletion.
- [ ] The affected list names real services observed calling the endpoint.
- [ ] An endpoint absent from the graph is distinguishable from one measured to have zero callers.
- [ ] On the reference estate the zombie tier distribution is usable — not concentrated in one tier.
