"""Stage 09 — Blast Radius.

Bounded BFS over the call graph. Answers what breaks if this endpoint is
removed, before anyone removes it.

The hop cap is the load-bearing decision. Removing an endpoint breaks the
services that call it; whether that breaks *their* callers depends on how each
handles a dependency failure — timeouts, circuit breakers, cached fallbacks —
which is second-order and unknowable from a call graph.

This is not a theoretical preference. Traversing the full transitive closure on
the reference estate rated 108 of 125 endpoints CRITICAL, which is the same as
rating none of them: an operator given a queue where everything is critical has
no queue.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from sentry_core.config import settings
from sentry_core.enums import BlastTier, Criticality

VERSION = "blast-1.0.0"

CRITICAL_CLASSES = {
    Criticality.PAYMENT.value,
    Criticality.SETTLEMENT.value,
    Criticality.REGULATORY.value,
}


@dataclass
class BlastResult:
    tier: BlastTier
    direct_callers: int
    hop2_callers: int
    affected: list[dict] = field(default_factory=list)
    datastores: list[str] = field(default_factory=list)
    touches_critical: bool = False
    in_graph: bool = False
    hop_limit: int = 2

    @property
    def express_eligible(self) -> bool:
        """ZERO unlocks the 30-vday express sunset — never immediate deletion.

        ``in_graph`` is required: an endpoint never observed in the graph has not
        been *proven* to have zero callers, it has merely never been seen, and
        that is different evidence.
        """
        return self.tier is BlastTier.ZERO and self.in_graph


def build_graph(
    services: list[dict],
    endpoints: list[dict],
    call_edges: list[dict],
    datastore_edges: list[dict],
) -> nx.DiGraph:
    g = nx.DiGraph()
    for s in services:
        g.add_node(s["id"], kind="service", criticality=s.get("criticality", "INTERNAL"),
                   name=s.get("name", s["id"]))
    for e in endpoints:
        g.add_node(e["id"], kind="endpoint", service=e.get("service_id"),
                   name=f"{e.get('method','')} {e.get('path_template','')}".strip())
    for c in call_edges:
        if c["caller_service_id"] in g and c["endpoint_id"] in g:
            g.add_edge(c["caller_service_id"], c["endpoint_id"], calls=c.get("calls", 0),
                       kind="calls")
    for e in endpoints:
        if e["id"] in g and e.get("service_id") in g:
            g.add_edge(e["id"], e["service_id"], kind="implements")
    for d in datastore_edges:
        if d["endpoint_id"] in g:
            g.add_node(d["datastore"], kind="datastore")
            g.add_edge(d["endpoint_id"], d["datastore"], kind="reads")
    return g


def _callers_at(g: nx.DiGraph, target: str, hop_limit: int) -> dict[int, list[str]]:
    """Reverse BFS from the endpoint, capped at hop_limit, service nodes only."""
    levels: dict[int, list[str]] = {}
    seen = {target}
    frontier = [target]
    for hop in range(1, hop_limit + 1):
        nxt: list[str] = []
        for node in frontier:
            for pred in g.predecessors(node):
                if pred in seen:
                    continue
                seen.add(pred)
                nxt.append(pred)
                if g.nodes[pred].get("kind") == "service":
                    levels.setdefault(hop, []).append(pred)
        if not nxt:
            break
        frontier = nxt
    return levels


def tier_for(direct: int, touches_critical: bool) -> BlastTier:
    """Keyed on *direct* callers, because those are the ones that break immediately.

    A critical service anywhere in the radius overrides the count: an endpoint
    two hops from settlement must not be throttled.
    """
    if touches_critical:
        return BlastTier.CRITICAL
    if direct == 0:
        return BlastTier.ZERO
    if direct <= 2:
        return BlastTier.LOW
    if direct <= 5:
        return BlastTier.MEDIUM
    return BlastTier.CRITICAL


def radius(g: nx.DiGraph, endpoint_id: str, hop_limit: int | None = None) -> BlastResult:
    limit = hop_limit if hop_limit is not None else settings.blast_hop_limit

    if endpoint_id not in g:
        return BlastResult(
            tier=BlastTier.ZERO, direct_callers=0, hop2_callers=0,
            in_graph=False, hop_limit=limit,
        )

    levels = _callers_at(g, endpoint_id, limit)
    direct = levels.get(1, [])
    hop2 = [n for h, nodes in levels.items() if h >= 2 for n in nodes]

    affected: list[dict] = []
    for hop, nodes in sorted(levels.items()):
        for n in nodes:
            calls = 0
            if g.has_edge(n, endpoint_id):
                calls = g.edges[n, endpoint_id].get("calls", 0)
            affected.append({
                "service_id": n,
                "name": g.nodes[n].get("name", n),
                "hop": hop,
                "calls": calls,
                "criticality": g.nodes[n].get("criticality", "INTERNAL"),
            })

    # Second-hop services count here even though they do not set the tier by
    # count: proximity to a payment path is what makes throttling unsafe.
    touches_critical = any(a["criticality"] in CRITICAL_CLASSES for a in affected)

    datastores = [
        d for _, d, attrs in g.out_edges(endpoint_id, data=True)
        if attrs.get("kind") == "reads"
    ]

    return BlastResult(
        tier=tier_for(len(direct), touches_critical),
        direct_callers=len(direct),
        hop2_callers=len(hop2),
        affected=affected,
        datastores=sorted(datastores),
        touches_critical=touches_critical,
        in_graph=True,
        hop_limit=limit,
    )


def retirement_path(result: BlastResult) -> dict:
    """What stage 11 will do, computed here so the impact screen can show an
    operator the consequence before they commit to it."""
    express = result.express_eligible
    canary = result.touches_critical
    if express:
        phases = ["B", "C", "D"]
        vdays = settings.express_quarantine_vdays
    else:
        phases = ["A", "B", "C", "D"]
        vdays = settings.phase_a_vdays + settings.phase_b_vdays + settings.phase_c_vdays
    return {
        "express": express,
        "canary": canary,
        "phases": phases,
        "estimated_vdays": vdays,
        "throttle_exempt": canary,
    }
