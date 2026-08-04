"""Pipeline orchestration.

Stage order is enforced in code, not documentation. A stage invoked with an
unsatisfied dependency raises rather than reading a table that has not been
written.
"""

from __future__ import annotations

from dataclasses import dataclass

STAGE_NAMES: dict[int, str] = {
    1: "Sensor Grid",
    2: "Baseline",
    3: "Correlation",
    4: "Classification",
    5: "Behaviour",
    6: "CDRI",
    7: "Forecast",
    8: "Findings",
    9: "Blast Radius",
    10: "Remediation",
    11: "Decommission",
    12: "Threat",
    13: "Zero-Trust",
    14: "Operations",
}

#: Two properties this encodes, both of which were defects in the source
#: architecture:
#:
#: * 05 precedes 06. CDRI's formula takes a behavioural-anomaly term r6. A
#:   pipeline where CDRI ran first would read an input from its own future.
#: * 07 depends on 04 and writes ``classification.pre_zombie`` back onto it.
#:   That is the one legal back-edge in the graph and it is explicit.
STAGE_DEPS: dict[int, frozenset[int]] = {
    1: frozenset(),
    # Correlation precedes baseline. The daily rollup aggregates by endpoint, and
    # endpoint identity is what correlation produces: observations arrive with a
    # null endpoint_id and stage 03 is what resolves it. Running the rollup first
    # aggregated zero rows and every downstream stage silently had no series to
    # work with — the same shape of defect as CDRI consuming an input produced
    # after it, which is why the order is asserted rather than assumed.
    3: frozenset({1}),
    2: frozenset({1, 3}),
    4: frozenset({2, 3}),
    5: frozenset({4}),
    6: frozenset({5}),
    7: frozenset({4}),
    9: frozenset({3}),
    8: frozenset({6, 7, 9}),
    # Remediation needs the score that selects an endpoint, the blast radius
    # that says what a change touches, and the finding that carries the
    # reason into the change request.
    10: frozenset({6, 8, 9}),
    # Decommission needs the confidence ramp from classification and the
    # impact analysis that decides whether the path is express or canary.
    11: frozenset({4, 9}),
    # Resurrection detection compares live endpoints against the fingerprints
    # captured at retirement, so it cannot run before the stage that captures
    # them. It also reads stage 03's call edges, which are part of the
    # behavioural profile — an endpoint's caller set is one of its features.
    12: frozenset({3, 11}),
    # Posture is assessed against applied controls and prioritised by CDRI,
    # so it reads stage 06's score and stage 10's applied set.
    13: frozenset({6, 10}),
    14: frozenset({6}),
}


class StageDependencyError(RuntimeError):
    def __init__(self, stage: int, missing: set[int]) -> None:
        self.stage = stage
        self.missing = sorted(missing)
        super().__init__(
            f"stage {stage} ({STAGE_NAMES.get(stage, '?')}) requires "
            f"{self.missing} which have not completed"
        )


def topological_order() -> list[int]:
    """Deterministic execution order.

    Ties are broken by stage number so two runs execute identically, which
    matters when comparing stage timings across runs.
    """
    done: set[int] = set()
    order: list[int] = []
    remaining = dict(STAGE_DEPS)
    while remaining:
        ready = sorted(s for s, deps in remaining.items() if deps <= done)
        if not ready:
            raise RuntimeError(f"cycle in STAGE_DEPS among {sorted(remaining)}")
        for s in ready:
            order.append(s)
            done.add(s)
            remaining.pop(s)
    return order


def check_dependencies(stage: int, completed: set[int]) -> None:
    missing = STAGE_DEPS.get(stage, frozenset()) - completed
    if missing:
        raise StageDependencyError(stage, set(missing))


@dataclass
class StageResult:
    stage: int
    records: int
    duration_ms: int
    ok: bool
    error: str | None = None
    detail: dict | None = None


def validate_graph() -> None:
    """Fail loudly on a malformed DAG at import time rather than mid-run."""
    for stage, deps in STAGE_DEPS.items():
        unknown = deps - set(STAGE_DEPS)
        if unknown:
            raise RuntimeError(f"stage {stage} depends on undefined stages {sorted(unknown)}")
    topological_order()


validate_graph()
