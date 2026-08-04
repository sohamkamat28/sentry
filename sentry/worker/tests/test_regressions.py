"""The four defects found in the predecessor build, encoded as failing-first tests.

Each of these shipped once. Each is now a test that fails if the fix is removed.
"""

from __future__ import annotations

import math

import networkx as nx
import pytest

from sentry_worker.engines import blast, cdri, forecast
from sentry_worker.engines.judge_scoring import latency_score
from sentry_worker.engines.fingerprint import behavioural_shingles, similarity


# ─────────────────────────────────────────────────────────────────────────────
# 1. Deseasonalisation: a rising endpoint must never forecast to zero
# ─────────────────────────────────────────────────────────────────────────────
def _weekly_series(days: int, base: float, growth: float, weekend_dip: float = 0.3) -> list[float]:
    """Rising volume with a hard weekly cycle — the real shape of banking traffic."""
    out = []
    for d in range(days):
        weekday = d % 7
        seasonal = weekend_dip if weekday >= 5 else 1.0
        out.append((base + growth * d) * seasonal)
    return out


def test_rising_endpoint_with_weekly_cycle_is_not_flagged_declining():
    """The regression that motivated deseasonalise().

    Volume is rising 2%/vday. The window ends on a Sunday (the trough). Without
    deseasonalisation the fitted slope is negative and the endpoint is flagged
    pre-zombie. With it, the slope is positive.
    """
    # 91 days ends on index 90; 90 % 7 == 6 -> Sunday, the low day.
    series = _weekly_series(91, base=100.0, growth=2.0)
    assert (len(series) - 1) % 7 == 6, "fixture must end on the weekly trough"

    proj = forecast.project(series)
    assert proj.deseasonalised is True
    assert proj.slope > 0, f"deseasonalised slope should be positive, got {proj.slope}"
    assert forecast.days_to_zombie(proj, current_silence=0) is None

    # And the naive path it replaced: fitting the raw series is negative.
    raw_level = series[0]
    raw_trend = series[1] - series[0]
    for t in range(1, len(series)):
        prev = raw_level
        raw_level = 0.3 * series[t] + 0.7 * (raw_level + raw_trend)
        raw_trend = 0.1 * (raw_level - prev) + 0.9 * raw_trend
    assert raw_trend < 0, "fixture must be one the naive fit gets wrong"


def test_deseasonalise_flattens_a_pure_weekly_cycle():
    series = [100.0 * (0.3 if d % 7 >= 5 else 1.0) for d in range(84)]
    adjusted, ok = forecast.deseasonalise(series)
    assert ok
    interior = adjusted[7:-7]
    spread = (max(interior) - min(interior)) / max(interior)
    assert spread < 0.05, f"weekly cycle should be removed, residual spread {spread:.3f}"


def test_short_series_reports_that_it_was_not_deseasonalised():
    proj = forecast.project([10.0, 9.0, 8.0])
    assert proj.deseasonalised is False  # caveat travels with the result


def test_declining_endpoint_is_still_caught():
    """The correction must not blunt the detector it protects."""
    series = [max(0.0, (200.0 - 3.0 * d)) * (0.3 if d % 7 >= 5 else 1.0) for d in range(91)]
    proj = forecast.project(series)
    assert proj.slope < 0
    assert forecast.days_to_zombie(proj, current_silence=0) is not None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Blast radius: the two-hop cap
# ─────────────────────────────────────────────────────────────────────────────
def _dense_estate(n_services: int = 25, n_endpoints: int = 25) -> nx.DiGraph:
    """A densely connected estate containing one settlement service.

    This is the shape that broke unbounded traversal. Every endpoint eventually
    reaches settlement through the closure, so `touches_critical` becomes true
    estate-wide and everything rates CRITICAL — the real over-rating mechanism.
    Caller counts are varied so a correctly bounded run produces a spread.
    """
    g = nx.DiGraph()
    for i in range(n_services):
        crit = "SETTLEMENT" if i == 0 else "INTERNAL"
        g.add_node(f"svc{i}", kind="service", criticality=crit, name=f"svc{i}")
    for j in range(n_endpoints):
        g.add_node(f"ep{j}", kind="endpoint", service=f"svc{j % n_services}", name=f"ep{j}")
        g.add_edge(f"ep{j}", f"svc{j % n_services}", kind="implements")
    # Varied fan-in: ep0 has none, then 1, 2, ... so tiers genuinely differ.
    for j in range(n_endpoints):
        for k in range(j % 7):
            g.add_edge(f"svc{(j + k + 1) % n_services}", f"ep{j}", calls=100, kind="calls")
    return g


def test_two_hop_cap_produces_a_usable_tier_distribution():
    """Unbounded traversal rates a dense estate almost entirely CRITICAL, which
    is the same as rating none of it. Capping at two hops restores a real queue."""
    from sentry_core.enums import BlastTier

    g = _dense_estate()
    eps = [n for n, a in g.nodes(data=True) if a["kind"] == "endpoint"]

    capped = [blast.radius(g, e, hop_limit=2) for e in eps]
    unbounded = [blast.radius(g, e, hop_limit=len(g)) for e in eps]

    capped_crit = sum(r.tier is BlastTier.CRITICAL for r in capped) / len(capped)
    unbounded_crit = sum(r.tier is BlastTier.CRITICAL for r in unbounded) / len(unbounded)

    assert unbounded_crit > 0.8, (
        f"fixture must reproduce the over-rating, got {unbounded_crit:.2f}"
    )
    assert capped_crit < 0.5, f"capped run still over-rates: {capped_crit:.2f} CRITICAL"
    assert len({r.tier for r in capped}) >= 3, "capped run must spread across tiers"


def test_critical_contamination_is_bounded_by_hop_limit():
    """The mechanism behind the previous test, isolated.

    A settlement service four hops away must not make an endpoint throttle-exempt;
    one two hops away must.
    """
    g = nx.DiGraph()
    g.add_node("ep", kind="endpoint", name="ep")
    for i in range(4):
        g.add_node(f"h{i}", kind="service", criticality="INTERNAL", name=f"h{i}")
    g.add_node("settle", kind="service", criticality="SETTLEMENT", name="settle")
    g.add_edge("h0", "ep", calls=1, kind="calls")
    g.add_edge("h1", "h0", calls=1, kind="calls")
    g.add_edge("h2", "h1", calls=1, kind="calls")
    g.add_edge("settle", "h2", calls=1, kind="calls")

    assert blast.radius(g, "ep", hop_limit=2).touches_critical is False
    assert blast.radius(g, "ep", hop_limit=4).touches_critical is True


def test_tier_keys_on_direct_callers():
    g = nx.DiGraph()
    g.add_node("ep", kind="endpoint", name="ep")
    for i in range(4):
        g.add_node(f"s{i}", kind="service", criticality="INTERNAL", name=f"s{i}")
    for i in range(3):
        g.add_edge(f"s{i}", "ep", calls=1, kind="calls")
    g.add_edge("s3", "s0", kind="calls")  # second hop
    r = blast.radius(g, "ep", hop_limit=2)
    assert r.direct_callers == 3
    from sentry_core.enums import BlastTier
    assert r.tier is BlastTier.MEDIUM


def test_critical_service_at_hop_two_overrides_the_count():
    """An endpoint one hop from a single caller, but two hops from settlement,
    must be CRITICAL — deliberately throttling a payment path is an incident."""
    g = nx.DiGraph()
    g.add_node("ep", kind="endpoint", name="ep")
    g.add_node("mid", kind="service", criticality="INTERNAL", name="mid")
    g.add_node("settle", kind="service", criticality="SETTLEMENT", name="settle")
    g.add_edge("mid", "ep", calls=10, kind="calls")
    g.add_edge("settle", "mid", calls=10, kind="calls")

    r = blast.radius(g, "ep", hop_limit=2)
    from sentry_core.enums import BlastTier
    assert r.direct_callers == 1
    assert r.touches_critical is True
    assert r.tier is BlastTier.CRITICAL
    assert blast.retirement_path(r)["throttle_exempt"] is True


def test_zero_blast_never_means_immediate_deletion():
    g = nx.DiGraph()
    g.add_node("ep", kind="endpoint", name="ep")
    r = blast.radius(g, "ep")
    path = blast.retirement_path(r)
    assert r.tier.value == "ZERO"
    assert path["express"] is True
    assert "C" in path["phases"], "express must still quarantine"
    assert path["estimated_vdays"] >= 30


def test_endpoint_absent_from_graph_is_distinguishable_from_measured_zero():
    """Never observed is not the same evidence as observed to have no callers."""
    g = nx.DiGraph()
    absent = blast.radius(g, "nope")
    assert absent.in_graph is False
    assert absent.express_eligible is False  # cannot fast-path on absent evidence


# ─────────────────────────────────────────────────────────────────────────────
# 3. Latency scoring: budget compliance is a threshold, not a gradient
# ─────────────────────────────────────────────────────────────────────────────
def test_patch_within_budget_passes():
    """The regression: scoring latency as a smooth ratio meant a patch using 68%
    of an available budget scored 32 and was rejected — a patch that was, by the
    bank's own stated policy, acceptable."""
    budget = 10_000
    score = latency_score(delta_us=6_800, budget_us=budget)
    assert score >= 70, f"68% of budget must pass the floor, scored {score}"


def test_latency_score_boundaries():
    assert latency_score(0, 10_000) == 100
    assert latency_score(-500, 10_000) == 100          # faster than control
    assert latency_score(10_000, 10_000) == 0          # exactly at budget: reject
    assert latency_score(12_000, 10_000) == 0          # over budget
    assert latency_score(100, 10_000) > latency_score(9_000, 10_000)


def test_latency_score_reports_headroom_monotonically():
    budget = 5_000
    scores = [latency_score(d, budget) for d in (500, 1500, 2500, 3500, 4500)]
    assert scores == sorted(scores, reverse=True)


def test_pass_requires_a_quarter_of_the_budget_left_unused():
    """The policy the floor actually encodes.

    Being *within* budget is not sufficient — a patch consuming 90% of the
    allowance leaves nothing for load variance. The pass boundary sits at 75%
    consumed, which admits the 68% case that motivated the fix and still refuses
    a patch cutting it fine.
    """
    budget = 10_000
    assert latency_score(6_800, budget) >= 70   # the regression case
    assert latency_score(7_500, budget) >= 70   # exactly at the boundary
    assert latency_score(9_000, budget) < 70    # too little headroom
    assert latency_score(9_900, budget) < 70


# ─────────────────────────────────────────────────────────────────────────────
# 4. Fingerprint: keyed on behaviour, not on the path
# ─────────────────────────────────────────────────────────────────────────────
_BEHAVIOUR = {
    "method": "GET",
    "response_fields": ["account.id", "account.balance", "account.currency", "asOf"],
    "data_classes": ["ACCOUNT_NO"],
    "callers": ["svc-mobile", "svc-branch"],
    "hour_shape": [0, 0, 0, 0, 1, 3, 8, 12, 14, 15, 15, 14, 12, 11, 9, 7, 4, 2, 1, 0, 0, 0, 0, 0],
    "auth": "none",
    "auth_missing_band": "high",
    "req_size_band": "small",
    "resp_size_band": "medium",
}


def test_renamed_redeployment_still_matches():
    """The regression: including path tokens weighted the one thing a rename
    changes. A redeployed endpoint scored 0.583 against a 0.85 threshold — the
    exact case the detector exists to catch."""
    original = behavioural_shingles({**_BEHAVIOUR, "path_template": "/internal/maturity"})
    renamed = behavioural_shingles({**_BEHAVIOUR, "path_template": "/api/v2/maturity-v2"})

    sim = similarity(original, renamed)
    assert sim >= 0.95, f"renamed redeployment scored {sim:.3f}, must be >= 0.95"


def test_no_path_token_leaks_into_the_shingle_set():
    shingles = behavioural_shingles({**_BEHAVIOUR, "path_template": "/internal/maturity"})
    joined = " ".join(shingles).lower()
    for token in ("internal", "maturity", "path"):
        assert token not in joined, f"path token {token!r} leaked into the fingerprint"


def test_behaviourally_different_endpoints_score_below_threshold():
    a = behavioural_shingles({**_BEHAVIOUR, "path_template": "/a"})
    b = behavioural_shingles({
        "method": "POST",
        "path_template": "/b",
        "response_fields": ["txn.id", "txn.status"],
        "data_classes": ["CARD", "CVV"],
        "callers": ["svc-atm"],
        "hour_shape": [5] * 24,
        "auth": "oauth2",
        "auth_missing_band": "none",
        "req_size_band": "large",
        "resp_size_band": "small",
    })
    assert similarity(a, b) < 0.85


# ─────────────────────────────────────────────────────────────────────────────
# CDRI invariants
# ─────────────────────────────────────────────────────────────────────────────
def test_all_indicators_high_scores_exactly_one():
    r = cdri.score(cdri.Inputs(
        auth="none", lifecycle="ZOMBIE", data_classes=["AADHAAR"],
        tls_version="1.0", rate_limited=False, anomaly_flag=True,
    ))
    assert r.score == 1.0
    assert r.tier.value == "CRITICAL"


def test_anomaly_contributes_exactly_once():
    """Applying the anomaly term a second time after the sum would double-count
    it and break the sum-to-one property."""
    inp = dict(auth="oauth2", lifecycle="ACTIVE", data_classes=[],
               tls_version="1.3", rate_limited=True)
    off = cdri.score(cdri.Inputs(**inp, anomaly_flag=False)).score
    on = cdri.score(cdri.Inputs(**inp, anomaly_flag=True)).score
    assert math.isclose(on - off, cdri.DEFAULT_WEIGHTS["anomaly"], abs_tol=1e-9)


def test_parts_resum_to_score():
    r = cdri.score(cdri.Inputs(
        auth="basic", lifecycle="DORMANT", data_classes=["IFSC"],
        tls_version="1.2", rate_limited=False, anomaly_flag=False,
    ))
    assert math.isclose(sum(p["contribution"] for p in r.parts), r.score, abs_tol=1e-6)


def test_weights_must_sum_to_one():
    with pytest.raises(cdri.WeightSumError) as e:
        cdri.score(
            cdri.Inputs(auth="none", lifecycle="ACTIVE", data_classes=[],
                        tls_version="1.3", rate_limited=True, anomaly_flag=False),
            weights={**cdri.DEFAULT_WEIGHTS, "no_auth": 0.30},
        )
    assert math.isclose(e.value.actual, 1.02, abs_tol=1e-6)


def test_absent_anomaly_is_recorded_as_absent_not_as_zero_risk():
    r = cdri.score(cdri.Inputs(
        auth="none", lifecycle="ZOMBIE", data_classes=[],
        tls_version="1.3", rate_limited=True, anomaly_flag=None,
    ))
    part = next(p for p in r.parts if p["key"] == "anomaly")
    assert part["source"] == "absent"


def test_time_to_breach_is_labelled_and_never_zero():
    days, factors = cdri.time_to_breach(
        cdri_score=0.93, auth="none", data_classes=["AADHAAR"],
        governance="SHADOW", anomaly_patterns=["ZOMBIE_TRAFFIC_SPIKE"],
        internet_reachable=True,
    )
    assert days is not None and days >= 1
    assert factors, "factors must be inspectable, not an oracular number"

    low, _ = cdri.time_to_breach(0.10, "oauth2", [], "OWNED", None, False)
    assert low is None, "no estimate offered below the meaningful threshold"
