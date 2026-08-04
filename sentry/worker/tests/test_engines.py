"""Engine correctness: truth tables, normalisation, the ladder, and the DAG."""

from __future__ import annotations

import pytest

from sentry_worker import pipeline
from sentry_worker.engines import baseline, behaviour, classification, correlation, frameworks
from sentry_core.enums import Confidence, Governance, Lifecycle

CONFIRMED = 120  # observed vdays past the window


# ─────────────────────────────────────────────────────────────────────────────
# Stage 04 — the full truth table
# ─────────────────────────────────────────────────────────────────────────────
def _f(**kw):
    base = dict(silent_vdays=0, in_gateway=True, has_reachable_owner=True,
                deprecated=False, in_code=True, owner_confidence=1.0, shadow_reliable=True)
    base.update(kw)
    return classification.Facts(**base)


@pytest.mark.parametrize(
    "facts,expect_life,expect_gov,note",
    [
        (_f(silent_vdays=5), Lifecycle.ACTIVE, Governance.OWNED, "healthy baseline"),
        (_f(silent_vdays=45), Lifecycle.DORMANT, Governance.OWNED,
         "days 31-89 matched no status in the source model"),
        (_f(silent_vdays=147), Lifecycle.ZOMBIE, Governance.OWNED, "silent past the window"),
        (_f(silent_vdays=200, has_reachable_owner=True), Lifecycle.ZOMBIE, Governance.OWNED,
         "a 200-day-silent endpoint WITH an owner is still a zombie"),
        (_f(silent_vdays=147, has_reachable_owner=False), Lifecycle.ZOMBIE, Governance.ORPHANED,
         "ownership modifies severity, not status"),
        (_f(silent_vdays=None), Lifecycle.ACTIVE, Governance.OWNED,
         "never called is unreleased, not dead"),
        (_f(silent_vdays=5, deprecated=True), Lifecycle.DEPRECATED, Governance.OWNED,
         "deprecated outranks the day count"),
        (_f(silent_vdays=5, in_gateway=False, in_code=False, has_reachable_owner=False),
         Lifecycle.ACTIVE, Governance.SHADOW, "traffic, no registry, no code"),
        (_f(silent_vdays=147, in_gateway=False, in_code=False, has_reachable_owner=False),
         Lifecycle.ZOMBIE, Governance.SHADOW, "the classic finding"),
        (_f(silent_vdays=5, in_gateway=False, in_code=True, has_reachable_owner=False),
         Lifecycle.ACTIVE, Governance.ORPHANED, "in code but unregistered is not shadow"),
    ],
)
def test_classification_truth_table(facts, expect_life, expect_gov, note):
    v = classification.classify(facts, observed_vdays=CONFIRMED)
    assert v is not None
    assert v.lifecycle is expect_life, note
    assert v.governance is expect_gov, note


def test_every_reachable_combination_yields_a_status():
    """Total coverage: no input combination may match zero statuses."""
    seen = 0
    for silent in (None, 0, 30, 31, 89, 90, 200):
        for gw in (True, False):
            for owner in (True, False):
                for dep in (True, False):
                    for code in (True, False):
                        v = classification.classify(
                            _f(silent_vdays=silent, in_gateway=gw, has_reachable_owner=owner,
                               deprecated=dep, in_code=code),
                            observed_vdays=CONFIRMED,
                        )
                        assert v is not None
                        assert isinstance(v.lifecycle, Lifecycle)
                        assert isinstance(v.governance, Governance)
                        seen += 1
    assert seen == 7 * 2 * 2 * 2 * 2


def test_shadow_is_withheld_when_the_gateway_collector_is_unhealthy():
    """Absence from a registry we could not read is not evidence."""
    facts = _f(silent_vdays=5, in_gateway=False, in_code=False,
               has_reachable_owner=False, shadow_reliable=False)
    v = classification.classify(facts, observed_vdays=CONFIRMED)
    assert v.governance is Governance.ORPHANED
    assert v.governance is not Governance.SHADOW


def test_no_verdict_below_baseline_confidence():
    assert classification.classify(_f(silent_vdays=5), observed_vdays=30) is None
    assert classification.classify(_f(silent_vdays=5), observed_vdays=31) is not None


def test_confidence_ramp_boundaries():
    assert baseline.confidence(30, 0) is Confidence.NONE
    assert baseline.confidence(31, 0) is Confidence.PROVISIONAL
    assert baseline.confidence(89, 0) is Confidence.PROVISIONAL
    assert baseline.confidence(90, 0) is Confidence.CONFIRMED


def test_backfill_advances_confidence():
    """Historical gateway logs are the difference between a 90-day pilot and a
    same-week result."""
    assert baseline.confidence(vday=10, first_vday=0) is Confidence.NONE
    assert baseline.confidence(vday=10, first_vday=0, backfilled_vdays=100) is Confidence.CONFIRMED


def test_severity_bump_on_low_confidence_ownership():
    v = classification.classify(_f(silent_vdays=5, owner_confidence=0.4), CONFIRMED)
    assert v.severity_bump is True


def test_trace_replays_to_the_stored_verdict():
    """An examiner must be able to re-run a recorded decision by hand."""
    for silent in (None, 5, 45, 147):
        for gw in (True, False):
            for code in (True, False):
                facts = _f(silent_vdays=silent, in_gateway=gw, in_code=code,
                           has_reachable_owner=False)
                v = classification.classify(facts, CONFIRMED)
                life, gov = classification.replay(v.trace)
                assert (life, gov) == (v.lifecycle.value, v.governance.value)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 03 — path normalisation
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/api/v1/accounts/8814/balance", "/api/v1/accounts/{id}/balance"),
        ("/api/v1/accounts/{id}/balance", "/api/v1/accounts/{id}/balance"),
        ("/api/v1/accounts/<int:id>/balance", "/api/v1/accounts/{id}/balance"),
        ("/api/v1/accounts/:id/balance", "/api/v1/accounts/{id}/balance"),
        ("/api/v1/txn/3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "/api/v1/txn/{id}"),
        ("/api/v1/blob/9a3f2b1c8d4e5f60a1b2", "/api/v1/blob/{id}"),
        ("/api/v1/report/2026-07-27", "/api/v1/report/{id}"),
        ("/api/v1/balance?acct=1", "/api/v1/balance"),
        ("/api//v1///balance/", "/api/v1/balance"),
        ("/API/V1/Balance", "/api/v1/balance"),
        ("/", "/"),
        ("", "/"),
    ],
)
def test_path_normalisation(raw, expected):
    assert correlation.normalise_path(raw) == expected


def test_soap_action_is_identity_not_a_fragment():
    a = correlation.normalise_path("/services/Finacle#GetBalance")
    b = correlation.normalise_path("/services/Finacle#PostTransfer")
    assert a != b
    assert a.endswith("#GetBalance")


def test_deep_paths_truncate_visibly():
    deep = "/" + "/".join(f"s{i}" for i in range(12))
    out = correlation.normalise_path(deep)
    assert out.endswith("/**")


def test_identity_is_stable_and_order_insensitive():
    a = correlation.endpoint_id("GET", "/api/v1/x", "svc_1")
    b = correlation.endpoint_id("get", "/api/v1/x", "svc_1")
    assert a == b
    assert a != correlation.endpoint_id("POST", "/api/v1/x", "svc_1")
    assert a != correlation.endpoint_id("GET", "/api/v1/x", "svc_2")


def test_same_path_on_two_services_is_two_endpoints():
    assert correlation.endpoint_id("GET", "/health", "svc_a") != \
           correlation.endpoint_id("GET", "/health", "svc_b")


def test_over_collapse_guard():
    many = {f"/{i}/{j}" for i in range(300) for j in range(2)}
    assert correlation.should_split("/{id}/{id}", many, {"schemaA", "schemaB"}, 200) is True
    assert correlation.should_split("/{id}/{id}", many, {"schemaA"}, 200) is False


# ─────────────────────────────────────────────────────────────────────────────
# Stage 03 — ownership ladder
# ─────────────────────────────────────────────────────────────────────────────
def _hr(employed=True, successor=None, head="head@bank.example"):
    def lookup(email):
        return {"employed": employed, "successor": successor, "department_head": head}
    return lookup


def test_codeowners_is_authoritative():
    o = correlation.resolve_ownership(
        {"email": "team@bank.example", "team": "Core"}, None, None, _hr())
    assert o.resolved_by == "codeowners"
    assert o.confidence == 1.0
    assert o.reachable is True


def test_falls_through_to_git_blame():
    o = correlation.resolve_ownership(None, {"email": "dev@bank.example"}, None, _hr())
    assert o.resolved_by == "git-blame"
    assert o.confidence == 0.75


def test_departed_owner_is_not_the_same_as_no_owner():
    """Routes to a department head rather than an inbox nobody reads."""
    o = correlation.resolve_ownership(
        None, {"email": "gone@bank.example"}, None, _hr(employed=False))
    assert o.reachable is False
    assert o.escalation == "head@bank.example"
    assert o.owner_email == "gone@bank.example"
    assert o.confidence == pytest.approx(0.375)


def test_successor_lookup_applies_a_discount():
    o = correlation.resolve_ownership(
        None, {"email": "gone@bank.example"}, None,
        _hr(employed=False, successor="new@bank.example"))
    assert o.owner_email == "new@bank.example"
    assert o.reachable is True
    assert o.confidence == pytest.approx(0.6)


def test_unresolved_records_every_rung_attempted():
    o = correlation.resolve_ownership(None, None, None, _hr(), department_head="dh@bank.example")
    assert o.resolved_by == "unresolved"
    assert o.confidence == 0.0
    assert o.escalation == "dh@bank.example"
    assert len(o.ladder) >= 4


def test_hr_unavailable_does_not_inflate_confidence():
    o = correlation.resolve_ownership(
        None, {"email": "dev@bank.example"}, None, lambda e: None)
    assert o.confidence == 0.75
    assert any(r["result"] == "unavailable" for r in o.ladder)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 08 — regulatory mapping
# ─────────────────────────────────────────────────────────────────────────────
def test_seven_frameworks_are_all_reachable():
    contexts = [
        {"auth": "none", "tls_version": "1.0", "lifecycle": "ZOMBIE", "governance": "SHADOW",
         "data_classes": ["AADHAAR", "CARD", "CVV"], "rate_limited": False,
         "internet_reachable": True, "blast_tier": "CRITICAL", "generator": "anthropic"},
    ]
    cited = {c["framework"] for c in frameworks.map_findings(contexts[0])}
    assert cited == set(frameworks.FRAMEWORKS), f"unreachable: {set(frameworks.FRAMEWORKS) - cited}"


def test_ffiec_cited_for_orphaned_and_shadow():
    for gov in ("ORPHANED", "SHADOW"):
        ctx = {"auth": "oauth2", "tls_version": "1.3", "lifecycle": "ACTIVE",
               "governance": gov, "data_classes": [], "rate_limited": True,
               "internet_reachable": False, "blast_tier": "LOW", "generator": "template"}
        assert any(c["framework"] == "FFIEC DA&M" for c in frameworks.map_findings(ctx))


def test_clean_endpoint_cites_no_violations():
    ctx = {"auth": "oauth2", "tls_version": "1.3", "lifecycle": "ACTIVE",
           "governance": "OWNED", "data_classes": [], "rate_limited": True,
           "internet_reachable": False, "blast_tier": "ZERO", "generator": "template"}
    violated = [c for c in frameworks.map_findings(ctx) if c["status"] == "VIOLATED"]
    assert violated == []


def test_every_citation_names_its_evidence():
    ctx = {"auth": "none", "tls_version": "1.0", "lifecycle": "ZOMBIE", "governance": "SHADOW",
           "data_classes": ["PAN"], "rate_limited": False, "internet_reachable": True,
           "blast_tier": "CRITICAL", "generator": "anthropic"}
    for c in frameworks.map_findings(ctx):
        assert c["evidence"], f"{c['framework']} {c['clause']} cited without evidence"


# ─────────────────────────────────────────────────────────────────────────────
# Stage 05 — behaviour
# ─────────────────────────────────────────────────────────────────────────────
def test_auth_sequence_never_fires_on_an_endpoint_with_no_auth():
    """CDRI already charges 0.28 for missing auth. Flagging it again here would
    double-count the same defect."""
    s = behaviour.Series("ep", calls=[100] * 30, resp_bytes=[200] * 30, err_calls=[0] * 30,
                         auth_missing=[100] * 30, hour_histogram=[4] * 24,
                         peer_counts=[10, 10], auth="none")
    feats = behaviour.extract(s)
    assert "AUTH_SEQUENCE" not in behaviour.patterns_for(s, feats)

    s.auth = "oauth2"
    assert "AUTH_SEQUENCE" in behaviour.patterns_for(s, feats)


def test_zombie_traffic_spike_requires_both_silence_and_volume():
    quiet = [0] * 70 + [0] * 7
    spike = [0] * 70 + [60] * 7
    trickle = [0] * 70 + [1] * 7
    for calls, expect in ((spike, True), (trickle, False), (quiet, False)):
        s = behaviour.Series("ep", calls=calls, resp_bytes=[100] * len(calls),
                             err_calls=[0] * len(calls), auth_missing=[0] * len(calls),
                             hour_histogram=[1] * 24, peer_counts=[5], auth="oauth2")
        got = "ZOMBIE_TRAFFIC_SPIKE" in behaviour.patterns_for(s, behaviour.extract(s))
        assert got is expect


def test_insufficient_history_is_reported_not_scored():
    short = [behaviour.Series(f"ep{i}", [1] * 5, [100] * 5, [0] * 5, [0] * 5,
                              [1] * 24, [1], "oauth2") for i in range(5)]
    rep = behaviour.run(short)
    assert rep.excluded_insufficient_history == 5
    assert all("INSUFFICIENT_HISTORY" in r.patterns for r in rep.results)
    assert all(r.flag is False for r in rep.results)


def test_forest_not_fitted_below_minimum_population_and_says_so():
    """A forest on twelve points is noise, and the report says so rather than
    presenting one."""
    few = [behaviour.Series(f"ep{i}", [10] * 30, [100] * 30, [0] * 30, [0] * 30,
                            [1] * 24, [3], "oauth2") for i in range(5)]
    rep = behaviour.run(few)
    assert rep.fitted is False
    assert rep.fitted_on == 0


def test_identical_inputs_produce_identical_scores():
    def estate():
        out = []
        for i in range(40):
            out.append(behaviour.Series(
                f"ep{i}", calls=[10 + i] * 30, resp_bytes=[200 + i * 3] * 30,
                err_calls=[i % 3] * 30, auth_missing=[0] * 30,
                hour_histogram=[(i + h) % 5 for h in range(24)],
                peer_counts=[5, 3, 1], auth="oauth2"))
        return out

    a = {r.endpoint_id: r.score for r in behaviour.run(estate()).results}
    b = {r.endpoint_id: r.score for r in behaviour.run(estate()).results}
    assert a == b, "a disputed verdict must be reproducible a week later"


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline DAG
# ─────────────────────────────────────────────────────────────────────────────
def test_behaviour_precedes_cdri():
    """CDRI consumes r6. A pipeline where it ran first would read an input from
    its own future."""
    order = pipeline.topological_order()
    assert order.index(5) < order.index(6)


def test_forecast_depends_on_classification():
    assert 4 in pipeline.STAGE_DEPS[7]


def test_findings_runs_after_score_projection_and_impact():
    order = pipeline.topological_order()
    for dep in (6, 7, 9):
        assert order.index(dep) < order.index(8)


def test_unsatisfied_dependency_raises():
    with pytest.raises(pipeline.StageDependencyError) as e:
        pipeline.check_dependencies(6, completed={1, 2, 3, 4})
    assert e.value.missing == [5]


def test_order_is_deterministic():
    assert pipeline.topological_order() == pipeline.topological_order()


# ─────────────────────────────────────────────────────────────────────────────
# Stage 02 — rollup
# ─────────────────────────────────────────────────────────────────────────────
def test_zero_days_are_materialised_contiguously():
    rows = {5: baseline.DailyRow("ep", 5, 10, 1, 0, None, None, None, 0, [0] * 24)}
    out = baseline.materialise_zero_days(rows, "ep", first_vday=0, current_vday=9)
    assert [r.vday for r in out] == list(range(10))
    assert sum(r.calls for r in out) == 10
    assert len(baseline.series_of(out)) == 10


def test_last_call_vday_is_none_for_a_never_called_endpoint():
    rows = [baseline.DailyRow("ep", v, 0, 0, 0, None, None, None, 0, [0] * 24) for v in range(10)]
    assert baseline.last_call_vday(rows) is None


def test_correlation_precedes_baseline():
    """The rollup aggregates by endpoint, and correlation is what assigns
    endpoint identity. Reversed, the rollup sees zero rows and every stage after
    it has no series — a silent, total failure rather than an error."""
    order = pipeline.topological_order()
    assert order.index(3) < order.index(2)


def test_classification_sees_both_identity_and_history():
    order = pipeline.topological_order()
    for dep in (2, 3):
        assert order.index(dep) < order.index(4)


# ─────────────────────────────────────────────────────────────────────────────
# Path normalisation: references
# ─────────────────────────────────────────────────────────────────────────────
def test_a_payment_reference_collapses_to_a_parameter():
    """Real references mix letters and digits and match none of the id patterns.

    Left as literals, every transaction produces its own endpoint row: an
    inventory that grows without bound and in which nothing ever accumulates
    enough history to be classified.
    """
    from sentry_worker.engines.correlation import normalise_path

    assert normalise_path("/api/v1/payments/upi/UPI7781XK92") == "/api/v1/payments/upi/{id}"
    assert normalise_path("/api/v1/settlement/rtgs/RTGS20260729A1") == \
        "/api/v1/settlement/rtgs/{id}"


def test_api_vocabulary_is_not_mistaken_for_a_reference():
    """Over-collapsing merges genuinely distinct endpoints, which is the worse
    error: it hides one behind another."""
    from sentry_worker.engines.correlation import normalise_path

    for path in (
        "/api/v1/accounts",
        "/api/v2beta/accounts",
        "/api/v3alpha1/accounts",
        "/base64/decode",
        "/oauth2/token",
        "/api/v1/legacy-balance",
        "/api/v1/settlement/rtgs",
    ):
        assert "{id}" not in normalise_path(path), path


# ─────────────────────────────────────────────────────────────────────────────
# The DAG itself
# ─────────────────────────────────────────────────────────────────────────────
def test_the_dependency_graph_has_no_duplicate_declarations():
    """A Python dict literal silently keeps the last of two identical keys.

    Adding `13: frozenset({6, 10})` above an existing `13: frozenset({6})`
    discarded the new dependency without a word, and stage 13 kept being
    ordered before the stage whose output it assesses. Parsing the source is
    the only way to see it — by the time the dict exists the duplicate is gone.
    """
    import ast
    import inspect
    import re

    from sentry_worker import pipeline

    source = inspect.getsource(pipeline)
    match = re.search(r"STAGE_DEPS:.*?=\s*(\{.*?\n\})", source, re.S)
    assert match, "STAGE_DEPS literal not found"

    keys = [ast.literal_eval(k) for k in
            ast.parse(match.group(1), mode="eval").body.keys]
    assert len(keys) == len(set(keys)), \
        f"duplicate stage keys in STAGE_DEPS: {sorted(k for k in keys if keys.count(k) > 1)}"


def test_every_declared_dependency_is_a_real_stage():
    from sentry_worker import pipeline

    known = set(pipeline.STAGE_DEPS)
    for stage, deps in pipeline.STAGE_DEPS.items():
        unknown = deps - known
        assert not unknown, f"stage {stage} depends on undeclared stage(s) {unknown}"


def test_zero_trust_is_ordered_after_the_controls_it_assesses():
    """Posture is measured against what is applied. Assessing before stage 10
    runs reports the estate as unhardened whatever stage 10 just did."""
    from sentry_worker import pipeline

    order = pipeline.topological_order()
    assert order.index(13) > order.index(10)
    assert order.index(13) > order.index(6)
