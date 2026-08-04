"""Stage 10 — what a control is allowed to be, and what the Judge is allowed to
conclude.

The apply path is exercised against a live Kong elsewhere. These are the
decisions that must hold whether or not a gateway is reachable.
"""

from __future__ import annotations

import pytest

from sentry_core.enums import Auth, Criticality
from sentry_worker.actuators import kong
from sentry_worker.engines import judge_scoring, remediation
from sentry_worker.judge import replay


def facts(**kw) -> remediation.EndpointFacts:
    base = dict(
        endpoint_id="ep_test",
        method="GET",
        path_template="/api/v1/accounts/{id}",
        service_name="core-accounts",
        criticality=Criticality.CUSTOMER,
        auth=Auth.NONE,
        tls_version="1.2",
        data_classes=["AADHAAR", "IFSC"],
        peak_calls_per_vday=4320,
        rate_limited=False,
    )
    base.update(kw)
    return remediation.EndpointFacts(**base)


ALL_FIRED = {"no_auth": 1.0, "data_exposure": 1.0, "weak_tls": 1.0, "no_rate_limit": 1.0}


# ─────────────────────────────────────────────────────────────────────────────
# Generation
# ─────────────────────────────────────────────────────────────────────────────
def test_only_indicators_that_fired_produce_a_control():
    """The plan is derived from the score, not from a checklist applied to
    everything. An endpoint with auth does not get an auth control."""
    plan = remediation.plan_for(
        facts(auth=Auth.OAUTH2, data_classes=[], tls_version="1.3"),
        {"no_rate_limit": 1.0},
    )
    assert [p.kind for p in plan.proposals] == ["rate-limit"]


def test_a_rate_limit_is_sized_from_observed_throughput():
    """A limit pulled from a constant either throttles the estate's own traffic
    or is too loose to bound an attack. This one comes from the endpoint's own
    peak."""
    plan = remediation.plan_for(facts(peak_calls_per_vday=288_000), {"no_rate_limit": 1.0})
    config = plan.proposals[0].plugin_config

    assert config["name"] == "rate-limiting"
    # 288000/day * 1.5 headroom / 1440 minutes = 300/min.
    assert config["config"]["minute"] == pytest.approx(300, abs=2)


def test_a_quiet_endpoint_gets_the_floor_not_a_derived_outage():
    """Three requests a minute derived from a quiet endpoint is a self-inflicted
    outage waiting for the first spike."""
    plan = remediation.plan_for(facts(peak_calls_per_vday=40), {"no_rate_limit": 1.0})
    assert plan.proposals[0].plugin_config["config"]["minute"] == remediation.RATE_LIMIT_FLOOR


@pytest.mark.parametrize("criticality", [
    Criticality.SETTLEMENT, Criticality.PAYMENT, Criticality.REGULATORY,
])
def test_settlement_and_payment_paths_are_never_throttled(criticality):
    """Rate-limiting a settlement path converts a security finding into a
    payment incident."""
    plan = remediation.plan_for(facts(criticality=criticality), {"no_rate_limit": 1.0})

    assert not plan.proposals
    assert plan.unaddressed[0]["indicator"] == "no_rate_limit"
    assert criticality.value.lower() in plan.unaddressed[0]["reason"].lower()


def test_an_indicator_with_no_gateway_remedy_is_recorded_not_dropped():
    """A scored risk that produced no control must say why. Showing nothing
    reads as 'nothing to do'."""
    plan = remediation.plan_for(facts(), {"zombie": 1.0, "anomaly": 1.0})

    assert not plan.proposals
    assert {u["indicator"] for u in plan.unaddressed} == {"zombie", "anomaly"}
    assert all(u["reason"] for u in plan.unaddressed)


def test_breaking_controls_declare_their_prerequisite_up_front():
    """key-auth turns every existing consumer into a 401 and a response mask
    removes a field somebody may read. Both are correct controls and both are
    outages if applied blind."""
    plan = remediation.plan_for(facts(), ALL_FIRED)
    by_kind = {p.kind: p for p in plan.proposals}

    assert by_kind["key-auth"].prerequisite
    assert by_kind["response-mask"].prerequisite


def test_the_stored_config_is_the_request_body():
    """No transformation between what an approver reviews and what is POSTed —
    a difference there is the one defect an approval process cannot catch."""
    plan = remediation.plan_for(facts(), {"data_exposure": 1.0})
    config = plan.proposals[0].plugin_config

    assert set(config) <= {"name", "config", "tags"}
    assert config["name"] == "response-transformer"
    assert "aadhaar" in config["config"]["remove"]["json"]
    assert "ifsc" in config["config"]["remove"]["json"]


# ─────────────────────────────────────────────────────────────────────────────
# The Judge
# ─────────────────────────────────────────────────────────────────────────────
def test_replay_shapes_are_deduplicated():
    """Replaying one shape four hundred times measures the gateway's cache, not
    the patch."""
    rows = [{"method": "GET", "path_raw": "/api/v1/accounts/8814"}] * 300
    rows += [{"method": "GET", "path_raw": "/api/v1/accounts/9902"}]

    shapes = replay.requests_from_observations(rows, limit=50)
    assert len(shapes) == 2


def test_a_body_bearing_method_is_marked_bodyless():
    """Stage 01 discards payloads in kernel, so there is no body to replay.
    Coverage is reported rather than implied."""
    shapes = replay.requests_from_observations(
        [{"method": "POST", "path_raw": "/api/v1/payments/upi"}], limit=10)
    assert shapes[0].bodyless is True


def test_the_judge_refuses_to_run_on_no_traffic():
    """Zero requests scores as REJECT, and reaching that through an empty replay
    would report 'the patch failed' when the truth is 'nothing tested it'."""
    with pytest.raises(replay.JudgeUnavailable):
        replay.run(endpoint_id="ep_x", upstream_url="https://svc:8443",
                   plugin_config={}, requests=[], criticality="CUSTOMER",
                   proxy_base="http://localhost:8000")


def test_the_judge_refuses_to_run_without_a_proxy():
    with pytest.raises(replay.JudgeUnavailable):
        replay.run(endpoint_id="ep_x", upstream_url="https://svc:8443",
                   plugin_config={},
                   requests=[replay.ReplayRequest("GET", "/x")],
                   criticality="CUSTOMER", proxy_base="")


def test_removing_an_undeclared_response_field_fails_the_schema_floor():
    """A consumer reading a field that disappears breaks, and nobody authorised
    this one going away."""
    scores = judge_scoring.Scores(
        schema=judge_scoring.schema_score(["aadhaar"], []),
        latency=100, error=100, exposure=100,
        latency_delta_us=0, budget_us=50_000, requests=40,
    )
    assert scores.verdict == "REJECT"
    assert "schema" in scores.failing


def test_a_mask_removing_exactly_what_it_declared_passes():
    """The removal is the authorised change.

    Scoring any removal as breaking meant a masking control could never pass:
    removing fields is its entire purpose, so the dimension that exists to catch
    breakage scored 0 precisely when the control worked, and no PAN or Aadhaar
    could ever be masked at the gateway.
    """
    scores = judge_scoring.Scores(
        schema=judge_scoring.schema_score(["aadhaar"], [],
                                          intended_removals=["aadhaar"]),
        latency=100, error=100, exposure=100,
        latency_delta_us=0, budget_us=50_000, requests=40,
    )
    assert scores.verdict == "PASS"


def test_a_mask_removing_more_than_it_declared_still_fails():
    """The distinction is between a control doing what it said and a control
    doing something else."""
    score = judge_scoring.schema_score(
        ["aadhaar", "accountHolder"], [], intended_removals=["aadhaar"])
    assert score == 0


def test_declared_removals_are_read_from_the_plugin_config():
    """Taken from what will actually be applied to the gateway, not from the
    remedy name the engine chose."""
    config = kong.response_mask(["aadhaar", "pan"])
    assert sorted(replay._declared_removals(config)) == ["aadhaar", "pan"]
    assert replay._declared_removals(kong.rate_limit(60)) == []


def test_a_patch_that_changes_nothing_observable_passes():
    """A rate limit above observed throughput is invisible to replayed traffic,
    which is exactly why it is the safe control."""
    scores = judge_scoring.Scores(
        schema=100, latency=judge_scoring.latency_score(1_200, 50_000),
        error=100, exposure=100,
        latency_delta_us=1_200, budget_us=50_000, requests=40,
    )
    assert scores.verdict == "PASS"
    assert not scores.failing


def test_json_key_extraction_reads_structure_not_values():
    body = b'{"accountNumber":"887221571166","ifsc":"HDFC0805208","nested":{"a":1}}'
    keys = replay._json_keys(body)
    assert "accountNumber" in keys and "nested.a" in keys
    assert "887221571166" not in keys


def test_the_variant_response_is_rescanned_for_data_classes():
    """A patch claiming to mask a field is checked against the bytes, not
    against its own configuration."""
    assert "AADHAAR" in replay._classes_in(b'{"aadhaar":"887221571166"}')
    assert "PAN" in replay._classes_in(b'{"pan":"ABCDE1234F"}')
    assert replay._classes_in(b'{"pan":"[REDACTED]"}') == set()


# ─────────────────────────────────────────────────────────────────────────────
# Guards on the Judge's own correctness
# ─────────────────────────────────────────────────────────────────────────────
def test_a_control_half_that_fails_everything_yields_no_verdict(monkeypatch):
    """Two identical failures agree perfectly.

    Kong rebuilds its router asynchronously, so requests issued straight after
    creating the shadow pair are answered ``no Route matched`` — on both halves,
    with identical structure, identical error rates and no data classes. Every
    dimension scored 100 and the patch passed, having never been exercised. A
    patch that passes because nothing was measured is worse than one that fails.
    """
    from sentry_worker.actuators import kong

    pair = replay._Pair(control_service="c", variant_service="v",
                        control_prefix="/c", variant_prefix="/v")
    monkeypatch.setattr(replay, "_build_pair", lambda *a, **k: pair)
    monkeypatch.setattr(replay, "_teardown", lambda p: None)
    monkeypatch.setattr(replay, "_await_pair", lambda *a, **k: None)
    # Stubbed like every other gateway call here. key-auth is deliberately the
    # plugin under test — it is the realistic case — and the Judge now
    # provisions a consumer for it, which is a real Admin API round trip this
    # test has no gateway for. The subject is what happens when both halves
    # answer identically without being exercised, not how the credential is
    # obtained.
    monkeypatch.setattr(replay, "_credential_for", lambda cfg: {"apikey": "test"})
    monkeypatch.setattr(replay, "_send",
                        lambda *a, **k: replay.Exchange(status=404, latency_us=100,
                                                        body=b'{"message":"no Route matched"}'))

    with pytest.raises(replay.JudgeUnavailable, match="never exercised"):
        replay.run(endpoint_id="ep_x", upstream_url="https://svc:8443",
                   plugin_config=kong.key_auth(),
                   requests=[replay.ReplayRequest("GET", "/api/v1/accounts/8814")],
                   criticality="CUSTOMER", proxy_base="http://kong:8000")


def test_a_pair_the_gateway_never_routes_is_reported_not_scored(monkeypatch):
    monkeypatch.setattr(replay, "ROUTER_READY_TIMEOUT_S", 0.2)
    monkeypatch.setattr(replay, "ROUTER_POLL_INTERVAL_S", 0.05)
    monkeypatch.setattr(replay, "_send",
                        lambda *a, **k: replay.Exchange(status=404, latency_us=1, body=b""))

    pair = replay._Pair(control_service="c", variant_service="v",
                        control_prefix="/c", variant_prefix="/v")
    with pytest.raises(replay.JudgeUnavailable, match="did not route"):
        replay._await_pair("http://kong:8000", pair, replay.ReplayRequest("GET", "/x"))


# ─────────────────────────────────────────────────────────────────────────────
# The gateway write and the database commit are not one transaction
# ─────────────────────────────────────────────────────────────────────────────
def test_an_applied_plugin_carries_the_control_that_owns_it():
    """A worker killed between the POST and the commit leaves a plugin
    enforcing policy no control row records. The tag is what makes it
    findable."""
    from sentry_worker.actuators import kong

    body = dict(kong.rate_limit(120))
    body["tags"] = sorted(set(body.get("tags", []))
                          | {kong.OWNED_TAG, f"{kong.CONTROL_TAG_PREFIX}42"})

    assert kong.control_id_of({"tags": body["tags"]}) == 42
    assert kong.OWNED_TAG in body["tags"]


def test_an_untagged_plugin_is_not_ours():
    """Anything an operator put on the gateway by hand must survive a
    reconcile."""
    from sentry_worker.actuators import kong

    assert kong.control_id_of({"tags": ["ops:manual"]}) is None
    assert kong.control_id_of({}) is None
