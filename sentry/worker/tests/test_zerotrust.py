"""Stage 13 — what counts as a control being in place, and what order to close
the gaps in.

The assessment is the part that can lie. It reads what is applied at the
gateway, and the difference between "applied" and "proposed" is the difference
between an endpoint that is protected and one that has a plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from sentry_core.enums import Auth, Criticality
from sentry_worker.engines import zerotrust


@dataclass
class FakeEndpoint:
    id: str = "ep_test"
    auth: Auth = Auth.NONE
    tls_version: str | None = "1.2"
    rate_limited: bool = False
    data_classes: list = field(default_factory=lambda: ["AADHAAR", "IFSC"])


def posture(applied=(), **kw):
    crit = kw.pop("criticality", Criticality.CUSTOMER)
    return zerotrust.assess(FakeEndpoint(**kw), crit, set(applied))


# ─────────────────────────────────────────────────────────────────────────────
# The five controls
# ─────────────────────────────────────────────────────────────────────────────
def test_a_bare_endpoint_satisfies_nothing():
    p = posture()
    assert p.satisfied == 0
    assert p.of == 5
    assert {c.key for c in p.gaps} == {"auth", "tls", "binding", "ratelimit", "response"}


def test_a_fully_hardened_endpoint_satisfies_everything():
    p = posture(auth=Auth.MTLS, tls_version="1.3", rate_limited=True, data_classes=[])
    assert p.satisfied == 5
    assert p.gaps == []


def test_the_score_is_a_count_not_a_percentage():
    """An operator acts on 'two of five controls missing'. Nobody has ever acted
    on '40%'."""
    p = posture(rate_limited=True, tls_version="1.3")
    assert (p.satisfied, p.of) == (2, 5)
    assert p.as_dict()["satisfied"] == 2 and p.as_dict()["of"] == 5


@pytest.mark.parametrize("auth,ok", [
    (Auth.NONE, False), (Auth.BASIC, False), (Auth.APIKEY, False),
    (Auth.BEARER, False), (Auth.OAUTH2, True), (Auth.MTLS, True),
])
def test_only_strong_authentication_satisfies_control_one(auth, ok):
    """A bearer token is authentication and it is not strong authentication.
    Counting it would report an endpoint as protected against the attack the
    control exists to prevent."""
    p = posture(auth=auth)
    assert next(c for c in p.controls if c.key == "auth").ok is ok


def test_mtls_satisfies_binding_without_a_separate_control():
    """A client certificate binds the channel to the key that holds it. There is
    nothing left for DPoP to add."""
    p = posture(auth=Auth.MTLS)
    assert next(c for c in p.controls if c.key == "binding").ok


def test_only_sensitive_classes_trigger_the_response_control():
    """IFSC is a bank branch code, not a customer identifier. Flagging it would
    put every endpoint in the estate on the gap list and make the list useless."""
    assert next(c for c in posture(data_classes=["IFSC"]).controls
                if c.key == "response").ok
    assert not next(c for c in posture(data_classes=["AADHAAR"]).controls
                    if c.key == "response").ok


# ─────────────────────────────────────────────────────────────────────────────
# Applied, not proposed
# ─────────────────────────────────────────────────────────────────────────────
def test_an_applied_control_satisfies_its_gap():
    p = posture(applied={"rate-limit", "tls-min", "response-mask", "dpop"})
    assert {c.key for c in p.gaps} == {"auth"}


def test_a_sunset_throttle_counts_as_rate_limiting():
    """Stage 11 applies one on the retirement path. It is a rate limit; the
    assessment should not ask for a second."""
    assert next(c for c in posture(applied={"sunset-throttle"}).controls
                if c.key == "ratelimit").ok


def test_the_caller_is_responsible_for_passing_applied_controls_only():
    """The engine is handed the applied set. This is the contract the runner and
    the API both honour — counting a PROPOSED control would report an endpoint
    as protected by configuration that is not on the gateway."""
    p = posture(applied={"dpop"})
    binding = next(c for c in p.controls if c.key == "binding")
    assert binding.ok and binding.current == ["dpop"]


# ─────────────────────────────────────────────────────────────────────────────
# Remedies
# ─────────────────────────────────────────────────────────────────────────────
def test_settlement_paths_are_remedied_with_mtls():
    p = posture(criticality=Criticality.SETTLEMENT)
    assert next(c for c in p.controls if c.key == "auth").remedy == "mtls"


@pytest.mark.parametrize("criticality", [
    Criticality.CUSTOMER, Criticality.PAYMENT, Criticality.REGULATORY,
    Criticality.INTERNAL,
])
def test_everything_else_is_remedied_with_oauth(criticality):
    """Recommending mTLS estate-wide generates a certificate-distribution
    programme nobody will run, and a recommendation nobody executes is worth
    nothing."""
    p = posture(criticality=criticality)
    assert next(c for c in p.controls if c.key == "auth").remedy == "oauth2"


def test_breaking_remedies_are_flagged_as_needing_migration():
    p = posture()
    by_key = {c.key: c for c in p.controls}
    assert by_key["auth"].requires_migration
    assert by_key["binding"].requires_migration
    # These break nobody who was already inside policy.
    assert not by_key["ratelimit"].requires_migration
    assert not by_key["tls"].requires_migration


# ─────────────────────────────────────────────────────────────────────────────
# Ordering
# ─────────────────────────────────────────────────────────────────────────────
def test_hardening_closes_the_harmless_gaps_first():
    """A run that fails partway must leave the endpoint better off than it
    started. Authentication is fourth because applying it turns every
    unprovisioned caller into a 401; binding is last because it means nothing
    before authentication exists.
    """
    assert [c.key for c in zerotrust.plan(posture())] == \
        ["ratelimit", "tls", "response", "auth", "binding"]


def test_the_plan_contains_only_gaps():
    p = posture(rate_limited=True, tls_version="1.3")
    assert [c.key for c in zerotrust.plan(p)] == ["response", "auth", "binding"]


def test_a_satisfied_endpoint_has_an_empty_plan():
    p = posture(auth=Auth.MTLS, tls_version="1.3", rate_limited=True, data_classes=[])
    assert zerotrust.plan(p) == []


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────
def test_partial_hardening_is_reported_as_partial():
    """Three of five applied is stated as three of five. Rounding it up to
    'hardened' puts an endpoint on a compliance report as protected by two
    controls that are not there."""
    before = posture()
    after = posture(applied={"rate-limit", "tls-min", "response-mask"})
    summary = zerotrust.summarise(
        [{"control": "ratelimit", "state": "APPLIED"},
         {"control": "tls", "state": "APPLIED"},
         {"control": "response", "state": "APPLIED"},
         {"control": "auth", "state": "REJECTED"},
         {"control": "binding", "state": "UNMEASURED"}],
        before, after)

    assert summary["applied"] == 3
    assert summary["attempted"] == 5
    assert summary["posture_before"] == "0/5"
    assert summary["posture_after"] == "3/5"
    assert summary["complete"] is False


def test_complete_hardening_says_so():
    before = posture()
    after = posture(auth=Auth.MTLS, tls_version="1.3", rate_limited=True,
                    data_classes=[])
    summary = zerotrust.summarise([{"control": "x", "state": "APPLIED"}], before, after)
    assert summary["complete"] is True


@pytest.mark.parametrize("criticality", [
    Criticality.PAYMENT, Criticality.SETTLEMENT, Criticality.REGULATORY,
])
def test_throttle_exempt_classes_are_offered_no_rate_limit_remedy(criticality):
    """The exemption belongs to the endpoint, not to the stage proposing the
    control. Stage 10 refuses to throttle these; offering the same remedy from
    the posture screen would let an operator apply exactly what the remediation
    queue declined.
    """
    p = posture(criticality=criticality)
    ratelimit = next(c for c in p.controls if c.key == "ratelimit")

    assert ratelimit.ok is False           # still a real gap
    assert ratelimit.remedy is None        # with nothing this system will do about it
    assert "ratelimit" not in [c.key for c in zerotrust.plan(p)]


def test_an_unremediable_gap_still_counts_against_the_score():
    """Dropping it from the assessment would hide a real weakness behind a
    better-looking number."""
    p = posture(criticality=Criticality.SETTLEMENT)
    assert p.satisfied == 0
    assert "ratelimit" in {c.key for c in p.gaps}
