"""Stage 11 — what may be retired, by which path, and on whose authority.

Every assertion here is about refusing to act rather than about acting. That is
the shape of the stage: the end of the workflow is a 410 and a WORM object, and
neither is reversible, so the interesting behaviour is all in the guards.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from sentry_core.enums import (
    BlastTier,
    Confidence,
    Criticality,
    Lifecycle,
    Phase,
)
from sentry_worker.engines import decommission


@dataclass
class FakeEndpoint:
    id: str = "ep_zombie"
    method: str = "GET"
    path_template: str = "/api/v1/legacy-balance"
    retired: bool = False
    deprecated: bool = False


@dataclass
class FakeClassification:
    lifecycle: Lifecycle = Lifecycle.ZOMBIE
    confidence: Confidence = Confidence.CONFIRMED


@dataclass
class FakeBlast:
    tier: BlastTier = BlastTier.ZERO
    in_graph: bool = True
    touches_critical: bool = False
    direct_callers: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Eligibility
# ─────────────────────────────────────────────────────────────────────────────
def test_a_confirmed_zombie_with_impact_analysis_is_eligible():
    decommission.eligible(FakeEndpoint(), FakeClassification(), FakeBlast())


def test_a_provisional_verdict_cannot_enter_the_workflow():
    """The confidence ramp having a consequence is the point.

    PROVISIONAL is the system saying it has fewer than ninety vdays of
    observation. An endpoint cannot start down a path that ends in a 410 on
    evidence the system itself describes as incomplete.
    """
    with pytest.raises(decommission.NotEligible) as exc:
        decommission.eligible(
            FakeEndpoint(), FakeClassification(confidence=Confidence.PROVISIONAL),
            FakeBlast())
    assert exc.value.code == "PROVISIONAL_VERDICT"


def test_an_active_endpoint_cannot_be_retired():
    with pytest.raises(decommission.NotEligible) as exc:
        decommission.eligible(
            FakeEndpoint(), FakeClassification(lifecycle=Lifecycle.ACTIVE), FakeBlast())
    assert exc.value.code == "NOT_ELIGIBLE"


def test_a_formally_deprecated_endpoint_is_eligible_without_being_a_zombie():
    """Work already in progress is not restarted from the beginning."""
    decommission.eligible(
        FakeEndpoint(deprecated=True),
        FakeClassification(lifecycle=Lifecycle.DEPRECATED), FakeBlast())


def test_retirement_without_impact_analysis_is_refused():
    with pytest.raises(decommission.NotEligible) as exc:
        decommission.eligible(FakeEndpoint(), FakeClassification(), None)
    assert exc.value.code == "NO_IMPACT_ANALYSIS"


def test_an_already_retired_endpoint_is_refused():
    with pytest.raises(decommission.NotEligible) as exc:
        decommission.eligible(FakeEndpoint(retired=True), FakeClassification(), FakeBlast())
    assert exc.value.code == "ALREADY_RETIRED"


# ─────────────────────────────────────────────────────────────────────────────
# Path selection
# ─────────────────────────────────────────────────────────────────────────────
def test_zero_blast_present_in_the_graph_takes_the_express_path():
    path = decommission.select_path(FakeBlast(tier=BlastTier.ZERO, in_graph=True))
    assert path.express and path.name == "express"
    assert path.phases == [Phase.B, Phase.C, Phase.D]


def test_an_endpoint_never_seen_in_the_graph_is_not_express():
    """Absence of data is not absence of dependants.

    An endpoint the graph never contained has not been shown to have zero
    callers; it has merely never been looked at. Treating the two as the same
    evidence is how a decommission becomes an incident.
    """
    path = decommission.select_path(FakeBlast(tier=BlastTier.ZERO, in_graph=False))
    assert not path.express
    assert path.phases[0] is Phase.A


def test_express_still_serves_the_full_quarantine():
    """Ninety days of silence cannot rule out an annual job. Express skips the
    throttle, never the watch."""
    path = decommission.select_path(FakeBlast(tier=BlastTier.ZERO, in_graph=True))
    assert Phase.C in path.phases


def test_a_critical_blast_radius_takes_the_canary_path_and_never_express():
    path = decommission.select_path(
        FakeBlast(tier=BlastTier.ZERO, in_graph=True, touches_critical=True))
    assert path.canary and not path.express
    assert path.name == "canary"


@pytest.mark.parametrize("criticality", [
    Criticality.PAYMENT, Criticality.SETTLEMENT, Criticality.REGULATORY,
])
def test_payment_paths_are_exempt_from_throttling(criticality):
    """Deliberately degrading a payment path to encourage migration is itself
    the incident it is trying to prevent."""
    assert decommission.criticality_is_exempt(criticality)


def test_ordinary_paths_are_not_exempt():
    assert not decommission.criticality_is_exempt(Criticality.CUSTOMER)
    assert not decommission.criticality_is_exempt(Criticality.INTERNAL)


# ─────────────────────────────────────────────────────────────────────────────
# Advancement
# ─────────────────────────────────────────────────────────────────────────────
def test_phases_advance_in_order():
    path = decommission.Path(express=False, canary=False)
    assert decommission.next_phase(Phase.NONE, path) is Phase.A
    assert decommission.next_phase(Phase.A, path) is Phase.B
    assert decommission.next_phase(Phase.B, path) is Phase.C
    assert decommission.next_phase(Phase.C, path) is Phase.D
    assert decommission.next_phase(Phase.D, path) is None


def test_nothing_advances_into_phase_d_on_a_timer():
    """Archival and a 410 are irreversible in effect.

    Automating the last transition would let the system retire an endpoint with
    the hidden callers its own quarantine found sitting unread.
    """
    assert decommission.may_auto_advance(Phase.B)
    assert decommission.may_auto_advance(Phase.C)
    assert not decommission.may_auto_advance(Phase.D)


def test_a_phase_is_not_due_before_its_length_has_elapsed():
    assert not decommission.due(current_vday=100, phase_vday=100, phase=Phase.A)
    assert not decommission.due(current_vday=129, phase_vday=100, phase=Phase.A)
    assert decommission.due(current_vday=130, phase_vday=100, phase=Phase.A)


def test_a_decommission_with_no_phase_clock_is_never_due():
    assert not decommission.due(current_vday=500, phase_vday=None, phase=Phase.A)


# ─────────────────────────────────────────────────────────────────────────────
# Phase A throttle
# ─────────────────────────────────────────────────────────────────────────────
def test_the_throttle_is_sized_from_observed_peak():
    """Felt by a caller that is still there, invisible to one that is not."""
    # 288000 calls/vday at 25% = 72000/vday = 50/minute.
    assert decommission.throttle_limit(288_000) == 50


def test_a_silent_endpoint_still_gets_a_usable_floor():
    """A zombie has near-zero traffic by definition, so the derived limit rounds
    to nothing. A limit of zero is a 410 by another name, three phases early."""
    assert decommission.throttle_limit(0) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Phase B sunset header
# ─────────────────────────────────────────────────────────────────────────────
def test_the_sunset_date_is_computed_through_the_virtual_clock():
    """RFC 8594 is machine-parseable, so client tooling acts on it — but only if
    the date is real. A compressed timeline must produce a correspondingly near
    date, not a fiction ninety calendar days out."""
    epoch = datetime(2026, 7, 1, tzinfo=timezone.utc)
    path = decommission.Path(express=False, canary=False)

    fast = decommission.sunset_at(0, path, Phase.B, epoch, scale_seconds=20)
    slow = decommission.sunset_at(0, path, Phase.B, epoch, scale_seconds=86400)

    assert fast < slow
    # B + C remaining = 60 vdays; at 20s each that is 20 minutes.
    assert (fast - epoch).total_seconds() == pytest.approx(60 * 20)


def test_the_sunset_header_is_imf_fixdate_not_isoformat():
    """RFC 8594 requires an HTTP-date. A client parsing an ISO string gets
    nothing, which makes the header decorative."""
    when = datetime(2026, 10, 21, 7, 28, 0, tzinfo=timezone.utc)
    assert decommission.rfc8594(when) == "Wed, 21 Oct 2026 07:28:00 GMT"


# ─────────────────────────────────────────────────────────────────────────────
# Canary
# ─────────────────────────────────────────────────────────────────────────────
def test_the_canary_walks_its_steps_down_to_zero():
    assert decommission.next_canary_split(None) == 0.10
    assert decommission.next_canary_split(0.10) == 0.01
    assert decommission.next_canary_split(0.01) == 0.00
    assert decommission.next_canary_split(0.00) is None


def test_the_canary_reverts_on_an_absolute_error_rise():
    """A ratio makes an endpoint with a 0.1% baseline trip on noise and one with
    a 5% baseline never trip at all."""
    assert decommission.canary_should_revert(baseline_error_rate=0.001,
                                             observed_error_rate=0.05)
    assert not decommission.canary_should_revert(baseline_error_rate=0.05,
                                                 observed_error_rate=0.06)


# ─────────────────────────────────────────────────────────────────────────────
# The certificate
# ─────────────────────────────────────────────────────────────────────────────
def test_the_certificate_carries_the_evidence_not_a_summary():
    """A certificate asserting a clean retirement is worth exactly as much as
    the evidence behind it."""
    evidence = decommission.Evidence(
        silent_vdays=147, confidence="CONFIRMED",
        blast={"tier": "ZERO", "direct_callers": 0, "in_graph": True},
        hidden_callers_found=1,
        phases=[{"phase": "C", "entered_vday": 222}],
        cdri_at_retirement=0.93,
        worm_object="s3://sentry-worm/decommission/ep_x/237.json.gz",
        worm_retain_until="2033-07-27T00:00:00Z",
        honeypot_activated=True,
        honeypot_legal_signoff="policy:LEGAL-2026-004",
    )
    body = decommission.certificate_body(FakeEndpoint(), "core-accounts", 237, evidence)

    assert body["retired_vday"] == 237
    ev = body["evidence"]
    assert ev["worm_object"].startswith("s3://")
    assert ev["worm_retain_until"]
    assert ev["hidden_callers_found"] == 1
    assert ev["blast"]["in_graph"] is True
    assert ev["honeypot_legal_signoff"] == "policy:LEGAL-2026-004"
