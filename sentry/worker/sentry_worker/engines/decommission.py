"""Stage 11 — phased decommission.

Four phases, a real gateway change at each, and a WORM archive before anything
goes dark. This module holds the decisions; the runner performs them.

The shape of the workflow is an argument about evidence. Ninety days of silence
is good evidence that nothing calls an endpoint and it is not proof, because a
quarterly reconciliation job is silent for eighty-nine of them. So the endpoint
is not deleted — it is throttled, then labelled, then watched while still fully
working, and only then archived and answered with a 410. Each phase is a chance
for a dependency nobody knew about to announce itself while the cost of being
wrong is still an alert rather than an outage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sentry_core.config import settings
from sentry_core.enums import BlastTier, Confidence, Criticality, Lifecycle, Phase

VERSION = "decommission-1.0.0"


class NotEligible(Exception):
    """Raised with a stable code so the console can explain the refusal."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        super().__init__(detail)


@dataclass(frozen=True)
class Path:
    express: bool
    canary: bool

    @property
    def name(self) -> str:
        if self.canary:
            return "canary"
        return "express" if self.express else "standard"

    @property
    def phases(self) -> list[Phase]:
        # Express skips the throttle, not the quarantine.
        return [Phase.B, Phase.C, Phase.D] if self.express else [Phase.A, Phase.B, Phase.C, Phase.D]


def eligible(ep, cls, blast) -> None:
    """Refuse enrolment unless the evidence supports it. Raises or returns None.

    The confidence ramp having a consequence is the point. A PROVISIONAL verdict
    is the system saying it has fewer than ninety vdays of observation, and an
    endpoint cannot enter a workflow that ends in a 410 on evidence the system
    itself describes as incomplete.
    """
    if ep.retired:
        raise NotEligible("ALREADY_RETIRED", "endpoint is already retired")
    if cls is None:
        raise NotEligible("NO_CLASSIFICATION", "run stage 04 first")
    if cls.confidence is not Confidence.CONFIRMED:
        raise NotEligible(
            "PROVISIONAL_VERDICT",
            f"confidence is {cls.confidence.value}; requires "
            f"{settings.window_vdays} vdays of observation")
    if cls.lifecycle is not Lifecycle.ZOMBIE and not ep.deprecated:
        raise NotEligible(
            "NOT_ELIGIBLE",
            f"lifecycle is {cls.lifecycle.value}; must be ZOMBIE or formally deprecated")
    if blast is None:
        raise NotEligible("NO_IMPACT_ANALYSIS", "run stage 09 first")


def select_path(blast) -> Path:
    """Express and canary are both decided from the blast radius.

    ``in_graph`` is required for express and is not a formality. An endpoint the
    graph never contained has not been shown to have zero callers; it has merely
    never been looked at, and those are different pieces of evidence. Treating
    absence of data as absence of dependants is how a decommission becomes an
    incident.

    Canary never throttles. Deliberately degrading a payment path to encourage
    migration is itself the incident it is trying to avoid.
    """
    express = blast.tier is BlastTier.ZERO and blast.in_graph
    canary = bool(blast.touches_critical)
    # A critical blast radius is never express, whatever the tier says.
    return Path(express=express and not canary, canary=canary)


def phase_length(phase: Phase) -> int:
    return {
        Phase.A: settings.phase_a_vdays,
        Phase.B: settings.phase_b_vdays,
        Phase.C: settings.phase_c_vdays,
    }.get(phase, 0)


def next_phase(current: Phase, path: Path) -> Phase | None:
    order = path.phases
    if current is Phase.NONE:
        return order[0]
    if current not in order:
        return None
    i = order.index(current)
    return order[i + 1] if i + 1 < len(order) else None


def may_auto_advance(to_phase: Phase) -> bool:
    """Phases A→B and B→C advance on the clock. Nothing advances into D.

    Archival and a 410 are irreversible in effect, so the last transition is a
    human's to make. Automating it would mean the system could retire an
    endpoint with nobody having looked at the hidden callers it found.
    """
    return to_phase is not Phase.D


def due(current_vday: int, phase_vday: int | None, phase: Phase) -> bool:
    if phase_vday is None:
        return False
    return (current_vday - phase_vday) >= phase_length(phase)


def throttle_limit(peak_calls_per_vday: int) -> int:
    """Phase A throttle: a fraction of observed peak, floored.

    Sized from what the endpoint actually served, so the throttle is felt by a
    caller that is still there and invisible to one that is not. A fixed number
    would either do nothing or take the endpoint down on the first phase.
    """
    per_minute = int(peak_calls_per_vday * (settings.throttle_pct / 100.0) / (24 * 60))
    return max(1, per_minute)


def sunset_at(entered_vday: int, path: Path, current_phase: Phase,
              epoch_wall: datetime, scale_seconds: int) -> datetime:
    """When the endpoint stops answering, in wall time.

    RFC 8594's ``Sunset`` header is machine-parseable, so client tooling picks
    the date up without anyone reading a memo — but only if it is a real date. It
    is computed from the phase clock through the vclock rather than written by
    hand, so a compressed timeline produces a correspondingly near date instead
    of a fiction ninety calendar days out.
    """
    remaining = 0
    order = path.phases
    start = order.index(current_phase) if current_phase in order else 0
    for phase in order[start:]:
        remaining += phase_length(phase)

    retire_vday = entered_vday + remaining
    if epoch_wall.tzinfo is None:
        epoch_wall = epoch_wall.replace(tzinfo=timezone.utc)
    return epoch_wall + timedelta(seconds=retire_vday * scale_seconds)


def rfc8594(when: datetime) -> str:
    """IMF-fixdate, as RFC 8594 requires. Not isoformat."""
    return when.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


# ── canary ───────────────────────────────────────────────────────────────────
def canary_steps() -> list[float]:
    return settings.canary_step_list


def next_canary_split(current: float | None) -> float | None:
    steps = canary_steps()
    if current is None:
        return steps[0] if steps else None
    for step in steps:
        if step < current:
            return step
    return None


def canary_should_revert(baseline_error_rate: float, observed_error_rate: float) -> bool:
    """Absolute rise over baseline, not a ratio.

    A ratio makes an endpoint with a 0.1% baseline trip on noise and one with a
    5% baseline never trip at all. The ceiling is the extra proportion of calls
    now failing that were not failing before.
    """
    return (observed_error_rate - baseline_error_rate) > settings.canary_error_ceiling


# ── the certificate ──────────────────────────────────────────────────────────
@dataclass
class Evidence:
    silent_vdays: int | None
    confidence: str
    blast: dict
    hidden_callers_found: int
    phases: list[dict] = field(default_factory=list)
    cdri_at_retirement: float | None = None
    worm_object: str | None = None
    worm_retain_until: str | None = None
    honeypot_activated: bool = False
    honeypot_legal_signoff: str | None = None


def certificate_body(ep, service_name: str, retired_vday: int, evidence: Evidence) -> dict:
    """The record that outlives the endpoint.

    Everything in it is read from a table another stage wrote. A certificate
    asserting a clean retirement is worth exactly as much as the evidence it
    carries, so it carries the evidence rather than a summary of it.
    """
    return {
        "endpoint": {
            "id": ep.id,
            "method": ep.method,
            "path": ep.path_template,
            "service": service_name,
        },
        "retired_vday": retired_vday,
        "evidence": {
            "silent_vdays": evidence.silent_vdays,
            "confidence": evidence.confidence,
            "blast": evidence.blast,
            "hidden_callers_found": evidence.hidden_callers_found,
            "phases": evidence.phases,
            "cdri_at_retirement": evidence.cdri_at_retirement,
            "worm_object": evidence.worm_object,
            "worm_retain_until": evidence.worm_retain_until,
            "honeypot_activated": evidence.honeypot_activated,
            "honeypot_legal_signoff": evidence.honeypot_legal_signoff,
        },
        "engine_version": VERSION,
    }


def criticality_is_exempt(criticality: Criticality) -> bool:
    """Payment, settlement and regulatory paths are never throttled."""
    return criticality in (Criticality.PAYMENT, Criticality.SETTLEMENT,
                           Criticality.REGULATORY)
