"""Stage 04 — Classification.

Two independent axes, five deterministic questions, no machine learning.

The choice not to use a model here is a design constraint, not a shortcut. A
bank must defend every verdict to a regulator, and "the model decided" is not a
defence. A rule tree can be re-run by hand by an examiner and reach the same
answer, which is what makes the output admissible.

Three defects in the source model are corrected here:

* ``DORMANT`` covers days 31-89, which previously matched no status at all.
* Ownership is not part of the lifecycle test. The original required "no active
  owner" for ZOMBIE, so a 200-day-silent endpoint *with* an owner matched
  nothing. Missing ownership now raises severity, it does not decide status.
* ``SHADOW`` is withheld when the gateway collector is unhealthy: absence from a
  registry we could not read is not evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentry_core.config import settings
from sentry_core.enums import Confidence, Governance, Lifecycle

VERSION = "cls-1.0.0"


@dataclass(frozen=True)
class Facts:
    """The five answers, plus the context needed to interpret them."""

    silent_vdays: int | None  # Q1: None means never called
    in_gateway: bool  # Q2
    has_reachable_owner: bool  # Q3
    deprecated: bool  # Q4
    in_code: bool  # Q5
    owner_confidence: float = 0.0
    shadow_reliable: bool = True


@dataclass
class Verdict:
    lifecycle: Lifecycle
    governance: Governance
    confidence: Confidence
    severity_bump: bool
    trace: list[dict] = field(default_factory=list)


def confidence_for(observed_vdays: int) -> Confidence:
    """The confidence ramp.

    Below the baseline the system is not entitled to an opinion. Between
    baseline and window it may hold one provisionally. Only past the full window
    can an endpoint enter the decommissioning workflow on observed evidence.
    """
    if observed_vdays <= settings.baseline_vdays:
        return Confidence.NONE
    if observed_vdays < settings.window_vdays:
        return Confidence.PROVISIONAL
    return Confidence.CONFIRMED


def lifecycle_for(silent_vdays: int | None, deprecated: bool) -> Lifecycle:
    if silent_vdays is None:
        # Discovered in code, never called: unreleased, not dead. ZOMBIE means
        # "was alive, now is not"; this endpoint has no traffic history to be
        # silent against.
        return Lifecycle.ACTIVE
    if deprecated:
        # Outranks the day count. A formally sunsetting endpoint still serving
        # traffic is not healthy; treating it as ACTIVE would hide work already
        # in progress.
        return Lifecycle.DEPRECATED
    if silent_vdays <= settings.active_vdays:
        return Lifecycle.ACTIVE
    if silent_vdays < settings.zombie_vdays:
        return Lifecycle.DORMANT
    return Lifecycle.ZOMBIE


def governance_for(
    in_gateway: bool, has_owner: bool, in_code: bool, shadow_reliable: bool
) -> Governance:
    if not in_gateway and not in_code:
        if not shadow_reliable:
            # The gateway collector is down, so "absent from the gateway" is
            # unproven. Fall back to the owner test rather than manufacture a
            # SHADOW verdict from a failed poll.
            return Governance.OWNED if has_owner else Governance.ORPHANED
        # Outranks ORPHANED: an endpoint in no registry and no repository has no
        # owner by construction, and reporting it as merely ownerless
        # understates it.
        return Governance.SHADOW
    return Governance.OWNED if has_owner else Governance.ORPHANED


def classify(facts: Facts, observed_vdays: int) -> Verdict | None:
    """Return the verdict, or None when the system is not yet entitled to one."""
    conf = confidence_for(observed_vdays)
    if conf is Confidence.NONE:
        # An absent row is unambiguous. A row stamped "not confident" invites
        # being read as a verdict.
        return None

    life = lifecycle_for(facts.silent_vdays, facts.deprecated)
    gov = governance_for(
        facts.in_gateway, facts.has_reachable_owner, facts.in_code, facts.shadow_reliable
    )
    bump = (not facts.has_reachable_owner) or (
        facts.owner_confidence < settings.ownership_confidence_floor
    )

    trace: list[dict] = [
        {"q": 1, "question": "days since last call", "answer": facts.silent_vdays,
         "source": "endpoint.last_call_vday"},
        {"q": 2, "question": "registered in gateway", "answer": facts.in_gateway,
         "source": "endpoint_source"},
        {"q": 3, "question": "reachable owner", "answer": facts.has_reachable_owner,
         "source": "ownership.reachable"},
        {"q": 4, "question": "formally deprecated", "answer": facts.deprecated,
         "source": "endpoint.deprecated"},
        {"q": 5, "question": "present in code", "answer": facts.in_code,
         "source": "endpoint_source"},
        {"rule": "lifecycle", "applied": _lifecycle_rule(facts), "result": life.value},
        {"rule": "governance", "applied": _governance_rule(facts), "result": gov.value},
        {"rule": "severity", "applied": _severity_rule(facts), "result": bump},
        {"rule": "confidence", "applied": f"observed {observed_vdays} vdays", "result": conf.value},
    ]
    return Verdict(life, gov, conf, bump, trace)


def _lifecycle_rule(f: Facts) -> str:
    if f.silent_vdays is None:
        return "never called -> ACTIVE (unreleased)"
    if f.deprecated:
        return "deprecated flag -> DEPRECATED"
    if f.silent_vdays <= settings.active_vdays:
        return f"q1 <= {settings.active_vdays} -> ACTIVE"
    if f.silent_vdays < settings.zombie_vdays:
        return f"{settings.active_vdays} < q1 < {settings.zombie_vdays} -> DORMANT"
    return f"q1 >= {settings.zombie_vdays} -> ZOMBIE"


def _governance_rule(f: Facts) -> str:
    if not f.in_gateway and not f.in_code:
        if not f.shadow_reliable:
            return "not q2 and not q5, but gateway unhealthy -> SHADOW withheld"
        return "not q2 and not q5 -> SHADOW"
    return "q3 -> OWNED" if f.has_reachable_owner else "not q3 -> ORPHANED"


def _severity_rule(f: Facts) -> str:
    if not f.has_reachable_owner:
        return "no reachable owner -> severity bump"
    if f.owner_confidence < settings.ownership_confidence_floor:
        return f"owner confidence {f.owner_confidence} < floor -> severity bump"
    return "no bump"


def replay(trace: list[dict]) -> tuple[str, str]:
    """Re-derive a verdict from a stored trace.

    An examiner replaying a recorded decision must reach the stored answer. The
    verification suite runs this over every row in the estate.
    """
    answers = {t["q"]: t["answer"] for t in trace if "q" in t}
    ctx = {t["rule"]: t for t in trace if "rule" in t}
    shadow_reliable = "withheld" not in ctx.get("governance", {}).get("applied", "")
    facts = Facts(
        silent_vdays=answers.get(1),
        in_gateway=bool(answers.get(2)),
        has_reachable_owner=bool(answers.get(3)),
        deprecated=bool(answers.get(4)),
        in_code=bool(answers.get(5)),
        shadow_reliable=shadow_reliable,
    )
    life = lifecycle_for(facts.silent_vdays, facts.deprecated)
    gov = governance_for(
        facts.in_gateway, facts.has_reachable_owner, facts.in_code, facts.shadow_reliable
    )
    return life.value, gov.value
