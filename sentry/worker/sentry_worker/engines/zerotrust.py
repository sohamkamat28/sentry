"""Stage 13 — zero-trust posture.

Five controls per endpoint, assessed against what is *applied* rather than what
was intended, and a hardening plan ordered so that stopping partway leaves the
endpoint better off than it started.

Owns no table. The assessment is a pure function of observed posture, and every
gateway change it recommends is applied through the stage 10 pipeline — generate,
judge, apply — so there is one audited write path and one judge gate. A hardening
route with its own actuator would be a second way for a plugin to reach
production, with its own bugs and its own audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentry_core.config import settings
from sentry_core.enums import Auth, Criticality

VERSION = "zerotrust-1.0.0"

#: Data classes that make control 5 fire.
SENSITIVE_CLASSES = frozenset({"PAN", "AADHAAR", "CARD", "CVV"})

#: Control kinds that constitute a sender-constrained token binding.
BINDING_KINDS = frozenset({"dpop", "mtls-auth"})

#: Kinds that satisfy each control when APPLIED, beyond the endpoint's own
#: observed posture. The assessment reads applied reality: a PROPOSED control is
#: a plan, and a plan protects nothing.
SATISFYING_KINDS: dict[str, frozenset[str]] = {
    "auth": frozenset({"key-auth", "oauth2", "mtls-auth"}),
    "tls": frozenset({"tls-min"}),
    "binding": BINDING_KINDS,
    "ratelimit": frozenset({"rate-limit", "sunset-throttle"}),
    "response": frozenset({"response-mask"}),
}


@dataclass(frozen=True)
class ControlAssessment:
    key: str
    ok: bool
    current: object
    remedy: str | None
    #: True when applying the remedy breaks callers that have not been prepared.
    #: The console requires an acknowledgement before proceeding on these.
    requires_migration: bool = False


@dataclass
class Posture:
    endpoint_id: str
    controls: list[ControlAssessment] = field(default_factory=list)
    priority: float = 0.0

    @property
    def satisfied(self) -> int:
        return sum(1 for c in self.controls if c.ok)

    @property
    def of(self) -> int:
        return len(self.controls)

    @property
    def gaps(self) -> list[ControlAssessment]:
        return [c for c in self.controls if not c.ok]

    def as_dict(self) -> dict:
        return {
            "endpoint_id": self.endpoint_id,
            # A count, not a percentage. An operator acts on "two of five
            # controls missing"; nobody has ever acted on "40%".
            "satisfied": self.satisfied,
            "of": self.of,
            "priority": self.priority,
            "controls": [
                {"key": c.key, "ok": c.ok, "current": c.current, "remedy": c.remedy,
                 "requires_migration": c.requires_migration}
                for c in self.controls
            ],
        }


def auth_remedy(criticality: Criticality | str) -> str:
    """Settlement paths get mTLS; everything else gets OAuth 2.0.

    Recommending mTLS estate-wide generates a certificate-distribution
    programme nobody will run, and a recommendation nobody executes is worth
    nothing. Reserving it for the endpoints where a leaked bearer token is
    materially worse keeps it executable.
    """
    value = criticality.value if isinstance(criticality, Criticality) else criticality
    return settings.zt_settlement_auth if value == Criticality.SETTLEMENT.value \
        else settings.zt_default_auth


def _throttle_exempt(criticality: Criticality | str) -> bool:
    value = criticality.value if isinstance(criticality, Criticality) else criticality
    return value in (Criticality.PAYMENT.value, Criticality.SETTLEMENT.value,
                     Criticality.REGULATORY.value)


def assess(ep, criticality: Criticality | str, applied_kinds: set[str],
           priority: float = 0.0) -> Posture:
    """Five controls, scored against applied reality.

    ``applied_kinds`` must contain only controls in state APPLIED. Counting a
    PROPOSED control would report an endpoint as protected by configuration that
    is not on the gateway — the precise fiction this system exists not to
    produce.
    """
    kinds = set(applied_kinds)
    auth_value = ep.auth.value if isinstance(ep.auth, Auth) else str(ep.auth)
    sensitive = sorted(set(ep.data_classes or []) & SENSITIVE_CLASSES)

    # Control 3 is the one rarely addressed elsewhere. A bearer token that leaks
    # is usable by anyone; a sender-constrained token is bound to the key that
    # requested it and is useless in another party's hands. On a settlement path
    # that difference is the whole of the risk, so it is a control in its own
    # right rather than a footnote to authentication.
    has_binding = bool(kinds & BINDING_KINDS) or auth_value == Auth.MTLS.value

    controls = [
        ControlAssessment(
            key="auth",
            ok=auth_value in (Auth.OAUTH2.value, Auth.MTLS.value)
            or bool(kinds & SATISFYING_KINDS["auth"]),
            current=auth_value,
            remedy=auth_remedy(criticality),
            requires_migration=True,
        ),
        ControlAssessment(
            key="tls",
            ok=ep.tls_version == settings.zt_tls_floor
            or bool(kinds & SATISFYING_KINDS["tls"]),
            current=ep.tls_version,
            remedy="tls-min",
            # Rejects only clients already below the institution's own policy.
            requires_migration=False,
        ),
        ControlAssessment(
            key="binding",
            ok=has_binding,
            current=sorted(kinds & BINDING_KINDS) or None,
            remedy="dpop",
            requires_migration=True,
        ),
        ControlAssessment(
            key="ratelimit",
            ok=bool(ep.rate_limited) or bool(kinds & SATISFYING_KINDS["ratelimit"]),
            current=bool(ep.rate_limited),
            # Payment, settlement and regulatory paths are throttle-exempt, and
            # the exemption is a property of the endpoint rather than of the
            # stage proposing the control. Stage 10 already refuses to throttle
            # them; offering the same remedy here would let an operator apply
            # from the posture screen exactly what the remediation queue
            # declined, and turn a security finding into a payment incident.
            remedy=None if _throttle_exempt(criticality) else "rate-limit",
            requires_migration=False,
        ),
        ControlAssessment(
            key="response",
            ok=not sensitive or bool(kinds & SATISFYING_KINDS["response"]),
            current=sensitive,
            remedy="response-mask",
            requires_migration=False,
        ),
    ]
    return Posture(endpoint_id=ep.id, controls=controls, priority=priority)


#: Hardening order: least disruptive first.
#:
#: A run that fails partway must leave the endpoint better off than it started,
#: which means the controls that cannot break a caller go first. Authentication
#: is fourth because applying it turns every unprovisioned caller into a 401,
#: and binding is last because it is meaningless before authentication exists.
HARDENING_ORDER = ["ratelimit", "tls", "response", "auth", "binding"]


def plan(posture: Posture) -> list[ControlAssessment]:
    """The gap set, in the order it should be applied.

    A gap with no remedy stays a gap and is reported as one — it is a real
    weakness that this system declines to close at the gateway, and dropping it
    from the assessment would hide it.
    """
    by_key = {c.key: c for c in posture.gaps if c.remedy is not None}
    return [by_key[k] for k in HARDENING_ORDER if k in by_key]


def summarise(results: list[dict], posture_before: Posture, posture_after: Posture) -> dict:
    """Report partial hardening as partial.

    Three of five controls applied is stated as three of five. Rounding it up to
    "hardened" would put an endpoint on a compliance report as protected by two
    controls that are not there.
    """
    applied = sum(1 for r in results if r.get("state") == "APPLIED")
    return {
        "attempted": len(results),
        "applied": applied,
        "posture_before": f"{posture_before.satisfied}/{posture_before.of}",
        "posture_after": f"{posture_after.satisfied}/{posture_after.of}",
        "complete": posture_after.satisfied == posture_after.of,
        "controls": results,
    }
