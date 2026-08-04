"""Stage 10 phase 1 — generate.

Turns a CDRI indicator that fired into a gateway control that would close it.

Nothing here modifies an application. Every control is Kong configuration, which
is the property that makes the virtual-patch track deployable inside an
emergency-change procedure: it is reversible by deleting a plugin, and the
rollback is one call with an id the apply step recorded.

The output is **exactly the JSON that will be POSTed**. There is no
transformation between what an approver reviews and what reaches the gateway,
because a difference between those two is the one defect an approval process
cannot catch.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentry_core.enums import Auth, Criticality

from ..actuators import kong

VERSION = "remediation-1.0.0"


@dataclass(frozen=True)
class EndpointFacts:
    """What the generator is allowed to know.

    Every field traces to a table another stage wrote. The generator never
    inspects a path string: an endpoint named ``/api/v1/payment-history`` is a
    reporting endpoint and one named ``/api/v1/xfr`` may be settlement, and a
    control sized from the name would be wrong in both directions.
    """

    endpoint_id: str
    method: str
    path_template: str
    service_name: str
    criticality: Criticality
    auth: Auth
    tls_version: str | None
    data_classes: list[str]
    #: p95 calls per vday over the baseline window, from endpoint_daily.
    peak_calls_per_vday: int
    #: Whether a rate-limiting plugin is already attached at the gateway.
    rate_limited: bool


@dataclass
class Proposal:
    """One control, ready to POST."""

    kind: str
    plugin_config: dict
    indicator: str
    rationale: str
    #: Set when applying this control alone cannot close the finding.
    prerequisite: str | None = None
    generator: str = "template"


@dataclass
class Plan:
    endpoint_id: str
    proposals: list[Proposal] = field(default_factory=list)
    #: Indicators that fired but have no gateway remedy, with the reason. Carried
    #: so the console can show why a scored risk produced no control instead of
    #: showing nothing.
    unaddressed: list[dict] = field(default_factory=list)


#: Headroom over observed peak.
#:
#: A limit at the observed peak throttles the estate's own normal traffic the
#: first time a batch runs slightly hot. Half again leaves room for ordinary
#: variance while still bounding a credential-stuffing or scraping run, which is
#: what the control is for.
RATE_LIMIT_HEADROOM = 1.5

#: Below this, a rate limit is set from the floor rather than from observation.
#: A limit of three per minute derived from a quiet endpoint is a self-inflicted
#: outage waiting for the first spike.
RATE_LIMIT_FLOOR = 60

TLS_FLOOR = "1.3"

#: Response fields to strip, by data class. Keyed on the class the kernel
#: detected, not on a field name pattern — the sensor reports that a response
#: carried an Aadhaar, and these are the field names that carry one.
MASK_FIELDS: dict[str, list[str]] = {
    "AADHAAR": ["aadhaar", "aadhaarNumber", "uid"],
    "PAN": ["pan", "panNumber"],
    "CARD": ["cardNumber", "pan", "card"],
    "CVV": ["cvv", "cvc", "securityCode"],
    "ACCOUNT_NO": ["accountNumber", "accountNo"],
    "IFSC": ["ifsc", "ifscCode"],
    "DOB": ["dob", "dateOfBirth"],
}

#: Endpoint classes where a throttle is not an acceptable control.
#:
#: Rate-limiting a settlement path converts a security finding into a payment
#: incident. These classes get the control proposed against them recorded as
#: unaddressed with the reason, rather than silently skipped.
THROTTLE_EXEMPT = {Criticality.SETTLEMENT, Criticality.PAYMENT, Criticality.REGULATORY}


def rate_limit_for(peak_calls_per_vday: int) -> int:
    """Per-minute limit from observed peak throughput."""
    per_minute = int(peak_calls_per_vday * RATE_LIMIT_HEADROOM / (24 * 60)) + 1
    return max(RATE_LIMIT_FLOOR, per_minute)


def mask_fields_for(data_classes: list[str]) -> list[str]:
    out: list[str] = []
    for cls in data_classes:
        for field_name in MASK_FIELDS.get(cls.upper(), []):
            if field_name not in out:
                out.append(field_name)
    return out


def plan_for(facts: EndpointFacts, fired: dict[str, float]) -> Plan:
    """Build the control set for one endpoint.

    ``fired`` is the CDRI part map: indicator key to its r value. Only
    indicators that actually fired produce a control, so the plan is derived
    from the score rather than from a checklist applied to everything.
    """
    plan = Plan(endpoint_id=facts.endpoint_id)

    if fired.get("no_rate_limit", 0) > 0 and not facts.rate_limited:
        if facts.criticality in THROTTLE_EXEMPT:
            plan.unaddressed.append({
                "indicator": "no_rate_limit",
                "reason": f"{facts.criticality.value} endpoints are throttle-exempt; "
                          "a rate limit here converts a security finding into a "
                          "payment incident",
            })
        else:
            limit = rate_limit_for(facts.peak_calls_per_vday)
            plan.proposals.append(Proposal(
                kind="rate-limit",
                plugin_config=kong.rate_limit(limit),
                indicator="no_rate_limit",
                rationale=f"observed peak {facts.peak_calls_per_vday} calls/vday; "
                          f"limit set to {limit}/minute at {RATE_LIMIT_HEADROOM}x headroom",
            ))

    if fired.get("no_auth", 0) > 0 and facts.auth is Auth.NONE:
        plan.proposals.append(Proposal(
            kind="key-auth",
            plugin_config=kong.key_auth(),
            indicator="no_auth",
            rationale="endpoint served every observed request without an "
                      "Authorization header",
            # Stated up front, because the Judge will reject this control on its
            # own and the reason should not look like a surprise. Every existing
            # consumer becomes a 401 the moment it applies.
            prerequisite="consumers must be provisioned with keys before this "
                         "can pass the Judge; applying it first is an outage",
        ))

    if fired.get("data_exposure", 0) > 0 and facts.data_classes:
        fields = mask_fields_for(facts.data_classes)
        if fields:
            plan.proposals.append(Proposal(
                kind="response-mask",
                plugin_config=kong.response_mask(fields),
                indicator="data_exposure",
                rationale="response bodies carried "
                          f"{', '.join(sorted(facts.data_classes))}; "
                          f"masking {len(fields)} candidate field names",
                prerequisite="removing a response field is breaking by "
                             "definition; the Judge will reject it until "
                             "consumers are known not to read these fields",
            ))
        else:
            plan.unaddressed.append({
                "indicator": "data_exposure",
                "reason": "no field-name mapping for the detected classes; "
                          "the kernel reports the class, not the field it "
                          "appeared in",
            })

    if fired.get("weak_tls", 0) > 0:
        # A pre-function that rejects below the floor is enforcement at the
        # gateway, but the estate's own callers negotiate what they negotiate.
        # Recorded as a proposal so the Judge measures the breakage rather than
        # the generator assuming it.
        plan.proposals.append(Proposal(
            kind="tls-min",
            plugin_config=kong.tls_min(TLS_FLOOR),
            indicator="weak_tls",
            rationale=f"observed TLS {facts.tls_version or 'unreported'}; "
                      f"floor is {TLS_FLOOR}",
            prerequisite="callers negotiating below the floor are rejected with "
                         "426 the moment this applies",
        ))

    if fired.get("zombie", 0) > 0:
        plan.unaddressed.append({
            "indicator": "zombie",
            "reason": "a zombie is retired at stage 11, not patched at the "
                      "gateway; a control here would keep a dead endpoint alive "
                      "and compliant",
        })

    if fired.get("anomaly", 0) > 0:
        plan.unaddressed.append({
            "indicator": "anomaly",
            "reason": "behavioural anomaly is a detection, not a defect with a "
                      "configuration remedy; it routes to investigation",
        })

    return plan


def fired_indicators(parts: list[dict]) -> dict[str, float]:
    """Indicator key to r value, for the parts that contributed anything."""
    return {p["key"]: p["r"] for p in parts if p.get("r", 0) > 0}
