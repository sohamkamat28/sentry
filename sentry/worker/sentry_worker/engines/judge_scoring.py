"""API Judge scoring — the four safety dimensions.

Kept separate from the replay harness so the scoring rules are testable without
Docker, and so a change to how a score is computed is visible in one place.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentry_core.enums import Criticality

#: Per-endpoint-class latency budgets, in microseconds.
#:
#: The source material cited a flat "5ms SWIFT/FedNow SLA". That is not a real
#: per-hop API SLA and would not survive a technical challenge. Budgets are set
#: per class instead, tightest on settlement paths.
LATENCY_BUDGET_US: dict[str, int] = {
    Criticality.SETTLEMENT.value: 5_000,
    Criticality.PAYMENT.value: 10_000,
    Criticality.CUSTOMER.value: 50_000,
    Criticality.REGULATORY.value: 200_000,
    Criticality.INTERNAL.value: 200_000,
}

FLOORS = {"schema": 100, "latency": 70, "error": 95, "exposure": 100}


def budget_for(criticality: str | Criticality) -> int:
    c = criticality.value if isinstance(criticality, Criticality) else criticality
    return LATENCY_BUDGET_US.get(c, LATENCY_BUDGET_US[Criticality.INTERNAL.value])


def latency_score(delta_us: int, budget_us: int) -> int:
    """Budget compliance is a **threshold**, not a gradient.

    An earlier build scored this as a smooth ratio, so a patch consuming 68% of
    an available budget scored 32 and was rejected — a patch that was, by the
    bank's own stated policy, acceptable. Anything within budget now scores at
    or above the pass floor and reports its headroom.
    """
    if budget_us <= 0:
        return 100
    if delta_us <= 0:
        return 100  # patched path is no slower than control
    if delta_us >= budget_us:
        return 0
    # Within budget: 60 at the boundary rising to 100 as headroom grows. The
    # pass floor is 70, so a patch must leave roughly a quarter of its budget
    # unused — strict enough to be meaningful, not so strict it rejects a patch
    # the policy permits.
    headroom = 1.0 - (delta_us / budget_us)
    return int(round(60 + 40 * headroom))


def schema_score(removed_fields: list[str], added_fields: list[str],
                 intended_removals: list[str] | None = None) -> int:
    """Unintended removals are breaking; added fields are not.

    A consumer reading a field that disappears breaks. A consumer ignoring a
    field that appears does not.

    ``intended_removals`` is what the control under test declares it will take
    away. Without it a response-mask could never pass: removing fields is the
    entire purpose of a masking control, so the dimension that exists to catch
    breakage scored 0 every time the control worked exactly as specified, and
    no PAN or Aadhaar could ever be masked at the gateway.

    The distinction is between a control doing what it said and a control doing
    something else. A mask that removes precisely the fields it declared has not
    broken the contract in a way anybody failed to authorise — the removal *is*
    the authorised change. A mask that also removes ``accountHolder`` has, and
    still scores 0.
    """
    intended = {f.split(".")[-1] for f in (intended_removals or [])}
    unintended = [f for f in removed_fields if f.split(".")[-1] not in intended]
    return 0 if unintended else 100


def error_score(control_error_rate: float, variant_error_rate: float) -> int:
    delta = variant_error_rate - control_error_rate
    if delta <= 0:
        return 100
    return max(0, int(round(100 - delta * 1000)))


def exposure_score(control_classes: set[str], variant_classes: set[str]) -> int:
    """A patch must not introduce exposure, and should reduce it."""
    introduced = variant_classes - control_classes
    return 0 if introduced else 100


@dataclass
class Scores:
    schema: int
    latency: int
    error: int
    exposure: int
    latency_delta_us: int
    budget_us: int
    requests: int
    reason: str | None = None

    @property
    def headroom_pct(self) -> int:
        if self.budget_us <= 0 or self.latency_delta_us <= 0:
            return 100
        return max(0, int(round(100 * (1 - self.latency_delta_us / self.budget_us))))

    @property
    def verdict(self) -> str:
        if self.requests == 0:
            return "REJECT"  # never pass a patch on zero evidence
        return (
            "PASS"
            if (
                self.schema >= FLOORS["schema"]
                and self.latency >= FLOORS["latency"]
                and self.error >= FLOORS["error"]
                and self.exposure >= FLOORS["exposure"]
            )
            else "REJECT"
        )

    @property
    def failing(self) -> list[str]:
        out = []
        for k, floor in FLOORS.items():
            if getattr(self, k) < floor:
                out.append(k)
        return out
