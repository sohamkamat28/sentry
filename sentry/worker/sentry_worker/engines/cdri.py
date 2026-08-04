"""Stage 06 — Composite Damage Risk Index.

Six weighted indicators summing to exactly 1.00. Every r value is read from a
table another stage wrote; this engine is arithmetic over facts, which is what
makes its output defensible.

The anomaly term is the sixth weight, supplied by stage 05. It is not applied a
second time after the sum. Applying it twice would double-count it and break the
property that the maximum is exactly 1.00 and that any two scores are comparable.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentry_core.config import settings
from sentry_core.enums import Auth, DataClass, Governance, Lifecycle, Tier

VERSION = "cdri-1.0.0"

DEFAULT_WEIGHTS: dict[str, float] = {
    "no_auth": 0.28,
    "zombie": 0.22,
    "data_exposure": 0.20,
    "weak_tls": 0.15,
    "no_rate_limit": 0.08,
    "anomaly": 0.07,
}

LABELS = {
    "no_auth": "No authentication",
    "zombie": "Zombie status",
    "data_exposure": "PII / financial data",
    "weak_tls": "TLS below 1.3",
    "no_rate_limit": "No rate limiting",
    "anomaly": "Behavioural anomaly",
}

TIER_BOUNDS: list[tuple[Tier, float]] = [
    (Tier.CRITICAL, 0.75),
    (Tier.HIGH, 0.50),
    (Tier.MEDIUM, 0.25),
    (Tier.LOW, 0.0),
]

TIER_ACTIONS = {
    Tier.CRITICAL: "Page on-call; eligible for the virtual-patch queue",
    Tier.HIGH: "Daily digest; action within 48 vhours",
    Tier.MEDIUM: "Weekly review queue; owner notified",
    Tier.LOW: "Register only",
}

_HIGH_RISK_CLASSES = {DataClass.PAN.value, DataClass.AADHAAR.value,
                      DataClass.CARD.value, DataClass.CVV.value}
_MED_RISK_CLASSES = {DataClass.ACCOUNT_NO.value, DataClass.DOB.value}


class WeightSumError(ValueError):
    """Weights must sum to 1.00. Raised with the actual sum so the console can
    show the residual while a slider is being dragged."""

    def __init__(self, actual: float) -> None:
        self.actual = actual
        super().__init__(f"weights sum to {actual:.6f}, must be 1.0")


def validate_weights(weights: dict[str, float]) -> None:
    missing = set(DEFAULT_WEIGHTS) - set(weights)
    if missing:
        raise ValueError(f"missing weights: {sorted(missing)}")
    unknown = set(weights) - set(DEFAULT_WEIGHTS)
    if unknown:
        raise ValueError(f"unknown weights: {sorted(unknown)}")
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-6:
        raise WeightSumError(total)


# ── indicator functions ──────────────────────────────────────────────────────
# Graded rather than binary where a middle state genuinely exists. Basic auth is
# not as bad as none and not as good as OAuth; scoring it 0.5 says so. Grading
# changes no maximum and makes ordering within a tier meaningful.

def auth_risk(auth: Auth | str) -> float:
    a = auth.value if isinstance(auth, Auth) else auth
    if a == Auth.NONE.value:
        return 1.0
    if a in (Auth.BASIC.value, Auth.APIKEY.value):
        return 0.5
    if a == Auth.BEARER.value:
        return 0.3
    return 0.0


def lifecycle_risk(life: Lifecycle | str | None) -> float:
    if life is None:
        return 0.0
    v = life.value if isinstance(life, Lifecycle) else life
    return {
        Lifecycle.ZOMBIE.value: 1.0,
        Lifecycle.DORMANT.value: 0.6,
        Lifecycle.DEPRECATED.value: 0.3,
        Lifecycle.ACTIVE.value: 0.0,
    }.get(v, 0.0)


def data_risk(classes: list[str] | None) -> float:
    s = set(classes or [])
    if s & _HIGH_RISK_CLASSES:
        return 1.0
    if s & _MED_RISK_CLASSES:
        return 0.6
    if DataClass.IFSC.value in s:
        return 0.3
    return 0.0


def tls_risk(version: str | None) -> float:
    if version in (None, "", "1.0", "1.1"):
        return 1.0
    if version == "1.2":
        return 0.5
    return 0.0


def tier_for(score: float) -> Tier:
    for tier, floor in TIER_BOUNDS:
        if score >= floor:
            return tier
    return Tier.LOW


@dataclass
class Inputs:
    auth: Auth | str
    lifecycle: Lifecycle | str | None
    data_classes: list[str]
    tls_version: str | None
    rate_limited: bool
    anomaly_flag: bool | None  # None = stage 05 has not run for this endpoint


@dataclass
class Result:
    score: float
    tier: Tier
    parts: list[dict]

    @property
    def action(self) -> str:
        return TIER_ACTIONS[self.tier]


def score(inp: Inputs, weights: dict[str, float] | None = None) -> Result:
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    validate_weights(w)

    r: dict[str, float] = {
        "no_auth": auth_risk(inp.auth),
        "zombie": lifecycle_risk(inp.lifecycle),
        "data_exposure": data_risk(inp.data_classes),
        "weak_tls": tls_risk(inp.tls_version),
        "no_rate_limit": 0.0 if inp.rate_limited else 1.0,
        "anomaly": 1.0 if inp.anomaly_flag else 0.0,
    }

    parts: list[dict] = []
    for key in DEFAULT_WEIGHTS:
        part = {
            "key": key,
            "label": LABELS[key],
            "r": round(r[key], 4),
            "w": round(w[key], 4),
            "contribution": round(r[key] * w[key], 6),
        }
        if key == "anomaly" and inp.anomaly_flag is None:
            # An unmeasured input reads as zero. The record says it was
            # unmeasured rather than measured-zero, so a reader can tell the
            # difference between "no anomaly" and "stage 05 has not run".
            part["source"] = "absent"
        parts.append(part)

    total = round(sum(p["contribution"] for p in parts), settings.cdri_round_dp)
    return Result(total, tier_for(total), parts)


def time_to_breach(
    cdri_score: float,
    auth: Auth | str,
    data_classes: list[str],
    governance: Governance | str | None,
    anomaly_patterns: list[str] | None,
    internet_reachable: bool,
) -> tuple[int | None, list[str]]:
    """Convert a score into a countdown.

    A CDRI of 0.92 is a debate; a deadline moves budget. This is a **heuristic**
    and is labelled as one everywhere it surfaces. The source material describes
    combining CVE activity with historical breach timing; no such feed is wired
    here, and claiming otherwise would be fabrication. The returned factor list
    is the seam where a real exploit-intelligence source replaces the estimate.
    """
    if cdri_score < settings.ttb_min_score:
        return None, []

    factors: list[str] = []
    base = float(settings.ttb_base_days) * (1.0 - 0.85 * cdri_score)
    factors.append(f"composite exposure x{1.0 - 0.85 * cdri_score:.2f}")

    a = auth.value if isinstance(auth, Auth) else auth
    if a == Auth.NONE.value:
        base *= 0.45
        factors.append("no_auth x0.45")
    if data_risk(data_classes) >= 0.6:
        base *= 0.60
        factors.append("sensitive data x0.60")
    g = governance.value if isinstance(governance, Governance) else governance
    if g == Governance.SHADOW.value:
        base *= 0.50
        factors.append("shadow x0.50")
    if anomaly_patterns and "ZOMBIE_TRAFFIC_SPIKE" in anomaly_patterns:
        base *= 0.25
        factors.append("under reconnaissance x0.25")
    if internet_reachable:
        base *= 0.50
        factors.append("internet reachable x0.50")

    return max(1, round(base)), factors
