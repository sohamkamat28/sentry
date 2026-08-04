"""Stage 07 — Pre-Zombie Forecast.

Projects call volume forward and flags endpoints on a trajectory to zero, 18-30
vdays before they get there.

Owns ``classification.pre_zombie`` — the one legal back-edge in the pipeline DAG.
Stage 04 evaluates lifecycle from observed history and has no access to a
projection, so it displays this flag rather than producing it.

Prophet is named in the source architecture; Holt is what runs. Holt captures
the trend component this decision needs, adds no heavy compiled dependency, and
is fully inspectable — an operator can be shown the level and the slope. The
seasonality Prophet would model is removed upstream by ``deseasonalise``.
``project`` has a stable signature so substituting Prophet is a drop-in change.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from sentry_core.config import settings

VERSION = "fc-1.0.0"


def deseasonalise(series: list[float], period: int | None = None) -> tuple[list[float], bool]:
    """Remove the weekly component by centred moving average over exactly one period.

    Banking traffic has a hard weekly cycle. Fitting a trend to the raw daily
    series makes the answer depend on which weekday the window happens to end.

    This is not hypothetical: fitting raw daily volume produced *declining*
    verdicts for endpoints whose volume was rising, and flagged 51 of 86 active
    endpoints as pre-zombie. The window ending on a Sunday was doing the work.

    Smoothing over exactly one period is what removes the cycle without eating
    the trend. A longer window flattens genuine decline; a shorter one leaves the
    cycle in.

    Returns (adjusted_series, was_deseasonalised).
    """
    p = period or settings.seasonal_period
    n = len(series)
    if n < p * 2:
        return list(series), False

    # Centred moving average over one full period: the trend-cycle estimate.
    trend: list[float | None] = [None] * n
    half = p // 2
    for i in range(n):
        lo, hi = i - half, i + half
        if p % 2 == 0:
            hi -= 1
        if lo < 0 or hi >= n:
            continue
        trend[i] = sum(series[lo : hi + 1]) / p

    # Ratio-to-trend, averaged per weekday position.
    ratios: list[list[float]] = [[] for _ in range(p)]
    for i in range(n):
        t = trend[i]
        if t and t > 0:
            ratios[i % p].append(series[i] / t)

    seasonal = [
        (sum(vals) / len(vals)) if vals else 1.0
        for vals in ratios
    ]
    mean = sum(seasonal) / p
    if mean <= 0:
        return list(series), False
    seasonal = [s / mean for s in seasonal]

    adjusted = [
        series[i] / seasonal[i % p] if seasonal[i % p] > 1e-9 else series[i]
        for i in range(n)
    ]
    return adjusted, True


@dataclass
class Projection:
    level: float
    slope: float
    points: list[float] = field(default_factory=list)
    deseasonalised: bool = True
    adjusted: list[float] = field(default_factory=list)


def project(
    series: list[float],
    horizon: int | None = None,
    alpha: float | None = None,
    beta: float | None = None,
) -> Projection:
    """Holt linear trend over the deseasonalised series."""
    h = horizon or settings.forecast_horizon
    a = alpha if alpha is not None else settings.forecast_alpha
    b = beta if beta is not None else settings.forecast_beta

    y, was_des = deseasonalise(series)
    if len(y) < 2:
        return Projection(level=float(y[0]) if y else 0.0, slope=0.0,
                          points=[0.0] * h, deseasonalised=was_des, adjusted=y)

    level = y[0]
    trend = y[1] - y[0]
    for t in range(1, len(y)):
        prev = level
        level = a * y[t] + (1 - a) * (level + trend)
        trend = b * (level - prev) + (1 - b) * trend

    points = [max(0.0, level + (k + 1) * trend) for k in range(h)]
    return Projection(level=level, slope=trend, points=points,
                      deseasonalised=was_des, adjusted=y)


def days_to_zombie(proj: Projection, current_silence: int) -> int | None:
    """Vdays until the endpoint *qualifies* as a zombie.

    Not vdays until traffic stops — it adds the silence requirement that follows
    the last call. That is the number an owner can act on.
    """
    if proj.slope >= 0:
        return None  # rising or flat traffic is never on a path to zero
    for k, v in enumerate(proj.points, start=1):
        if v < settings.zombie_floor_calls:
            return k + max(0, settings.zombie_vdays - current_silence)
    return None


def signals(
    proj: Projection,
    series: list[float],
    vdays_since_commit: int | None,
    owner_reachable: bool,
    owner_confidence: float,
) -> dict:
    """Three weighted signals.

    Declining volume alone over-flags: an endpoint can be quiet and actively
    maintained. Requiring a composite floor as well as a projection is what keeps
    the flag actionable — an endpoint being deliberately drained by a migration
    has recent commits and a reachable owner, and is not flagged.
    """
    baseline = max(1.0, (sum(series[-30:]) / max(1, len(series[-30:]))) or 1.0)
    volume = min(1.0, max(0.0, -proj.slope / baseline)) if proj.slope < 0 else 0.0

    if vdays_since_commit is None:
        commit = 0.5
        commit_estimated = True
    else:
        commit = 1.0 - math.exp(-vdays_since_commit / 180.0)
        commit_estimated = False

    if not owner_reachable:
        owner = 1.0
    else:
        owner = max(0.0, 1.0 - owner_confidence)

    composite = 0.50 * volume + 0.30 * commit + 0.20 * owner
    return {
        "call_volume": round(volume, 4),
        "commit_recency": round(commit, 4),
        "commit_estimated": commit_estimated,
        "owner_activity": round(owner, 4),
        "composite": round(composite, 4),
    }


@dataclass
class ForecastResult:
    days_to_zombie: int | None
    pre_zombie: bool
    projection: Projection
    signals: dict


def run_one(
    series: list[float],
    current_silence: int,
    vdays_since_commit: int | None,
    owner_reachable: bool,
    owner_confidence: float,
) -> ForecastResult:
    proj = project(series)
    dtz = days_to_zombie(proj, current_silence)
    sig = signals(proj, series, vdays_since_commit, owner_reachable, owner_confidence)
    flag = (
        dtz is not None
        and dtz <= settings.pre_zombie_horizon
        and sig["composite"] >= settings.pre_zombie_risk_floor
    )
    return ForecastResult(dtz, flag, proj, sig)
