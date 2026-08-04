"""Stage 05 — Behavioural Intelligence.

Isolation Forest over per-endpoint call features, producing r6 — the sixth CDRI
input.

Runs *before* stage 06. In the source architecture CDRI sat at stage 5 and
consumed an input stage 6 produced, which is a linear pipeline reading from its
own future. The order is enforced by STAGE_DEPS, not by convention.

Isolation Forest construction and the psi = 256 subsample follow Liu, Ting &
Zhou, *Isolation-Based Anomaly Detection*, ACM TKDD 6(1), 2012.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from sentry_core.config import settings

VERSION = "beh-1.0.0"

FEATURE_NAMES = [
    "call_frequency_hourly",
    "payload_size_mean",
    "payload_size_cv",
    "auth_missing_ratio",
    "source_ip_entropy",
    "error_ratio",
    "tod_concentration",
]


@dataclass
class Series:
    endpoint_id: str
    calls: list[int]
    resp_bytes: list[int]
    err_calls: list[int]
    auth_missing: list[int]
    hour_histogram: list[int]
    peer_counts: list[int]
    auth: str = "none"


def _gini(values: list[float]) -> float:
    """Concentration of the daily rhythm.

    Distinguishes a steady service from a nightly batch — two endpoints with
    identical daily volume and completely different behaviour.
    """
    v = sorted(float(x) for x in values)
    n = len(v)
    total = sum(v)
    if n == 0 or total <= 0:
        return 0.0
    cum = sum((i + 1) * x for i, x in enumerate(v))
    return max(0.0, min(1.0, (2 * cum) / (n * total) - (n + 1) / n))


def _entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


def extract(s: Series) -> dict[str, float]:
    n = max(1, len(s.calls))
    total_calls = sum(s.calls)

    mean_bytes = float(np.mean(s.resp_bytes)) if s.resp_bytes else 0.0
    std_bytes = float(np.std(s.resp_bytes)) if s.resp_bytes else 0.0
    # Magnitude and variability are separate features: a zombie returning the
    # same volume in a different shape is the exfiltration signal, and one
    # moment cannot express it.
    cv = (std_bytes / mean_bytes) if mean_bytes > 0 else 0.0

    return {
        "call_frequency_hourly": total_calls / (n * 24.0),
        "payload_size_mean": mean_bytes,
        "payload_size_cv": cv,
        "auth_missing_ratio": (sum(s.auth_missing) / total_calls) if total_calls else 0.0,
        "source_ip_entropy": _entropy(s.peer_counts),
        "error_ratio": (sum(s.err_calls) / total_calls) if total_calls else 0.0,
        "tod_concentration": _gini([float(x) for x in s.hour_histogram]),
    }


def trailing_zero_vdays(calls: list[int], before: int = 7) -> int:
    """Consecutive silent vdays immediately preceding the trailing window."""
    head = calls[:-before] if before and len(calls) > before else calls
    count = 0
    for v in reversed(head):
        if v > 0:
            break
        count += 1
    return count


def patterns_for(s: Series, feats: dict[str, float]) -> list[str]:
    """Named patterns run alongside the forest.

    The forest says how anomalous, not why. These three encode domain knowledge
    seven features cannot learn, and give the console a reason rather than a
    number.
    """
    out: list[str] = []

    silent = trailing_zero_vdays(s.calls, before=7)
    if silent >= 60 and sum(s.calls[-7:]) >= settings.spike_min_calls:
        out.append("ZOMBIE_TRAFFIC_SPIKE")

    # An endpoint with no auth configured is not anomalous for serving
    # unauthenticated requests — that is its documented behaviour, and CDRI
    # already charges 0.28 for it. Flagging it here would double-count.
    if feats["auth_missing_ratio"] > settings.auth_anomaly_ratio and s.auth != "none":
        out.append("AUTH_SEQUENCE")

    if feats["payload_size_cv"] > settings.payload_cv_threshold and len(s.resp_bytes) >= 14:
        recent = float(np.mean(s.resp_bytes[-7:]))
        baseline = float(np.mean(s.resp_bytes[:-7])) or 1.0
        if recent > baseline * 3:
            out.append("PAYLOAD_DEVIATION")

    return out


@dataclass
class Result:
    endpoint_id: str
    flag: bool
    score: float
    isolation_depth: float
    patterns: list[str] = field(default_factory=list)
    features: dict = field(default_factory=dict)


@dataclass
class RunReport:
    results: list[Result]
    fitted: bool
    fitted_on: int
    excluded_insufficient_history: int
    params: dict


def run(series: list[Series]) -> RunReport:
    eligible = [s for s in series if len(s.calls) >= settings.min_series_vdays]
    excluded = [s for s in series if len(s.calls) < settings.min_series_vdays]

    results: list[Result] = []
    for s in excluded:
        # Fitting a forest on three points and reporting the result as a verdict
        # would be fabrication. Report the exclusion instead.
        results.append(Result(s.endpoint_id, False, 0.0, 0.0,
                              ["INSUFFICIENT_HISTORY"], extract(s)))

    if not eligible:
        return RunReport(results, False, 0, len(excluded), _params())

    feats = [extract(s) for s in eligible]

    if len(eligible) < settings.min_fit_endpoints:
        # A forest on twelve points is noise. Pattern rules still run, and the
        # API reports that the model was not fitted.
        for s, f in zip(eligible, feats):
            pats = patterns_for(s, f)
            results.append(Result(s.endpoint_id, bool(pats), 0.0, 0.0, pats, f))
        return RunReport(results, False, 0, len(excluded), _params())

    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler

    x = np.array([[f[k] for k in FEATURE_NAMES] for f in feats], dtype=float)

    # RobustScaler, not StandardScaler: banking traffic is heavily skewed and a
    # handful of endpoints carry orders of magnitude more calls than the rest.
    # Mean/variance scaling lets those dominate every axis.
    scaler = RobustScaler()
    xs = scaler.fit_transform(x)
    xs = np.nan_to_num(xs, nan=0.0, posinf=0.0, neginf=0.0)

    forest = IsolationForest(
        n_estimators=settings.anomaly_n_estimators,
        max_samples=min(settings.anomaly_max_samples, len(xs)),
        contamination=settings.anomaly_contamination,
        random_state=settings.anomaly_seed,  # identical inputs, identical verdicts
        n_jobs=-1,
    )
    forest.fit(xs)
    raw = forest.score_samples(xs)
    forest_flags = forest.predict(xs) == -1

    for s, f, r, ff in zip(eligible, feats, raw, forest_flags):
        pats = patterns_for(s, f)
        depth = -math.log2(max(1e-9, -float(r)))
        results.append(Result(
            endpoint_id=s.endpoint_id,
            flag=bool(ff) or bool(pats),
            score=round(float(r), 6),
            isolation_depth=round(depth, 4),
            patterns=pats,
            features=f,
        ))

    return RunReport(results, True, len(eligible), len(excluded), _params())


def _params() -> dict:
    return {
        "n_estimators": settings.anomaly_n_estimators,
        "max_samples": settings.anomaly_max_samples,
        "contamination": settings.anomaly_contamination,
        "seed": settings.anomaly_seed,
        "features": FEATURE_NAMES,
        "engine_version": VERSION,
    }
