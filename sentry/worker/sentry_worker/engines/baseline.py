"""Stage 02 — Baseline & Confidence.

Rolls raw observations into a daily series and governs when the system is
allowed to have an opinion.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentry_core.config import settings
from sentry_core.enums import Confidence

VERSION = "base-1.0.0"


def confidence(vday: int, first_vday: int, backfilled_vdays: int = 0) -> Confidence:
    """The confidence ramp.

    The source architecture specifies a 30-day baseline while stages 03, 09 and
    11 all reason over 90 days. At go-live that data cannot exist. Rather than
    pretending otherwise, observation age determines what may be concluded:

    * <= 30 vdays: registry construction only. No verdicts of any kind.
    * 31-89 vdays: verdicts computed and stamped PROVISIONAL. Cannot enter the
      decommissioning workflow — enforced at stage 11, not by convention.
    * >= 90 vdays: CONFIRMED.
    """
    observed = (vday - first_vday) + backfilled_vdays
    if observed <= settings.baseline_vdays:
        return Confidence.NONE
    if observed < settings.window_vdays:
        return Confidence.PROVISIONAL
    return Confidence.CONFIRMED


def observed_vdays(vday: int, first_vday: int, backfilled_vdays: int = 0) -> int:
    return max(0, (vday - first_vday) + backfilled_vdays)


@dataclass
class DailyRow:
    endpoint_id: str
    vday: int
    calls: int
    distinct_peers: int
    err_calls: int
    p50_latency_us: int | None
    p95_latency_us: int | None
    mean_resp_bytes: int | None
    auth_missing: int
    hour_histogram: list[int]


def _percentile(values: list[int], q: float) -> int | None:
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(q * (len(s) - 1)))))
    return s[k]


def rollup(
    endpoint_id: str,
    vday: int,
    observations: list[dict],
    peers: set[str] | None = None,
) -> DailyRow:
    """Aggregate one endpoint's observations for one vday.

    Idempotent by construction: the caller upserts, so re-running after stage 03
    backfills unresolved observations produces a corrected row rather than an
    additive one.

    ``peers`` overrides the caller set. It exists because the caller's identity
    and the authoritative call count come from different halves of the same
    exchange: only the client-side sighting knows who called, and counting both
    sides would double every figure. The caller passes the union of names seen
    across both halves alongside the single half it wants counted.
    """
    latencies = [o["latency_us"] for o in observations if o.get("latency_us") is not None]
    sizes = [o["resp_bytes"] for o in observations if o.get("resp_bytes") is not None]
    hours = [0] * 24
    for o in observations:
        ts = o.get("wall_ts")
        if ts is not None:
            hours[ts.hour % 24] += 1

    return DailyRow(
        endpoint_id=endpoint_id,
        vday=vday,
        calls=len(observations),
        distinct_peers=(
            len(peers)
            if peers is not None
            else len({o.get("peer_service") for o in observations if o.get("peer_service")})
        ),
        err_calls=sum(1 for o in observations if (o.get("status") or 0) >= 400),
        p50_latency_us=_percentile(latencies, 0.50),
        p95_latency_us=_percentile(latencies, 0.95),
        mean_resp_bytes=int(sum(sizes) / len(sizes)) if sizes else None,
        auth_missing=sum(1 for o in observations if not o.get("auth_present")),
        hour_histogram=hours,
    )


def materialise_zero_days(
    rows: dict[int, DailyRow],
    endpoint_id: str,
    first_vday: int,
    current_vday: int,
    captured_vdays: set[int] | None = None,
) -> list[DailyRow]:
    """Fill silent vdays with explicit zeros — but only where capture was live.

    A series with missing days produces a different trend slope from one with
    explicit zeros. Gap filling happens here once rather than being re-derived,
    differently, by every consumer.

    ``captured_vdays`` is the set of vdays in which the platform received any
    observation at all, from any endpoint. A vday absent from it is one where
    the sensor was not running, and an endpoint's silence in it says nothing
    about the endpoint. Writing a zero there manufactures evidence of death out
    of a monitoring outage: the virtual clock advances on wall time whether or
    not anything is watching, so a stopped agent, a redeployed node or a
    suspended host would age the entire estate into ZOMBIE and put it in front
    of an operator as a retirement queue.

    Passing ``None`` fills every vday, which is correct only when capture is
    known to have been continuous.
    """
    out: list[DailyRow] = []
    for v in range(first_vday, current_vday + 1):
        if v in rows:
            out.append(rows[v])
        elif captured_vdays is None or v in captured_vdays:
            out.append(DailyRow(endpoint_id, v, 0, 0, 0, None, None, None, 0, [0] * 24))
        # else: no capture that vday, so no row and no claim either way.
    return out


def series_of(rows: list[DailyRow]) -> list[float]:
    return [float(r.calls) for r in sorted(rows, key=lambda r: r.vday)]


def last_call_vday(rows: list[DailyRow]) -> int | None:
    """None for an endpoint discovered in code but never called.

    That is not a zombie — it is unreleased, and stage 04 separates the two.
    """
    called = [r.vday for r in rows if r.calls > 0]
    return max(called) if called else None
