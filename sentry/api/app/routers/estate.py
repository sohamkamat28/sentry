"""Analytical read surfaces: discovery through impact."""

from __future__ import annotations


from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session


from sentry_core import clock
from sentry_core.config import settings
from sentry_core.db import get_session
from sentry_core.enums import Source
from sentry_core.models import (
    Anomaly,
    Blast,
    Cdri,
    Classification,
    Endpoint,
    EndpointDaily,
    EndpointSource,
    Finding,
    Forecast,
    Observation,
    Ownership,
    Service,
    StageRun,
)

from .. import contracts
from ..errors import NotFound
from ..security import Claims, viewer

router = APIRouter(tags=["estate"])


def _shadow_ids(db: Session) -> set[str]:
    """Shadow is defined once, here, in SQL: known to us by any sensor, absent
    from the gateway registry AND absent from every code repository.

    The starting set is every endpoint we have discovered, not only the ones the
    kernel probe saw. Anchoring it to eBPF made this disagree with the engine
    that actually assigns governance: `classification.governance_for` asks only
    "in no gateway and no code", regardless of which sensor found the endpoint,
    so a SOAP operation discovered by the legacy inventory scan and registered
    nowhere was SHADOW on the estate and invisible to this count.

    The console showed both numbers on one screen — `shadow 33` in the header
    from the classification totals, `SHADOW 32` in the tile from here — which
    reads as one of them being wrong, and one of them was. They are now the same
    set by construction, and `test_shadow_count_matches_classification` holds
    them together.
    """
    known = select(EndpointSource.endpoint_id).distinct()
    gw = select(EndpointSource.endpoint_id).where(EndpointSource.source == Source.GATEWAY)
    code = select(EndpointSource.endpoint_id).where(EndpointSource.source == Source.CODE)
    return set(db.execute(known).scalars()) - set(db.execute(gw).scalars()) - set(
        db.execute(code).scalars())


def _gateway_healthy(db: Session) -> bool:
    """When the gateway collector has produced nothing, absence from the gateway
    is unproven and no SHADOW verdict may rest on it."""
    return db.execute(
        select(func.count()).select_from(EndpointSource)
        .where(EndpointSource.source == Source.GATEWAY)
    ).scalar_one() > 0


# ── stage 01 ─────────────────────────────────────────────────────────────────
@router.get("/discovery", responses={200: {"model": contracts.Discovery}})
def discovery(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    vday = clock.current_vday(db)
    per_source = dict(db.execute(
        select(EndpointSource.source, func.count()).group_by(EndpointSource.source)
    ).all())

    all_ids = {s: set(db.execute(
        select(EndpointSource.endpoint_id).where(EndpointSource.source == s)).scalars())
        for s in Source}

    sources = []
    for s in Source:
        others = set().union(*(v for k, v in all_ids.items() if k is not s)) if len(all_ids) > 1 else set()
        obs = db.execute(
            select(func.count()).select_from(Observation)
            .where(Observation.source == s, Observation.vday >= vday - 1)
        ).scalar_one()
        sources.append({
            "source": s.value,
            "endpoints": per_source.get(s, 0),
            "observations_24v": obs,
            "exclusive": len(all_ids[s] - others),
            "healthy": per_source.get(s, 0) > 0,
        })

    return {
        "vday": vday,
        "sources": sources,
        "shadow_reliable": _gateway_healthy(db),
        "shadow_count": len(_shadow_ids(db)),
    }


# ── stage 02 ─────────────────────────────────────────────────────────────────
@router.get("/baseline", responses={200: {"model": contracts.Baseline}})
def baseline(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    vday = clock.current_vday(db)
    conf = dict(db.execute(
        select(Classification.confidence, func.count()).group_by(Classification.confidence)
    ).all())
    total = db.execute(select(func.count()).select_from(Endpoint)).scalar_one()
    confirmed = db.execute(
        select(func.count()).select_from(Classification)
        .where(Classification.confidence == "CONFIRMED")
    ).scalar_one()
    growth = [
        {"vday": v, "n": n} for v, n in db.execute(
            select(Endpoint.first_vday, func.count()).group_by(Endpoint.first_vday)
            .order_by(Endpoint.first_vday)
        ).all()
    ]
    return {
        "vday": vday,
        "registry_size": total,
        "confidence": {str(getattr(k, "value", k)): v for k, v in conf.items()},
        "growth": growth,
        "verdicts_permitted": bool(conf),
        "decommission_permitted": confirmed,
    }


@router.get("/baseline/{endpoint_id}/series", responses={200: {"model": contracts.BaselineEndpointIdSeries}})
def series(endpoint_id: str, db: Session = Depends(get_session),
           _: Claims = Depends(viewer)) -> dict:
    rows = list(db.execute(
        select(EndpointDaily).where(EndpointDaily.endpoint_id == endpoint_id)
        .order_by(EndpointDaily.vday)
    ).scalars())
    if not rows:
        raise NotFound("SERIES_NOT_FOUND", f"no daily series for {endpoint_id}")
    return {
        "endpoint_id": endpoint_id,
        "series": [{"vday": r.vday, "calls": r.calls, "errors": r.err_calls,
                    "p95_latency_us": r.p95_latency_us} for r in rows],
    }


# ── stage 03 ─────────────────────────────────────────────────────────────────
@router.get("/correlation", responses={200: {"model": contracts.Correlation}})
def correlation(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    sightings = db.execute(select(func.count()).select_from(EndpointSource)).scalar_one()
    endpoints = db.execute(select(func.count()).select_from(Endpoint)).scalar_one()
    resolved_by = dict(db.execute(
        select(Ownership.resolved_by, func.count()).group_by(Ownership.resolved_by)
    ).all())
    unreachable = db.execute(
        select(func.count()).select_from(Ownership).where(Ownership.reachable.is_(False))
    ).scalar_one()
    return {
        "sightings": sightings,
        "endpoints": endpoints,
        "dedup_ratio": round(sightings / endpoints, 3) if endpoints else 0,
        "ownership": {"resolved_by": resolved_by, "unreachable": unreachable},
        "shadow_reliable": _gateway_healthy(db),
        "window_vdays": 90,
    }


@router.get("/correlation/{endpoint_id}/ownership", responses={200: {"model": contracts.CorrelationEndpointIdOwnership}})
def ownership(endpoint_id: str, db: Session = Depends(get_session),
              _: Claims = Depends(viewer)) -> dict:
    o = db.get(Ownership, endpoint_id)
    if o is None:
        raise NotFound("OWNERSHIP_NOT_FOUND", f"no ownership record for {endpoint_id}")
    return {
        "endpoint_id": endpoint_id, "owner_email": o.owner_email, "owner_team": o.owner_team,
        "resolved_by": o.resolved_by, "confidence": o.confidence, "reachable": o.reachable,
        "escalation": o.escalation, "ladder": o.ladder,
    }


# ── stage 04 ─────────────────────────────────────────────────────────────────
@router.get("/classification", responses={200: {"model": contracts.Classification}})
def classification(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    matrix = [
        {"lifecycle": str(getattr(lc, "value", lc)),
         "governance": str(getattr(gv, "value", gv)), "n": n}
        for lc, gv, n in db.execute(
            select(Classification.lifecycle, Classification.governance, func.count())
            .group_by(Classification.lifecycle, Classification.governance)
        ).all()
    ]
    conf = dict(db.execute(
        select(Classification.confidence, func.count()).group_by(Classification.confidence)
    ).all())
    return {
        "vday": clock.current_vday(db),
        "matrix": matrix,
        "confidence": {str(getattr(k, "value", k)): v for k, v in conf.items()},
        "shadow_reliable": _gateway_healthy(db),
    }


@router.get("/classification/{endpoint_id}", responses={200: {"model": contracts.ClassificationEndpointId}})
def classification_detail(endpoint_id: str, db: Session = Depends(get_session),
                          _: Claims = Depends(viewer)) -> dict:
    c = db.get(Classification, endpoint_id)
    if c is None:
        raise NotFound("CLASSIFICATION_NOT_FOUND",
                       "no verdict — the endpoint may be below baseline confidence")
    return {
        "endpoint_id": endpoint_id,
        "lifecycle": c.lifecycle.value, "governance": c.governance.value,
        "confidence": c.confidence.value, "severity_bump": c.severity_bump,
        "pre_zombie": c.pre_zombie, "trace": c.trace,
        "vday": c.vday, "engine_version": c.engine_version,
    }


# ── register ─────────────────────────────────────────────────────────────────
@router.get("/estate", responses={200: {"model": contracts.Estate}})
def estate(
    lifecycle: str | None = None, governance: str | None = None,
    tier: str | None = None, team: str | None = None, q: str | None = None,
    limit: int = Query(50, ge=1, le=500), cursor: str | None = None,
    db: Session = Depends(get_session), _: Claims = Depends(viewer),
) -> dict:
    stmt = (
        select(Endpoint, Classification, Cdri, Service)
        .join(Service, Service.id == Endpoint.service_id)
        .outerjoin(Classification, Classification.endpoint_id == Endpoint.id)
        .outerjoin(Cdri, Cdri.endpoint_id == Endpoint.id)
    )
    if lifecycle:
        stmt = stmt.where(Classification.lifecycle == lifecycle)
    if governance:
        stmt = stmt.where(Classification.governance == governance)
    if tier:
        stmt = stmt.where(Cdri.tier == tier)
    if team:
        stmt = stmt.where(Service.team == team)
    if q:
        stmt = stmt.where(Endpoint.path_template.ilike(f"%{q}%"))
    if cursor:
        stmt = stmt.where(Endpoint.id > cursor)

    stmt = stmt.order_by(Cdri.score.desc().nullslast(), Endpoint.id).limit(limit + 1)
    rows = list(db.execute(stmt).all())
    has_more = len(rows) > limit
    rows = rows[:limit]

    return {
        "items": [
            {
                "id": e.id, "method": e.method, "path": e.path_template,
                "service": s.name, "team": s.team, "criticality": s.criticality.value,
                "auth": e.auth.value, "tls_version": e.tls_version,
                "rate_limited": e.rate_limited, "data_classes": e.data_classes,
                "last_call_vday": e.last_call_vday, "retired": e.retired,
                "lifecycle": c.lifecycle.value if c else None,
                "governance": c.governance.value if c else None,
                "confidence": c.confidence.value if c else None,
                "pre_zombie": c.pre_zombie if c else False,
                "cdri": d.score if d else None,
                "tier": d.tier.value if d else None,
                "time_to_breach_d": d.time_to_breach_d if d else None,
            }
            for e, c, d, s in rows
        ],
        "next_cursor": rows[-1][0].id if has_more and rows else None,
    }


@router.get("/estate/{endpoint_id}", responses={200: {"model": contracts.EstateEndpointId}})
def endpoint_detail(endpoint_id: str, db: Session = Depends(get_session),
                    _: Claims = Depends(viewer)) -> dict:
    e = db.get(Endpoint, endpoint_id)
    if e is None:
        raise NotFound("ENDPOINT_NOT_FOUND", endpoint_id)
    svc = db.get(Service, e.service_id)
    c = db.get(Classification, endpoint_id)
    d = db.get(Cdri, endpoint_id)
    a = db.get(Anomaly, endpoint_id)
    f = db.get(Forecast, endpoint_id)
    b = db.get(Blast, endpoint_id)
    o = db.get(Ownership, endpoint_id)
    sources = [s.source.value for s in db.execute(
        select(EndpointSource).where(EndpointSource.endpoint_id == endpoint_id)).scalars()]

    return {
        "id": e.id, "method": e.method, "path": e.path_template,
        "service": {"id": svc.id, "name": svc.name, "team": svc.team,
                    "criticality": svc.criticality.value} if svc else None,
        "auth": e.auth.value, "tls_version": e.tls_version, "rate_limited": e.rate_limited,
        "data_classes": e.data_classes, "deprecated": e.deprecated,
        "internet_reachable": e.internet_reachable, "retired": e.retired,
        "honeypot_active": e.honeypot_active,
        "first_vday": e.first_vday, "last_call_vday": e.last_call_vday,
        "total_calls": e.total_calls, "sources": sources,
        "classification": {"lifecycle": c.lifecycle.value, "governance": c.governance.value,
                           "confidence": c.confidence.value, "pre_zombie": c.pre_zombie,
                           "severity_bump": c.severity_bump, "trace": c.trace} if c else None,
        "cdri": {"score": d.score, "tier": d.tier.value, "parts": d.parts,
                 "weights_version": d.weights_version,
                 "time_to_breach": {"days": d.time_to_breach_d, "basis": "heuristic",
                                    "factors": d.ttb_factors}} if d else None,
        "anomaly": {"flag": a.flag, "score": a.score, "patterns": a.patterns,
                    "features": a.features} if a else None,
        "forecast": {"days_to_zombie": f.days_to_zombie, "slope": f.slope,
                     "signals": f.signals, "deseasonalised": f.deseasonalised} if f else None,
        "blast": {"tier": b.tier.value, "direct_callers": b.direct_callers,
                  "hop2_callers": b.hop2_callers, "touches_critical": b.touches_critical,
                  "in_graph": b.in_graph, "hop_limit": b.hop_limit,
                  "affected": b.affected} if b else None,
        "ownership": {"owner_email": o.owner_email, "reachable": o.reachable,
                      "confidence": o.confidence, "resolved_by": o.resolved_by,
                      "escalation": o.escalation, "ladder": o.ladder} if o else None,
    }


# ── stages 05-09 read surfaces ───────────────────────────────────────────────
@router.get("/behaviour", responses={200: {"model": contracts.Behaviour}})
def behaviour(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    flagged = list(db.execute(select(Anomaly).where(Anomaly.flag.is_(True))).scalars())
    pattern_counts: dict[str, int] = {}
    for a in db.execute(select(Anomaly)).scalars():
        for p in a.patterns:
            pattern_counts[p] = pattern_counts.get(p, 0) + 1
    total = db.execute(select(func.count()).select_from(Anomaly)).scalar_one()

    # Whether the model fitted at all, taken from the stage's own last run.
    #
    # Without this the response reads "scored 15, flagged 0" — which an operator
    # is entitled to read as "fifteen endpoints checked, none anomalous". When
    # the forest never fitted, nothing was checked: the correct claim is that
    # the estate is below the sample size the model requires, and no verdict has
    # been formed either way.
    last = db.execute(
        select(StageRun).where(StageRun.stage == 5)
        .order_by(StageRun.id.desc()).limit(1)
    ).scalar_one_or_none()
    detail = (last.detail or {}) if last else {}
    fitted = bool(detail.get("fitted"))

    return {
        "fitted": fitted,
        "fitted_on": detail.get("fitted_on", 0),
        "min_fit_endpoints": settings.min_fit_endpoints,
        "withheld": None if fitted else (
            f"the isolation forest requires {settings.min_fit_endpoints} endpoints "
            f"with sufficient history and fitted on {detail.get('fitted_on', 0)}; "
            f"no anomaly verdict has been formed for any endpoint"),
        # None, not 0, when nothing was fitted. A zero here is a measurement.
        "flagged": len(flagged) if fitted else None,
        "scored": total if fitted else None,
        "patterns": pattern_counts,
        "excluded_insufficient_history": pattern_counts.get("INSUFFICIENT_HISTORY", 0),
        "items": [{"endpoint_id": a.endpoint_id, "score": a.score,
                   "isolation_depth": a.isolation_depth, "patterns": a.patterns}
                  for a in flagged],
    }


@router.get("/risk", responses={200: {"model": contracts.Risk}})
def risk(limit: int = Query(50, ge=1, le=500), tier: str | None = None,
         db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    stmt = select(Cdri, Endpoint).join(Endpoint, Endpoint.id == Cdri.endpoint_id)
    if tier:
        stmt = stmt.where(Cdri.tier == tier)
    rows = list(db.execute(stmt.order_by(Cdri.score.desc()).limit(limit)).all())
    return {
        "items": [
            {"endpoint_id": d.endpoint_id, "method": e.method, "path": e.path_template,
             "score": d.score, "tier": d.tier.value, "parts": d.parts,
             "weights_version": d.weights_version,
             "time_to_breach": {"days": d.time_to_breach_d, "basis": "heuristic",
                                "factors": d.ttb_factors}}
            for d, e in rows
        ]
    }


@router.get("/forecast", responses={200: {"model": contracts.Forecast}})
def forecast(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    rows = list(db.execute(
        select(Forecast, Endpoint).join(Endpoint, Endpoint.id == Forecast.endpoint_id)
        .where(Forecast.days_to_zombie.isnot(None))
        .order_by(Forecast.days_to_zombie)
    ).all())
    active = db.execute(
        select(func.count()).select_from(Classification)
        .where(Classification.lifecycle == "ACTIVE")
    ).scalar_one()
    flagged = db.execute(
        select(func.count()).select_from(Classification)
        .where(Classification.pre_zombie.is_(True))
    ).scalar_one()
    return {
        "flagged": flagged,
        "active": active,
        "flagged_ratio": round(flagged / active, 4) if active else 0.0,
        "items": [{"endpoint_id": f.endpoint_id, "method": e.method, "path": e.path_template,
                   "days_to_zombie": f.days_to_zombie, "slope": f.slope,
                   "signals": f.signals, "deseasonalised": f.deseasonalised}
                  for f, e in rows],
    }


@router.get("/forecast/{endpoint_id}", responses={200: {"model": contracts.ForecastEndpointId}})
def forecast_detail(endpoint_id: str, db: Session = Depends(get_session),
                    _: Claims = Depends(viewer)) -> dict:
    f = db.get(Forecast, endpoint_id)
    if f is None:
        raise NotFound("FORECAST_NOT_FOUND", endpoint_id)
    # Observed and deseasonalised are returned together so the console can show
    # both lines: the operator sees the correction rather than being told of it.
    return {
        "endpoint_id": endpoint_id, "days_to_zombie": f.days_to_zombie,
        "slope": f.slope, "level": f.level, "signals": f.signals,
        "deseasonalised": f.deseasonalised, "observed": f.observed,
        "adjusted": f.adjusted, "projection": f.projection,
    }


@router.get("/findings", responses={200: {"model": contracts.Findings}})
def findings(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    sub = select(Finding.endpoint_id, func.max(Finding.vday).label("v")).group_by(
        Finding.endpoint_id).subquery()
    rows = list(db.execute(
        select(Finding, Endpoint)
        .join(sub, (Finding.endpoint_id == sub.c.endpoint_id) & (Finding.vday == sub.c.v))
        .join(Endpoint, Endpoint.id == Finding.endpoint_id)
    ).all())
    by_gen: dict[str, int] = {}
    for f, _e in rows:
        by_gen[f.generator] = by_gen.get(f.generator, 0) + 1
    return {
        "generators": by_gen,
        "items": [{"id": f.id, "endpoint_id": f.endpoint_id, "method": e.method,
                   "path": e.path_template, "generator": f.generator, "model": f.model,
                   "narrative": f.narrative, "regulations": f.regulations,
                   "time_to_breach_d": f.time_to_breach_d, "vday": f.vday}
                  for f, e in rows],
    }


@router.get("/findings/frameworks", responses={200: {"model": contracts.FindingsFrameworks}})
def framework_coverage(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    from sentry_worker.engines.frameworks import FRAMEWORKS

    counts = {f: 0 for f in FRAMEWORKS}
    for f in db.execute(select(Finding)).scalars():
        for cite in f.regulations:
            if cite.get("status") == "VIOLATED":
                counts[cite["framework"]] = counts.get(cite["framework"], 0) + 1
    return {"frameworks": list(FRAMEWORKS), "violations": counts}


@router.get("/impact/{endpoint_id}", responses={200: {"model": contracts.ImpactEndpointId}})
def impact(endpoint_id: str, db: Session = Depends(get_session),
           _: Claims = Depends(viewer)) -> dict:
    b = db.get(Blast, endpoint_id)
    if b is None:
        raise NotFound("IMPACT_NOT_ANALYSED", "run stage 09 for this endpoint")
    from sentry_worker.engines.blast import BlastResult, retirement_path
    from sentry_core.enums import BlastTier

    stub = BlastResult(tier=BlastTier(b.tier.value), direct_callers=b.direct_callers,
                       hop2_callers=b.hop2_callers, affected=b.affected,
                       datastores=b.datastores, touches_critical=b.touches_critical,
                       in_graph=b.in_graph, hop_limit=b.hop_limit)
    return {
        "endpoint_id": endpoint_id, "tier": b.tier.value, "hop_limit": b.hop_limit,
        "direct_callers": b.direct_callers, "hop2_callers": b.hop2_callers,
        "touches_critical": b.touches_critical, "in_graph": b.in_graph,
        "datastores": b.datastores, "affected": b.affected,
        "retirement_path": retirement_path(stub),
    }
