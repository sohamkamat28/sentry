"""Clock, policy, audit, and pipeline control."""

from __future__ import annotations


from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session


from sentry_worker.engines import cdri as cdri_engine
from sentry_worker.pipeline import STAGE_DEPS, STAGE_NAMES, topological_order
from sentry_core import clock, live
from sentry_core.config import settings
from sentry_core.db import get_session
from sentry_core.enums import Source
from sentry_core.models import (
    AuditEntry,
    Cdri,
    Classification,
    Endpoint,
    Observation,
    PipelineRun,
    PolicySetting,
    PolicyWeights,
    StageRun,
)

from ..audit import ledger
from ..bootstrap import current_weights
from .. import contracts
from ..errors import NotFound, ValidationError
from ..security import Claims, admin, analyst, viewer

router = APIRouter(tags=["system"])


# ── clock ────────────────────────────────────────────────────────────────────
@router.get("/clock", responses={200: {"model": contracts.Clock}})
def get_clock(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    vc = clock.ensure_vclock(db)
    return {
        "vday": clock.current_vday(db),
        "scale_seconds": vc.scale_seconds,
        "paused": vc.paused_at is not None,
        "epoch_wall": vc.epoch_wall,
        "real_time": vc.scale_seconds == 86400,
    }


class ClockSet(BaseModel):
    vday: int = Field(ge=0)


@router.post("/clock/set", responses={200: {"model": contracts.ClockSet}})
def set_clock(body: ClockSet, db: Session = Depends(get_session),
              c: Claims = Depends(admin)) -> dict:
    before = clock.current_vday(db)
    after = clock.set_vday(db, body.vday)
    ledger.record(db, actor=c.actor, action="clock.set",
                  detail={"from": before, "to": after})
    db.commit()
    return {"vday": after, "previous": before}


@router.post("/clock/pause", responses={200: {"model": contracts.ClockPause}})
def pause_clock(db: Session = Depends(get_session), c: Claims = Depends(admin)) -> dict:
    v = clock.pause(db)
    ledger.record(db, actor=c.actor, action="clock.paused", detail={"vday": v})
    db.commit()
    return {"vday": v, "paused": True}


@router.post("/clock/resume", responses={200: {"model": contracts.ClockResume}})
def resume_clock(db: Session = Depends(get_session), c: Claims = Depends(admin)) -> dict:
    v = clock.resume(db)
    ledger.record(db, actor=c.actor, action="clock.resumed", detail={"vday": v})
    db.commit()
    return {"vday": v, "paused": False}


# ── policy ───────────────────────────────────────────────────────────────────
@router.get("/policy/weights", responses={200: {"model": contracts.PolicyWeights}})
def get_weights(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    version, weights = current_weights(db)
    history = [
        {"version": r.version, "weights": r.weights, "note": r.note,
         "created_by": r.created_by, "created_at": r.created_at}
        for r in db.execute(
            select(PolicyWeights).order_by(PolicyWeights.version.desc()).limit(20)
        ).scalars()
    ]
    return {
        "version": version,
        "weights": weights,
        "sum": round(sum(weights.values()), 6),
        "defaults": cdri_engine.DEFAULT_WEIGHTS,
        "history": history,
    }


class WeightsUpdate(BaseModel):
    weights: dict[str, float]
    note: str | None = None


@router.post("/policy/weights", responses={200: {"model": contracts.PolicyWeights}})
def set_weights(body: WeightsUpdate, db: Session = Depends(get_session),
                c: Claims = Depends(analyst)) -> dict:
    try:
        cdri_engine.validate_weights(body.weights)
    except cdri_engine.WeightSumError as e:
        # Surfaced with the actual sum so the console can show the residual
        # while a slider is being dragged.
        raise ValidationError("WEIGHTS_MUST_SUM_TO_ONE",
                              f"weights sum to {e.actual:.6f}",
                              {"actual_sum": round(e.actual, 6), "required": 1.0}) from e
    except ValueError as e:
        raise ValidationError("WEIGHTS_INVALID", str(e)) from e

    before_version, before = current_weights(db)
    row = PolicyWeights(weights=dict(body.weights), note=body.note, created_by=c.actor)
    db.add(row)
    db.flush()

    ledger.record(db, actor=c.actor, action="policy.weights.changed",
                  detail={"from_version": before_version, "to_version": row.version,
                          "before": before, "after": body.weights, "note": body.note})
    db.commit()
    return {"version": row.version, "weights": row.weights,
            "note": "estate re-score queued"}


@router.post("/policy/weights/reset", responses={200: {"model": contracts.PolicyWeightsReset}})
def reset_weights(db: Session = Depends(get_session), c: Claims = Depends(analyst)) -> dict:
    row = PolicyWeights(weights=dict(cdri_engine.DEFAULT_WEIGHTS),
                        note="reset to defaults", created_by=c.actor)
    db.add(row)
    db.flush()
    ledger.record(db, actor=c.actor, action="policy.weights.reset",
                  detail={"version": row.version})
    db.commit()
    return {"version": row.version, "weights": row.weights}


@router.get("/policy/settings", responses={200: {"model": contracts.PolicySettings}})
def get_settings_(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    rows = {r.key: r.value for r in db.execute(select(PolicySetting)).scalars()}
    warnings = []
    if settings.window_vdays < 90:
        # Quarterly banking processes are the reason for 90. Lowering it changes
        # what the word "zombie" means.
        warnings.append(
            f"window_vdays is {settings.window_vdays}; below 90 a quarterly batch "
            f"endpoint will classify as a zombie"
        )
    return {"settings": rows, "warnings": warnings}


class SettingUpdate(BaseModel):
    value: dict


@router.put("/policy/settings/{key}", responses={200: {"model": contracts.PolicySettingsKey}})
def put_setting(key: str, body: SettingUpdate, db: Session = Depends(get_session),
                c: Claims = Depends(admin)) -> dict:
    row = db.get(PolicySetting, key)
    before = dict(row.value) if row else None
    if row is None:
        row = PolicySetting(key=key, value=body.value, updated_by=c.actor)
        db.add(row)
    else:
        row.value = body.value
        row.updated_by = c.actor
    ledger.record(db, actor=c.actor, action="policy.setting.changed", target=key,
                  detail={"before": before, "after": body.value})
    db.commit()
    return {"key": key, "value": body.value}


# ── audit ────────────────────────────────────────────────────────────────────
@router.get("/audit", responses={200: {"model": contracts.Audit}})
def list_audit(limit: int = 50, cursor: int | None = None, actor: str | None = None,
               target: str | None = None, db: Session = Depends(get_session),
               _: Claims = Depends(viewer)) -> dict:
    limit = max(1, min(limit, 500))
    stmt = select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(limit + 1)
    if cursor:
        stmt = stmt.where(AuditEntry.seq < cursor)
    if actor:
        stmt = stmt.where(AuditEntry.actor == actor)
    if target:
        stmt = stmt.where(AuditEntry.target == target)

    rows = list(db.execute(stmt).scalars())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {
        "items": [
            {"seq": r.seq, "wall_ts": r.wall_ts, "vday": r.vday, "actor": r.actor,
             "action": r.action, "target": r.target, "detail": r.detail,
             "entry_hash": r.entry_hash.hex()}
            for r in rows
        ],
        "next_cursor": rows[-1].seq if has_more and rows else None,
    }


@router.get("/audit/verify", responses={200: {"model": contracts.AuditVerify}})
def verify_audit(db: Session = Depends(get_session), _: Claims = Depends(admin)) -> dict:
    r = ledger.verify(db)
    return {"ok": r.ok, "entries": r.entries, "broken_at": r.broken_at, "reason": r.reason}


# ── pipeline ─────────────────────────────────────────────────────────────────
@router.get("/pipeline", responses={200: {"model": contracts.Pipeline}})
def pipeline_status(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    run = db.execute(
        select(PipelineRun).order_by(PipelineRun.id.desc()).limit(1)
    ).scalar_one_or_none()
    stages = []
    if run:
        by_stage = {s.stage: s for s in db.execute(
            select(StageRun).where(StageRun.run_id == run.id)).scalars()}
        for n in topological_order():
            s = by_stage.get(n)
            stages.append({
                "stage": n, "name": STAGE_NAMES.get(n, "?"),
                "depends_on": sorted(STAGE_DEPS.get(n, [])),
                "ok": s.ok if s else None,
                "records": s.records if s else 0,
                "duration_ms": s.duration_ms if s else 0,
                "error": s.error if s else None,
            })
    else:
        stages = [{"stage": n, "name": STAGE_NAMES.get(n, "?"),
                   "depends_on": sorted(STAGE_DEPS.get(n, [])), "ok": None,
                   "records": 0, "duration_ms": 0, "error": None}
                  for n in topological_order()]

    return {
        "vday": clock.current_vday(db),
        "run": {"id": run.id, "trigger": run.trigger, "started_at": run.started_at,
                "finished_at": run.finished_at, "ok": run.ok} if run else None,
        "stages": stages,
        "order": topological_order(),
    }


# ── live ─────────────────────────────────────────────────────────────────────
#: Components whose liveness an operator judges the estate by, and the source
#: row that proves each one is doing its job. A component is assessed on
#: evidence it produced, not on a heartbeat it sent — a sensor that reports
#: healthy while capturing nothing is the failure this whole system exists to
#: catch, and it must not be able to hide behind its own status field.
_HEALTH_SOURCES = {
    "agent": Source.EBPF,
    "gateway": Source.GATEWAY,
    "code": Source.CODE,
    "legacy": Source.LEGACY,
}

#: How stale the newest row from a source may be before its component is
#: doubted, expressed in virtual days so it tracks VCLOCK_SCALE_SECONDS. The
#: collectors run once per pipeline pass and the sensor runs continuously, so
#: the sensor gets the tighter window.
_STALE_VDAYS = {"agent": 2, "gateway": 12, "code": 12, "legacy": 12}


@router.get("/live", responses={200: {"model": contracts.Live}})
def live_status(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    """The capture stream, the pipeline in flight, and what is actually alive.

    Polled at a couple of seconds, which is why it reads Redis rather than
    counting rows: `ingest/internal/store/live.go` already increments
    `live:src:<source>` on the capture hot path for exactly this purpose, and
    its comment has called them "the console's capture stream" since they were
    written. Nothing has ever read them — this route is the missing half.

    **`None` and `0` are different answers and this must never fold them
    together.** `live_counts` returns None when the cache cannot answer and a
    zero when nothing was captured; rendering the first as the second turns a
    Redis outage into a report of an idle estate, which is precisely the class
    of lie the rest of the product refuses to tell. The `source` field carries
    which one happened, and the console renders them differently.

    Postgres is the fallback and is authoritative when it answers: the counters
    are a cache with a TTL, and every number here has `SELECT count(*) FROM
    observation` behind it.
    """
    vday = clock.current_vday(db)
    sources = [s.value for s in Source]

    counts = live.live_counts(vday, sources)
    if counts is not None:
        origin = "redis"
    else:
        # Not an error, and not zero. The authoritative count for this vday,
        # named as such so the operator knows the fast path is down.
        rows = db.execute(
            select(Observation.source, func.count())
            .where(Observation.vday == vday)
            .group_by(Observation.source)
        ).all()
        by_source = {s.value if hasattr(s, "value") else str(s): n for s, n in rows}
        counts = {"total": sum(by_source.values())}
        counts.update({s: by_source.get(s, 0) for s in sources})
        origin = "postgres" if live.client() is None else "unavailable"

    # Per-component liveness, from the newest evidence each one produced.
    health = []
    for name, source in _HEALTH_SOURCES.items():
        last = db.execute(
            select(func.max(Observation.vday)).where(Observation.source == source)
        ).scalar_one_or_none()
        behind = None if last is None else vday - last
        if last is None:
            state = "unknown"
        elif behind is not None and behind <= _STALE_VDAYS[name]:
            state = "ok"
        else:
            state = "stale"
        health.append({"component": name, "state": state,
                       "last_vday": last, "vdays_behind": behind})

    # Redis is judged on reachability rather than on evidence: it holds no
    # observations of its own, and a cache that is down degrades the console
    # without degrading the estate.
    health.append({
        "component": "redis",
        "state": "ok" if live.ping() else ("off" if live.client() is None else "down"),
        "last_vday": None, "vdays_behind": None,
    })

    run = db.execute(
        select(PipelineRun).order_by(PipelineRun.id.desc()).limit(1)
    ).scalar_one_or_none()
    done = 0
    if run is not None:
        done = db.execute(
            select(func.count()).select_from(StageRun)
            .where(StageRun.run_id == run.id, StageRun.ok.is_not(None))
        ).scalar_one()

    return {
        "vday": vday,
        "scale_seconds": settings.vclock_scale_seconds,
        "observed": counts,
        # Which store answered. A console that cannot tell these apart cannot
        # tell a quiet estate from a blind one.
        "source": origin,
        "counters": live.counters(["sentry_scan_skipped_total"]),
        "health": health,
        "pipeline": {
            "run_id": run.id if run else None,
            "trigger": run.trigger if run else None,
            "started_at": run.started_at if run else None,
            "ok": run.ok if run else None,
            # ok is None while a cycle is still in flight, which is what makes
            # this a live readout rather than a report of the last one.
            "running": bool(run is not None and run.ok is None),
            "stages_done": done,
            "stages_total": len(topological_order()),
        },
    }


@router.get("/system", responses={200: {"model": contracts.System}})
def system_summary(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    """Status bar: the numbers an operator wants without opening a surface."""
    total = db.execute(select(func.count()).select_from(Endpoint)).scalar_one()
    retired = db.execute(
        select(func.count()).select_from(Endpoint).where(Endpoint.retired.is_(True))
    ).scalar_one()
    by_life = dict(db.execute(
        select(Classification.lifecycle, func.count()).group_by(Classification.lifecycle)
    ).all())
    by_gov = dict(db.execute(
        select(Classification.governance, func.count()).group_by(Classification.governance)
    ).all())
    by_tier = dict(db.execute(
        select(Cdri.tier, func.count()).group_by(Cdri.tier)
    ).all())
    mean_cdri = db.execute(select(func.avg(Cdri.score))).scalar_one()

    return {
        "org": settings.org_name,
        "vday": clock.current_vday(db),
        "endpoints": total,
        "retired": retired,
        "lifecycle": {str(getattr(k, "value", k)): v for k, v in by_life.items()},
        "governance": {str(getattr(k, "value", k)): v for k, v in by_gov.items()},
        "tiers": {str(getattr(k, "value", k)): v for k, v in by_tier.items()},
        "mean_cdri": round(float(mean_cdri), 4) if mean_cdri is not None else None,
    }
