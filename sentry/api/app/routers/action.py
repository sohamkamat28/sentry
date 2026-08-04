"""Mutating surfaces: remediation, decommission, zero-trust, threat, operations.

The analyst/approver boundary sits exactly at the Kong write. An analyst can
generate and prove a control and cannot apply it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session


from sentry_core import clock
from sentry_core.config import settings
from sentry_core.db import get_session
from sentry_core.enums import Confidence, ControlState, Criticality, Lifecycle, Phase
from sentry_core.models import (
    Blast,
    Cdri,
    Certificate,
    ChangeRequest,
    Classification,
    Control,
    Decommission,
    Endpoint,
    Fingerprint,
    GateEvent,
    JudgeRun,
    PipelineRun,
    Probe,
    ResurrectionAlert,
    Service,
)

from ..audit import ledger
from ..bootstrap import setting
from .. import contracts
from ..errors import Conflict, NotFound
from ..security import Claims, analyst, approver, ci_gate, viewer

router = APIRouter(tags=["action"])


def _gateway_route_for(db: Session, endpoint_id: str) -> str | None:
    """Which gateway route fronts an endpoint, read from the gateway now.

    A control attaches to a route, not a service: a service usually fronts
    several endpoints and only one of them was judged. The lookup is live
    because a route can be renamed or removed between the collector pass and an
    approver clicking apply, and attaching a plugin to a stale name either 404s
    or patches the wrong route.
    """
    from sentry_worker.collectors import gateway

    ep = db.get(Endpoint, endpoint_id)
    if ep is None:
        return None
    snapshot = gateway.collect()
    if not snapshot.healthy:
        return None
    # Delegates to the stage 11 runner's implementation.
    #
    # This was a second copy of the same matching logic, and it diverged the
    # moment one of them learned that a SOAP identity carries a `#Operation`
    # fragment no gateway route path contains: the control plane found the route
    # and the runner did not, so hardening reported "no gateway route fronts
    # this endpoint" while apply would have worked. There is one.
    from sentry_worker.runner import _route_for

    return _route_for(snapshot, ep)


# ── stage 10 ─────────────────────────────────────────────────────────────────
@router.get("/remediation", responses={200: {"model": contracts.Remediation}})
def remediation_queue(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    rows = list(db.execute(
        select(Cdri, Endpoint).join(Endpoint, Endpoint.id == Cdri.endpoint_id)
        .where(Cdri.tier.in_(["CRITICAL", "HIGH"]), Endpoint.retired.is_(False))
        .order_by(Cdri.score.desc())
    ).all())
    controls: dict[str, list] = {}
    for c in db.execute(select(Control)).scalars():
        controls.setdefault(c.endpoint_id, []).append(c)

    return {
        "items": [
            {
                "endpoint_id": d.endpoint_id, "method": e.method, "path": e.path_template,
                "score": d.score, "tier": d.tier.value,
                "time_to_breach_d": d.time_to_breach_d,
                "controls": [
                    {"id": c.id, "kind": c.kind, "state": c.state.value,
                     "generator": c.generator, "kong_plugin_id": c.kong_plugin_id}
                    for c in controls.get(d.endpoint_id, [])
                ],
                "applied": sum(
                    1 for c in controls.get(d.endpoint_id, [])
                    if c.state is ControlState.APPLIED
                ),
            }
            for d, e in rows
        ]
    }


@router.get("/remediation/{endpoint_id}", responses={200: {"model": contracts.RemediationEndpointId}})
def remediation_detail(endpoint_id: str, db: Session = Depends(get_session),
                       _: Claims = Depends(viewer)) -> dict:
    if db.get(Endpoint, endpoint_id) is None:
        raise NotFound("ENDPOINT_NOT_FOUND", endpoint_id)

    controls = list(db.execute(
        select(Control).where(Control.endpoint_id == endpoint_id)
        .order_by(Control.id.desc())).scalars())
    judge = {j.id: j for j in db.execute(
        select(JudgeRun).where(JudgeRun.endpoint_id == endpoint_id)).scalars()}
    cr = db.execute(
        select(ChangeRequest).where(ChangeRequest.endpoint_id == endpoint_id)
        .order_by(ChangeRequest.id.desc()).limit(1)).scalar_one_or_none()

    def judge_block(c: Control) -> dict | None:
        j = judge.get(c.judge_run_id) if c.judge_run_id else None
        if j is None:
            return None
        headroom = 0
        if j.budget_us > 0 and j.latency_delta_us > 0:
            headroom = max(0, round(100 * (1 - j.latency_delta_us / j.budget_us)))
        return {
            "verdict": j.verdict, "reason": j.reason,
            "replay": {"requests": j.requests, "exact": j.replay_exact,
                       "schema_synthesised": j.replay_synthesised,
                       "bodyless": j.replay_bodyless,
                       # Bodies were never captured at stage 01, so coverage is
                       # reported rather than implied.
                       "coverage": "partial" if (j.replay_synthesised or j.replay_bodyless)
                       else "exact"},
            "scores": {"schema": j.schema_score, "latency": j.latency_score,
                       "error": j.error_score, "exposure": j.exposure_score},
            "latency_delta_us": j.latency_delta_us, "budget_us": j.budget_us,
            "headroom_pct": headroom,
        }

    return {
        "endpoint_id": endpoint_id,
        "controls": [
            {"id": c.id, "kind": c.kind, "state": c.state.value, "generator": c.generator,
             "plugin_config": c.plugin_config, "kong_plugin_id": c.kong_plugin_id,
             "origin_stage": c.origin_stage, "error": c.error, "actor": c.actor,
             "judge": judge_block(c)}
            for c in controls
        ],
        "change_request": {
            "number": cr.number, "state": cr.state, "sys_id": cr.sys_id, "stub": cr.stub,
        } if cr else None,
    }


class ApplyBody(BaseModel):
    control_id: int


@router.post("/remediation/{endpoint_id}/apply", status_code=202, responses={200: {"model": contracts.RemediationEndpointIdApply}})
def apply_control(endpoint_id: str, body: ApplyBody, db: Session = Depends(get_session),
                  c: Claims = Depends(approver)) -> dict:
    """Queue a Kong write.

    APPLIED is set by the worker only on a 2xx from Kong carrying a plugin id.
    There is no path where a control is recorded as applied without Kong having
    confirmed it.
    """
    ctrl = db.get(Control, body.control_id)
    if ctrl is None or ctrl.endpoint_id != endpoint_id:
        raise NotFound("CONTROL_NOT_FOUND", str(body.control_id))
    if ctrl.state is ControlState.APPLIED:
        raise Conflict("ALREADY_APPLIED", "control is already applied",
                       {"control_id": ctrl.id, "kong_plugin_id": ctrl.kong_plugin_id})
    if ctrl.state is not ControlState.JUDGED:
        raise Conflict("NOT_JUDGED", "a control must pass the API Judge before it is applied",
                       {"state": ctrl.state.value})

    ctrl.actor = c.actor
    ledger.record(db, actor=c.actor, action="control.apply.requested", target=endpoint_id,
                  detail={"control_id": ctrl.id, "kind": ctrl.kind})
    db.commit()

    # Applied here and now, not handed to a queue.
    #
    # This is one HTTP call to the gateway and it either returns a plugin id or
    # it does not. Deferring it to a worker put an unanswerable question between
    # the approver and the outcome — the route returned a task id and 202, and
    # whether the exposure had actually closed was somewhere else. The approver
    # gets the answer in the response that carried their decision.
    from sentry_worker.actuators import control_plane

    route_name = _gateway_route_for(db, ctrl.endpoint_id)
    if route_name is None:
        raise Conflict("NO_GATEWAY_ROUTE",
                       "no gateway route fronts this endpoint, so no gateway "
                       "control can reach it", {"endpoint_id": ctrl.endpoint_id})
    try:
        applied = control_plane.apply(
            db, endpoint_id=ctrl.endpoint_id, route_name=route_name,
            kind=ctrl.kind, plugin_config=ctrl.plugin_config,
            origin_stage=10, actor=c.actor, judge_run_id=ctrl.judge_run_id,
            generator=ctrl.generator)
    except control_plane.ApplyFailed as exc:
        raise Conflict("GATEWAY_REFUSED", str(exc),
                       {"control_id": exc.control.id}) from exc

    # The actuator found this policy already applied and handed back the row
    # that holds the plugin, rather than writing a second row for one plugin.
    #
    # The control the approver clicked is then answered: it is not applied, and
    # it never will be, because there is nothing left for it to do. Leaving it
    # JUDGED would offer the same button again on the next render and put the
    # approver in the loop the actuator was just fixed to break.
    if applied.id != ctrl.id:
        ctrl.state = ControlState.SUPERSEDED
        ctrl.superseded_by = applied.id
        ctrl.error = (
            f"superseded: control {applied.id} already applies this policy "
            f"(plugin {applied.kong_plugin_id})"
        )[:500]
        ledger.record(db, actor=c.actor, action="control.superseded",
                      target=endpoint_id,
                      detail={"control_id": ctrl.id, "kind": ctrl.kind,
                              "superseded_by": applied.id})
        db.commit()

    return {"control_id": applied.id, "state": applied.state.value,
            "kong_plugin_id": applied.kong_plugin_id,
            "superseded_control_id": ctrl.id if applied.id != ctrl.id else None}


@router.post("/remediation/control/{control_id}/revert", status_code=202, responses={200: {"model": contracts.RemediationControlControlIdRevert}})
def revert_control(control_id: int, db: Session = Depends(get_session),
                   c: Claims = Depends(approver)) -> dict:
    ctrl = db.get(Control, control_id)
    if ctrl is None:
        raise NotFound("CONTROL_NOT_FOUND", str(control_id))
    if ctrl.state is not ControlState.APPLIED:
        raise Conflict("NOT_APPLIED", "only an applied control can be reverted",
                       {"state": ctrl.state.value})

    ledger.record(db, actor=c.actor, action="control.revert.requested",
                  target=ctrl.endpoint_id, detail={"control_id": control_id})
    db.commit()

    from sentry_worker.actuators import control_plane

    # Which other rows this removes enforcement for, read before the revert
    # because afterwards they no longer say APPLIED. One plugin can be claimed
    # by more than one control — two endpoints differing only by a SOAP
    # operation fragment share a route — and the approver is told what their
    # click actually took off the gateway.
    also = [c_.id for c_ in db.execute(
        select(Control).where(Control.kong_plugin_id == ctrl.kong_plugin_id,
                              Control.state == ControlState.APPLIED,
                              Control.id != ctrl.id)
    ).scalars()] if ctrl.kong_plugin_id else []

    control_plane.revert(db, ctrl, actor=c.actor, reason="reverted from the console")
    return {"control_id": ctrl.id, "state": ctrl.state.value,
            "also_reverted": also}


# ── stage 11 ─────────────────────────────────────────────────────────────────
@router.get("/decommission", responses={200: {"model": contracts.Decommission}})
def decommission_board(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    rows = list(db.execute(
        select(Decommission, Endpoint).join(Endpoint, Endpoint.id == Decommission.endpoint_id)
    ).all())
    by_phase: dict[str, int] = {}
    for d, _e in rows:
        by_phase[d.phase.value] = by_phase.get(d.phase.value, 0) + 1
    return {
        "vday": clock.current_vday(db),
        "by_phase": by_phase,
        "items": [
            {"endpoint_id": d.endpoint_id, "method": e.method, "path": e.path_template,
             "phase": d.phase.value, "express": d.express, "canary": d.canary,
             "canary_split": d.canary_split, "entered_vday": d.entered_vday,
             "phase_vday": d.phase_vday, "hold": d.hold, "hold_reason": d.hold_reason,
             "hidden_callers": d.hidden_callers, "worm_object": d.worm_object,
             "worm_retain_until": d.worm_retain_until, "certificate_id": d.certificate_id}
            for d, e in rows
        ],
    }


@router.post("/decommission/{endpoint_id}/enrol", status_code=201, responses={200: {"model": contracts.DecommissionEndpointIdEnrol}})
def enrol(endpoint_id: str, db: Session = Depends(get_session),
          c: Claims = Depends(approver)) -> dict:
    """Eligibility is enforced here, in code.

    A PROVISIONAL verdict cannot enter the workflow — that is the confidence
    ramp from stage 02 having a real consequence rather than being a label.
    """
    e = db.get(Endpoint, endpoint_id)
    if e is None:
        raise NotFound("ENDPOINT_NOT_FOUND", endpoint_id)
    if e.retired:
        raise Conflict("ALREADY_RETIRED", endpoint_id)

    cls = db.get(Classification, endpoint_id)
    if cls is None:
        raise Conflict("NOT_CLASSIFIED", "no verdict yet for this endpoint")
    if cls.confidence is not Confidence.CONFIRMED:
        raise Conflict("PROVISIONAL_VERDICT",
                       "requires 90 vdays of observation before decommissioning",
                       {"confidence": cls.confidence.value})
    if cls.lifecycle is not Lifecycle.ZOMBIE and not e.deprecated:
        raise Conflict("NOT_ELIGIBLE", "lifecycle must be ZOMBIE or formally deprecated",
                       {"lifecycle": cls.lifecycle.value})

    blast = db.get(Blast, endpoint_id)
    if blast is None:
        raise Conflict("NO_IMPACT_ANALYSIS", "run stage 09 before enrolling")

    existing = db.get(Decommission, endpoint_id)
    if existing is not None and existing.phase is not Phase.NONE:
        raise Conflict("ALREADY_ENROLLED", endpoint_id, {"phase": existing.phase.value})

    vday = clock.current_vday(db)
    express = blast.tier.value == "ZERO" and blast.in_graph
    canary = blast.touches_critical
    first_phase = Phase.B if express else Phase.A

    d = existing or Decommission(endpoint_id=endpoint_id)
    d.phase = first_phase
    d.express = express
    d.canary = canary
    d.canary_split = settings.canary_step_list[0] if canary else None
    d.entered_vday = vday
    d.phase_vday = vday
    db.add(d)

    ledger.record(db, actor=c.actor, action="decommission.enrolled", target=endpoint_id,
                  detail={"express": express, "canary": canary,
                          "blast_tier": blast.tier.value, "first_phase": first_phase.value})
    db.commit()
    return {"endpoint_id": endpoint_id, "phase": first_phase.value,
            "express": express, "canary": canary}


class AdvanceBody(BaseModel):
    reason: str


@router.post("/decommission/{endpoint_id}/advance", status_code=202, responses={200: {"model": contracts.DecommissionEndpointIdAdvance}})
def advance(endpoint_id: str, body: AdvanceBody, db: Session = Depends(get_session),
            c: Claims = Depends(approver)) -> dict:
    """Release a decommission for its next phase.

    This records an approver's decision; it does not perform the transition. The
    stage 11 runner is the single place phases move, so there is one code path
    that applies gateway controls, archives to WORM and issues a certificate —
    a second path reachable from a route would be a second way for an endpoint
    to be retired, with its own bugs.

    From Phase C the release matters most: nothing advances into Phase D on a
    timer, because archival and a 410 are irreversible in effect and somebody
    has to have read the hidden callers the quarantine surfaced.
    """
    d = db.get(Decommission, endpoint_id)
    if d is None or d.phase is Phase.NONE:
        raise NotFound("NOT_ENROLLED", endpoint_id)

    d.released_for_phase_d = True
    d.released_by = c.actor
    d.released_at = datetime.now(timezone.utc)

    ledger.record(db, actor=c.actor, action="decommission.released",
                  target=endpoint_id,
                  detail={"from": d.phase.value, "reason": body.reason})
    db.commit()

    return {"endpoint_id": endpoint_id, "from_phase": d.phase.value,
            "released_by": c.actor,
            "note": "the stage 11 runner performs the transition on its next pass"}


class HoldBody(BaseModel):
    reason: str
    hold: bool = True


@router.post("/decommission/{endpoint_id}/hold", responses={200: {"model": contracts.DecommissionEndpointIdHold}})
def hold(endpoint_id: str, body: HoldBody, db: Session = Depends(get_session),
         c: Claims = Depends(approver)) -> dict:
    d = db.get(Decommission, endpoint_id)
    if d is None:
        raise NotFound("NOT_ENROLLED", endpoint_id)
    d.hold = body.hold
    d.hold_reason = body.reason
    ledger.record(db, actor=c.actor,
                  action="decommission.held" if body.hold else "decommission.released",
                  target=endpoint_id, detail={"reason": body.reason})
    db.commit()
    return {"endpoint_id": endpoint_id, "hold": d.hold, "reason": d.hold_reason}


@router.get("/decommission/{endpoint_id}/worm/verify", responses={200: {"model": contracts.DecommissionEndpointIdWormVerify}})
def worm_verify(endpoint_id: str, db: Session = Depends(get_session),
                _: Claims = Depends(viewer)) -> dict:
    """Attempt a delete against the archived object and report the refusal.

    A configuration flag is a claim; a refused delete is evidence.
    """
    d = db.get(Decommission, endpoint_id)
    if d is None or not d.worm_object:
        raise NotFound("NO_WORM_OBJECT", "endpoint has not reached phase D")

    from sentry_worker.actuators.worm import verify_immutable

    return verify_immutable(d.worm_object, d.worm_retain_until)


# ── stage 12 ─────────────────────────────────────────────────────────────────
@router.get("/threat", responses={200: {"model": contracts.Threat}})
def threat(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    active = db.execute(
        select(func.count()).select_from(Endpoint).where(Endpoint.honeypot_active.is_(True))
    ).scalar_one()
    probes = db.execute(select(func.count()).select_from(Probe)).scalar_one()
    sources = db.execute(select(func.count(func.distinct(Probe.source_ip)))).scalar_one()
    prints = db.execute(select(func.count()).select_from(Fingerprint)).scalar_one()
    recent = list(db.execute(
        select(Probe).order_by(Probe.id.desc()).limit(100)).scalars())
    alerts = list(db.execute(
        select(ResurrectionAlert).order_by(ResurrectionAlert.id.desc())).scalars())
    signoff = setting(db, "honeypot_legal_signoff")

    return {
        "honeypots_active": active,
        "probes_total": probes,
        "unique_sources": sources,
        "fingerprints": prints,
        "threshold": settings.resurrection_threshold,
        "legal_signoff": signoff,
        "probes": [{"id": p.id, "at": p.wall_ts, "vday": p.vday,
                    "endpoint_id": p.endpoint_id, "source_ip": p.source_ip,
                    "source_asn": p.source_asn, "watermark": p.watermark}
                   for p in recent],
        "alerts": [{"new_endpoint_id": a.new_endpoint_id, "origin_path": a.origin_path,
                    "similarity": a.similarity, "threshold": a.threshold,
                    "lsh_hit": a.lsh_hit, "vday": a.vday}
                   for a in alerts],
    }


@router.get("/threat/probes", responses={200: {"model": contracts.ThreatProbes}})
def threat_probes(endpoint_id: str | None = None, source_ip: str | None = None,
                  asn: str | None = None, limit: int = 200,
                  db: Session = Depends(get_session),
                  _: Claims = Depends(viewer)) -> dict:
    """The probe stream.

    Bodies are returned as digests. They were never stored in cleartext — probe
    payloads are attacker-supplied, and the hash is enough to correlate repeat
    attempts without holding the content.
    """
    q = select(Probe).order_by(Probe.id.desc()).limit(min(limit, 1000))
    if endpoint_id:
        q = q.where(Probe.endpoint_id == endpoint_id)
    if source_ip:
        q = q.where(Probe.source_ip == source_ip)
    if asn:
        q = q.where(Probe.source_asn == asn)

    rows = list(db.execute(q).scalars())
    return {
        "count": len(rows),
        "probes": [{
            "id": p.id, "at": p.wall_ts, "vday": p.vday,
            "endpoint_id": p.endpoint_id, "method": p.method, "path_raw": p.path_raw,
            "source_ip": p.source_ip, "source_asn": p.source_asn, "geo": p.geo,
            "headers": p.headers, "watermark": p.watermark,
            "session_fp": p.session_fp,
            "body_sha256": p.body_sha256.hex() if p.body_sha256 else None,
        } for p in rows],
    }


@router.get("/threat/resurrection-scan", responses={200: {"model": contracts.ThreatResurrectionScan}})
def resurrection_scan(db: Session = Depends(get_session),
                      _: Claims = Depends(viewer)) -> dict:
    """Current alerts, with the count of signatures they were matched against.

    ``fingerprints`` is part of the response rather than a detail: zero alerts
    against zero fingerprints is an unarmed detector, and zero alerts against
    seventeen is a clean scan. The console renders those differently and cannot
    tell them apart without this number.
    """
    prints = db.execute(select(func.count()).select_from(Fingerprint)).scalar_one()
    rows = list(db.execute(
        select(ResurrectionAlert).order_by(ResurrectionAlert.similarity.desc())
    ).scalars())

    out = []
    for a in rows:
        new_ep = db.get(Endpoint, a.new_endpoint_id)
        out.append({
            "new_endpoint_id": a.new_endpoint_id,
            "new_endpoint": None if new_ep is None
            else f"{new_ep.method} {new_ep.path_template}",
            "origin_endpoint_id": a.origin_endpoint_id,
            "origin_path": a.origin_path,
            "similarity": a.similarity,
            "threshold": a.threshold,
            "lsh_hit": a.lsh_hit,
            "vday": a.vday,
            "created_at": a.created_at,
        })
    return {"fingerprints": prints, "threshold": settings.resurrection_threshold,
            "alerts": out}


@router.get("/threat/fingerprint/{endpoint_id}", responses={200: {"model": contracts.ThreatFingerprintEndpointId}})
def threat_fingerprint(endpoint_id: str, db: Session = Depends(get_session),
                       _: Claims = Depends(viewer)) -> dict:
    """The feature set and shingles behind a similarity score, for audit.

    A score is a number somebody is asked to act on. This is what it was
    computed from — including how many observations went into it, because a
    0.91 built on four sightings and one built on four thousand are different
    claims.
    """
    row = db.get(Fingerprint, endpoint_id)
    if row is None:
        raise HTTPException(404, "no fingerprint captured for this endpoint")
    return {
        "endpoint_id": row.endpoint_id,
        "captured_vday": row.captured_vday,
        "origin_path": row.origin_path,
        "origin_method": row.origin_method,
        "features": row.features,
        "shingles": row.shingles,
        "shingle_count": len(row.shingles or []),
    }


@router.post("/threat/rescan", responses={200: {"model": contracts.ThreatRescan}})
def threat_rescan(db: Session = Depends(get_session),
                  c: Claims = Depends(analyst)) -> dict:
    """Re-run the index against every live endpoint.

    Rebuilds from Postgres rather than from any cache, so this is also the
    recovery path after a Redis flush.
    """
    from sentry_worker import runner

    vday = clock.current_vday(db)
    outcome = runner.stage_12_threat(db, vday)
    ledger.record(db, actor=c.actor, action="threat.rescan", target=None,
                  detail={"alerts": outcome.records,
                          "fingerprints": outcome.detail.get("fingerprints", 0)})
    db.commit()
    return {"vday": vday, "alerts_raised": outcome.records, **outcome.detail}


# ── stage 13 ─────────────────────────────────────────────────────────────────
def _posture(e: Endpoint, svc: Service | None, applied_kinds: set[str]) -> dict:
    """Delegates to the stage 13 engine.

    The assessment used to be written out here as well, which meant the console
    and the pipeline could disagree about whether an endpoint was hardened —
    two implementations of one judgement, drifting apart on the next change to
    either. There is one.
    """
    from sentry_worker.engines import zerotrust

    criticality = svc.criticality if svc else Criticality.INTERNAL
    return zerotrust.assess(e, criticality, applied_kinds).as_dict()


class HardenPreviewBody(BaseModel):
    endpoint_id: str


@router.get("/zerotrust", responses={200: {"model": contracts.Zerotrust}})
def zerotrust(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    rows = list(db.execute(
        select(Endpoint, Service, Cdri)
        .join(Service, Service.id == Endpoint.service_id)
        .outerjoin(Cdri, Cdri.endpoint_id == Endpoint.id)
        .where(Endpoint.retired.is_(False))
    ).all())
    applied: dict[str, set[str]] = {}
    for c in db.execute(select(Control).where(Control.state == ControlState.APPLIED)).scalars():
        applied.setdefault(c.endpoint_id, set()).add(c.kind)

    items, gaps = [], {"auth": 0, "tls": 0, "binding": 0, "ratelimit": 0, "response": 0}
    dist = {i: 0 for i in range(6)}
    for e, svc, d in rows:
        p = _posture(e, svc, applied.get(e.id, set()))
        dist[p["satisfied"]] += 1
        for c in p["controls"]:
            if not c["ok"]:
                gaps[c["key"]] += 1
        items.append({"endpoint_id": e.id, "method": e.method, "path": e.path_template,
                      "satisfied": p["satisfied"], "of": 5,
                      "priority": d.score if d else 0.0, "controls": p["controls"]})

    items.sort(key=lambda i: (-i["priority"], i["satisfied"]))
    return {"distribution": dist, "gaps": gaps, "items": items}


@router.get("/zerotrust/{endpoint_id}", responses={200: {"model": contracts.ZerotrustEndpointId}})
def zerotrust_detail(endpoint_id: str, db: Session = Depends(get_session),
                     _: Claims = Depends(viewer)) -> dict:
    ep = db.get(Endpoint, endpoint_id)
    if ep is None:
        raise NotFound("ENDPOINT_NOT_FOUND", endpoint_id)
    applied = {c.kind for c in db.execute(
        select(Control).where(Control.endpoint_id == endpoint_id,
                              Control.state == ControlState.APPLIED)).scalars()}
    d = db.get(Cdri, endpoint_id)
    posture = _posture(ep, ep.service, applied)
    posture["priority"] = d.score if d else 0.0
    posture["method"] = ep.method
    posture["path"] = ep.path_template
    return posture


@router.post("/zerotrust/harden-preview", responses={200: {"model": contracts.ZerotrustHardenPreview}})
def harden_preview(body: HardenPreviewBody, db: Session = Depends(get_session),
                   _: Claims = Depends(analyst)) -> dict:
    """What hardening would do, with no writes.

    An analyst can see the plan and cannot execute it. The boundary between the
    two roles sits exactly at the gateway write, which is why this route exists
    separately rather than as a flag on the one that applies.
    """
    from sentry_core import clock
    from sentry_worker.runner import harden_endpoint

    ep = db.get(Endpoint, body.endpoint_id)
    if ep is None:
        raise NotFound("ENDPOINT_NOT_FOUND", body.endpoint_id)
    return harden_endpoint(db, ep, clock.current_vday(db),
                           actor="preview", dry_run=True)


@router.post("/zerotrust/{endpoint_id}/harden", status_code=202, responses={200: {"model": contracts.ZerotrustEndpointIdHarden}})
def harden(endpoint_id: str, db: Session = Depends(get_session),
           c: Claims = Depends(approver)) -> dict:
    """Delegates entirely to the stage 10 pipeline.

    There is no separate hardening path that bypasses the judge. A control
    applied from this surface has been differentially tested exactly like one
    applied from remediation.
    """
    if db.get(Endpoint, endpoint_id) is None:
        raise NotFound("ENDPOINT_NOT_FOUND", endpoint_id)
    from sentry_core import clock
    from sentry_worker.runner import harden_endpoint

    ledger.record(db, actor=c.actor, action="zerotrust.harden.requested", target=endpoint_id)
    db.commit()

    # Synchronous, and the result is the response.
    #
    # Each control is judged against the endpoint's own traffic before it is
    # applied, so this takes seconds rather than milliseconds — but an approver
    # authorising a change to a production gateway is entitled to know what
    # happened to it, and a task id defers that to somewhere they have to go
    # looking.
    return harden_endpoint(db, db.get(Endpoint, endpoint_id),
                           clock.current_vday(db), actor=c.actor)


# ── stage 14 ─────────────────────────────────────────────────────────────────
@router.get("/operations", responses={200: {"model": contracts.Operations}})
def operations(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    from sentry_worker.pipeline import STAGE_NAMES

    gates = list(db.execute(
        select(GateEvent).order_by(GateEvent.id.desc()).limit(20)).scalars())
    return {
        "vday": clock.current_vday(db),
        "scan_interval_vhours": settings.scan_interval_vhours,
        "scheduler_enabled": settings.scheduler_enabled,
        "siem": {"host": settings.siem_host, "format": settings.siem_format,
                 "configured": bool(settings.siem_host)},
        "stages": STAGE_NAMES,
        "gate_events": [{"repo": g.repo, "pr": g.pr_number, "sha": g.commit_sha[:8],
                         "passed": g.passed, "checks": g.checks, "at": g.wall_ts}
                        for g in gates],
    }


@router.get("/operations/leaderboard", responses={200: {"model": contracts.OperationsLeaderboard}})
def leaderboard(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    """Delegates to the stage 14 engine.

    This route used to carry its own copy of the debt formula, and it had
    quietly diverged: it omitted the ownership-confidence factor entirely, so
    the console charged teams in full for endpoints attributed to them by a
    0.40-confidence guess while the pipeline did not. Two implementations of one
    judgement is one too many.
    """
    from sentry_worker.engines import operations as ops
    from sentry_worker.runner import _leaderboard_rows

    return {"teams": ops.leaderboard(_leaderboard_rows(db))}


class GateCheck(BaseModel):
    repo: str
    pr_number: int
    commit_sha: str
    routes: list[dict]


@router.post("/gate/check", responses={200: {"model": contracts.GateCheckResult}})
def gate_check(body: GateCheck, db: Session = Depends(get_session),
               _: Claims = Depends(ci_gate)) -> dict:
    """Pre-merge gate. Prevents the next generation of zombies at authorship.

    Delegates to the stage 14 runner, which matches declared routes against the
    endpoints this database records as retired — not against a list the caller
    supplied. A gate that trusts CI to tell it what has been retired can be
    talked out of its own finding.
    """
    from sentry_worker.runner import run_gate

    return run_gate(db, repo=body.repo, pr_number=body.pr_number,
                    commit_sha=body.commit_sha, routes=body.routes)


@router.get("/gate/events", responses={200: {"model": contracts.GateEvents}})
def gate_events(db: Session = Depends(get_session), _: Claims = Depends(viewer)) -> dict:
    rows = list(db.execute(
        select(GateEvent).order_by(GateEvent.id.desc()).limit(50)).scalars())
    return {"events": [
        {"id": g.id, "repo": g.repo, "pr": g.pr_number, "sha": g.commit_sha[:8],
         "passed": g.passed, "checks": g.checks, "at": g.wall_ts}
        for g in rows]}


@router.get("/operations/siem", responses={200: {"model": contracts.OperationsSiem}})
def operations_siem(_: Claims = Depends(viewer)) -> dict:
    """Delivery status and what is still spooled.

    A SIEM that is down shows here as a spool depth rather than as silence.
    """
    from sentry_worker.actuators import siem

    emitter = siem.default_emitter()
    return {**emitter.stats(), "recent": emitter.peek(20)}


def _running_cycle(db: Session) -> dict:
    """The in-flight pass, for a refusal that names what it collided with.

    A row with no `finished_at` is a cycle that has not reported an outcome yet.
    Read on its own session so an aborted request does not leave the caller's
    transaction holding a snapshot from before the other cycle started.
    """
    from sentry_core.db import SessionLocal

    with SessionLocal() as fresh:
        run = fresh.execute(
            select(PipelineRun).where(PipelineRun.finished_at.is_(None))
            .order_by(PipelineRun.id.desc()).limit(1)).scalars().first()
        if run is None:
            return {}
        return {"running_run_id": run.id, "trigger": run.trigger,
                "started_at": run.started_at.isoformat()}


@router.post("/operations/scan", status_code=202, responses={200: {"model": contracts.OperationsScan}})
def trigger_scan(db: Session = Depends(get_session),
                 c: Claims = Depends(analyst)) -> dict:
    """Run a cycle now.

    Synchronous, because the alternative is a task id for a job with no worker
    behind it — which is what this route used to return.

    Under the same lock beat's dispatcher takes. Without it this route ran a
    cycle in the API process while the worker was running one of its own, and
    the two interleaved: stage 02 wrote the daily rollup for a vday the other
    cycle had already written, and the pass died on `endpoint_daily_pkey`. The
    lock is not the worker's — it is the deployment's, and every entry point
    into a cycle goes through it.

    A held lock is a 409 rather than a queued run: the operator asked for a
    cycle now, one is already running now, and reporting that is more useful
    than starting a second one behind it. The refusal names the run holding the
    lock — at a compressed clock scale the scheduled cadence is shorter than a
    cycle takes, so this is the ordinary answer rather than the exceptional one,
    and "a cycle is already running" without saying *which* would read as a
    fault instead of as the thing the operator asked for already happening.
    """
    from sentry_core import live
    from sentry_worker.runner import scan_cycle

    try:
        with live.scan_lock(ttl_s=live.SCAN_LOCK_TTL_S):
            run_id, outcomes = scan_cycle(db, trigger="manual", actor=c.actor)
    except live.NotAcquired as exc:
        live.bump("sentry_scan_skipped_total")
        raise Conflict("CYCLE_IN_PROGRESS", str(exc),
                       detail=_running_cycle(db)) from None

    return {"run_id": run_id,
            "stages": [{"stage": o.stage, "records": o.records,
                        "duration_ms": o.duration_ms,
                        "error": o.detail.get("error"),
                        "skipped": o.detail.get("skipped")}
                       for o in outcomes]}
