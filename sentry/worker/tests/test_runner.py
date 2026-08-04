"""The pipeline runner against a real database, on observations shaped like the
ones the kernel sensor actually produces.

These are the defects the engine tests cannot see, because they are not in the
engines. They are in what the runner feeds them.
"""

from __future__ import annotations

import os  # noqa: F401  — DATABASE_URL is set by the root conftest
from datetime import datetime, timedelta, timezone

import pytest

from sentry_core.db import SessionLocal, create_all  # noqa: E402
from sentry_core.enums import BlastTier, Source  # noqa: E402
from sentry_core.models import (  # noqa: E402
    Blast,
    CallEdge,
    Endpoint,
    EndpointDaily,
    Observation,
)
from sentry_worker import runner  # noqa: E402

BASE_TS = datetime(2026, 7, 1, 9, 0, tzinfo=timezone.utc)


def _obs(**kw) -> Observation:
    """One sighting. Defaults are what an eBPF row looks like."""
    fields = {
        "vday": 0,
        "wall_ts": BASE_TS,
        "source": Source.EBPF,
        "method": "GET",
        "path_raw": "/api/v1/accounts/8814",
        "host": "core-accounts",
        "port": 8443,
        "status": 200,
        "auth_present": False,
        "data_classes": [],
    }
    fields.update(kw)
    return Observation(**fields)


@pytest.fixture
def db():
    create_all()
    with SessionLocal() as s:
        # Independent of any other test in the run.
        for table in (Blast, CallEdge, EndpointDaily, Observation, Endpoint):
            s.query(table).delete()
        s.commit()
        yield s
        s.rollback()


def _run(db, vday: int = 0) -> None:
    runner.stage_03_correlation(db, vday)
    runner.stage_02_baseline(db, vday)
    db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Two-sided capture
# ─────────────────────────────────────────────────────────────────────────────
def test_an_exchange_seen_from_both_ends_is_counted_once(db):
    """A call between two instrumented workloads produces two rows.

    The caller's SSL_write and the callee's SSL_read are both genuine sightings
    of the same exchange. Counting both is the difference between reporting
    twenty calls and reporting forty, on every figure the product derives from
    volume.
    """
    for i in range(20):
        ts = BASE_TS + timedelta(seconds=i)
        db.add(_obs(wall_ts=ts, direction="EGRESS", peer_service="traffic"))
        db.add(_obs(wall_ts=ts, direction="INGRESS"))
    db.commit()

    _run(db)

    daily = db.query(EndpointDaily).filter(EndpointDaily.vday == 0).all()
    assert len(daily) == 1
    assert daily[0].calls == 20, "both halves of each exchange were counted"


def test_a_client_only_sighting_is_still_counted(db):
    """An endpoint whose server is outside the estate is seen from one side only.

    Preferring a fixed direction would report zero calls for it. The rule takes
    whichever half saw more, so single-sided capture needs no special case.
    """
    for i in range(12):
        db.add(_obs(wall_ts=BASE_TS + timedelta(seconds=i),
                    direction="EGRESS", peer_service="traffic"))
    db.commit()

    _run(db)

    daily = db.query(EndpointDaily).one()
    assert daily.calls == 12


def test_the_caller_survives_being_the_uncounted_half(db):
    """Only the egress row knows who called; only one half gets counted.

    If the counting rule also decided which rows contribute callers, an endpoint
    counted from its ingress side would report zero distinct peers while its
    call graph showed edges — the two figures would contradict each other in the
    console.
    """
    for i in range(20):
        ts = BASE_TS + timedelta(seconds=i)
        db.add(_obs(wall_ts=ts, direction="EGRESS", peer_service="payments-upi"))
        db.add(_obs(wall_ts=ts, direction="EGRESS", peer_service="settlement-rtgs"))
        # More ingress rows than egress, so ingress is the counted half.
        for _ in range(3):
            db.add(_obs(wall_ts=ts, direction="INGRESS"))
    db.commit()

    _run(db)

    daily = db.query(EndpointDaily).one()
    assert daily.calls == 60
    assert daily.distinct_peers == 2


def test_a_registry_entry_is_not_counted_as_a_call(db):
    """A gateway route is a declaration that the endpoint exists.

    It is not evidence that anyone invoked it. Counting it would make
    registered-but-never-invoked — one of the findings this system exists to
    produce — indistinguishable from an endpoint carrying traffic.
    """
    db.add(_obs(direction="EGRESS", peer_service="traffic"))
    db.add(_obs(direction="INGRESS"))
    db.add(_obs(source=Source.GATEWAY, direction=None, status=None))
    db.commit()

    _run(db)

    daily = db.query(EndpointDaily).one()
    assert daily.calls == 1, "the registry entry was counted as traffic"

    # ...but it is still a source, which is what keeps the endpoint off the
    # shadow list.
    from sentry_core.models import EndpointSource
    srcs = {s.source for s in db.query(EndpointSource).all()}
    assert Source.GATEWAY in srcs and Source.EBPF in srcs


# ─────────────────────────────────────────────────────────────────────────────
# The call graph
# ─────────────────────────────────────────────────────────────────────────────
def test_a_named_caller_becomes_an_edge_and_a_blast_radius(db):
    """The whole reason peer_service exists.

    Without a caller name there are no call edges; without edges every endpoint
    scores a ZERO blast radius, and a decommission queue in which nothing has
    dependants is not a queue.
    """
    for i in range(10):
        ts = BASE_TS + timedelta(seconds=i)
        db.add(_obs(wall_ts=ts, host="shadow-fx-rate", path_raw="/internal/fx/rate",
                    direction="EGRESS", peer_service="payments-upi"))
        db.add(_obs(wall_ts=ts, host="shadow-fx-rate", path_raw="/internal/fx/rate",
                    direction="EGRESS", peer_service="settlement-rtgs"))
        # The callers themselves must exist as services for the edge to stand.
        db.add(_obs(wall_ts=ts, host="payments-upi", path_raw="/api/v1/payments/upi/UPI1",
                    direction="EGRESS", peer_service="traffic"))
        db.add(_obs(wall_ts=ts, host="settlement-rtgs", path_raw="/api/v1/settlement/rtgs/R1",
                    direction="EGRESS", peer_service="traffic"))
    db.commit()

    _run(db)
    runner.stage_09_blast(db, 0)
    db.commit()

    fx = db.query(Endpoint).filter(Endpoint.host == "shadow-fx-rate").one()
    callers = {e.caller_service_id for e in
               db.query(CallEdge).filter(CallEdge.endpoint_id == fx.id).all()}
    assert len(callers) == 2, "both calling services should have produced an edge"

    tier = db.get(Blast, fx.id).tier
    assert tier is not BlastTier.ZERO, "an endpoint with two callers is not unreferenced"


def test_an_unnamed_caller_asserts_no_edge(db):
    """A workload the resolver could not name contributes nothing.

    Inventing an edge from an unnamed caller would put a fabricated dependency
    in front of an operator deciding whether it is safe to remove an endpoint.
    """
    for i in range(10):
        db.add(_obs(wall_ts=BASE_TS + timedelta(seconds=i), direction="EGRESS",
                    peer_service=None))
    db.commit()

    _run(db)

    assert db.query(CallEdge).count() == 0


def test_a_caller_that_serves_nothing_still_produces_an_edge(db):
    """A workload at the edge of the estate calls without being called.

    Only hosts seen in a request produced a service row, so a batch driver or a
    mobile backend contributed no node and its edges were discarded. The
    endpoints it was the sole consumer of then reported zero dependants — which
    is the figure a recommendation to retire them is built on.
    """
    for i in range(8):
        db.add(_obs(wall_ts=BASE_TS + timedelta(seconds=i),
                    host="kyc-service", path_raw="/api/v1/kyc/9902",
                    direction="EGRESS", peer_service="batch-recon"))
    db.commit()

    _run(db)
    runner.stage_09_blast(db, 0)
    db.commit()

    ep = db.query(Endpoint).one()
    edges = db.query(CallEdge).filter(CallEdge.endpoint_id == ep.id).all()
    assert [e.caller_service_id for e in edges], "the sole consumer produced no edge"
    assert db.get(Blast, ep.id).tier is not BlastTier.ZERO


def test_a_sensor_outage_does_not_age_the_estate_into_zombies(db):
    """The virtual clock advances on wall time whether or not anything is watching.

    An endpoint called every vday up to 100, then a stretch where the agent was
    down, must not be reported as silent for that stretch. Counting raw clock
    vdays means a weekend of downtime pushes the whole estate past the
    ninety-vday threshold and puts it in front of an operator as a retirement
    queue.
    """
    for v in range(0, 101):
        db.add(_obs(vday=v, wall_ts=BASE_TS + timedelta(seconds=v),
                    direction="INGRESS"))
    db.commit()

    # Clock has run on to 400; nothing was captured after vday 100.
    _run(db, vday=400)
    runner.stage_04_classification(db, 400)
    db.commit()

    from sentry_core.enums import Lifecycle
    from sentry_core.models import Classification
    ep = db.query(Endpoint).one()
    verdict = db.get(Classification, ep.id)

    assert verdict is not None
    assert verdict.lifecycle is not Lifecycle.ZOMBIE, (
        "300 unwatched vdays were counted as silence")


def test_silence_in_watched_vdays_is_still_silence(db):
    """The guard must not make an endpoint unretireable.

    Other endpoints kept being called throughout, so the sensor was demonstrably
    running — and this one was not called. That is the evidence ZOMBIE needs.
    """
    for v in range(0, 101):
        db.add(_obs(vday=v, wall_ts=BASE_TS + timedelta(seconds=v),
                    direction="INGRESS"))
    # A second endpoint carries on, so every vday to 400 is a watched vday.
    for v in range(0, 401):
        db.add(_obs(vday=v, wall_ts=BASE_TS + timedelta(seconds=v),
                    host="kyc-service", path_raw="/api/v1/kyc/9902",
                    direction="INGRESS"))
    db.commit()

    _run(db, vday=400)
    runner.stage_04_classification(db, 400)
    db.commit()

    from sentry_core.enums import Lifecycle
    from sentry_core.models import Classification
    dead = db.query(Endpoint).filter(Endpoint.host == "core-accounts").one()
    alive = db.query(Endpoint).filter(Endpoint.host == "kyc-service").one()

    assert db.get(Classification, dead.id).lifecycle is Lifecycle.ZOMBIE
    assert db.get(Classification, alive.id).lifecycle is Lifecycle.ACTIVE


# ─────────────────────────────────────────────────────────────────────────────
# Stage 11 — the runner's guards
# ─────────────────────────────────────────────────────────────────────────────
def _zombie(db, vday: int = 400):
    """An endpoint with a full observation history that then went silent, while
    other traffic kept the sensor demonstrably alive."""
    from sentry_core.enums import BlastTier, Confidence, Governance, Lifecycle
    from sentry_core.models import Blast, Classification

    for v in range(0, 101):
        db.add(_obs(vday=v, wall_ts=BASE_TS + timedelta(seconds=v), direction="INGRESS"))
    for v in range(0, vday + 1):
        db.add(_obs(vday=v, wall_ts=BASE_TS + timedelta(seconds=v),
                    host="kyc-service", path_raw="/api/v1/kyc/9902", direction="INGRESS"))
    db.commit()

    _run(db, vday=vday)
    runner.stage_04_classification(db, vday)
    db.commit()

    ep = db.query(Endpoint).filter(Endpoint.host == "core-accounts").one()
    db.merge(Blast(endpoint_id=ep.id, tier=BlastTier.ZERO, direct_callers=0,
                   hop2_callers=0, affected=[], datastores=[], touches_critical=False,
                   in_graph=True, hop_limit=2, vday=vday, engine_version="t"))
    db.commit()
    assert db.get(Classification, ep.id).lifecycle is Lifecycle.ZOMBIE
    assert db.get(Classification, ep.id).confidence is Confidence.CONFIRMED
    return ep


def test_only_a_confirmed_zombie_is_enrolled(db, monkeypatch):
    from sentry_core.models import Decommission
    from sentry_worker.collectors import gateway

    monkeypatch.setattr(gateway, "collect",
                        lambda: gateway.GatewaySnapshot(routes=[], healthy=True))
    ep = _zombie(db)

    out = runner.stage_11_decommission(db, 400)
    db.commit()

    assert out.detail["enrolled"] == 1
    assert db.get(Decommission, ep.id) is not None
    # The endpoint that kept serving is refused, with the reason named.
    assert out.detail["not_eligible"].get("NOT_ELIGIBLE") == 1


def test_a_zero_blast_zombie_takes_the_express_path(db, monkeypatch):
    from sentry_core.enums import Phase
    from sentry_core.models import Decommission
    from sentry_worker.collectors import gateway

    monkeypatch.setattr(gateway, "collect",
                        lambda: gateway.GatewaySnapshot(routes=[], healthy=True))
    ep = _zombie(db)

    runner.stage_11_decommission(db, 400)
    db.commit()

    dec = db.get(Decommission, ep.id)
    assert dec.express is True
    # Express starts at B — it skips the throttle, not the quarantine.
    assert dec.phase is Phase.B


def test_phase_d_waits_for_an_approver_rather_than_the_clock(db, monkeypatch):
    """Archival and a 410 are irreversible in effect.

    The clock is long past due here and the runner still refuses, because
    nobody has read the hidden callers the quarantine surfaced.
    """
    from sentry_core.enums import Phase
    from sentry_core.models import Decommission
    from sentry_worker.collectors import gateway

    monkeypatch.setattr(gateway, "collect",
                        lambda: gateway.GatewaySnapshot(routes=[], healthy=True))
    ep = _zombie(db)
    runner.stage_11_decommission(db, 400)
    db.commit()

    dec = db.get(Decommission, ep.id)
    dec.phase = Phase.C
    dec.phase_vday = 0          # long overdue
    db.commit()

    out = runner.stage_11_decommission(db, 400)
    db.commit()

    assert db.get(Decommission, ep.id).phase is Phase.C
    assert db.get(Endpoint, ep.id).retired is False
    assert any(r.get("action") == "awaiting-release" for r in out.detail["results"])


def test_phase_d_blocks_when_the_archive_is_unavailable(db, monkeypatch):
    """Retiring an endpoint whose history was not archived destroys the evidence
    the archive exists to preserve, and there is no recovering it afterwards."""
    from sentry_core.enums import Phase
    from sentry_core.models import Decommission
    from sentry_worker.actuators import worm
    from sentry_worker.collectors import gateway

    monkeypatch.setattr(gateway, "collect",
                        lambda: gateway.GatewaySnapshot(routes=[], healthy=True))

    def unavailable(*a, **k):
        raise worm.WormUnavailable("MINIO_ENDPOINT is not configured")

    monkeypatch.setattr(worm, "archive", unavailable)

    ep = _zombie(db)
    runner.stage_11_decommission(db, 400)
    db.commit()

    dec = db.get(Decommission, ep.id)
    dec.phase = Phase.C
    dec.phase_vday = 0
    dec.released_for_phase_d = True
    db.commit()

    out = runner.stage_11_decommission(db, 400)
    db.commit()

    assert out.detail["blocked"] == 1
    assert out.detail["retired"] == 0
    assert db.get(Endpoint, ep.id).retired is False
    # The endpoint keeps serving, and the reason is stated.
    blocked = [r for r in out.detail["results"] if r.get("blocked")]
    assert "WORM archive unavailable" in blocked[0]["reason"]


def test_a_held_decommission_does_not_advance(db, monkeypatch):
    from sentry_core.enums import Phase
    from sentry_core.models import Decommission
    from sentry_worker.collectors import gateway

    monkeypatch.setattr(gateway, "collect",
                        lambda: gateway.GatewaySnapshot(routes=[], healthy=True))
    ep = _zombie(db)
    runner.stage_11_decommission(db, 400)
    db.commit()

    dec = db.get(Decommission, ep.id)
    before = dec.phase
    dec.hold = True
    dec.hold_reason = "third-party integration found during quarantine"
    dec.phase_vday = 0
    db.commit()

    out = runner.stage_11_decommission(db, 400)
    db.commit()

    assert db.get(Decommission, ep.id).phase is before
    assert out.detail["on_hold"] == 1


def test_the_platforms_own_replay_traffic_is_not_counted_as_usage(db):
    """The Judge replays real shapes through the gateway to the real upstream,
    so the sensor sees them and cannot tell them from a caller.

    Counted, they reset the silence clock on the very endpoint stage 10 is
    judging — and stage 10 judges the endpoints under scrutiny, so a zombie
    stays alive precisely because the system keeps examining it. This was
    observed: `container:...` (Kong, replaying) appeared as the only caller of
    an endpoint nothing in the estate had called for ninety vdays.
    """
    for i in range(5):
        db.add(_obs(wall_ts=BASE_TS + timedelta(seconds=i), direction="INGRESS"))
    for i in range(40):
        db.add(_obs(wall_ts=BASE_TS + timedelta(seconds=i), direction="INGRESS",
                    synthetic=True))
    db.commit()

    _run(db)

    assert db.query(EndpointDaily).one().calls == 5


def test_synthetic_traffic_is_kept_even_though_it_is_not_counted(db):
    """An operator asking why a judged endpoint shows a spike deserves to see
    it. The row stays; only the arithmetic ignores it."""
    db.add(_obs(direction="INGRESS"))
    db.add(_obs(direction="INGRESS", synthetic=True))
    db.commit()

    _run(db)

    assert db.query(Observation).filter(Observation.synthetic.is_(True)).count() == 1
    assert db.query(EndpointDaily).one().calls == 1


def test_one_exchange_is_one_hidden_caller_not_two(db, monkeypatch):
    """A call between two instrumented workloads is captured twice, and only the
    egress copy knows who made it.

    Counting both listed the same three calls as two dependants — the caller's
    name and an "unresolved" placeholder — which reads to an operator as two
    teams to contact when there is one.
    """
    from sentry_core.enums import Phase
    from sentry_core.models import Decommission
    from sentry_worker.collectors import gateway

    monkeypatch.setattr(gateway, "collect",
                        lambda: gateway.GatewaySnapshot(routes=[], healthy=True))
    ep = _zombie(db)
    runner.stage_11_decommission(db, 400)
    db.commit()

    dec = db.get(Decommission, ep.id)
    dec.phase = Phase.C
    dec.phase_vday = 400
    db.commit()

    for i in range(3):
        db.add(_obs(vday=401, wall_ts=BASE_TS + timedelta(seconds=i),
                    direction="EGRESS", peer_service="batch-recon"))
        db.add(_obs(vday=401, wall_ts=BASE_TS + timedelta(seconds=i),
                    direction="INGRESS"))
    db.commit()
    _run(db, vday=401)

    runner.stage_11_decommission(db, 401)
    db.commit()

    callers = db.get(Decommission, ep.id).hidden_callers
    assert [c["service"] for c in callers] == ["batch-recon"]
    assert callers[0]["calls"] == 3


def test_a_caller_from_outside_the_estate_is_still_surfaced(db, monkeypatch):
    """Unidentifiable and real. A client outside the estate produces no egress
    sighting, and it is exactly the dependency the quarantine exists to find."""
    from sentry_core.enums import Phase
    from sentry_core.models import Decommission
    from sentry_worker.collectors import gateway

    monkeypatch.setattr(gateway, "collect",
                        lambda: gateway.GatewaySnapshot(routes=[], healthy=True))
    ep = _zombie(db)
    runner.stage_11_decommission(db, 400)
    db.commit()

    dec = db.get(Decommission, ep.id)
    dec.phase = Phase.C
    dec.phase_vday = 400
    db.commit()

    for i in range(2):
        db.add(_obs(vday=401, wall_ts=BASE_TS + timedelta(seconds=i),
                    direction="INGRESS"))
    db.commit()
    _run(db, vday=401)

    runner.stage_11_decommission(db, 401)
    db.commit()

    callers = db.get(Decommission, ep.id).hidden_callers
    assert len(callers) == 1
    assert callers[0]["service"].startswith("unresolved")


def test_the_platforms_own_probes_are_not_hidden_callers(db, monkeypatch):
    """The Judge replays against the endpoint it is judging. Reporting that as a
    dependency would halt a retirement on the system's own traffic."""
    from sentry_core.enums import Phase
    from sentry_core.models import Decommission
    from sentry_worker.collectors import gateway

    monkeypatch.setattr(gateway, "collect",
                        lambda: gateway.GatewaySnapshot(routes=[], healthy=True))
    ep = _zombie(db)
    runner.stage_11_decommission(db, 400)
    db.commit()

    dec = db.get(Decommission, ep.id)
    dec.phase = Phase.C
    dec.phase_vday = 400
    db.commit()

    for i in range(5):
        db.add(_obs(vday=401, wall_ts=BASE_TS + timedelta(seconds=i),
                    direction="EGRESS", peer_service="container:abc123",
                    synthetic=True))
    db.commit()
    _run(db, vday=401)

    runner.stage_11_decommission(db, 401)
    db.commit()

    assert db.get(Decommission, ep.id).hidden_callers == []


# ─────────────────────────────────────────────────────────────────────────────
# Stage 14 — the scan cycle
# ─────────────────────────────────────────────────────────────────────────────
def test_one_failing_stage_does_not_abort_the_cycle(db, monkeypatch):
    """Aborting loses every stage after the broken one, including the ones with
    no dependency on it.

    A transient fault in the forecast would take out the SIEM feed and the audit
    trail with it. The cycle completes and reports partial.
    """
    from sentry_core.models import PipelineRun, StageRun
    from sentry_worker import runner as r

    def explode(db_, vday):
        raise RuntimeError("forecast blew up")

    monkeypatch.setitem(r.STAGES, 7, explode)
    monkeypatch.setattr(r, "stage_01_gateway",
                        lambda db_, v: r.StageOutcome(1, 0, 0, {"collector": "gateway"}))
    monkeypatch.setitem(r.STAGES, 1, lambda db_, v: r.StageOutcome(1, 0, 0, {}))
    monkeypatch.setitem(r.STAGES, 10, lambda db_, v: r.StageOutcome(10, 0, 0, {}))
    monkeypatch.setitem(r.STAGES, 13, lambda db_, v: r.StageOutcome(13, 0, 0, {}))
    monkeypatch.setitem(r.STAGES, 14, lambda db_, v: r.StageOutcome(14, 0, 0, {}))

    db.add(_obs(direction="INGRESS"))
    db.commit()

    run_id, outcomes = r.scan_cycle(db, trigger="test")
    db.commit()

    by_stage = {o.stage: o for o in outcomes}
    assert "forecast blew up" in by_stage[7].detail["error"]
    # Stages that do not depend on it still ran.
    assert by_stage[14].detail.get("error") is None
    assert by_stage[14].detail.get("skipped") is None

    run = db.get(PipelineRun, run_id)
    assert run.finished_at is not None
    assert run.ok is False, "a cycle with a failed stage is not ok"

    failed_rows = db.query(StageRun).filter(StageRun.run_id == run_id,
                                            StageRun.ok.is_(False)).all()
    assert any("forecast blew up" in (s.error or "") for s in failed_rows)


def test_a_stage_whose_input_failed_is_skipped_not_run_on_stale_data(db, monkeypatch):
    """Running stage 06 after stage 05 failed would score every endpoint against
    last cycle's anomaly term and report the result as this cycle's."""
    from sentry_worker import runner as r

    def explode(db_, vday):
        raise RuntimeError("behaviour blew up")

    monkeypatch.setitem(r.STAGES, 5, explode)
    for stage in (1, 10, 13, 14):
        monkeypatch.setitem(r.STAGES, stage,
                            lambda db_, v, _s=stage: r.StageOutcome(_s, 0, 0, {}))

    db.add(_obs(direction="INGRESS"))
    db.commit()

    _run_id, outcomes = r.scan_cycle(db, trigger="test")
    db.commit()

    by_stage = {o.stage: o for o in outcomes}
    assert by_stage[6].detail.get("skipped") is True
    assert "depends on stage(s) [5]" in by_stage[6].detail["reason"]


def test_a_clean_cycle_is_recorded_as_ok(db, monkeypatch):
    from sentry_core.models import PipelineRun
    from sentry_worker import runner as r

    for stage in (1, 10, 13, 14):
        monkeypatch.setitem(r.STAGES, stage,
                            lambda db_, v, _s=stage: r.StageOutcome(_s, 0, 0, {}))

    db.add(_obs(direction="INGRESS"))
    db.commit()

    run_id, outcomes = r.scan_cycle(db, trigger="manual", actor="analyst@dev")
    db.commit()

    run = db.get(PipelineRun, run_id)
    assert run.ok is True
    assert run.trigger == "manual" and run.actor == "analyst@dev"
    assert all(not o.detail.get("error") for o in outcomes)
