"""Control-plane behaviour: identity, the audit chain, policy, and eligibility."""

from __future__ import annotations

import os  # noqa: F401  — DATABASE_URL is set by the root conftest

import pytest

os.environ.setdefault("AUTH_DISABLED", "true")
os.environ.setdefault("REDIS_URL", "")

from fastapi.testclient import TestClient  # noqa: E402

from app.audit import ledger  # noqa: E402
from app.main import app  # noqa: E402
from sentry_core.db import SessionLocal, create_all  # noqa: E402
from sentry_core.enums import BlastTier, Confidence, Criticality, Governance, Lifecycle  # noqa: E402
from sentry_core.models import (  # noqa: E402
    AuditEntry,
    Blast,
    Classification,
    Endpoint,
    Service,
)

VIEWER = {"Authorization": "Bearer dev-viewer"}
ANALYST = {"Authorization": "Bearer dev-analyst"}
APPROVER = {"Authorization": "Bearer dev-approver"}
ADMIN = {"Authorization": "Bearer dev-admin"}


@pytest.fixture(scope="module")
def client():
    create_all()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def seeded(client):
    """A minimal estate written directly — this fixture exercises the API, not
    discovery."""
    with SessionLocal() as db:
        svc = Service(id="svc_test", name="test-svc", team="Core", first_vday=0, last_vday=0,
                      criticality=Criticality.CUSTOMER)
        db.merge(svc)
        for eid, life, conf in (
            ("ep_zombie", Lifecycle.ZOMBIE, Confidence.CONFIRMED),
            ("ep_prov", Lifecycle.ZOMBIE, Confidence.PROVISIONAL),
        ):
            db.merge(Endpoint(id=eid, method="GET", path_template=f"/{eid}",
                              service_id="svc_test", first_vday=0))
            db.merge(Classification(endpoint_id=eid, lifecycle=life,
                                    governance=Governance.ORPHANED, confidence=conf,
                                    trace=[], vday=200, engine_version="t"))
            db.merge(Blast(endpoint_id=eid, tier=BlastTier.ZERO, direct_callers=0,
                           hop2_callers=0, affected=[], datastores=[],
                           touches_critical=False, in_graph=True, hop_limit=2,
                           vday=200, engine_version="t"))
        db.commit()
    return True


# ── identity ─────────────────────────────────────────────────────────────────
def test_no_token_is_rejected(client):
    r = client.get("/api/v1/system")
    assert r.status_code == 401
    assert r.json()["error"]["class"] == "unauthenticated"


def test_viewer_can_read(client):
    assert client.get("/api/v1/system", headers=VIEWER).status_code == 200


def test_viewer_cannot_change_policy(client):
    r = client.post("/api/v1/policy/weights",
                    json={"weights": {"no_auth": 1.0, "zombie": 0.0, "data_exposure": 0.0,
                                      "weak_tls": 0.0, "no_rate_limit": 0.0, "anomaly": 0.0}},
                    headers=VIEWER)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "ROLE_REQUIRED"


def test_analyst_cannot_apply_a_control(client, seeded):
    """The analyst/approver boundary sits exactly at the Kong write."""
    r = client.post("/api/v1/remediation/ep_zombie/apply",
                    json={"control_id": 1}, headers=ANALYST)
    assert r.status_code == 403
    assert set(r.json()["error"]["detail"]["required"]) == {"approver", "admin"}


def test_analyst_cannot_enrol_for_decommission(client, seeded):
    r = client.post("/api/v1/decommission/ep_zombie/enrol", headers=ANALYST)
    assert r.status_code == 403


def test_admin_inherits_every_role(client):
    assert client.get("/api/v1/audit/verify", headers=ADMIN).status_code == 200
    assert client.get("/api/v1/audit/verify", headers=APPROVER).status_code == 403


# ── audit chain ──────────────────────────────────────────────────────────────
def test_chain_verifies_on_a_populated_ledger(client):
    with SessionLocal() as db:
        for i in range(5):
            ledger.record(db, actor="test", action="test.event", target=f"t{i}",
                          detail={"i": i})
        db.commit()
    r = client.get("/api/v1/audit/verify", headers=ADMIN).json()
    assert r["ok"] is True
    assert r["entries"] >= 5


def test_tampering_with_one_entry_is_detected_at_the_right_sequence(client):
    """Altering any historical entry must invalidate the chain from that point.

    This is the property that makes the ledger evidence rather than a log.
    """
    with SessionLocal() as db:
        for i in range(3):
            ledger.record(db, actor="test", action="tamper.fixture", detail={"i": i})
        db.commit()
        rows = db.query(AuditEntry).order_by(AuditEntry.seq).all()
        victim = rows[len(rows) // 2]
        victim_seq = victim.seq
        original_detail = dict(victim.detail)  # exact, so the restore is exact
        victim.detail = {"i": 999, "tampered": True}
        db.commit()

    r = client.get("/api/v1/audit/verify", headers=ADMIN).json()
    assert r["ok"] is False
    assert r["broken_at"] == victim_seq
    assert "hash" in r["reason"]

    # Restore the exact original so later tests see a valid chain.
    with SessionLocal() as db:
        db.get(AuditEntry, victim_seq).detail = original_detail
        db.commit()

    assert client.get("/api/v1/audit/verify", headers=ADMIN).json()["ok"] is True


def test_governance_actions_are_audited(client, seeded):
    before = client.get("/api/v1/audit", headers=VIEWER).json()["items"]
    client.post("/api/v1/clock/set", json={"vday": 200}, headers=ADMIN)
    after = client.get("/api/v1/audit", headers=VIEWER).json()["items"]
    assert len(after) > len(before)
    assert after[0]["action"] == "clock.set"
    assert after[0]["actor"] == "admin@dev.local"


# ── policy ───────────────────────────────────────────────────────────────────
def test_weights_must_sum_to_one_and_the_residual_is_returned(client):
    """The console shows the residual while a slider is dragged, so the error
    must carry the actual sum rather than a bare rejection."""
    bad = {"no_auth": 0.30, "zombie": 0.22, "data_exposure": 0.20,
           "weak_tls": 0.15, "no_rate_limit": 0.08, "anomaly": 0.07}
    r = client.post("/api/v1/policy/weights", json={"weights": bad}, headers=ANALYST)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "WEIGHTS_MUST_SUM_TO_ONE"
    assert err["detail"]["actual_sum"] == pytest.approx(1.02)


def test_valid_weight_change_versions_and_audits(client):
    good = {"no_auth": 0.30, "zombie": 0.20, "data_exposure": 0.20,
            "weak_tls": 0.15, "no_rate_limit": 0.08, "anomaly": 0.07}
    before = client.get("/api/v1/policy/weights", headers=VIEWER).json()["version"]
    r = client.post("/api/v1/policy/weights",
                    json={"weights": good, "note": "tighten auth"}, headers=ANALYST)
    assert r.status_code == 200
    assert r.json()["version"] > before

    audit = client.get("/api/v1/audit", headers=VIEWER).json()["items"]
    assert any(a["action"] == "policy.weights.changed" for a in audit)


def test_weight_history_is_retained(client):
    """A score must stay interpretable against the policy in force when it was
    made, so a superseded version is never deleted."""
    h = client.get("/api/v1/policy/weights", headers=VIEWER).json()["history"]
    assert len(h) >= 2


# ── decommission eligibility ─────────────────────────────────────────────────
def test_provisional_verdict_cannot_be_enrolled(client, seeded):
    """The confidence ramp having a real consequence rather than being a label."""
    r = client.post("/api/v1/decommission/ep_prov/enrol", headers=APPROVER)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "PROVISIONAL_VERDICT"


def test_confirmed_zombie_can_be_enrolled_and_gets_the_express_path(client, seeded):
    r = client.post("/api/v1/decommission/ep_zombie/enrol", headers=APPROVER)
    assert r.status_code == 201
    body = r.json()
    assert body["express"] is True       # ZERO blast, present in graph
    assert body["phase"] == "B"          # express skips throttling
    assert body["canary"] is False


def test_double_enrolment_conflicts(client, seeded):
    r = client.post("/api/v1/decommission/ep_zombie/enrol", headers=APPROVER)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "ALREADY_ENROLLED"


def test_worm_verify_requires_phase_d(client, seeded):
    r = client.get("/api/v1/decommission/ep_zombie/worm/verify", headers=VIEWER)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "NO_WORM_OBJECT"


# ── read surfaces ────────────────────────────────────────────────────────────
def test_system_summary_shape(client, seeded):
    b = client.get("/api/v1/system", headers=VIEWER).json()
    for k in ("vday", "endpoints", "retired", "lifecycle", "governance", "tiers"):
        assert k in b


def test_shadow_reliability_is_reported(client):
    """With no gateway collector output, absence from the gateway is unproven
    and the API must say so rather than letting a SHADOW verdict rest on it."""
    b = client.get("/api/v1/discovery", headers=VIEWER).json()
    assert b["shadow_reliable"] is False


def test_classification_detail_returns_the_replayable_trace(client, seeded):
    b = client.get("/api/v1/classification/ep_zombie", headers=VIEWER).json()
    assert b["lifecycle"] == "ZOMBIE"
    assert "trace" in b


def test_missing_endpoint_is_a_clean_404(client):
    r = client.get("/api/v1/estate/ep_nope", headers=VIEWER)
    assert r.status_code == 404
    assert r.json()["error"]["class"] == "not_found"


def test_pipeline_reports_dependencies(client):
    b = client.get("/api/v1/pipeline", headers=VIEWER).json()
    stages = {s["stage"]: s for s in b["stages"]}
    assert 5 in stages[6]["depends_on"], "CDRI must depend on Behaviour"
    assert b["order"].index(5) < b["order"].index(6)


def test_health_and_readiness_are_distinct(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code in (200, 503)
    assert "checks" in client.get("/readyz").json()


# ── ledger portability regression ────────────────────────────────────────────
def test_hash_survives_a_timestamp_round_trip_through_storage():
    """The chain must verify identically whether the driver returns a tz-aware
    or a naive datetime.

    Hashing isoformat() made a chain written under one driver appear broken when
    verified under another — the worst possible failure for the one structure
    whose purpose is to prove nothing changed.
    """
    from datetime import datetime, timezone

    aware = datetime(2026, 7, 28, 9, 21, 13, 85670, tzinfo=timezone.utc)
    naive = aware.replace(tzinfo=None)

    assert ledger.canonical_ts(aware) == ledger.canonical_ts(naive)

    kw = dict(seq=7, vday=3, actor="a", action="x", target=None, detail={"k": 1})
    assert ledger.compute_hash(ledger.GENESIS, wall_ts=aware, **kw) == \
           ledger.compute_hash(ledger.GENESIS, wall_ts=naive, **kw)


def test_chain_still_verifies_after_a_fresh_session_reads_it_back(client):
    """Writes and verification happen in different sessions in production; this
    is the path the isoformat bug actually broke."""
    with SessionLocal() as db:
        ledger.record(db, actor="roundtrip", action="rt.event", detail={"n": 1})
        db.commit()
    with SessionLocal() as db:
        assert ledger.verify(db).ok is True


# ── raw data durability ──────────────────────────────────────────────────────
def test_deleting_an_endpoint_does_not_destroy_its_observations():
    """Observations are the evidence an endpoint was derived from, not the other
    way round. Rebuilding the registry — which re-running correlation does — must
    leave the raw rows for stage 03 to re-resolve."""
    from sentry_core.models import Observation

    fk = next(fk for fk in Observation.__table__.foreign_keys
              if fk.column.table.name == "endpoint")
    assert fk.ondelete == "SET NULL", (
        f"observation.endpoint_id is ON DELETE {fk.ondelete}; cascading from the "
        f"derived aggregate to the raw evidence destroys the source of truth"
    )


# ── one cycle at a time, across both entry points ───────────────────────────
def test_manual_scan_runs_under_the_scan_lock(client, monkeypatch):
    """The manual route must take the same lock beat's dispatcher takes.

    It did not. `/operations/scan` called the runner directly in the API process
    while the worker was running its own scheduled cycle, the two interleaved,
    and stage 02 died on `endpoint_daily_pkey` writing a rollup the other cycle
    had already written. The lock is the deployment's, not the worker's.
    """
    import contextlib

    from sentry_core import live
    from sentry_worker import runner

    entered: list[int] = []

    @contextlib.contextmanager
    def recording_lock(*, ttl_s, key="lock:scan"):
        entered.append(ttl_s)
        yield "token"

    monkeypatch.setattr(live, "scan_lock", recording_lock)
    monkeypatch.setattr(runner, "scan_cycle", lambda db, **kw: (0, []))

    r = client.post("/api/v1/operations/scan", headers=ANALYST)

    assert r.status_code == 202
    assert entered, "the manual scan route ran a cycle without taking the lock"
    assert entered[0] == live.SCAN_LOCK_TTL_S


def test_manual_scan_refuses_when_a_cycle_is_already_running(client, monkeypatch):
    """A held lock is reported, not queued behind. Starting a second cycle is
    the condition the lock exists to prevent, and silently waiting would hide a
    cadence already overrunning its interval."""
    import contextlib

    from sentry_core import live
    from sentry_worker import runner

    @contextlib.contextmanager
    def held(*, ttl_s, key="lock:scan"):
        raise live.NotAcquired("another cycle holds the scan lock")
        yield  # pragma: no cover

    ran: list[bool] = []
    monkeypatch.setattr(live, "scan_lock", held)
    monkeypatch.setattr(runner, "scan_cycle",
                        lambda db, **kw: (ran.append(True), (0, []))[1])

    r = client.post("/api/v1/operations/scan", headers=ANALYST)

    assert r.status_code == 409
    assert r.json()["error"]["code"] == "CYCLE_IN_PROGRESS"
    assert not ran, "the cycle ran despite the lock being held"


def test_the_lock_ttl_has_one_definition(client):
    """Two entry points into one cycle, one TTL. `sentry_worker.tasks` used to
    own it and the API cannot import that module to reach it — doing so would
    construct a Celery app inside the web process."""
    from sentry_core import live
    from sentry_worker import tasks

    assert tasks.SCAN_LOCK_TTL_S is live.SCAN_LOCK_TTL_S


def test_the_refusal_names_the_cycle_it_collided_with(client, monkeypatch):
    """At a compressed clock scale the scheduled cadence is shorter than a cycle
    takes, so a held lock is the ordinary answer. A 409 that says only "another
    cycle holds the lock" reads as a fault; naming the run lets the console send
    the operator to the pass that is already running."""
    import contextlib

    from sentry_core import live
    from sentry_core.db import SessionLocal
    from sentry_core.models import PipelineRun

    with SessionLocal() as db:
        run = PipelineRun(trigger="scheduled", actor=None)
        db.add(run)
        db.commit()
        running_id = run.id

    @contextlib.contextmanager
    def held(*, ttl_s, key="lock:scan"):
        raise live.NotAcquired("another cycle holds the scan lock")
        yield  # pragma: no cover

    monkeypatch.setattr(live, "scan_lock", held)

    r = client.post("/api/v1/operations/scan", headers=ANALYST)

    assert r.status_code == 409
    detail = r.json()["error"]["detail"]
    assert detail["running_run_id"] == running_id
    assert detail["trigger"] == "scheduled"
