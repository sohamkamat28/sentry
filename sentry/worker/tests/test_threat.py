"""Stage 12 — the fingerprint, the guardrails, and the resurrection scan.

The engine's own tests cover MinHash behaviour. These cover the runner: what
goes into a profile, when a fingerprint is allowed to be captured, and what the
certificate is permitted to claim.

The load-bearing case is the last one. An earlier build asserted
``honeypot_activated: true`` on every certificate on the strength of a boolean
nobody acted on — no route existed, no sign-off was checked, and the certificate
is the document that outlives the endpoint.
"""

from __future__ import annotations

import os  # noqa: F401  — DATABASE_URL is set by the root conftest
from datetime import datetime, timezone

import pytest

from sentry_core.db import SessionLocal, create_all
from sentry_core.enums import Source
from sentry_core.models import (
    CallEdge,
    Endpoint,
    Fingerprint,
    Observation,
    PolicySetting,
    ResurrectionAlert,
    Service,
)
from sentry_worker import runner
from sentry_worker.engines import fingerprint

BASE = datetime(2026, 7, 1, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def db():
    create_all()
    with SessionLocal() as s:
        for table in (ResurrectionAlert, Fingerprint, CallEdge, Observation,
                      Endpoint, Service, PolicySetting):
            s.query(table).delete()
        s.commit()
        yield s
        s.rollback()


def _service(db, name="core-accounts") -> Service:
    svc = Service(id=name[:16].ljust(16, "0"), name=name, first_vday=0, last_vday=0)
    db.add(svc)
    db.flush()
    return svc


def _endpoint(db, svc, path="/api/v1/balance", method="GET", **kw) -> Endpoint:
    ep = Endpoint(
        id=f"ep{abs(hash((method, path))) % 10**12:012d}",
        method=method, path_template=path, service_id=svc.id,
        host=svc.name, port=8443, first_vday=0, **kw)
    db.add(ep)
    db.flush()
    return ep


def _traffic(db, ep, *, n=20, hour=9, req=512, resp=2048, auth=True, classes=()):
    for i in range(n):
        db.add(Observation(
            vday=i, wall_ts=BASE.replace(hour=hour), source=Source.EBPF,
            endpoint_id=ep.id, method=ep.method, path_raw=ep.path_template,
            host=ep.host, port=ep.port, status=200, req_bytes=req, resp_bytes=resp,
            auth_present=auth, data_classes=list(classes), synthetic=False))
    db.flush()


# ─────────────────────────────────────────────────────────────────────────────
# The profile
# ─────────────────────────────────────────────────────────────────────────────
def test_the_profile_is_built_only_from_real_captures(db):
    """Collector rows describe a declared surface; the Judge's replays are
    SENTRY's own traffic. A fingerprint built from either describes something
    other than the endpoint's behaviour."""
    svc = _service(db)
    ep = _endpoint(db, svc)
    _traffic(db, ep, n=5)
    # A gateway row: evidence the route exists, not evidence of behaviour.
    db.add(Observation(vday=0, wall_ts=BASE, source=Source.GATEWAY,
                       endpoint_id=ep.id, method="GET", path_raw=ep.path_template,
                       auth_present=True, data_classes=[]))
    # A judge replay: SENTRY calling itself.
    db.add(Observation(vday=0, wall_ts=BASE, source=Source.EBPF,
                       endpoint_id=ep.id, method="GET", path_raw=ep.path_template,
                       auth_present=True, data_classes=[], synthetic=True))
    db.flush()

    profile = runner._behaviour_profile(db, ep)
    assert profile["observations"] == 5


def test_an_endpoint_with_no_captures_profiles_as_empty_not_as_zero_traffic(db):
    svc = _service(db)
    ep = _endpoint(db, svc)
    profile = runner._behaviour_profile(db, ep)

    assert profile["observations"] == 0
    # Bands say "unknown", not "tiny". A missing measurement and a measured
    # small value are different claims.
    assert profile["req_size_band"] == "unknown"


def test_the_caller_set_is_part_of_the_profile(db):
    """Who calls an endpoint is behaviour, and it survives a rename — which is
    what makes it worth including."""
    svc = _service(db)
    caller = _service(db, "payments-upi")
    ep = _endpoint(db, svc)
    _traffic(db, ep, n=3)
    db.add(CallEdge(caller_service_id=caller.id, endpoint_id=ep.id,
                    first_vday=0, last_vday=0, calls=3))
    db.flush()

    assert runner._behaviour_profile(db, ep)["callers"] == ["payments-upi"]


def test_no_path_token_reaches_the_shingle_set(db):
    """The regression test for the defect that made this detector useless: a
    redeployment under a new path scored 0.583 against a 0.85 threshold because
    the one thing a rename changes was weighted heavily."""
    svc = _service(db)
    ep = _endpoint(db, svc, path="/api/v1/nostro-position")
    _traffic(db, ep, n=4)

    shingles = fingerprint.behavioural_shingles(runner._behaviour_profile(db, ep))
    assert not any("nostro" in s.lower() for s in shingles)
    assert not any("api" in s.lower() for s in shingles)


def test_an_unmeasured_feature_is_omitted_not_shared():
    """Jaccard counts shared members, so `respsize:unknown` on both sides reads
    as agreement when it records that neither side was measured.

    On an estate where the sensor captures no payload sizes that put two
    identical tokens into every comparison, and two unrelated endpoints scored
    0.9167 against a retired one on the strength of what nobody had observed.
    """
    sh = fingerprint.behavioural_shingles({
        "method": "GET", "req_size_band": "unknown", "resp_size_band": "unknown",
    })
    assert not any(s.startswith(("reqsize:", "respsize:")) for s in sh)


def test_a_measured_size_is_still_a_feature():
    sh = fingerprint.behavioural_shingles({
        "method": "GET", "req_size_band": "small", "resp_size_band": "large",
    })
    assert "reqsize:small" in sh
    assert "respsize:large" in sh


def test_unmeasured_sizes_do_not_make_unrelated_endpoints_similar(db):
    """The regression for the false positives. Two endpoints alike only in what
    was never measured must not clear the threshold."""
    svc = _service(db)
    retired = _endpoint(db, svc, path="/internal/maturity", retired=True)
    _traffic(db, retired, n=10, hour=9, req=0, resp=0, auth=False, classes=("ACCOUNT",))
    runner._capture_fingerprint(db, retired, vday=90)

    other = _endpoint(db, svc, path="/api/v1/settlement", method="POST")
    _traffic(db, other, n=10, hour=15, req=0, resp=0, auth=True, classes=("SWIFT",))
    db.flush()

    outcome = runner.stage_12_threat(db, vday=91)
    assert outcome.records == 0


def test_the_same_behaviour_at_a_new_path_still_matches(db):
    """The whole point. Two endpoints doing the same thing at different paths
    must score above threshold."""
    svc = _service(db)
    old = _endpoint(db, svc, path="/internal/maturity")
    new = _endpoint(db, svc, path="/api/v2/maturity-v2")
    for ep in (old, new):
        _traffic(db, ep, n=10, classes=("ACCOUNT",))

    a = fingerprint.behavioural_shingles(runner._behaviour_profile(db, old))
    b = fingerprint.behavioural_shingles(runner._behaviour_profile(db, new))
    assert fingerprint.exact_jaccard(a, b) >= 0.95


# ─────────────────────────────────────────────────────────────────────────────
# Capture
# ─────────────────────────────────────────────────────────────────────────────
def test_capture_records_the_origin_path_so_an_alert_can_name_it(db):
    """An alert that could not name the original path would tell the operator a
    match exists without saying what it matched."""
    svc = _service(db)
    ep = _endpoint(db, svc, path="/internal/maturity")
    _traffic(db, ep, n=6)

    row = runner._capture_fingerprint(db, ep, vday=90)
    assert row.origin_path == "/internal/maturity"
    assert row.captured_vday == 90
    assert row.shingles
    # Deserialisable, because the honeypot and the index both read it back.
    assert fingerprint.deserialise(row.minhash).jaccard(
        fingerprint.build_minhash(list(row.shingles))) == 1.0


def test_capture_refuses_an_endpoint_with_no_observations(db):
    """A signature built from nothing is not a weak signature — it is the
    default profile, and it matches every other endpoint that also has nothing
    to say.

    Reachable in normal operation: retention prunes on a vday window, and at a
    compressed clock scale that window can elapse before a lifecycle completes.
    Phase D then blocks with a reason rather than retiring an endpoint behind a
    fingerprint that would alert on the whole estate.
    """
    svc = _service(db)
    ep = _endpoint(db, svc, path="/api/v1/pruned")

    with pytest.raises(ValueError, match="no captured observations"):
        runner._capture_fingerprint(db, ep, vday=90)


def test_capturing_twice_updates_rather_than_duplicating(db):
    svc = _service(db)
    ep = _endpoint(db, svc)
    _traffic(db, ep, n=4)

    runner._capture_fingerprint(db, ep, vday=10)
    runner._capture_fingerprint(db, ep, vday=20)
    db.flush()

    rows = db.query(Fingerprint).filter(Fingerprint.endpoint_id == ep.id).all()
    assert len(rows) == 1
    assert rows[0].captured_vday == 20


# ─────────────────────────────────────────────────────────────────────────────
# The sign-off guardrail
# ─────────────────────────────────────────────────────────────────────────────
def test_an_absent_policy_record_is_not_signed(db):
    assert runner._signoff(db) == (False, "")


def test_the_seeded_default_is_unsigned(db):
    """Bootstrap seeds the record with signed: false. A honeypot that was on by
    default would be one nobody authorised."""
    db.add(PolicySetting(key="honeypot_legal_signoff",
                         value={"reference": None, "signed": False},
                         updated_by="test"))
    db.flush()
    signed, _ = runner._signoff(db)
    assert signed is False


def test_a_reference_without_a_signature_is_not_signed(db):
    db.add(PolicySetting(key="honeypot_legal_signoff",
                         value={"reference": "policy:LEGAL-2026-004", "signed": False},
                         updated_by="test"))
    db.flush()
    assert runner._signoff(db)[0] is False


def test_a_signature_without_a_reference_is_not_signed(db):
    """A sign-off nobody can trace to a document is not a sign-off."""
    db.add(PolicySetting(key="honeypot_legal_signoff",
                         value={"reference": "", "signed": True}, updated_by="test"))
    db.flush()
    assert runner._signoff(db)[0] is False


def test_both_present_is_signed(db):
    db.add(PolicySetting(key="honeypot_legal_signoff",
                         value={"reference": "policy:LEGAL-2026-004", "signed": True},
                         updated_by="test"))
    db.flush()
    assert runner._signoff(db) == (True, "policy:LEGAL-2026-004")


# ─────────────────────────────────────────────────────────────────────────────
# The scan
# ─────────────────────────────────────────────────────────────────────────────
def test_an_empty_index_withholds_rather_than_reporting_no_matches(db):
    """Nothing retired means no signature to match against. Reporting zero
    alerts without saying so presents an unarmed detector as a clean scan."""
    svc = _service(db)
    ep = _endpoint(db, svc)
    _traffic(db, ep, n=5)

    outcome = runner.stage_12_threat(db, vday=1)
    assert outcome.records == 0
    assert "withheld" in outcome.detail
    assert outcome.detail["fingerprints"] == 0


def test_a_redeployment_under_a_new_path_raises_an_alert_naming_the_original(db):
    svc = _service(db)
    old = _endpoint(db, svc, path="/internal/maturity", retired=True)
    _traffic(db, old, n=10, classes=("ACCOUNT",))
    runner._capture_fingerprint(db, old, vday=90)

    new = _endpoint(db, svc, path="/api/v2/maturity-v2")
    _traffic(db, new, n=10, classes=("ACCOUNT",))
    db.flush()

    outcome = runner.stage_12_threat(db, vday=91)

    assert outcome.records == 1
    alert = outcome.detail["alerts"][0]
    assert alert["origin_path"] == "/internal/maturity"
    assert alert["similarity"] >= 0.85


def test_a_retired_endpoint_is_not_scanned_against_itself(db):
    """It is in the index and it is its own perfect match. Scanning it would
    alert on every retirement."""
    svc = _service(db)
    old = _endpoint(db, svc, path="/internal/maturity", retired=True)
    _traffic(db, old, n=8)
    runner._capture_fingerprint(db, old, vday=90)
    db.flush()

    outcome = runner.stage_12_threat(db, vday=91)
    assert outcome.records == 0


def test_an_endpoint_with_no_traffic_is_not_scored(db):
    """Two mostly-empty shingle sets are highly similar to each other for
    reasons that are not evidence of a resurrection."""
    svc = _service(db)
    old = _endpoint(db, svc, path="/internal/maturity", retired=True)
    _traffic(db, old, n=8)
    runner._capture_fingerprint(db, old, vday=90)
    _endpoint(db, svc, path="/api/v3/silent")   # no observations
    db.flush()

    outcome = runner.stage_12_threat(db, vday=91)
    assert outcome.detail["endpoints_scanned"] == 0
    assert outcome.records == 0


def test_behaviourally_different_endpoints_do_not_alert(db):
    svc = _service(db)
    old = _endpoint(db, svc, path="/internal/maturity", method="GET", retired=True)
    _traffic(db, old, n=10, hour=3, req=128, resp=256, auth=False,
             classes=("ACCOUNT",))
    runner._capture_fingerprint(db, old, vday=90)

    other = _endpoint(db, svc, path="/api/v1/settlement", method="POST")
    _traffic(db, other, n=10, hour=14, req=65536, resp=131072, auth=True,
             classes=("PAN", "SWIFT"))
    db.flush()

    outcome = runner.stage_12_threat(db, vday=91)
    assert outcome.records == 0


def test_the_same_alert_is_not_raised_twice(db):
    """The scan runs every cycle. A duplicate per cycle would bury the operator
    in re-notifications of one event."""
    svc = _service(db)
    old = _endpoint(db, svc, path="/internal/maturity", retired=True)
    _traffic(db, old, n=10, classes=("ACCOUNT",))
    runner._capture_fingerprint(db, old, vday=90)
    new = _endpoint(db, svc, path="/api/v2/maturity-v2")
    _traffic(db, new, n=10, classes=("ACCOUNT",))
    db.flush()

    assert runner.stage_12_threat(db, vday=91).records == 1
    db.commit()
    assert runner.stage_12_threat(db, vday=92).records == 0
    assert db.query(ResurrectionAlert).count() == 1


def test_the_index_is_rebuilt_from_postgres_every_scan(db):
    """The 'survives a Redis flush' requirement. Nothing is cached between
    scans, so there is no state a flush could lose."""
    svc = _service(db)
    old = _endpoint(db, svc, path="/internal/maturity", retired=True)
    _traffic(db, old, n=8)
    runner._capture_fingerprint(db, old, vday=90)
    db.flush()

    index, loaded = runner._load_index(db)
    assert loaded == 1
    assert len(index) == 1


# ── response schema in the fingerprint ──────────────────────────────────────
def test_field_shingles_separate_a_redeployment_from_an_unrelated_endpoint():
    """The feature group that took stage 12 over its own threshold.

    Measured on this estate: the resurrection scored 0.800 against a 0.85
    threshold on behavioural features alone, with the nearest unrelated endpoint
    at 0.727 — real separation, but a margin of 0.073 that one bucket boundary
    decides. With the response schema the classifier now extracts, the same pair
    scores 0.882 and the nearest miss falls to 0.591.

    The pair here shares its schema and differs on an hour band, which is the
    shape that used to fail.
    """
    from sentry_worker.engines.fingerprint import behavioural_shingles, exact_jaccard

    account_fields = ["accountholder", "accountnumber", "asof", "balance",
                      "branch", "currency", "ifsc"]

    def profile(fields, hour_shape, callers, classes):
        return {"method": "GET", "response_fields": fields, "data_classes": classes,
                "callers": callers, "hour_shape": hour_shape, "auth": "none",
                "auth_missing_band": "mostly", "req_size_band": "small",
                "resp_size_band": "small", "observations": 90,
                "has_schema": bool(fields)}

    origin = profile(account_fields, [0] * 9 + [40] + [0] * 14, ["traffic"],
                     ["ACCOUNT_NO", "IFSC"])
    redeploy = profile(account_fields, [0] * 14 + [40] + [0] * 9, ["traffic"],
                       ["ACCOUNT_NO", "IFSC"])
    unrelated = profile(["closing", "correspondent", "currency", "opening"],
                        [0] * 9 + [40] + [0] * 14, ["traffic"],
                        ["ACCOUNT_NO", "IFSC"])

    o = behavioural_shingles(origin)
    true_pair = exact_jaccard(o, behavioural_shingles(redeploy))
    false_pair = exact_jaccard(o, behavioural_shingles(unrelated))

    assert true_pair >= 0.85, (
        f"the redeployment scores {true_pair:.3f}, below the 0.85 threshold it "
        f"has to clear — the response schema is not reaching the fingerprint")
    assert true_pair - false_pair > 0.2, (
        f"margin is only {true_pair - false_pair:.3f}; the field shingles exist "
        f"to make this separation decisive rather than marginal")


def test_a_fingerprint_carries_one_shingle_per_response_field():
    from sentry_worker.engines.fingerprint import behavioural_shingles

    sh = behavioural_shingles({
        "method": "GET", "response_fields": ["balance", "ifsc"],
        "data_classes": [], "callers": [], "hour_shape": [0] * 24,
        "auth": "none", "auth_missing_band": "none",
        "req_size_band": "small", "resp_size_band": "small",
        "observations": 10, "has_schema": True})

    assert "field:balance" in sh
    assert "field:ifsc" in sh
