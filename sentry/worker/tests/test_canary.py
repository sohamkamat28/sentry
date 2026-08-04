"""The canary migration path.

Selected whenever a blast radius touches a payment, settlement or regulatory
system, because deliberately degrading one of those to encourage migration is
itself the incident the sunset is trying to avoid.

It could be selected, and it could not run: the runner set `canary_split` and
changed nothing at the gateway, so the number moved 0.10 → 0.01 → 0.00 across
three phases while every request kept reaching the endpoint being retired.
"""

from __future__ import annotations

import os  # noqa: F401  — DATABASE_URL is set by the root conftest

import pytest

from sentry_core.db import SessionLocal, create_all
from sentry_core.enums import Criticality
from sentry_core.models import Endpoint, Service
from sentry_worker import runner
from sentry_worker.actuators import kong
from sentry_worker.engines import decommission


@pytest.fixture
def db():
    create_all()
    with SessionLocal() as s:
        for table in (Endpoint, Service):
            s.query(table).delete()
        s.commit()
        yield s
        s.rollback()


def _svc(db, name, criticality=Criticality.PAYMENT):
    svc = Service(id=name[:16].ljust(16, "0"), name=name, criticality=criticality,
                  first_vday=0, last_vday=0)
    db.add(svc)
    db.flush()
    return svc


def _ep(db, svc, path="/api/v1/payments/upi/{id}", method="GET"):
    ep = Endpoint(id=f"ep{abs(hash((svc.name, path))) % 10**12:012d}",
                  method=method, path_template=path, service_id=svc.id,
                  host=svc.name, port=8443, first_vday=0)
    db.add(ep)
    db.flush()
    return ep


# ─────────────────────────────────────────────────────────────────────────────
# Weights
# ─────────────────────────────────────────────────────────────────────────────
def test_the_split_is_the_share_still_on_the_old_endpoint():
    """0.10 means a tenth of traffic still reaches what is being retired."""
    w = kong.canary_weights("up", "old:8443", "new:8443", 0.10)
    assert w == {"old:8443": 100, "new:8443": 900}


def test_a_one_percent_step_is_a_whole_number():
    """Weights are integers and 1000 rather than 100 is why 0.01 does not become
    a rounding decision."""
    w = kong.canary_weights("up", "old:8443", "new:8443", 0.01)
    assert w == {"old:8443": 10, "new:8443": 990}


def test_the_final_step_moves_everything():
    w = kong.canary_weights("up", "old:8443", "new:8443", 0.0)
    assert w == {"old:8443": 0, "new:8443": 1000}


def test_the_steps_descend_to_zero():
    steps = []
    current = None
    while (nxt := decommission.next_canary_split(current)) is not None:
        steps.append(nxt)
        current = nxt
    assert steps == sorted(steps, reverse=True)
    assert steps[-1] == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Choosing a replacement
# ─────────────────────────────────────────────────────────────────────────────
def test_a_registered_replacement_serving_the_same_path_is_found(db):
    old = _svc(db, "payments-upi")
    new = _svc(db, "payments-upi-v2")
    ep = _ep(db, old)
    _ep(db, new)

    assert runner._replacement_for(db, ep) == "payments-upi-v2:8443"


def test_a_replacement_serving_a_different_path_is_not_a_replacement(db):
    """Same name, different contract. Shifting traffic onto it would be an
    outage dressed as a migration."""
    old = _svc(db, "payments-upi")
    new = _svc(db, "payments-upi-v2")
    ep = _ep(db, old)
    _ep(db, new, path="/api/v2/payments/different")

    assert runner._replacement_for(db, ep) is None


def test_no_replacement_at_all_returns_none(db):
    ep = _ep(db, _svc(db, "payments-upi"))
    assert runner._replacement_for(db, ep) is None


def test_an_absent_replacement_stops_the_migration_rather_than_starting_one(db):
    """The state the estate was actually in: parked in canary with nowhere to
    go, and it looked like progress."""
    from sentry_core.models import Decommission

    ep = _ep(db, _svc(db, "payments-upi"))
    dec = Decommission(endpoint_id=ep.id, canary=True, canary_split=0.10,
                       entered_vday=0, phase_vday=0, hidden_callers=[])

    out = runner._shift_canary(db, dec, ep, route_name="upi-route", actor="test")
    assert "canary_error" in out
    assert "replacement" in out["canary_error"]


def test_no_gateway_route_stops_the_migration(db):
    from sentry_core.models import Decommission

    ep = _ep(db, _svc(db, "payments-upi"))
    dec = Decommission(endpoint_id=ep.id, canary=True, canary_split=0.10,
                       entered_vday=0, phase_vday=0, hidden_callers=[])

    out = runner._shift_canary(db, dec, ep, route_name=None, actor="test")
    assert "canary_error" in out


# ─────────────────────────────────────────────────────────────────────────────
# Selection
# ─────────────────────────────────────────────────────────────────────────────
def test_a_payment_endpoint_never_gets_throttled():
    """Canary never throttles. Degrading a payment path to encourage migration
    is the incident it is avoiding."""
    assert decommission.criticality_is_exempt(Criticality.PAYMENT)
    assert decommission.criticality_is_exempt(Criticality.SETTLEMENT)
    assert decommission.criticality_is_exempt(Criticality.REGULATORY)


def test_an_internal_endpoint_is_not_exempt():
    assert not decommission.criticality_is_exempt(Criticality.INTERNAL)
