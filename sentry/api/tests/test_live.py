"""The live capture stream, and the distinction it exists to preserve.

`ingest/internal/store/live.go` has incremented `live:src:<source>` on the
capture hot path since it was written, and its comment calls those counters
"the console's capture stream". Nothing ever read them — the route was never
built, so the console has never had a real-time feed.

The property under test is not that the numbers are right. It is that a cache
which cannot answer never renders as an estate with nothing to say.
"""

from __future__ import annotations

import os  # noqa: F401  — DATABASE_URL is set by the root conftest

os.environ.setdefault("AUTH_DISABLED", "true")
os.environ.setdefault("REDIS_URL", "")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from sentry_core import live  # noqa: E402
from sentry_core.db import create_all  # noqa: E402

VIEWER = {"Authorization": "Bearer dev-viewer"}


@pytest.fixture(scope="module")
def client():
    create_all()
    with TestClient(app) as c:
        yield c


def test_live_reports_which_store_answered(client):
    r = client.get("/api/v1/live", headers=VIEWER)
    assert r.status_code == 200
    body = r.json()
    assert body["source"] in ("redis", "postgres", "unavailable")


def test_a_cache_that_cannot_answer_is_not_reported_as_an_idle_estate(client, monkeypatch):
    """The defect this endpoint is shaped around.

    `live_counts` returns None when Redis cannot be reached and a zero when
    nothing was captured. Folding the first into the second turns an outage into
    a report of a quiet estate — the console would show a calm dashboard while
    the sensor was blind. `source` has to say which happened.
    """
    monkeypatch.setattr(live, "live_counts", lambda *a, **k: None)
    monkeypatch.setattr(live, "client", lambda: object())  # configured, but failing

    body = client.get("/api/v1/live", headers=VIEWER).json()

    assert body["source"] == "unavailable", (
        "a Redis failure reported itself as a successful read; an operator "
        "cannot distinguish a quiet estate from a blind one")


def test_an_unconfigured_cache_falls_back_to_postgres_and_says_so(client, monkeypatch):
    """No Redis is not a failure. The authoritative count is still available and
    the console should be told it is reading the slow path."""
    monkeypatch.setattr(live, "live_counts", lambda *a, **k: None)
    monkeypatch.setattr(live, "client", lambda: None)

    body = client.get("/api/v1/live", headers=VIEWER).json()

    assert body["source"] == "postgres"
    assert body["observed"]["total"] >= 0


def test_a_cache_that_answers_zero_is_reported_as_zero(client, monkeypatch):
    """The other half of the same distinction. Nothing captured is a real
    measurement and must not be disguised as a cache miss."""
    monkeypatch.setattr(live, "live_counts", lambda *a, **k: {"total": 0, "ebpf": 0})

    body = client.get("/api/v1/live", headers=VIEWER).json()

    assert body["source"] == "redis"
    assert body["observed"]["total"] == 0


def test_health_is_derived_from_captured_evidence(client):
    """A component is judged on what it produced, not on a status it claims.

    An agent that reports healthy while capturing nothing is the failure the
    whole product exists to catch, so `state` must come from the newest
    observation the source actually wrote.
    """
    body = client.get("/api/v1/live", headers=VIEWER).json()
    names = {h["component"] for h in body["health"]}

    assert {"agent", "gateway", "redis"} <= names
    for h in body["health"]:
        assert h["state"] in ("ok", "stale", "unknown", "down", "off")
        if h["component"] != "redis" and h["last_vday"] is None:
            assert h["state"] == "unknown", (
                "a source that has never written a row must read as unknown, "
                "not as healthy")


def test_pipeline_running_is_true_only_while_a_cycle_is_in_flight(client):
    """`ok is None` is what makes this a live readout rather than a report of
    the last completed pass."""
    body = client.get("/api/v1/live", headers=VIEWER).json()
    p = body["pipeline"]

    assert p["stages_total"] == 14
    if p["run_id"] is None:
        assert p["running"] is False
    else:
        assert p["running"] == (p["ok"] is None)


def test_live_requires_a_token(client):
    assert client.get("/api/v1/live").status_code == 401
