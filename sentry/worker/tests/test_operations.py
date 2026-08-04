"""Stage 14 — the leaderboard, the CI gate, and the SIEM feed.

The gate is the part that matters. Every other stage finds zombies after they
exist; this one refuses the next generation at the pull request.
"""

from __future__ import annotations

import socket
import threading

import pytest

from sentry_worker.actuators import siem
from sentry_worker.engines import operations


# ─────────────────────────────────────────────────────────────────────────────
# Security debt leaderboard
# ─────────────────────────────────────────────────────────────────────────────
def row(**kw) -> dict:
    base = {"team": "payments", "lifecycle": "ACTIVE", "governance": "DOCUMENTED",
            "pre_zombie": False, "cdri_score": 0.0, "cdri_tier": "LOW",
            "owner_resolved": True, "ownership_confidence": 1.0}
    base.update(kw)
    return base


def test_debt_weights_zombies_heaviest():
    """A zombie is the endpoint with no owner and no reason to exist; a
    pre-zombie is a prediction. Charging them the same invites an argument about
    the forecast instead of action on the endpoint."""
    zombies = operations.accumulate([row(lifecycle="ZOMBIE")])["payments"]
    pre = operations.accumulate([row(pre_zombie=True)])["payments"]

    assert zombies.debt == 2.0
    assert pre.debt == 0.5


def test_a_team_is_not_charged_for_endpoints_it_may_not_own():
    """Scaled by ownership confidence. Without this the leaderboard becomes a
    dispute about attribution, and a leaderboard people argue with is not
    prompting anyone to act."""
    confident = operations.accumulate(
        [row(lifecycle="ZOMBIE", ownership_confidence=1.0)])["payments"]
    guessed = operations.accumulate(
        [row(lifecycle="ZOMBIE", ownership_confidence=0.4)])["payments"]

    assert confident.debt == 2.0
    assert guessed.debt == pytest.approx(0.8)
    # The underlying debt is identical; only the charge differs.
    assert confident.raw == guessed.raw


def test_unowned_endpoints_are_charged_in_full_to_nobody():
    """An estate's worst debt is usually the endpoints nobody will claim.
    Omitting them would make the total look better the less anyone knew."""
    teams = operations.accumulate([row(team=None, lifecycle="ZOMBIE",
                                       ownership_confidence=0.0)])

    assert operations.UNATTRIBUTED in teams
    assert teams[operations.UNATTRIBUTED].debt == 2.0


def test_only_critical_cdri_scores_are_charged():
    hot = operations.accumulate([row(cdri_tier="CRITICAL", cdri_score=0.9)])["payments"]
    cool = operations.accumulate([row(cdri_tier="HIGH", cdri_score=0.9)])["payments"]

    assert hot.debt == pytest.approx(1.35)
    assert cool.debt == 0.0


def test_the_trend_is_shown_beside_the_absolute_figure():
    """A team going from 90 to 60 is doing better than one static at 55, and
    only the trend says so."""
    board = operations.leaderboard(
        [row(team="payments", lifecycle="ZOMBIE")] * 30,
        previous={"payments": 90.0})

    entry = board[0]
    assert entry["debt"] == 60.0
    assert entry["trend"] == -30.0


def test_a_team_with_no_history_has_no_trend():
    board = operations.leaderboard([row(lifecycle="ZOMBIE")])
    assert board[0]["trend"] is None


def test_the_board_is_ordered_worst_first():
    board = operations.leaderboard([
        row(team="core", lifecycle="ZOMBIE"),
        row(team="payments", lifecycle="ZOMBIE"),
        row(team="payments", lifecycle="ZOMBIE"),
    ])
    assert [b["team"] for b in board] == ["payments", "core"]


# ─────────────────────────────────────────────────────────────────────────────
# The CI pre-merge gate
# ─────────────────────────────────────────────────────────────────────────────
def route(**kw) -> operations.RouteDeclaration:
    base = {"method": "POST", "path": "/api/v3/transfer", "file": "src/routes.py",
            "line": 48, "owner": "payments-team", "has_auth_middleware": True,
            "in_catalogue": True}
    base.update(kw)
    return operations.RouteDeclaration(**base)


def named(checks, name):
    return next(c for c in checks if c.name == name)


def test_a_well_formed_route_passes_every_check():
    result = operations.run_gate([route()])
    assert result.passed()
    assert result.failed == []


def test_a_route_with_no_owner_fails():
    checks = operations.check_route(route(owner=None))
    assert not named(checks, "owner-tag").passed
    assert "CODEOWNERS" in named(checks, "owner-tag").detail


def test_a_route_with_no_auth_middleware_fails_with_its_location():
    """An annotation on the diff, at the line that introduced it."""
    checks = operations.check_route(route(has_auth_middleware=False))
    check = named(checks, "auth-middleware")

    assert not check.passed
    assert check.file == "src/routes.py" and check.line == 48


def test_an_unregistered_route_is_a_warning_not_an_error():
    """Registering a route in a catalogue is a separate change in most
    repositories. Blocking the code change on it teaches people to bypass the
    gate, and a bypassed gate catches nothing."""
    checks = operations.check_route(route(in_catalogue=False))
    check = named(checks, "catalogue-registration")

    assert not check.passed
    assert check.severity == "warn"

    result = operations.GateResult(checks=checks)
    assert result.passed(fail_on="error")       # ships, with the annotation
    assert not result.passed(fail_on="warn")    # blocked, if the institution says so


def test_a_resurrected_endpoint_fails_the_gate():
    """The check that closes the loop. A developer recreating a decommissioned
    endpoint under a new path is caught at the pull request rather than six
    months later by the sensor — a conversation instead of an incident."""
    checks = operations.check_route(
        route(path="/api/v3/balance"),
        retired_matches=[{"path": "/api/v1/legacy-balance", "score": 0.91}])
    check = named(checks, "no-resurrection")

    assert not check.passed
    assert "/api/v1/legacy-balance" in check.detail and "0.91" in check.detail


def test_a_weak_similarity_is_not_a_resurrection():
    checks = operations.check_route(
        route(), retired_matches=[{"path": "/api/v1/other", "score": 0.42}])
    assert named(checks, "no-resurrection").passed


def test_a_listener_below_the_tls_floor_fails():
    checks = operations.check_route(route(tls_floor="1.0"), tls_floor="1.3")
    assert not named(checks, "tls-policy").passed


def test_fail_on_never_reports_without_blocking():
    """How an institution adopts a gate without stopping every team on day one.
    The alternative is that it gets disabled in week two and never comes back."""
    result = operations.run_gate([route(owner=None, has_auth_middleware=False)])

    assert not result.passed(fail_on="error")
    assert result.passed(fail_on="never")
    assert len(result.failed) == 2  # still reported


def test_a_pull_request_with_no_routes_passes():
    """This gate has an opinion about API surface and none about anything
    else."""
    assert operations.run_gate([]).passed()


# ─────────────────────────────────────────────────────────────────────────────
# SIEM
# ─────────────────────────────────────────────────────────────────────────────
def test_cef_carries_the_score_and_the_endpoint():
    line = siem.to_cef(siem.Event(
        name="ZOMBIE_CRITICAL", message="Zombie endpoint with no authentication",
        endpoint_id="ep_9f2c8a1b", method="GET", path="/api/v1/legacy-balance",
        service="core-accounts", cdri=0.93, frameworks=["RBI-4.2", "DPDP-8"],
        time_to_breach_d=2))

    assert line.startswith("CEF:0|SENTRY|APILifecycle|1.0|ZOMBIE_CRITICAL|")
    assert "|9|" in line                       # severity
    assert "cs1Label=CDRI cs1=0.930" in line
    assert "cs2Label=Frameworks cs2=RBI-4.2;DPDP-8" in line
    assert "cn1Label=TimeToBreachDays cn1=2" in line


def test_cef_escapes_equals_in_values():
    """An unescaped `=` splits one field into two and silently corrupts every
    field after it. The parser does not complain; it reads the wrong thing."""
    line = siem.to_cef(siem.Event(name="SHADOW_DETECTED", message="x",
                                  path="/api/v1/q?a=b"))
    assert r"request=/api/v1/q?a\=b" in line


def test_cef_escapes_pipes_in_the_header():
    line = siem.to_cef(siem.Event(name="X", message="a|b"))
    assert r"a\|b" in line


def test_severities_differentiate_events():
    """Every event at the same severity is the same as no severity at all."""
    assert siem.SEVERITY["ZOMBIE_CRITICAL"] > siem.SEVERITY["HONEYPOT_PROBE"]
    assert siem.SEVERITY["HONEYPOT_PROBE"] > siem.SEVERITY["CONTROL_APPLIED"]


def test_leef_is_tab_delimited():
    line = siem.to_leef(siem.Event(name="SHADOW_DETECTED", message="m",
                                   path="/x", method="GET"))
    assert line.startswith("LEEF:2.0|SENTRY|APILifecycle|1.0|SHADOW_DETECTED|")
    assert "\t" in line


def test_hec_is_json():
    import json
    doc = json.loads(siem.to_hec(siem.Event(name="X", message="m", cdri=0.5)))
    assert doc["event"]["name"] == "X" and doc["event"]["cdri"] == 0.5


def test_an_unreachable_sink_spools_rather_than_drops():
    """A SIEM that is down must not stall a pipeline run and must not silently
    swallow the alerts raised while it was."""
    e = siem.Emitter(host="127.0.0.1", port=1, fmt="cef", spool_max=100)

    assert e.emit(siem.Event(name="ZOMBIE_CRITICAL", message="m")) is False
    assert e.spooled == 1
    assert e.failures == 1
    assert e.sent == 0


def test_the_spool_is_bounded_and_counts_what_it_drops():
    """Bounding it is what stops a delay becoming an unbounded memory leak."""
    e = siem.Emitter(host="127.0.0.1", port=1, fmt="cef", spool_max=3)
    for i in range(10):
        e.emit(siem.Event(name="X", message=f"m{i}"))

    assert e.spooled == 3
    assert e.dropped == 7
    # The newest are kept: they are the ones an analyst most likely still needs.
    assert "m9" in e.peek()[-1]


def test_a_recovered_sink_drains_the_spool():
    received: list[bytes] = []
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    port = server.getsockname()[1]

    def serve():
        for _ in range(4):
            conn, _addr = server.accept()
            with conn:
                received.append(conn.recv(4096))

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    e = siem.Emitter(host="127.0.0.1", port=port, fmt="cef", spool_max=100)
    # Spool three while the sink is "down".
    e.host = "127.0.0.1"
    down = siem.Emitter(host="127.0.0.1", port=1, fmt="cef", spool_max=100)
    for i in range(3):
        down.emit(siem.Event(name="X", message=f"queued{i}"))
    e._spool.extend(down.peek(10))

    assert e.emit(siem.Event(name="X", message="live")) is True
    t.join(timeout=5)

    assert e.spooled == 0
    assert e.sent == 4
    blob = b"".join(received)
    for i in range(3):
        assert f"queued{i}".encode() in blob


def test_an_unconfigured_sink_spools_without_reporting_a_failure():
    """No sink configured is a deployment that has not wired one, not a delivery
    failure. The events are still held so an operator can see what would have
    been sent."""
    e = siem.Emitter(host=None, fmt="cef", spool_max=10)

    assert e.emit(siem.Event(name="X", message="m")) is False
    assert e.spooled == 1
    assert e.failures == 0
    assert e.configured is False


def test_a_declared_team_is_charged_in_full():
    """The factor discounts a guessed attribution, so it applies only where the
    ownership ladder actually made one.

    A team declared on the service — by a gateway tag, say — is not a guess.
    Applying a 0.0 ladder confidence to it charged every team nothing: an estate
    with seven orphaned endpoints reported zero debt across the board, which is
    worse than a wrong number because it looks like good news.
    """
    declared = operations.accumulate([row(lifecycle="ZOMBIE",
                                          owner_resolved=False,
                                          ownership_confidence=0.0)])["payments"]
    assert declared.debt == 2.0


def test_a_ladder_resolved_owner_is_still_discounted_by_its_confidence():
    guessed = operations.accumulate([row(lifecycle="ZOMBIE",
                                         owner_resolved=True,
                                         ownership_confidence=0.4)])["payments"]
    assert guessed.debt == pytest.approx(0.8)
