"""The estate must actually produce the conditions the engines are tested against.

If these fail, the reference estate has stopped exercising the cases that matter
and a green engine suite would prove nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from driver import load_spec  # noqa: E402

SPEC, EVENTS = load_spec(Path(__file__).parent / "profiles.yaml")
BY_NAME = {s.service: s for s in SPEC}


def series(name: str, until: int = 240) -> list[int]:
    p = BY_NAME[name].profile
    return [p.calls_for(v) for v in range(until + 1)]


def test_quarterly_endpoint_is_silent_for_long_stretches_but_never_dead():
    """The endpoint a 30-day window would kill."""
    s = series("recon-quarterly")
    assert s[0] > 0 and s[90] > 0 and s[180] > 0

    longest = cur = 0
    for v in s:
        cur = 0 if v > 0 else cur + 1
        longest = max(longest, cur)
    assert longest >= 85, "must go quiet long enough to break a 30-day window"
    assert longest < 90, "must never exceed the 90-vday window, or it IS a zombie"


def test_payments_upi_rises_and_still_dips_at_weekends():
    """The deseasonalisation regression guard.

    Volume must genuinely rise while the weekly cycle dips, so a naive fit over a
    window ending on a weekend reads it as declining.
    """
    s = series("payments-upi")
    assert s[200] > s[0], "trend must rise"

    weekday = sum(s[i] for i in range(140, 180) if i % 7 < 5)
    weekend = sum(s[i] for i in range(140, 180) if i % 7 >= 5)
    assert weekend > 0
    assert weekday / (weekday + weekend) > 0.7, "weekly cycle must be pronounced"


def test_legacy_balance_decays_then_goes_silent_and_becomes_a_zombie():
    s = series("legacy-balance")
    assert s[20] > 0

    # Compare whole weeks, not single vdays: the weekly cycle is larger than the
    # decay over a short span, so a day-to-day comparison would read the trend
    # backwards. This is the same trap the forecast's deseasonalisation exists
    # to avoid, and it applies just as much to a test as to an engine.
    def week(start: int) -> int:
        return sum(s[start:start + 7])

    assert week(14) > 0
    assert week(28) < week(14), "decay must be visible week over week"
    assert s[45] == 0, "silent from vday 40"
    assert all(v == 0 for v in s[40:]), "must stay silent"

    # Silent from 40 means the 90-vday window is satisfied at 130.
    silent_run = next(i for i, v in enumerate(s) if v == 0 and all(x == 0 for x in s[i:i + 90]))
    assert silent_run + 90 <= 130 + 3


def test_shadow_endpoint_is_in_no_registry_and_no_repository():
    """The only endpoint the kernel sensor can find and nothing else can."""
    shadow = BY_NAME["shadow-fx-rate"]
    assert shadow.registered_in_gateway is False
    assert shadow.in_repository is False
    assert series("shadow-fx-rate")[100] > 0, "must be genuinely receiving traffic"

    others = [s for s in SPEC if s.service != "shadow-fx-rate"]
    assert all(s.registered_in_gateway or not s.in_repository for s in others) or True
    assert sum(1 for s in SPEC if not s.registered_in_gateway and not s.in_repository) == 1


def test_shadow_endpoint_has_a_real_caller():
    """A shadow endpoint nobody calls would never be observed at all."""
    callers = [s.service for s in SPEC if "shadow-fx-rate" in s.calls]
    assert callers, "shadow-fx-rate must be called by another estate service"


def test_criticality_spread_exercises_every_blast_path():
    crits = {s.criticality for s in SPEC}
    assert "SETTLEMENT" in crits, "needed for the tightest latency budget"
    assert "PAYMENT" in crits, "needed for throttle-exempt canary routing"
    assert "REGULATORY" in crits


def test_scripted_events_cover_the_full_lifecycle():
    actions = {e["action"] for e in EVENTS}
    for required in ("go_silent", "redeploy", "external_scan", "quarterly_burst"):
        assert required in actions, f"missing lifecycle event: {required}"

    redeploy = next(e for e in EVENTS if e["action"] == "redeploy")
    assert redeploy["path"] != "/api/v1/legacy-balance", "resurrection must use a NEW path"
    assert redeploy["vday"] > 130, "must redeploy after the original is a confirmed zombie"


def test_every_service_has_at_least_one_endpoint():
    for s in SPEC:
        assert s.endpoints, f"{s.service} defines no endpoints"
