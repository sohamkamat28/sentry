"""Rungs 1 and 4 of the ownership ladder.

Rung 2 (git blame) is covered in test_code_collector.py and the ladder's own
ordering logic in test_engines.py. These are the two rungs that had no inputs
at all: every endpoint in the estate resolved to nobody because CODEOWNERS was
never read and the employment question was never asked.

The case the directory tests are built around is a departed owner with no
successor. That is worse than an unowned endpoint, because it reads as resolved
on every report while the escalation goes to an address nobody opens.
"""

from __future__ import annotations

import json

import pytest

from sentry_worker.collectors import codeowners, directory
from sentry_worker.engines import correlation

SAMPLE = """\
# Catch-all first, because the last match wins.
*                       @bank/platform      platform@bank.example

/services/accounts/**   @bank/core-banking  priya.raman@bank.example
*.tf                    @bank/infra
/vendor/
"""


# ─────────────────────────────────────────────────────────────────────────────
# CODEOWNERS
# ─────────────────────────────────────────────────────────────────────────────
def test_the_last_matching_rule_wins_not_the_first():
    """Reading top-down-first-match assigns everything to the catch-all and
    silently discards every specific rule below it."""
    rules = codeowners.parse(SAMPLE)
    owners = codeowners.owners_for(rules, "services/accounts/src/balance.py")

    assert owners.team == "core-banking"
    assert owners.email == "priya.raman@bank.example"


def test_an_unclaimed_path_falls_to_the_catch_all():
    rules = codeowners.parse(SAMPLE)
    assert codeowners.owners_for(rules, "README.md").team == "platform"


def test_a_pattern_with_no_owners_unassigns():
    """`/vendor/` on its own is a deliberate statement that nobody owns that
    tree. Treating it as 'no match' attributes vendored code to whoever owns
    the repository."""
    rules = codeowners.parse(SAMPLE)
    owners = codeowners.owners_for(rules, "vendor/left-pad/index.js")

    assert owners.matched          # a rule did match
    assert owners.email is None    # and it assigned nobody
    assert owners.team is None


def test_an_extension_pattern_matches_at_any_depth():
    """An unanchored pattern with no slash is not rooted at the top."""
    rules = codeowners.parse(SAMPLE)
    assert codeowners.owners_for(rules, "deploy/aws/main.tf").team == "infra"


def test_comments_and_blank_lines_are_not_rules():
    assert len(codeowners.parse(SAMPLE)) == 4


def test_a_bare_handle_is_not_turned_into_an_address():
    """Inventing `handle@example.com` produces an address that does not exist
    and routes escalations into a void."""
    rules = codeowners.parse("*  @some-person\n")
    owners = codeowners.owners_for(rules, "any/file.py")

    assert owners.email is None
    assert owners.team == "some-person"


def test_a_repository_with_no_codeowners_returns_none(tmp_path):
    """None and an empty rule list are different: no file means ownership was
    never declared, an empty file means it was declared as nothing."""
    assert codeowners.load(str(tmp_path)) is None


def test_the_github_directory_is_searched(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text("*  @bank/core\n")
    rules = codeowners.load(str(tmp_path))

    assert rules is not None
    assert codeowners.owners_for(rules, "x.py").team == "core"


# ─────────────────────────────────────────────────────────────────────────────
# HR directory
# ─────────────────────────────────────────────────────────────────────────────
PEOPLE = {"people": [
    {"email": "priya.raman@bank.example", "team": "core-banking", "employed": True},
    {"email": "martin.weiss@bank.example", "team": "core-banking", "employed": False,
     "successor": None, "department_head": "elena.rossi@bank.example"},
    {"email": "sofia.almeida@bank.example", "team": "payments", "employed": False,
     "successor": "johan.lindqvist@bank.example"},
]}


@pytest.fixture
def hr(tmp_path):
    p = tmp_path / "directory.json"
    p.write_text(json.dumps(PEOPLE))
    return directory.load(str(p))


def test_an_employed_owner_keeps_full_confidence(hr):
    o = correlation.resolve_ownership(
        {"email": "priya.raman@bank.example", "team": "core-banking"},
        None, None, hr.lookup)

    assert o.resolved_by == "codeowners"
    assert o.confidence == 1.00
    assert o.reachable is True


def test_a_departed_owner_with_a_successor_hands_over_at_reduced_confidence(hr):
    """Somebody took the work over. Weaker evidence than a declaration, and
    much stronger than nothing."""
    o = correlation.resolve_ownership(
        {"email": "sofia.almeida@bank.example", "team": "payments"},
        None, None, hr.lookup)

    assert o.owner_email == "johan.lindqvist@bank.example"
    assert o.confidence == 0.80
    assert o.reachable is True


def test_a_departed_owner_with_no_successor_stays_on_the_record(hr):
    """The load-bearing case. Blanking the owner destroys the only lead anyone
    has; leaving them contactable sends the escalation nowhere. Both."""
    o = correlation.resolve_ownership(
        {"email": "martin.weiss@bank.example", "team": "core-banking"},
        None, None, hr.lookup)

    assert o.owner_email == "martin.weiss@bank.example"   # the lead is kept
    assert o.reachable is False                           # and marked unreachable
    assert o.escalation == "elena.rossi@bank.example"     # with somewhere to go
    assert o.confidence == 0.50


def test_somebody_absent_from_a_reachable_directory_does_not_work_here(hr):
    o = correlation.resolve_ownership(
        {"email": "ghost@bank.example"}, None, None, hr.lookup)

    assert o.reachable is False


def test_an_unavailable_directory_leaves_confidence_untouched(tmp_path):
    """Unavailable is a fourth outcome and must not collapse into the other
    three. The employment question is unanswered, so confidence is neither
    inflated by assuming employment nor discounted by assuming departure."""
    hr = directory.load(str(tmp_path / "absent.json"))
    assert hr.available is False

    o = correlation.resolve_ownership(
        {"email": "priya.raman@bank.example", "team": "core-banking"},
        None, None, hr.lookup)

    assert o.confidence == 1.00
    assert o.reachable is True
    assert any(r["result"] == "unavailable" for r in o.ladder)


def test_an_unconfigured_directory_is_unavailable_not_empty():
    hr = directory.load("")
    assert hr.available is False
    assert hr.lookup("anyone@bank.example") is None


def test_a_csv_export_loads_with_loose_column_names(tmp_path):
    """No two HR systems agree on a header, and an unrecognised column silently
    becomes a person with no employment status — which reads as departed."""
    p = tmp_path / "people.csv"
    p.write_text("Email Address,Department,Status,Manager\n"
                 "wei.chen@bank.example,settlement,Active,tomas.varga@bank.example\n")
    hr = directory.load(str(p))

    row = hr.lookup("wei.chen@bank.example")
    assert row["employed"] is True
    assert row["team"] == "settlement"


def test_the_estate_directory_fixture_parses():
    """The file the running estate actually mounts."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    hr = directory.load(str(root / "estate" / "hr-stub" / "directory.json"))

    assert hr.available is True
    assert hr.lookup("martin.weiss@bank.example")["employed"] is False
