"""Stage 14 — continuous operations.

The loop that closes: what a scan cycle reports, what a team owes, and what the
pre-merge gate refuses.

The gate is the part that matters most. Every other stage finds zombies after
they exist; this one stops the next generation being written, at the pull
request, by the person who still remembers why they wrote it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentry_core.config import settings
from sentry_core.enums import Governance, Lifecycle, Tier

VERSION = "operations-1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# Security debt leaderboard
# ─────────────────────────────────────────────────────────────────────────────
#: What each kind of debt is worth.
#:
#: A zombie is the heaviest because it is the one with no owner and no reason to
#: exist. A pre-zombie is a fraction of one because it is a prediction, and
#: charging a team full price for a forecast invites an argument about the
#: forecast instead of action on the endpoint.
DEBT_WEIGHTS = {
    "zombie": 2.0,
    "critical_cdri": 1.5,
    "orphaned": 1.0,
    "pre_zombie": 0.5,
}


@dataclass
class TeamDebt:
    team: str
    zombies: int = 0
    orphaned: int = 0
    pre_zombie: int = 0
    critical_score: float = 0.0
    endpoints: int = 0
    #: Mean ownership confidence across the team's endpoints.
    confidence: float = 0.0
    previous: float | None = None

    @property
    def raw(self) -> float:
        return (DEBT_WEIGHTS["zombie"] * self.zombies
                + DEBT_WEIGHTS["critical_cdri"] * self.critical_score
                + DEBT_WEIGHTS["orphaned"] * self.orphaned
                + DEBT_WEIGHTS["pre_zombie"] * self.pre_zombie)

    @property
    def debt(self) -> float:
        """Scaled by how confidently the endpoints are attributed to this team.

        A team is not charged for endpoints assigned to it by a 0.40-confidence
        guess at a metadata field. Without this the leaderboard becomes a
        dispute about attribution, and a leaderboard people are arguing with is
        not prompting anyone to act.
        """
        return round(self.raw * self.confidence, 2)

    @property
    def trend(self) -> float | None:
        """Change since the trend window. Negative is improvement.

        Shown beside the absolute figure because a team going from 90 to 60 is
        doing better than one static at 55, and only the trend says so.
        """
        if self.previous is None:
            return None
        return round(self.debt - self.previous, 2)

    def as_dict(self) -> dict:
        return {
            "team": self.team,
            "debt": self.debt,
            "raw": round(self.raw, 2),
            "trend": self.trend,
            "endpoints": self.endpoints,
            "zombies": self.zombies,
            "orphaned": self.orphaned,
            "pre_zombie": self.pre_zombie,
            "critical_score": round(self.critical_score, 3),
            "ownership_confidence": round(self.confidence, 2),
        }


#: Where an endpoint with no resolved owner is charged.
#:
#: Not dropped. An estate's worst debt is usually exactly the endpoints nobody
#: will claim, and omitting them from the leaderboard would make the total look
#: better the less anyone knew.
UNATTRIBUTED = "(unattributed)"


def accumulate(rows: list[dict]) -> dict[str, TeamDebt]:
    """Fold per-endpoint facts into per-team debt.

    Each row is one endpoint: ``team``, ``lifecycle``, ``governance``,
    ``pre_zombie``, ``cdri_score``, ``cdri_tier``, ``owner_resolved`` and
    ``ownership_confidence``.
    """
    teams: dict[str, TeamDebt] = {}
    confidences: dict[str, list[float]] = {}

    for row in rows:
        team = row.get("team") or UNATTRIBUTED
        debt = teams.setdefault(team, TeamDebt(team=team))
        debt.endpoints += 1

        if row.get("lifecycle") == Lifecycle.ZOMBIE.value:
            debt.zombies += 1
        if row.get("governance") == Governance.ORPHANED.value:
            debt.orphaned += 1
        if row.get("pre_zombie"):
            debt.pre_zombie += 1
        if row.get("cdri_tier") == Tier.CRITICAL.value:
            debt.critical_score += float(row.get("cdri_score") or 0.0)

        # The factor discounts a *guessed* attribution, so it applies only where
        # the ownership ladder actually made one.
        #
        # A team can also be known without the ladder — declared on the service
        # by a gateway tag, say — and that attribution is not a guess. Applying
        # a 0.0 ladder confidence to it charged every team nothing: the estate
        # had seven orphaned endpoints and the leaderboard reported zero debt
        # across the board, which is the one output worse than a wrong number.
        confidences.setdefault(team, []).append(
            float(row["ownership_confidence"])
            if row.get("owner_resolved") and row.get("ownership_confidence") is not None
            else 1.0)

    for team, debt in teams.items():
        vals = confidences.get(team) or [1.0]
        # An unattributed endpoint is charged in full: there is no owner to be
        # unfair to, and discounting it would reward an estate for knowing less
        # about itself.
        debt.confidence = 1.0 if team == UNATTRIBUTED else sum(vals) / len(vals)

    return teams


def leaderboard(rows: list[dict], previous: dict[str, float] | None = None) -> list[dict]:
    teams = accumulate(rows)
    for team, debt in teams.items():
        if previous and team in previous:
            debt.previous = previous[team]
    return sorted((d.as_dict() for d in teams.values()),
                  key=lambda d: -d["debt"])


# ─────────────────────────────────────────────────────────────────────────────
# CI pre-merge gate
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class RouteDeclaration:
    """One route as the pull request declares it."""

    method: str
    path: str
    file: str | None = None
    line: int | None = None
    owner: str | None = None
    has_auth_middleware: bool = False
    in_catalogue: bool = False
    tls_floor: str | None = None


@dataclass
class Check:
    name: str
    passed: bool
    detail: str | None = None
    file: str | None = None
    line: int | None = None
    #: warn-level checks do not fail the build under GATE_FAIL_ON=error.
    severity: str = "error"

    def as_dict(self) -> dict:
        out = {"name": self.name, "passed": self.passed, "severity": self.severity}
        if self.detail:
            out["detail"] = self.detail
        if self.file:
            out["file"] = self.file
        if self.line is not None:
            out["line"] = self.line
        return out


@dataclass
class GateResult:
    checks: list[Check] = field(default_factory=list)

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]

    def passed(self, fail_on: str | None = None) -> bool:
        """Whether the build should go green.

        ``fail_on`` decides which severities count. ``never`` reports the
        findings and lets the build pass, which is how an institution adopts a
        gate without stopping every team on day one — the alternative is that
        the gate gets disabled in week two and never comes back.
        """
        mode = (fail_on or settings.gate_fail_on).lower()
        if mode == "never":
            return True
        blocking = {"error"} if mode == "error" else {"error", "warn"}
        return not any(c.severity in blocking for c in self.failed)

    def as_dict(self, fail_on: str | None = None) -> dict:
        return {"passed": self.passed(fail_on),
                "checks": [c.as_dict() for c in self.checks]}


def check_route(route: RouteDeclaration, *, retired_matches: list[dict] | None = None,
                tls_floor: str | None = None) -> list[Check]:
    """The five pre-merge checks, for one declared route."""
    floor = tls_floor or settings.zt_tls_floor
    checks = [
        Check(
            name="owner-tag",
            passed=bool(route.owner),
            detail=None if route.owner else
            f"{route.method} {route.path} has no resolvable owner; add a "
            "CODEOWNERS entry or an @api-owner annotation",
            file=route.file, line=route.line,
        ),
        Check(
            name="auth-middleware",
            passed=route.has_auth_middleware,
            detail=None if route.has_auth_middleware else
            f"{route.method} {route.path} has no authentication middleware in "
            "its chain",
            file=route.file, line=route.line,
        ),
        Check(
            name="catalogue-registration",
            passed=route.in_catalogue,
            detail=None if route.in_catalogue else
            f"{route.method} {route.path} is absent from the service's OpenAPI "
            "definition; it would be discovered as SHADOW",
            file=route.file, line=route.line,
            # A warning, not an error. Registering a route in a catalogue is a
            # separate change in most repositories, and blocking the code change
            # on it teaches people to bypass the gate.
            severity="warn",
        ),
    ]

    # The check that closes the loop.
    #
    # A developer recreating a decommissioned endpoint under a new path is
    # caught here, at the pull request, rather than six months later by the
    # sensor — which is the difference between a conversation and an incident.
    # A match with no score is an abstention, not a zero. A retired endpoint
    # whose fingerprint was never captured cannot be compared against, and
    # folding that into "no match" would report "we cannot tell" as "definitely
    # not a resurrection" — which is the failure mode this whole system exists
    # to avoid.
    scored = [m for m in (retired_matches or []) if m.get("score") is not None]
    abstained = [m for m in (retired_matches or []) if m.get("score") is None]

    best = max(scored, key=lambda m: m["score"], default=None)
    resurrected = bool(best and best["score"] >= settings.resurrection_threshold)

    if resurrected:
        detail = (f"{route.method} {route.path} matches retired {best['path']} at "
                  f"{best['score']:.2f}")
    elif abstained and not scored:
        detail = (f"{len(abstained)} retired endpoint(s) have no captured "
                  f"fingerprint; this route could not be compared")
    else:
        detail = None

    checks.append(Check(
        name="no-resurrection",
        passed=not resurrected,
        detail=detail,
        file=route.file, line=route.line,
    ))

    tls_ok = route.tls_floor is None or route.tls_floor >= floor
    checks.append(Check(
        name="tls-policy",
        passed=tls_ok,
        detail=None if tls_ok else
        f"listener permits TLS {route.tls_floor}, below the {floor} floor",
        file=route.file, line=route.line,
    ))
    return checks


def run_gate(routes: list[RouteDeclaration],
             resurrection_matches: dict[str, list[dict]] | None = None,
             *, tls_floor: str | None = None) -> GateResult:
    """Every declared route against every check.

    A pull request adding no routes passes trivially, and that is correct: this
    gate has an opinion about API surface and none about anything else.
    """
    result = GateResult()
    for route in routes:
        key = f"{route.method.upper()} {route.path}"
        result.checks.extend(check_route(
            route,
            retired_matches=(resurrection_matches or {}).get(key),
            tls_floor=tls_floor))
    return result
