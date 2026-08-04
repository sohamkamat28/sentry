"""Stage 08 — Findings.

Composes score, projection and impact into prose a compliance officer can hand
to an examiner unmodified, and maps each to an exact clause.

Two generators sit behind one interface. ``generator`` is recorded on every row
and surfaced in the API and console: a template narrative is never presented as
model output. The system does not claim a model ran when one did not.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Protocol

from . import frameworks

VERSION = "find-1.0.0"


@dataclass
class Context:
    endpoint_id: str
    method: str
    path: str
    service: str
    silent_vdays: int | None
    lifecycle: str
    governance: str
    auth: str
    tls_version: str | None
    rate_limited: bool
    data_classes: list[str]
    internet_reachable: bool
    cdri_score: float
    cdri_tier: str
    cdri_parts: list[dict]
    blast_tier: str | None
    blast_affected: list[dict]
    time_to_breach_d: int | None
    ttb_factors: list[str]
    anomaly_patterns: list[str]
    owner_email: str | None
    owner_reachable: bool
    escalation: str | None
    pre_zombie: bool
    days_to_zombie: int | None

    def as_prompt_dict(self) -> dict:
        """The model context.

        Data classes are labels, never values — the values were discarded in
        kernel at stage 01 and have no representation anywhere in the system, so
        no customer identifier can reach a prompt.
        """
        return {
            "endpoint": f"{self.method} {self.path}",
            "service": self.service,
            "lifecycle": self.lifecycle,
            "governance": self.governance,
            "silent_vdays": self.silent_vdays,
            "auth": self.auth,
            "tls_version": self.tls_version,
            "rate_limited": self.rate_limited,
            "data_classes_detected": self.data_classes,
            "cdri": {"score": self.cdri_score, "tier": self.cdri_tier, "parts": self.cdri_parts},
            "blast_radius": {"tier": self.blast_tier, "affected": self.blast_affected[:10]},
            "anomaly_patterns": self.anomaly_patterns,
            "time_to_breach_days": self.time_to_breach_d,
            "owner": {"email": self.owner_email, "reachable": self.owner_reachable},
        }

    def as_rule_ctx(self) -> dict:
        return {
            "auth": self.auth,
            "tls_version": self.tls_version,
            "rate_limited": self.rate_limited,
            "data_classes": self.data_classes,
            "lifecycle": self.lifecycle,
            "governance": self.governance,
            "internet_reachable": self.internet_reachable,
            "blast_tier": self.blast_tier,
        }


@dataclass
class Narrative:
    summary: str
    technical: str
    action: str
    confidence: float | None = None
    reasoning: str | None = None


class Generator(Protocol):
    name: str

    def generate(self, ctx: Context) -> Narrative: ...


# ── template generator ───────────────────────────────────────────────────────
def _humanise(classes: list[str]) -> str:
    names = {
        "PAN": "PAN numbers", "AADHAAR": "Aadhaar numbers", "IFSC": "IFSC codes",
        "ACCOUNT_NO": "account numbers", "CARD": "card numbers", "CVV": "card verification values",
        "DOB": "dates of birth",
    }
    vals = [names.get(c, c) for c in sorted(classes)]
    if not vals:
        return ""
    if len(vals) == 1:
        return vals[0]
    return ", ".join(vals[:-1]) + " and " + vals[-1]


class TemplateGenerator:
    """Deterministic and dependency-free.

    Not a placeholder: it produces a correct, complete, citable finding. The
    model version reads better and adapts to unusual combinations.
    """

    name = "template"

    def generate(self, ctx: Context) -> Narrative:
        ep = f"{ctx.method} {ctx.path}"

        s: list[str] = []
        if ctx.silent_vdays is None:
            s.append(f"{ep} is defined in code but has never been observed serving traffic.")
        elif ctx.lifecycle == "ZOMBIE":
            s.append(
                f"{ep} has not been called in {ctx.silent_vdays} days and remains "
                f"registered and reachable."
            )
        else:
            s.append(f"{ep} was last called {ctx.silent_vdays} days ago.")

        if ctx.governance == "SHADOW":
            s.append(
                "It appears in no gateway registry and in no code repository, so it is "
                "subject to no authentication policy, no rate limiting and no monitoring."
            )
        elif ctx.governance == "ORPHANED":
            if ctx.owner_email and not ctx.owner_reachable:
                s.append(
                    f"Its last known owner ({ctx.owner_email}) is no longer reachable; "
                    f"escalation routes to {ctx.escalation or 'the owning department head'}."
                )
            else:
                s.append("No owner could be resolved for it.")

        if ctx.auth == "none":
            s.append("It enforces no authentication.")
        elif ctx.auth in ("basic", "apikey"):
            s.append(f"It uses {ctx.auth} authentication, which is below current policy.")

        if ctx.data_classes:
            s.append(f"Responses have been observed to carry {_humanise(ctx.data_classes)}.")

        if ctx.tls_version in (None, "", "1.0", "1.1"):
            s.append(f"Transport is {ctx.tls_version or 'unencrypted'}.")

        tech: list[str] = [
            f"CDRI {ctx.cdri_score:.2f} ({ctx.cdri_tier}). "
            + ", ".join(
                f"{p['label']} {p['r']:.1f}x{p['w']:.2f}"
                for p in ctx.cdri_parts if p["contribution"] > 0
            )
        ]
        if ctx.blast_tier:
            n = len([a for a in ctx.blast_affected if a.get("hop") == 1])
            tech.append(f"Blast radius {ctx.blast_tier}: {n} direct caller(s).")
        if ctx.anomaly_patterns:
            tech.append("Behavioural signals: " + ", ".join(ctx.anomaly_patterns) + ".")
        if ctx.pre_zombie and ctx.days_to_zombie:
            tech.append(f"Projected to reach zombie status in {ctx.days_to_zombie} days.")

        if ctx.cdri_tier == "CRITICAL":
            act = ("Apply a virtual patch at the gateway now and submit the change request "
                   "for the permanent fix.")
        elif ctx.cdri_tier == "HIGH":
            act = "Assign an owner and schedule remediation within 48 hours."
        else:
            act = "Add to the weekly review queue and notify the owning team."

        if ctx.time_to_breach_d is not None:
            s.insert(0, f"Estimated {ctx.time_to_breach_d} days before active exploitation "
                        f"(heuristic).")

        return Narrative(summary=" ".join(s), technical=" ".join(tech), action=act)


# ── composition ──────────────────────────────────────────────────────────────
@dataclass
class Result:
    narrative: Narrative
    generator: str
    model: str | None
    regulations: list[dict] = field(default_factory=list)


def finding_id(endpoint_id: str, vday: int) -> str:
    key = f"{endpoint_id}⋮{vday}⋮{VERSION}"
    return "fnd_" + hashlib.blake2s(key.encode(), digest_size=8).hexdigest()


def build(ctx: Context, generator: Generator, model: str | None = None) -> Result:
    narrative = generator.generate(ctx)
    rule_ctx = ctx.as_rule_ctx()
    rule_ctx["generator"] = generator.name
    return Result(
        narrative=narrative,
        generator=generator.name,
        model=model if generator.name != "template" else None,
        regulations=frameworks.map_findings(rule_ctx),
    )


def prompt_digest(ctx: Context) -> bytes:
    payload = json.dumps(ctx.as_prompt_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).digest()
