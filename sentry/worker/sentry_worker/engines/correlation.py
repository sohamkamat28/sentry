"""Stage 03 — Correlation.

Turns four independent streams of sightings into one registry: deduplicated
endpoints, a call graph, and an owner with a confidence score.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

VERSION = "corr-1.0.0"

# ── path normalisation ───────────────────────────────────────────────────────
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_B64URL = re.compile(r"^[A-Za-z0-9_-]{22,}$")
_DIGITS = re.compile(r"^\d{2,}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_PLACEHOLDER = re.compile(r"^(\{[^}]*\}|:[A-Za-z_]\w*|<[^>]*>|\[[^\]]*\])$")

#: A reference: letters and digits mixed, long enough not to be a path word.
#:
#: Payment and settlement references look like ``UPI7781XK92``, not like an
#: integer, and none of the patterns above match them. Every distinct reference
#: therefore became its own endpoint — one row per transaction, an inventory
#: that grows without bound and in which no endpoint ever accumulates enough
#: history to be classified.
#:
#: Six characters and at least two digits. Both bounds are there to keep API
#: vocabulary out: a word that carries a digit at all usually carries exactly
#: one (``oauth2``, ``s3``, ``utf8``), while a reference is mostly digits.
#: Segments with no digit — ``accounts``, ``balance``, ``settlement`` — never
#: reach the test.
_REFERENCE = re.compile(r"^(?=[A-Za-z0-9]*[A-Za-z])(?=(?:[A-Za-z]*\d){2})[A-Za-z0-9]{6,}$")

#: API version segments, which are the one common case that satisfies the
#: reference shape and must not collapse. ``/api/v2beta/accounts`` normalising
#: to ``/api/{id}/accounts`` merges every version of every endpoint into one
#: row.
_VERSION_SEG = re.compile(r"^v\d+[a-z]*\d*$", re.I)

#: Segments that satisfy the reference shape but are API vocabulary rather than
#: identifiers. Collapsing one of these merges genuinely distinct endpoints,
#: which is the worse error of the two.
_RESERVED = frozenset({
    "oauth2", "base64", "sha256", "sha512", "md5sum", "utf8mb4",
    "iso8601", "rfc3339", "x509cert", "pkcs12",
})


MAX_SEGMENTS = 8


def _is_param(seg: str) -> bool:
    if seg.lower() in _RESERVED or _VERSION_SEG.match(seg):
        return False
    return bool(
        _PLACEHOLDER.match(seg)
        or _DIGITS.match(seg)
        or _UUID.match(seg)
        or _HEX.match(seg)
        or _DATE.match(seg)
        or _B64URL.match(seg)
        or _REFERENCE.match(seg)
    )


def normalise_path(raw: str) -> str:
    """Collapse parameter segments so one endpoint is one registry row.

    The SOAP ``#action`` suffix is identity, not a fragment: two operations on
    one URL are two endpoints, and the kernel probe emits them in this form so
    the legacy collector's WSDL parse correlates on identity rather than by
    heuristic.
    """
    if not raw:
        return "/"

    action = ""
    if "#" in raw:
        raw, _, action = raw.partition("#")
        action = f"#{action}"  # case preserved: SOAPAction is case-sensitive

    raw = raw.split("?", 1)[0]
    raw = raw.lower()
    raw = re.sub(r"/{2,}", "/", raw)
    if len(raw) > 1:
        raw = raw.rstrip("/")
    if not raw:
        raw = "/"

    segs = [s for s in raw.split("/") if s != ""]
    out = ["{id}" if _is_param(s) else s for s in segs]

    truncated = False
    if len(out) > MAX_SEGMENTS:
        out = out[:MAX_SEGMENTS]
        truncated = True

    path = "/" + "/".join(out) if out else "/"
    if truncated:
        path += "/**"
    return path + action


def endpoint_id(method: str, path_template: str, service_id: str) -> str:
    """Content-derived identity.

    Deduplication is a property of this function, not a merge pass that could
    run twice and differ. The same endpoint seen by four sources produces four
    provenance rows against one registry row.
    """
    key = f"{method.upper()}⋮{path_template}⋮{service_id}"
    return "ep_" + hashlib.blake2s(key.encode(), digest_size=8).hexdigest()


def service_id(name: str) -> str:
    return "svc_" + hashlib.blake2s(name.encode(), digest_size=6).hexdigest()


# ── over-collapse guard ──────────────────────────────────────────────────────
def should_split(template: str, raw_paths: set[str], schemas: set[str], max_merge: int) -> bool:
    """Detect a template that has absorbed genuinely distinct endpoints.

    A path of all-numeric segments normalises to ``/{id}/{id}`` and would merge
    unrelated routes. Silent over-merging understates the estate, which is the
    failure mode that matters: an endpoint you never counted is one you never
    secured.
    """
    return len(raw_paths) > max_merge and len(schemas) > 1


# ── ownership ladder ─────────────────────────────────────────────────────────
@dataclass
class Ownership:
    owner_email: str | None = None
    owner_team: str | None = None
    resolved_by: str = "unresolved"
    confidence: float = 0.0
    reachable: bool = False
    escalation: str | None = None
    ladder: list[dict] = field(default_factory=list)


RUNG_CONFIDENCE = {"codeowners": 1.00, "git-blame": 0.75, "gateway-metadata": 0.40}


def resolve_ownership(
    codeowners: dict | None,
    git_blame: dict | None,
    gateway_metadata: dict | None,
    hr_lookup,
    department_head: str | None = None,
) -> Ownership:
    """Four rungs, tried in order, each recording what it returned.

    Two properties change outcomes and are worth stating:

    * A departed owner is not the same as no owner. ``reachable=False`` with a
      named escalation routes to a department head rather than an address nobody
      reads.
    * Confidence is retained rather than thresholded away. The debt leaderboard
      weights by it, so a team is not charged for an endpoint whose ownership
      rests on a null metadata field.
    """
    ladder: list[dict] = []
    rungs = [
        ("codeowners", codeowners),
        ("git-blame", git_blame),
        ("gateway-metadata", gateway_metadata),
    ]

    for rung_name, result in rungs:
        if not result or not result.get("email"):
            ladder.append({"rung": rung_name, "result": "no match"})
            continue

        email = result["email"]
        team = result.get("team")
        base = RUNG_CONFIDENCE[rung_name]
        ladder.append({"rung": rung_name, "result": f"matched {email}"})

        hr = hr_lookup(email) if hr_lookup else None
        if hr is None:
            # Directory unavailable: record it, do not inflate confidence.
            ladder.append({"rung": "hr-directory", "result": "unavailable"})
            return Ownership(email, team, rung_name, base, True, None, ladder)

        if hr.get("employed"):
            ladder.append({"rung": "hr-directory", "result": "employed"})
            return Ownership(email, team or hr.get("team"), rung_name, base, True, None, ladder)

        successor = hr.get("successor")
        if successor:
            ladder.append({"rung": "hr-directory", "result": f"departed, successor {successor}"})
            return Ownership(successor, team or hr.get("team"), rung_name,
                             round(base * 0.8, 4), True, None, ladder)

        head = hr.get("department_head") or department_head
        ladder.append({"rung": "hr-directory", "result": "departed, no successor"})
        return Ownership(email, team, rung_name, round(base * 0.5, 4), False, head, ladder)

    ladder.append({"rung": "unresolved", "result": "all rungs exhausted"})
    return Ownership(None, None, "unresolved", 0.0, False, department_head, ladder)
