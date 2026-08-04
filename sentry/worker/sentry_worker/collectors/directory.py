"""Rung 4 of the ownership ladder — the HR directory.

This rung does not find an owner. It decides whether the owner the rungs above
found still works here, and that is a different question with a different
consequence: an endpoint attributed to somebody who left two years ago is worse
than one attributed to nobody, because the first looks resolved on every report
and the escalation goes to an address no one reads.

Three outcomes, and the ladder distinguishes all three:

* **Employed** — confidence stands.
* **Departed with a successor** — the successor inherits at 0.8× confidence.
  Somebody took the work over; that is weaker evidence than a declaration, and
  stronger than nothing.
* **Departed with no successor** — the original owner is kept on the record at
  0.5× and ``reachable`` goes false, with the department head named as the
  escalation. Blanking the owner here would destroy the only lead anyone has.

Unavailable is a fourth outcome and must not collapse into any of the three. A
directory that cannot be reached means the employment question is unanswered,
so confidence is left exactly as the rung above set it — neither inflated by
assuming employment nor discounted by assuming departure.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

TIMEOUT_S = 5.0


@dataclass
class Directory:
    """An employment directory, loaded once per scan.

    Held in memory for the duration of a cycle rather than queried per endpoint:
    a scan resolves thousands of endpoints and the directory changes on the
    timescale of a working day.
    """

    people: dict[str, dict]
    source: str
    available: bool = True
    error: str | None = None

    def lookup(self, email: str):
        """The signature ``resolve_ownership`` expects: a dict, or None.

        None means unavailable — not "not found". A person absent from a
        reachable directory is someone who does not work here, which is a
        departure with no successor, and that is what is returned.
        """
        if not self.available:
            return None
        row = self.people.get((email or "").strip().lower())
        if row is None:
            return {"employed": False, "successor": None,
                    "department_head": None, "team": None,
                    "note": "not present in directory"}
        return row

    def __len__(self) -> int:
        return len(self.people)


def _normalise(raw: dict) -> dict:
    """One row, from whatever the export called its columns.

    No two HR systems agree on a header, and an unrecognised column silently
    becomes a person with no employment status — which reads as departed.
    """
    def get(*names, default=None):
        for n in names:
            for key in raw:
                if key.strip().lower().replace(" ", "_") == n:
                    value = raw[key]
                    if isinstance(value, str):
                        value = value.strip()
                    if value not in (None, ""):
                        return value
        return default

    employed = get("employed", "active", "is_active", "status", default=None)
    if isinstance(employed, str):
        employed = employed.strip().lower() in {"true", "yes", "y", "1",
                                                "active", "employed", "current"}
    elif employed is None:
        employed = True

    return {
        "employed": bool(employed),
        "team": get("team", "department", "dept", "org"),
        "successor": (get("successor", "successor_email", "replacement") or None),
        "department_head": (get("department_head", "manager", "head",
                                "manager_email") or None),
    }


def _index(rows: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for raw in rows:
        email = None
        for key in raw:
            if key.strip().lower().replace(" ", "_") in ("email", "email_address",
                                                         "mail", "upn"):
                email = (raw[key] or "").strip().lower()
                break
        if not email:
            continue
        out[email] = _normalise(raw)
    return out


def from_file(path: str) -> Directory:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return Directory({}, source=path, available=False, error=str(exc))

    try:
        if p.suffix.lower() == ".json":
            data = json.loads(text)
            rows = data if isinstance(data, list) else data.get("people", [])
        else:
            rows = list(csv.DictReader(text.splitlines()))
    except (ValueError, csv.Error) as exc:
        return Directory({}, source=path, available=False,
                         error=f"unparseable: {exc}")

    return Directory(_index(rows), source=path)


def from_url(url: str) -> Directory:
    try:
        with httpx.Client(timeout=TIMEOUT_S) as c:
            r = c.get(url)
            r.raise_for_status()
            data = r.json()
    except Exception as exc:  # noqa: BLE001
        # Unavailable, and recorded as such. The ladder leaves confidence
        # untouched rather than guessing at employment in either direction.
        return Directory({}, source=url, available=False,
                         error=f"{type(exc).__name__}: {exc}"[:200])

    rows = data if isinstance(data, list) else data.get("people", [])
    return Directory(_index(rows), source=url)


def load(source: str | None) -> Directory:
    """Load from a URL or a path. An unconfigured directory is unavailable."""
    if not source:
        return Directory({}, source="", available=False,
                         error="no HR directory configured")
    if source.startswith(("http://", "https://")):
        return from_url(source)
    return from_file(source)
