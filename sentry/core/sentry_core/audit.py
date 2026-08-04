"""Append-only, tamper-evident audit ledger.

Lives in ``sentry_core`` rather than in the API because it has more than one
writer. The control plane records approvals here; the worker records the
automated actions with production effect — a virtual patch reaching the gateway,
a certificate issued at retirement. A ledger only one process can append to
would leave exactly the events that happen without a human out of the record
that exists to prove what happened.

Entries are hash chained: altering or removing any historical entry invalidates
every entry after it. Verification walks the chain and reports the first break.

What is audited: every state change reachable from an approver or admin route,
plus every automated action with production effect. Analytical results are not
audited — a CDRI score is not a governance event; the weight change that altered
it is.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .clock import current_vday
from .models import AuditEntry

GENESIS = b"\x00" * 32


def canonical_json(obj: dict) -> str:
    """Stable across serialiser versions: sorted keys, fixed separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def canonical_ts(ts: datetime) -> int:
    """Integer microseconds since the Unix epoch, UTC.

    The hash must not depend on how a driver represents a timestamp. Postgres
    returns tz-aware datetimes and SQLite returns naive ones, so hashing
    ``isoformat()`` makes a chain written by one and verified by the other appear
    broken — which is the worst possible failure mode for the one structure whose
    entire purpose is to prove nothing changed.

    A naive value is treated as UTC, which is what both drivers store.
    """
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return int(ts.astimezone(timezone.utc).timestamp() * 1_000_000)


def compute_hash(prev_hash: bytes, *, seq: int, wall_ts: datetime, vday: int,
                 actor: str, action: str, target: str | None, detail: dict) -> bytes:
    payload = canonical_json({
        "seq": seq,
        "wall_us": canonical_ts(wall_ts),
        "vday": vday,
        "actor": actor,
        "action": action,
        "target": target,
        "detail": detail,
    })
    return hashlib.blake2b(prev_hash + payload.encode(), digest_size=32).digest()


def record(db: Session, *, actor: str, action: str, target: str | None = None,
           detail: dict | None = None) -> AuditEntry:
    """Append one entry.

    The tail row is locked for update so concurrent appends serialise. Throughput
    is bounded and adequate: audit entries are governance events, not telemetry.
    """
    detail = detail or {}
    stmt = select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)
    if db.bind and db.bind.dialect.name != "sqlite":
        stmt = stmt.with_for_update()
    tail = db.execute(stmt).scalar_one_or_none()
    prev = tail.entry_hash if tail else GENESIS

    entry = AuditEntry(
        vday=current_vday(db),
        actor=actor,
        action=action,
        target=target,
        detail=detail,
        prev_hash=prev,
        entry_hash=GENESIS,  # replaced below once seq is assigned
    )
    db.add(entry)
    db.flush()  # assigns seq and the server default wall_ts

    entry.entry_hash = compute_hash(
        prev, seq=entry.seq, wall_ts=entry.wall_ts, vday=entry.vday,
        actor=entry.actor, action=entry.action, target=entry.target, detail=entry.detail,
    )
    db.flush()
    return entry


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    broken_at: int | None = None
    reason: str | None = None


def verify(db: Session) -> VerifyResult:
    """Walk the chain from genesis.

    Returns the sequence number of the first entry whose stored hash does not
    match a recomputation, or whose prev_hash does not match its predecessor.
    """
    total = db.execute(select(func.count()).select_from(AuditEntry)).scalar_one()
    prev = GENESIS
    checked = 0

    for entry in db.execute(select(AuditEntry).order_by(AuditEntry.seq)).scalars():
        if entry.prev_hash != prev:
            return VerifyResult(False, total, entry.seq, "prev_hash does not match predecessor")
        expected = compute_hash(
            prev, seq=entry.seq, wall_ts=entry.wall_ts, vday=entry.vday,
            actor=entry.actor, action=entry.action, target=entry.target, detail=entry.detail,
        )
        if expected != entry.entry_hash:
            return VerifyResult(False, total, entry.seq, "entry content does not match its hash")
        prev = entry.entry_hash
        checked += 1

    return VerifyResult(True, checked)
