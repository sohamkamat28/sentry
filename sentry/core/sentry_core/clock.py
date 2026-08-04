"""The virtual clock — the system's only analysis time base.

Every window in SENTRY (30-vday baseline, 90-vday correlation window, 90-vday
sunset) is measured in virtual days. ``scale_seconds`` is 86400 in production,
making a vday a calendar day; lower values compress the timeline so a full
lifecycle can be exercised in minutes.

This is not a simulation layer bolted onto the side. It is the single time
source, and the same code path serves both settings. Nothing about the analysis
changes with scale — only the wall-clock interval between observations.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import VClock


def ensure_vclock(db: Session) -> VClock:
    vc = db.get(VClock, 1)
    if vc is None:
        vc = VClock(
            id=1,
            epoch_wall=datetime.now(timezone.utc),
            scale_seconds=settings.vclock_scale_seconds,
        )
        db.add(vc)
        db.flush()
    return vc


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def current_vday(db: Session, at: datetime | None = None) -> int:
    vc = db.execute(select(VClock).where(VClock.id == 1)).scalar_one_or_none()
    if vc is None:
        vc = ensure_vclock(db)
    if vc.paused_at is not None and vc.paused_vday is not None:
        return vc.paused_vday
    now = _as_utc(at or datetime.now(timezone.utc))
    elapsed = (now - _as_utc(vc.epoch_wall)).total_seconds()
    return max(0, math.floor(elapsed / vc.scale_seconds))


def vday_to_wall(db: Session, vday: int) -> datetime:
    """Wall-clock instant a vday begins. Used for RFC 8594 Sunset headers and
    for correlating SENTRY events with SIEM records."""
    vc = ensure_vclock(db)
    return _as_utc(vc.epoch_wall) + timedelta(seconds=vday * vc.scale_seconds)


def pause(db: Session) -> int:
    vc = ensure_vclock(db)
    if vc.paused_at is None:
        vc.paused_vday = current_vday(db)
        vc.paused_at = datetime.now(timezone.utc)
    db.flush()
    return vc.paused_vday or 0


def resume(db: Session) -> int:
    """Resume without losing the paused interval: the epoch is shifted forward
    so vday continues from where it stopped rather than jumping."""
    vc = ensure_vclock(db)
    if vc.paused_at is not None:
        drift = datetime.now(timezone.utc) - _as_utc(vc.paused_at)
        vc.epoch_wall = _as_utc(vc.epoch_wall) + drift
        vc.paused_at = None
        vc.paused_vday = None
    db.flush()
    return current_vday(db)


def set_vday(db: Session, vday: int) -> int:
    """Move the clock to a specific vday by shifting the epoch.

    Admin-only. Used to drive an estate through its lifecycle without waiting
    for wall time, and to reproduce a historical state during an investigation.
    """
    vc = ensure_vclock(db)
    vc.epoch_wall = datetime.now(timezone.utc) - timedelta(seconds=vday * vc.scale_seconds)
    if vc.paused_at is not None:
        vc.paused_vday = vday
    db.flush()
    return current_vday(db)
