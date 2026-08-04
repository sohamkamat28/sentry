"""First-run policy seeding.

Weights and thresholds live in the database rather than in environment
configuration because they are governed: versioned, audited, and changeable by
an analyst without a redeploy.
"""

from __future__ import annotations


from sqlalchemy import select
from sqlalchemy.orm import Session


from sentry_worker.engines.cdri import DEFAULT_WEIGHTS
from sentry_worker.engines.judge_scoring import LATENCY_BUDGET_US
from sentry_core.config import settings
from sentry_core.models import PolicySetting, PolicyWeights

DEFAULT_SETTINGS: dict[str, dict] = {
    "latency_budget_us": LATENCY_BUDGET_US,
    "tier_bounds": {"CRITICAL": 0.75, "HIGH": 0.50, "MEDIUM": 0.25, "LOW": 0.0},
    "resurrection_threshold": {"value": 0.85},
    "blast_hop_limit": {"value": 2},
    "scan_interval_vhours": {"value": 6},
    "express_sunset_vdays": {"value": 30},
    "anomaly_contamination": {"value": 0.05},
    # Without this record present, Phase D completes with 410 and no honeypot.
    # The guardrail is enforced by the code path, not by a policy document.
    "honeypot_legal_signoff": {"reference": None, "signed": False},
}


def seed_policy(db: Session) -> None:
    if db.execute(select(PolicyWeights).limit(1)).scalar_one_or_none() is None:
        db.add(PolicyWeights(weights=dict(DEFAULT_WEIGHTS), note="initial defaults",
                             created_by="system:bootstrap"))

    existing = {k for (k,) in db.execute(select(PolicySetting.key))}
    for key, value in DEFAULT_SETTINGS.items():
        if key not in existing:
            db.add(PolicySetting(key=key, value=value, updated_by="system:bootstrap"))

    db.flush()


def current_weights(db: Session) -> tuple[int, dict]:
    row = db.execute(
        select(PolicyWeights).order_by(PolicyWeights.version.desc()).limit(1)
    ).scalar_one_or_none()
    if row is None:
        seed_policy(db)
        db.flush()
        row = db.execute(
            select(PolicyWeights).order_by(PolicyWeights.version.desc()).limit(1)
        ).scalar_one()
    return row.version, dict(row.weights)


def setting(db: Session, key: str, default: dict | None = None) -> dict:
    row = db.get(PolicySetting, key)
    return dict(row.value) if row else (default or DEFAULT_SETTINGS.get(key, {}))
