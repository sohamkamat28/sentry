"""The Celery application and the schedule.

``celery -A sentry_worker.tasks worker`` and ``... beat`` both resolve to the
``app`` in this module; compose runs one of each.

The cadence is expressed in virtual hours and converted to wall seconds here,
because everything else in the system measures time in vdays and a schedule
pinned to wall time would drift out of step with the analysis windows the moment
``VCLOCK_SCALE_SECONDS`` changed. At the production scale (86400) a 6-vhour
cadence is six hours; at the demonstration scale (30) it is 7.5 seconds, and the
same code runs both.

Two properties this module is responsible for:

* **Exactly one cycle at a time.** Stage ordering is checked within a cycle, not
  between two concurrent ones, so overlapping passes would satisfy every
  dependency assertion and still interleave their writes. The Redis lock excludes
  them; a cycle that cannot take the lock is skipped and counted, never queued
  behind the running one.
* **A skip is a recorded event.** ``sentry_scan_skipped_total`` moving is how an
  operator learns the cycle is overrunning its interval. Silently dropping the
  tick would present a system running at half the configured cadence as one
  running at the configured cadence.
"""

from __future__ import annotations

import logging
import os

from celery import Celery
from celery.signals import worker_ready
from sqlalchemy import delete, select

from sentry_core import clock, live
from sentry_core.config import settings
from sentry_core.db import SessionLocal
from sentry_core.models import Observation, Probe

log = logging.getLogger(__name__)

#: A vhour in wall seconds, the cycle interval, and the lock's TTL. Defined
#: beside the lock in ``sentry_core.live`` and re-exported here, because the API
#: takes the same lock on its manual scan route and the two must not drift.
VHOUR_S = live.VHOUR_S
SCAN_INTERVAL_S = live.SCAN_INTERVAL_S
SCAN_LOCK_TTL_S = live.SCAN_LOCK_TTL_S

app = Celery(
    "sentry",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_default_queue="sentry",
    # A cycle is not idempotent — it writes stage rows, applies gateway controls
    # and archives to WORM — so a task must never be redelivered because a worker
    # died mid-run. late-ack with reject-on-worker-lost off means at-most-once.
    task_acks_late=False,
    task_reject_on_worker_lost=False,
    # One cycle per worker process. Concurrency here would put two cycles in one
    # worker, which the Redis lock would then serialise into a queue of skips.
    worker_concurrency=1,
    worker_prefetch_multiplier=1,
    # Bound the result set; these are fire-and-forget schedules, and an unbounded
    # backend is a slow memory leak in Redis.
    result_expires=int(max(600, SCAN_INTERVAL_S * 20)),
    beat_schedule={
        "scan-cycle": {
            "task": "sentry.scan_cycle",
            "schedule": SCAN_INTERVAL_S,
            # If beat was down, run once on recovery rather than replaying every
            # tick it missed. Ten skipped cycles do not need ten catch-up runs;
            # the next cycle reads current state regardless.
            "options": {"expires": SCAN_INTERVAL_S * 0.9},
        },
        "retention": {
            "task": "sentry.retention",
            # Once per vday. Observation pruning is bounded by the retention
            # window, not by the scan cadence.
            "schedule": settings.vclock_scale_seconds,
            "options": {"expires": settings.vclock_scale_seconds * 0.9},
        },
    },
)


@app.task(name="sentry.scan_cycle", bind=True)
def scan_cycle(self, trigger: str = "scheduled", actor: str | None = None) -> dict:
    """One pipeline pass, serialised across the deployment.

    Imported inside the task rather than at module scope: the runner pulls in
    scikit-learn, networkx and the Kong client, and beat — which never executes a
    task — should not pay for them to publish a schedule.
    """
    if not settings.scheduler_enabled:
        return {"ran": False, "reason": "scheduler disabled"}

    from . import runner

    try:
        with live.scan_lock(ttl_s=SCAN_LOCK_TTL_S):
            with SessionLocal() as db:
                clock.ensure_vclock(db)
                db.commit()
                run_id, outcomes = runner.scan_cycle(db, trigger=trigger, actor=actor)
                failed = [o.stage for o in outcomes if o.detail.get("error")]
                skipped = [o.stage for o in outcomes if o.detail.get("skipped")]
                return {
                    "ran": True,
                    "run_id": run_id,
                    "stages": len(outcomes),
                    "records": sum(o.records for o in outcomes),
                    "failed": failed,
                    "skipped": skipped,
                }
    except live.NotAcquired as exc:
        # The interval is shorter than the cycle takes. Counted so the cadence
        # can be corrected, and not retried: the next tick is the retry.
        live.bump("sentry_scan_skipped_total")
        log.warning("scan cycle skipped: %s", exc)
        return {"ran": False, "reason": str(exc)}


@app.task(name="sentry.retention")
def retention() -> dict:
    """Drop observations and probes past the retention window.

    Deletes by vday, not by wall timestamp. The partitioned tables are
    range-partitioned on vday, so this is the column that lets Postgres drop
    whole partitions instead of scanning rows — and it is the column every
    analysis window is measured in, so retention and analysis cannot disagree
    about which day is being discarded.
    """
    with SessionLocal() as db:
        vday = clock.current_vday(db)
        cutoff = vday - settings.observation_retention_vdays
        if cutoff <= 0:
            return {"pruned": 0, "cutoff": cutoff, "reason": "inside retention window"}

        obs = db.execute(
            delete(Observation).where(Observation.vday < cutoff)
        ).rowcount or 0
        # Probes are evidence of an attempt against a retired endpoint. They are
        # kept on the same window as observations rather than forever: the
        # resurrection alert they produced is the durable record, and it lives in
        # a table this never touches.
        probes = db.execute(delete(Probe).where(Probe.vday < cutoff)).rowcount or 0
        db.commit()
        if obs or probes:
            log.info("retention pruned %d observations, %d probes below vday %d",
                     obs, probes, cutoff)
        return {"pruned": obs, "probes": probes, "cutoff": cutoff}


@app.task(name="sentry.run_stage")
def run_stage(stage: int) -> dict:
    """A single stage, for an operator re-running one step.

    Takes the same lock as a full cycle. A stage run concurrently with a cycle
    would write the same rows the cycle is writing.
    """
    from . import pipeline, runner

    fn = runner.STAGES.get(stage)
    if fn is None:
        return {"ran": False, "reason": f"stage {stage} has no runner"}

    try:
        with live.scan_lock(ttl_s=SCAN_LOCK_TTL_S):
            with SessionLocal() as db:
                vday = clock.current_vday(db)
                outcome = fn(db, vday)
                db.commit()
                return {"ran": True, "stage": stage, "records": outcome.records,
                        "detail": outcome.detail}
    except live.NotAcquired as exc:
        live.bump("sentry_scan_skipped_total")
        return {"ran": False, "reason": str(exc)}


@worker_ready.connect
def _announce(sender=None, **_kw) -> None:
    """State the cadence at startup.

    The interval is derived from two settings and a division, so the effective
    value is not readable from the environment alone. A schedule nobody can see
    is one nobody notices is wrong.
    """
    log.info(
        "sentry worker ready: scan every %.2fs (%d vhours at scale %ds), "
        "lock ttl %ds, scheduler_enabled=%s",
        SCAN_INTERVAL_S, settings.scan_interval_vhours,
        settings.vclock_scale_seconds, SCAN_LOCK_TTL_S, settings.scheduler_enabled,
    )
    if not live.ping():
        # Without Redis there is no broker, so a worker that reports ready here
        # has a broker but no lock. Worth saying plainly.
        log.warning("redis not reachable: cycles will not be serialised")


# Kept so `python -m sentry_worker.tasks` reports the schedule without starting
# a worker, which is the quickest way to check a deployment's effective cadence.
if __name__ == "__main__":
    print(f"scan interval: {SCAN_INTERVAL_S:.3f}s "
          f"({settings.scan_interval_vhours} vhours at scale "
          f"{settings.vclock_scale_seconds}s)")
    print(f"lock ttl:      {SCAN_LOCK_TTL_S}s")
    print(f"broker:        {os.environ.get('REDIS_URL', settings.redis_url)}")
    for name, entry in app.conf.beat_schedule.items():
        print(f"  {name}: {entry['task']} every {entry['schedule']}s")
