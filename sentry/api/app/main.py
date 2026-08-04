"""SENTRY control plane."""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from sentry_core.clock import ensure_vclock
from sentry_core.config import settings
from sentry_core.db import SessionLocal, create_all

from .audit import ledger
from .bootstrap import seed_policy
from .errors import SentryError, handler
from .routers import action, estate, system

log = logging.getLogger("sentry.api")


def _configure_logging() -> None:
    handler_ = logging.StreamHandler(sys.stdout)
    if settings.log_format == "json":
        handler_.setFormatter(logging.Formatter(
            '{"ts":"%(asctime)s","level":"%(levelname)s","service":"api",'
            '"logger":"%(name)s","msg":"%(message)s"}'
        ))
    else:
        handler_.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s  %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler_]
    root.setLevel(settings.log_level.upper())


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _configure_logging()

    if settings.database_url.startswith("sqlite"):
        # Local and test only. Production schema comes from Alembic.
        create_all()

    with SessionLocal() as db:
        ensure_vclock(db)
        seed_policy(db)
        db.commit()

        if settings.audit_verify_on_boot:
            result = ledger.verify(db)
            if not result.ok:
                # A broken chain is not a warning. Refusing to serve is the
                # whole point of keeping one.
                raise RuntimeError(
                    f"audit chain broken at seq {result.broken_at}: {result.reason}"
                )
            log.info("audit chain verified: %d entries", result.entries)

    yield


app = FastAPI(
    title="SENTRY",
    version="1.0.0",
    description="API lifecycle security platform.",
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(SentryError, handler)

app.include_router(system.router, prefix="/api/v1")
app.include_router(estate.router, prefix="/api/v1")
app.include_router(action.router, prefix="/api/v1")


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    """Process alive. Never touches a dependency — conflating this with
    readiness causes restart loops when a downstream is merely slow."""
    return {"ok": True}


@app.get("/readyz", include_in_schema=False)
def readyz():
    from fastapi.responses import JSONResponse
    from sqlalchemy import text

    checks: dict[str, str] = {}

    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:
        checks["postgres"] = f"unreachable: {type(exc).__name__}"

    if settings.redis_url:
        try:
            import redis

            redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2).ping()
            checks["redis"] = "ok"
        except Exception as exc:
            checks["redis"] = f"unreachable: {type(exc).__name__}"

    ready = all(v == "ok" for v in checks.values())
    return JSONResponse(status_code=200 if ready else 503,
                        content={"ready": ready, "checks": checks})


#: Counters incremented by processes with no HTTP listener of their own.
#:
#: The Celery worker cannot be scraped — it has no port — so a prometheus_client
#: Counter inside it is invisible. Redis is the only thing both processes see,
#: and this is where those values reach a scraper.
_WORKER_COUNTERS = {
    "sentry_scan_skipped_total":
        "Pipeline cycles skipped because the previous one still held the lock.",
}


@app.get("/metrics", include_in_schema=False)
def metrics() -> PlainTextResponse:
    from sentry_core import live

    body = generate_latest().decode()

    counters = live.counters(list(_WORKER_COUNTERS))
    for name, help_text in _WORKER_COUNTERS.items():
        # Absent when Redis is unreachable, rather than emitted as 0. A counter
        # that reads zero because nothing could be read is indistinguishable
        # from one that reads zero because nothing happened, and an alert rule
        # cannot tell them apart either.
        if name not in counters:
            continue
        body += f"# HELP {name} {help_text}\n# TYPE {name} counter\n"
        body += f"{name} {counters[name]}\n"

    body += ("# HELP sentry_live_counter_errors_total Redis operations that "
             "failed while updating live counters.\n"
             "# TYPE sentry_live_counter_errors_total counter\n"
             f"sentry_live_counter_errors_total {live.failures()}\n")

    return PlainTextResponse(body, media_type=CONTENT_TYPE_LATEST)
