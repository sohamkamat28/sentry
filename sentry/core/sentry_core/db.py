"""Engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import Base

_connect_args: dict = {}
if settings.database_url.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine: Engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    future=True,
    connect_args=_connect_args,
)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record) -> None:
    """SQLite ignores foreign keys unless asked, which would let the engine test
    suite pass against referential integrity the production database enforces."""
    if settings.database_url.startswith("sqlite"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency."""
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def create_all() -> None:
    """Test and local bootstrap only. Production schema comes from Alembic.

    Refused outside dev, and that is not a formality. A ``create_all`` against a
    production database builds whatever the models currently say and records
    nothing about having done so — which is how four schema changes reached a
    running database with no migration behind them and no way to tell what a
    given deployment actually contains.

    Use ``alembic upgrade head``. An existing database that ``create_all`` built
    is brought under control with ``alembic stamp head``, once
    ``tools/check_migrations.py`` has confirmed it already matches; stamping one
    that does not match records a lie about what it holds.
    """
    if settings.env != "dev":
        raise RuntimeError(
            f"create_all() is refused in {settings.env}: the schema comes from "
            "Alembic. Run `alembic upgrade head`.")
    Base.metadata.create_all(engine)
