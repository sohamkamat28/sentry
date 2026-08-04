"""Alembic environment.

The schema of record is ``sentry_core.models.Base.metadata``. Migrations exist
to move a database to it, and ``tools/check_migrations.py`` fails if a migration
run leaves any difference — so the models and the migration history cannot drift
apart without something going red.

``create_all`` remains, for the test suite and a throwaway local database. It is
not the production path and never was; the difference is that until now there
was no other one.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from sentry_core.config import settings
from sentry_core.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    """One source for the URL, shared with every other process.

    ``-x url=...`` overrides it, which is how the drift check points a migration
    run at a scratch database without touching the environment the rest of the
    session is using.
    """
    override = context.get_x_argument(as_dictionary=True).get("url")
    return override or settings.database_url


def _include_object(obj, name, type_, reflected, compare_to):
    """Keep other tenants of the database out of the diff.

    Kong shares this PostgreSQL server and has its own schema in its own
    database, but a misconfigured URL would otherwise have Alembic autogenerate
    a migration that drops another product's tables.
    """
    if type_ == "table" and getattr(obj, "schema", None) not in (None, "public"):
        return False
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # A widened enum or a changed column width must show up as a
            # difference. Without these two, the CHECK constraint behind an enum
            # silently keeps its old value list — which is exactly how adding
            # REJECTED to ControlState produced a constraint violation on a
            # database that had already been migrated.
            compare_type=True,
            compare_server_default=True,
            include_object=_include_object,
            # SQLite cannot ALTER a column. Batch mode rebuilds the table
            # instead, so the same migration runs on the test database and on
            # PostgreSQL.
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
