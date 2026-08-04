"""The migration history has to stay true to the models.

Without this the history is a set of files nobody is required to keep current,
and the first time that matters is a production deploy where ``upgrade head``
produces a schema the code cannot use. Four schema changes were applied by
dropping tables and by hand-written DDL before these migrations existed; this is
what stops the fifth.

Runs against a throwaway SQLite file. ``tools/check_migrations.py --url`` runs
the same comparison against PostgreSQL, where server defaults are compared too.
"""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def migrated_url():
    """An empty database with every migration applied."""
    from alembic import command
    from alembic.config import Config

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    url = f"sqlite:///{path}"

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "api" / "migrations"))
    cfg.cmd_opts = argparse.Namespace(x=[f"url={url}"])
    command.upgrade(cfg, "head")

    yield url

    if os.path.exists(path):
        os.unlink(path)


def test_migrations_produce_exactly_the_declared_schema(migrated_url):
    """The check that makes migrations worth having.

    A model changed without a migration shows up here as an added table or
    column; a migration that does not do what its model says shows up as a type
    or nullability difference.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from sentry_core.models import Base

    engine = create_engine(migrated_url)
    with engine.connect() as connection:
        context = MigrationContext.configure(
            connection,
            # Server defaults are compared on PostgreSQL by
            # tools/check_migrations.py. SQLite reports a default as the text it
            # stored, so `now()` returns as CURRENT_TIMESTAMP and every
            # timestamp column reads as a difference — noise, not signal.
            opts={"compare_type": True, "compare_server_default": False},
        )
        differences = compare_metadata(context, Base.metadata)

    assert differences == [], (
        "the migration history and the models disagree; generate a revision "
        f"with `alembic revision --autogenerate`:\n{differences}")


def test_every_model_table_exists_after_upgrade(migrated_url):
    """A blunter version of the same question, in case the comparison above ever
    grows a blind spot."""
    from sentry_core.models import Base

    present = set(inspect(create_engine(migrated_url)).get_table_names())
    declared = set(Base.metadata.tables)

    assert declared - present == set(), \
        f"tables declared in models but absent after migration: {declared - present}"


def test_the_history_is_linear(migrated_url):
    """One head.

    Two heads mean two people generated a revision from the same parent, and
    `upgrade head` fails on a database that has seen neither — at deploy time,
    which is the worst moment to find out.
    """
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "api" / "migrations"))
    heads = ScriptDirectory.from_config(cfg).get_heads()

    assert len(heads) == 1, f"migration history has {len(heads)} heads: {heads}"


def test_every_revision_has_a_downgrade(migrated_url):
    """A migration that cannot be reversed is a deploy that cannot be rolled
    back."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "api" / "migrations"))
    script = ScriptDirectory.from_config(cfg)

    missing = []
    for revision in script.walk_revisions():
        source = Path(revision.path).read_text()
        body = source.split("def downgrade()", 1)
        if len(body) < 2 or body[1].strip().rstrip(":").lstrip(" ->None:").strip() in ("", "pass"):
            missing.append(revision.revision)

    assert not missing, f"revisions with no downgrade: {missing}"
