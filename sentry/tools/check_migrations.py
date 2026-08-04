"""Assert the migration history and the models agree.

Runs every migration against an empty database and then asks Alembic what still
differs from ``Base.metadata``. Anything it finds is drift: a model change
somebody made without a migration, or a migration that does not do what its
model says.

This is the check that makes migrations worth having. Without it the history is
a set of files nobody is required to keep true, and the first time that matters
is a production deploy where ``upgrade head`` produces a schema the code cannot
use.

    python tools/check_migrations.py                       # sqlite, throwaway
    python tools/check_migrations.py --url postgresql://…   # a scratch database

The URL is dropped and recreated. Never point it at anything you want to keep.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _diff(url: str) -> list:
    """Every difference between the migrated database and the models."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine

    from sentry_core.models import Base

    engine = create_engine(url)
    with engine.connect() as connection:
        # Server defaults are compared on PostgreSQL and not on SQLite.
        #
        # SQLite reports a default as the text it stored, so `now()` comes back
        # `CURRENT_TIMESTAMP` and `false` comes back `0` — sixteen differences
        # that are all the same default written two ways. Every one of them is
        # noise, and a check that always fails is a check nobody runs.
        # PostgreSQL is the production target and is compared strictly;
        # structure, types and nullability are compared on both.
        compare_defaults = connection.dialect.name != "sqlite"
        context = MigrationContext.configure(
            connection,
            opts={"compare_type": True,
                  "compare_server_default": compare_defaults},
        )
        return compare_metadata(context, Base.metadata)


def _upgrade(url: str) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "api" / "migrations"))
    cfg.cmd_opts = argparse.Namespace(x=[f"url={url}"])
    command.upgrade(cfg, "head")


def _describe(diff) -> str:
    """Render a diff entry the way a person needs to read it.

    Alembic's raw tuples name the object but not what to do about it, and the
    whole value of this check is that the failure tells you which migration is
    missing.
    """
    kind = diff[0] if isinstance(diff, tuple) else str(diff)
    if kind == "add_table":
        return f"table {diff[1].name} exists in the models and in no migration"
    if kind == "remove_table":
        return f"table {diff[1].name} exists in the migrations and in no model"
    if kind == "add_column":
        return (f"column {diff[2]}.{diff[3].name} exists in the models and in no "
                f"migration")
    if kind == "remove_column":
        return (f"column {diff[2]}.{diff[3].name} exists in the migrations and in "
                f"no model")
    if kind in ("add_index", "remove_index", "add_constraint", "remove_constraint"):
        return f"{kind}: {diff[1]}"
    if kind == "modify_type":
        return f"column {diff[2]}.{diff[3]} type differs: {diff[5]} -> {diff[6]}"
    if kind == "modify_default":
        return f"column {diff[2]}.{diff[3]} server default differs"
    if kind == "modify_nullable":
        return f"column {diff[2]}.{diff[3]} nullability differs"
    return repr(diff)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="scratch database URL; dropped and recreated")
    args = parser.parse_args()

    tmp: str | None = None
    if args.url:
        url = args.url
    else:
        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(tmp)
        url = f"sqlite:///{tmp}"

    os.environ["DATABASE_URL"] = url
    os.environ.setdefault("REDIS_URL", "")
    sys.path.insert(0, str(REPO_ROOT))

    try:
        _upgrade(url)
        differences = _diff(url)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)

    if not differences:
        print(f"migrations match the models ({url.split('://')[0]})")
        return 0

    print(f"{len(differences)} difference(s) between the migration history and "
          f"the models:\n", file=sys.stderr)
    for d in differences:
        # A modify_* diff arrives as a list of tuples, one per changed aspect.
        for entry in (d if isinstance(d, list) else [d]):
            print(f"  - {_describe(entry)}", file=sys.stderr)
    print("\nGenerate the missing revision with:\n"
          "  alembic revision --autogenerate -m '<what changed>'", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
