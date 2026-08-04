"""observation.response_fields — the names of a response body's JSON keys

Schema, never content. The kernel writes a key name into the outgoing record as
it reads it and rewinds over any token that turns out to be a value, so no value
has a path to this column.

Added because stage 12's fingerprint is specified to key on response schema and
had none: the classifier extracted data classes and discarded everything else,
leaving nine behavioural features to carry the whole verdict. The estate's own
resurrection scored 0.80 against a 0.85 threshold on those alone.

`server_default '[]'` rather than a nullable column: every row written before
this migration was observed by a sensor that could not report field names, and
that is an empty set rather than an unknown one. A NULL here would be
indistinguishable from a response the classifier read and found no keys in.

Revision ID: 7d02d8cac0fa
Revises: 992ab6845fae
Created: 2026-08-02 07:27:48.128867+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '7d02d8cac0fa'
down_revision: str | None = '992ab6845fae'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Added nullable, backfilled, then constrained.
    #
    # A declared `server_default` would make the drift check compare
    # `'[]'::json = '[]'`, and PostgreSQL has no equality operator for `json` —
    # the column would be unverifiable. Doing the backfill here instead keeps the
    # NOT NULL guarantee and leaves the schema comparable.
    #
    # `batch_alter_table` because SQLite has no `ALTER COLUMN ... SET NOT NULL`
    # and this schema is required to build on both dialects — PostgreSQL is the
    # production target, SQLite keeps the engine suite runnable without a
    # container. Alembic emits a plain ALTER on PostgreSQL and rebuilds the
    # table on SQLite.
    op.add_column("observation", sa.Column("response_fields", sa.JSON(), nullable=True))
    op.execute("UPDATE observation SET response_fields = '[]' WHERE response_fields IS NULL")
    with op.batch_alter_table("observation") as batch:
        batch.alter_column("response_fields", existing_type=sa.JSON(), nullable=False)


def downgrade() -> None:
    op.drop_column("observation", "response_fields")
