"""Datastore edges record which collector asserted them.

A registry export is the core banking platform's own statement of where an
interface's data lives; an inference from an ORM call is a reading of code. An
operator deciding whether retiring an operation touches the general ledger needs
to know which of the two they are looking at.

Existing rows are backfilled to `legacy`, because the legacy collector is the
only writer that has ever produced one.

Revision ID: 992ab6845fae
Revises: f6d8eb434582
Created: 2026-07-30 04:17:52.477560+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '992ab6845fae'
down_revision: str | None = 'f6d8eb434582'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add, backfill, then constrain.
    #
    # A NOT NULL column with no default cannot be added to a table that has rows
    # — autogenerate produces exactly that, and it fails on the first database
    # where the table is not empty. The server default is dropped afterwards
    # because the models do not declare one: leaving it would show up as drift on
    # the next `make migrations-check`.
    source = sa.Enum('ebpf', 'gateway', 'code', 'legacy',
                     name='datastore_source_t', native_enum=False,
                     create_constraint=True)
    op.add_column('datastore_edge',
                  sa.Column('source', source, nullable=False,
                            server_default='legacy'))
    op.add_column('datastore_edge',
                  sa.Column('first_vday', sa.Integer(), nullable=False,
                            server_default='0'))
    # Batch mode, because SQLite has no ALTER COLUMN. It rebuilds the table
    # instead, so one migration runs on the test database and on PostgreSQL.
    with op.batch_alter_table('datastore_edge') as batch:
        batch.alter_column('source', server_default=None)
        batch.alter_column('first_vday', server_default=None)


def downgrade() -> None:
    with op.batch_alter_table('datastore_edge') as batch:
        batch.drop_column('first_vday')
        batch.drop_column('source')
