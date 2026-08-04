"""endpoint.request_schema — the request body a service publishes for itself

Written by the OpenAPI collector in stage 01. An attribute rather than a fifth
discovery `Source`: a published contract says what a caller must send, not
whether anything is calling, and SHADOW is a query over the sources that answer
the existence question.

Nullable on purpose. NULL means no contract was readable, which is not the same
as a contract that declares no body — the Judge replays bodyless and counts it in
the first case, and synthesises from the schema in the second.

Revision ID: 9d48883f201b
Revises: 7d02d8cac0fa
Created: 2026-08-02 07:40:44.521930+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '9d48883f201b'
down_revision: str | None = '7d02d8cac0fa'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('endpoint', sa.Column('request_schema', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('endpoint', 'request_schema')
