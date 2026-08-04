"""control.SUPERSEDED — a control whose policy is already enforced by another

A FAILED control says an operator has something to fix. 636 rows on the
Remediation surface said that about two policies that were live at the gateway
the whole time: a re-proposal commits a fresh control row before it writes, and
the write was a create-only POST, so every retry of an already-applied policy
left another unactionable row. The actuator is idempotent now, which stops the
next one being created and does nothing about the ones already there.

SUPERSEDED is that missing outcome — never applied, and it does not need to be.
It is deliberately not REVERTED (enforcement was never removed, because this row
never had any), not REJECTED (nothing measured this and found it unsafe), and not
a deletion (the row is the audit trail of a policy this system proposed, and a
compliance system that erases its own history to tidy a screen has traded the
thing it exists for).

``superseded_by`` names the control that actually holds the plugin. It is a real
question: where a SOAP operation and its containing URL collapse onto one gateway
route, the enforcing control belongs to a *different* endpoint.

No rows are transitioned here. Deciding whether a policy is genuinely enforced
means reading the live gateway and comparing configs, and a migration must not
depend on Kong being reachable — a deploy would then fail for a reason that has
nothing to do with the schema. ``control_plane.reconcile_failed`` does it, from
evidence, on every stage 10 pass. This migration only makes the state sayable.

Revision ID: c41a7f5b9e83
Revises: 9d48883f201b
Created: 2026-08-03 05:12:18.402771+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c41a7f5b9e83'
down_revision: str | None = '9d48883f201b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


#: Enums are ``native_enum=False`` for SQLite portability, so the state column is
#: VARCHAR + CHECK. Both halves have to move: the constraint has to admit the new
#: value, and the column has to be wide enough to hold it. ``SUPERSEDED`` is ten
#: characters and the column was sized VARCHAR(8) by the longest of the six
#: original states, so widening the constraint alone would produce a state the
#: schema permits and the column cannot store.
_OLD = ('PROPOSED', 'JUDGED', 'APPLIED', 'REJECTED', 'REVERTED', 'FAILED')
_NEW = (*_OLD, 'SUPERSEDED')
_CONSTRAINT = 'control_state_t'


def _state(*values: str) -> sa.Enum:
    return sa.Enum(*values, name=_CONSTRAINT, native_enum=False,
                   create_constraint=True)


#: The FK has to match ``control.id``, which is BigInteger on PostgreSQL and
#: Integer on SQLite — the same variant the models declare as ``BigPK``.
_FK_TYPE = sa.BigInteger().with_variant(sa.Integer(), 'sqlite')


def upgrade() -> None:
    with op.batch_alter_table('control') as batch:
        batch.alter_column('state', existing_type=_state(*_OLD),
                           type_=_state(*_NEW), existing_nullable=False)
        batch.add_column(sa.Column('superseded_by', _FK_TYPE, nullable=True))
        batch.create_foreign_key(
            'fk_control_superseded_by', 'control', ['superseded_by'], ['id'],
        )


def downgrade() -> None:
    # A SUPERSEDED row cannot survive the narrower constraint. It goes back to
    # FAILED, which is where it came from and is the safe direction: it reappears
    # as something an operator is asked to look at, rather than being dropped.
    op.execute(
        sa.text("UPDATE control SET state = 'FAILED' WHERE state = 'SUPERSEDED'")
    )
    with op.batch_alter_table('control') as batch:
        batch.drop_constraint('fk_control_superseded_by', type_='foreignkey')
        batch.drop_column('superseded_by')
        batch.alter_column('state', existing_type=_state(*_NEW),
                           type_=_state(*_OLD), existing_nullable=False)
