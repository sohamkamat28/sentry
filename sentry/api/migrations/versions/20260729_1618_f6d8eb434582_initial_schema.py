"""Baseline: the schema as the models declare it.

Everything before this revision was applied by ``create_all`` and, latterly, by
hand-written DDL — which is how ``observation.direction``, ``observation.synthetic``,
the widened ``ControlState`` and the Phase D release columns each reached a
running database without a record of having done so. This revision is the point
that stops: from here the models and the history are compared on every test run
by ``api/tests/test_migrations.py``.

An existing database built by ``create_all`` is brought under control with
``alembic stamp`` after ``tools/check_migrations.py`` confirms it already
matches. Stamping one that does not match records a lie about what it contains.

Revision ID: f6d8eb434582
Revises: 
Created: 2026-07-29 16:18:47.059464+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'f6d8eb434582'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('audit_entry',
    sa.Column('seq', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('wall_ts', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('actor', sa.String(length=256), nullable=False),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('target', sa.String(length=256), nullable=True),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('prev_hash', sa.LargeBinary(), nullable=False),
    sa.Column('entry_hash', sa.LargeBinary(), nullable=False),
    sa.PrimaryKeyConstraint('seq')
    )
    op.create_index(op.f('ix_audit_entry_actor'), 'audit_entry', ['actor'], unique=False)
    op.create_index(op.f('ix_audit_entry_target'), 'audit_entry', ['target'], unique=False)
    op.create_table('gate_event',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('repo', sa.String(length=256), nullable=False),
    sa.Column('pr_number', sa.Integer(), nullable=False),
    sa.Column('commit_sha', sa.String(length=64), nullable=False),
    sa.Column('checks', sa.JSON(), nullable=False),
    sa.Column('passed', sa.Boolean(), nullable=False),
    sa.Column('wall_ts', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('pipeline_run',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('trigger', sa.String(length=32), nullable=False),
    sa.Column('actor', sa.String(length=256), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('ok', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('policy_setting',
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('value', sa.JSON(), nullable=False),
    sa.Column('updated_by', sa.String(length=256), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('policy_weights',
    sa.Column('version', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('weights', sa.JSON(), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('created_by', sa.String(length=256), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('version')
    )
    op.create_table('service',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('team', sa.String(length=96), nullable=True),
    sa.Column('criticality', sa.Enum('PAYMENT', 'SETTLEMENT', 'REGULATORY', 'CUSTOMER', 'INTERNAL', name='criticality_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('stack', sa.String(length=96), nullable=True),
    sa.Column('first_vday', sa.Integer(), nullable=False),
    sa.Column('last_vday', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_service_team'), 'service', ['team'], unique=False)
    op.create_table('vclock',
    sa.Column('id', sa.SmallInteger(), autoincrement=False, nullable=False),
    sa.Column('epoch_wall', sa.DateTime(timezone=True), nullable=False),
    sa.Column('scale_seconds', sa.Integer(), nullable=False),
    sa.Column('paused_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('paused_vday', sa.Integer(), nullable=True),
    sa.CheckConstraint('id = 1', name='ck_vclock_singleton'),
    sa.CheckConstraint('scale_seconds BETWEEN 1 AND 86400', name='ck_vclock_scale'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('endpoint',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('method', sa.String(length=8), nullable=False),
    sa.Column('path_template', sa.String(length=512), nullable=False),
    sa.Column('service_id', sa.String(length=32), nullable=False),
    sa.Column('host', sa.String(length=128), nullable=True),
    sa.Column('port', sa.Integer(), nullable=True),
    sa.Column('first_vday', sa.Integer(), nullable=False),
    sa.Column('last_call_vday', sa.Integer(), nullable=True),
    sa.Column('total_calls', sa.BigInteger(), nullable=False),
    sa.Column('auth', sa.Enum('none', 'basic', 'apikey', 'bearer', 'oauth2', 'mtls', name='auth_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('tls_version', sa.String(length=8), nullable=True),
    sa.Column('rate_limited', sa.Boolean(), nullable=False),
    sa.Column('data_classes', sa.JSON(), nullable=False),
    sa.Column('deprecated', sa.Boolean(), nullable=False),
    sa.Column('internet_reachable', sa.Boolean(), nullable=False),
    sa.Column('retired', sa.Boolean(), nullable=False),
    sa.Column('honeypot_active', sa.Boolean(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['service_id'], ['service.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('method', 'path_template', 'service_id', name='uq_endpoint_identity')
    )
    op.create_index(op.f('ix_endpoint_last_call_vday'), 'endpoint', ['last_call_vday'], unique=False)
    op.create_index(op.f('ix_endpoint_path_template'), 'endpoint', ['path_template'], unique=False)
    op.create_index(op.f('ix_endpoint_retired'), 'endpoint', ['retired'], unique=False)
    op.create_index(op.f('ix_endpoint_service_id'), 'endpoint', ['service_id'], unique=False)
    op.create_table('stage_run',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('run_id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), nullable=False),
    sa.Column('stage', sa.SmallInteger(), nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('records', sa.Integer(), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.Column('ok', sa.Boolean(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['run_id'], ['pipeline_run.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('run_id', 'stage', name='uq_stage_run')
    )
    op.create_table('ai_decision',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('endpoint_id', sa.String(length=32), nullable=True),
    sa.Column('purpose', sa.String(length=48), nullable=False),
    sa.Column('model', sa.String(length=64), nullable=False),
    sa.Column('prompt_sha256', sa.LargeBinary(), nullable=False),
    sa.Column('output_sha256', sa.LargeBinary(), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('reasoning', sa.Text(), nullable=True),
    sa.Column('input_tokens', sa.Integer(), nullable=True),
    sa.Column('output_tokens', sa.Integer(), nullable=True),
    sa.Column('latency_ms', sa.Integer(), nullable=True),
    sa.Column('ok', sa.Boolean(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('wall_ts', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('anomaly',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('flag', sa.Boolean(), nullable=False),
    sa.Column('score', sa.Float(), nullable=False),
    sa.Column('isolation_depth', sa.Float(), nullable=False),
    sa.Column('patterns', sa.JSON(), nullable=False),
    sa.Column('features', sa.JSON(), nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('engine_version', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id')
    )
    op.create_table('blast',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('tier', sa.Enum('ZERO', 'LOW', 'MEDIUM', 'CRITICAL', name='blast_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('direct_callers', sa.Integer(), nullable=False),
    sa.Column('hop2_callers', sa.Integer(), nullable=False),
    sa.Column('affected', sa.JSON(), nullable=False),
    sa.Column('datastores', sa.JSON(), nullable=False),
    sa.Column('touches_critical', sa.Boolean(), nullable=False),
    sa.Column('in_graph', sa.Boolean(), nullable=False),
    sa.Column('hop_limit', sa.Integer(), nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('engine_version', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id')
    )
    op.create_table('call_edge',
    sa.Column('caller_service_id', sa.String(length=32), nullable=False),
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('first_vday', sa.Integer(), nullable=False),
    sa.Column('last_vday', sa.Integer(), nullable=False),
    sa.Column('calls', sa.BigInteger(), nullable=False),
    sa.ForeignKeyConstraint(['caller_service_id'], ['service.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('caller_service_id', 'endpoint_id')
    )
    op.create_index(op.f('ix_call_edge_endpoint_id'), 'call_edge', ['endpoint_id'], unique=False)
    op.create_table('cdri',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('score', sa.Float(), nullable=False),
    sa.Column('tier', sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='tier_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('parts', sa.JSON(), nullable=False),
    sa.Column('weights_version', sa.Integer(), nullable=False),
    sa.Column('time_to_breach_d', sa.Integer(), nullable=True),
    sa.Column('ttb_factors', sa.JSON(), nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('engine_version', sa.String(length=32), nullable=False),
    sa.CheckConstraint('score >= 0 AND score <= 1', name='ck_cdri_range'),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['weights_version'], ['policy_weights.version'], ),
    sa.PrimaryKeyConstraint('endpoint_id')
    )
    op.create_index(op.f('ix_cdri_score'), 'cdri', ['score'], unique=False)
    op.create_index(op.f('ix_cdri_tier'), 'cdri', ['tier'], unique=False)
    op.create_table('certificate',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('body', sa.JSON(), nullable=False),
    sa.Column('content_hash', sa.LargeBinary(), nullable=False),
    sa.Column('worm_object', sa.String(length=512), nullable=False),
    sa.Column('approved_by', sa.String(length=256), nullable=False),
    sa.Column('issued_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('classification',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('lifecycle', sa.Enum('ACTIVE', 'DORMANT', 'DEPRECATED', 'ZOMBIE', name='lifecycle_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('governance', sa.Enum('OWNED', 'ORPHANED', 'SHADOW', name='governance_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('confidence', sa.Enum('NONE', 'PROVISIONAL', 'CONFIRMED', name='confidence_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('severity_bump', sa.Boolean(), nullable=False),
    sa.Column('pre_zombie', sa.Boolean(), nullable=False),
    sa.Column('trace', sa.JSON(), nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('engine_version', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id')
    )
    op.create_index('ix_classification_axes', 'classification', ['lifecycle', 'governance'], unique=False)
    op.create_table('datastore_edge',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('datastore', sa.String(length=128), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id', 'datastore')
    )
    op.create_table('decommission',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('phase', sa.Enum('NONE', 'A', 'B', 'C', 'D', 'RETIRED', 'REVERTED', name='phase_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('express', sa.Boolean(), nullable=False),
    sa.Column('canary', sa.Boolean(), nullable=False),
    sa.Column('canary_split', sa.Float(), nullable=True),
    sa.Column('entered_vday', sa.Integer(), nullable=True),
    sa.Column('phase_vday', sa.Integer(), nullable=True),
    sa.Column('hold', sa.Boolean(), nullable=False),
    sa.Column('hold_reason', sa.Text(), nullable=True),
    sa.Column('released_for_phase_d', sa.Boolean(), nullable=False),
    sa.Column('released_by', sa.String(length=256), nullable=True),
    sa.Column('released_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('hidden_callers', sa.JSON(), nullable=False),
    sa.Column('worm_object', sa.String(length=512), nullable=True),
    sa.Column('worm_retain_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('certificate_id', sa.String(length=32), nullable=True),
    sa.Column('reverted_reason', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id')
    )
    op.create_table('endpoint_daily',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('calls', sa.BigInteger(), nullable=False),
    sa.Column('distinct_peers', sa.Integer(), nullable=False),
    sa.Column('err_calls', sa.BigInteger(), nullable=False),
    sa.Column('p50_latency_us', sa.Integer(), nullable=True),
    sa.Column('p95_latency_us', sa.Integer(), nullable=True),
    sa.Column('mean_resp_bytes', sa.Integer(), nullable=True),
    sa.Column('auth_missing', sa.BigInteger(), nullable=False),
    sa.Column('hour_histogram', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id', 'vday')
    )
    op.create_index('ix_endpoint_daily_vday', 'endpoint_daily', ['vday'], unique=False)
    op.create_table('endpoint_source',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('source', sa.Enum('ebpf', 'gateway', 'code', 'legacy', name='source_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('first_vday', sa.Integer(), nullable=False),
    sa.Column('last_vday', sa.Integer(), nullable=False),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id', 'source')
    )
    op.create_table('finding',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('narrative', sa.JSON(), nullable=False),
    sa.Column('generator', sa.String(length=32), nullable=False),
    sa.Column('model', sa.String(length=64), nullable=True),
    sa.Column('regulations', sa.JSON(), nullable=False),
    sa.Column('time_to_breach_d', sa.Integer(), nullable=True),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('engine_version', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_finding_endpoint_id'), 'finding', ['endpoint_id'], unique=False)
    op.create_index('ix_finding_ep_vday', 'finding', ['endpoint_id', 'vday'], unique=False)
    op.create_table('fingerprint',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('minhash', sa.LargeBinary(), nullable=False),
    sa.Column('features', sa.JSON(), nullable=False),
    sa.Column('shingles', sa.JSON(), nullable=False),
    sa.Column('captured_vday', sa.Integer(), nullable=False),
    sa.Column('origin_path', sa.String(length=512), nullable=False),
    sa.Column('origin_method', sa.String(length=8), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id')
    )
    op.create_table('forecast',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('days_to_zombie', sa.Integer(), nullable=True),
    sa.Column('slope', sa.Float(), nullable=False),
    sa.Column('level', sa.Float(), nullable=False),
    sa.Column('signals', sa.JSON(), nullable=False),
    sa.Column('observed', sa.JSON(), nullable=False),
    sa.Column('adjusted', sa.JSON(), nullable=False),
    sa.Column('projection', sa.JSON(), nullable=False),
    sa.Column('deseasonalised', sa.Boolean(), nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('engine_version', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id')
    )
    op.create_table('judge_run',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('requests', sa.Integer(), nullable=False),
    sa.Column('replay_exact', sa.Integer(), nullable=False),
    sa.Column('replay_synthesised', sa.Integer(), nullable=False),
    sa.Column('replay_bodyless', sa.Integer(), nullable=False),
    sa.Column('schema_score', sa.SmallInteger(), nullable=False),
    sa.Column('latency_score', sa.SmallInteger(), nullable=False),
    sa.Column('error_score', sa.SmallInteger(), nullable=False),
    sa.Column('exposure_score', sa.SmallInteger(), nullable=False),
    sa.Column('verdict', sa.String(length=16), nullable=False),
    sa.Column('reason', sa.String(length=64), nullable=True),
    sa.Column('latency_delta_us', sa.Integer(), nullable=False),
    sa.Column('budget_us', sa.Integer(), nullable=False),
    sa.Column('diff_summary', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_judge_run_endpoint_id'), 'judge_run', ['endpoint_id'], unique=False)
    op.create_table('observation',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('wall_ts', sa.DateTime(timezone=True), nullable=False),
    sa.Column('endpoint_id', sa.String(length=32), nullable=True),
    sa.Column('source', sa.Enum('ebpf', 'gateway', 'code', 'legacy', name='source_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('method', sa.String(length=8), nullable=False),
    sa.Column('path_raw', sa.String(length=1024), nullable=False),
    sa.Column('host', sa.String(length=128), nullable=True),
    sa.Column('port', sa.Integer(), nullable=True),
    sa.Column('status', sa.SmallInteger(), nullable=True),
    sa.Column('latency_us', sa.Integer(), nullable=True),
    sa.Column('req_bytes', sa.Integer(), nullable=True),
    sa.Column('resp_bytes', sa.Integer(), nullable=True),
    sa.Column('auth_present', sa.Boolean(), nullable=False),
    sa.Column('auth_scheme', sa.String(length=32), nullable=True),
    sa.Column('tls_version', sa.String(length=8), nullable=True),
    sa.Column('data_classes', sa.JSON(), nullable=False),
    sa.Column('direction', sa.String(length=8), nullable=True),
    sa.Column('synthetic', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('peer_service', sa.String(length=128), nullable=True),
    sa.Column('peer_ip', sa.String(length=64), nullable=True),
    sa.Column('pid', sa.Integer(), nullable=True),
    sa.Column('cgroup_id', sa.BigInteger(), nullable=True),
    sa.Column('backfill', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_observation_direction'), 'observation', ['direction'], unique=False)
    op.create_index(op.f('ix_observation_endpoint_id'), 'observation', ['endpoint_id'], unique=False)
    op.create_index('ix_observation_ep_vday', 'observation', ['endpoint_id', 'vday'], unique=False)
    op.create_index(op.f('ix_observation_peer_service'), 'observation', ['peer_service'], unique=False)
    op.create_index(op.f('ix_observation_synthetic'), 'observation', ['synthetic'], unique=False)
    op.create_index('ix_observation_unresolved', 'observation', ['vday'], unique=False, postgresql_where=sa.text('endpoint_id IS NULL'))
    op.create_index(op.f('ix_observation_vday'), 'observation', ['vday'], unique=False)
    op.create_table('ownership',
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('owner_email', sa.String(length=256), nullable=True),
    sa.Column('owner_team', sa.String(length=96), nullable=True),
    sa.Column('resolved_by', sa.String(length=32), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=False),
    sa.Column('reachable', sa.Boolean(), nullable=False),
    sa.Column('escalation', sa.String(length=256), nullable=True),
    sa.Column('ladder', sa.JSON(), nullable=False),
    sa.Column('resolved_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('confidence >= 0 AND confidence <= 1', name='ck_ownership_conf'),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('endpoint_id')
    )
    op.create_table('probe',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('wall_ts', sa.DateTime(timezone=True), nullable=False),
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('source_ip', sa.String(length=64), nullable=False),
    sa.Column('source_asn', sa.String(length=128), nullable=True),
    sa.Column('geo', sa.String(length=64), nullable=True),
    sa.Column('method', sa.String(length=8), nullable=False),
    sa.Column('path_raw', sa.String(length=1024), nullable=False),
    sa.Column('headers', sa.JSON(), nullable=False),
    sa.Column('body_sha256', sa.LargeBinary(), nullable=True),
    sa.Column('watermark', sa.String(length=64), nullable=False),
    sa.Column('session_fp', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_probe_endpoint_id'), 'probe', ['endpoint_id'], unique=False)
    op.create_index(op.f('ix_probe_source_ip'), 'probe', ['source_ip'], unique=False)
    op.create_index(op.f('ix_probe_vday'), 'probe', ['vday'], unique=False)
    op.create_table('resurrection_alert',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('new_endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('origin_endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('origin_path', sa.String(length=512), nullable=False),
    sa.Column('similarity', sa.Float(), nullable=False),
    sa.Column('threshold', sa.Float(), nullable=False),
    sa.Column('lsh_hit', sa.Boolean(), nullable=False),
    sa.Column('vday', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['new_endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('new_endpoint_id', 'origin_endpoint_id', name='uq_resurrection_pair')
    )
    op.create_table('control',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('kind', sa.String(length=48), nullable=False),
    sa.Column('plugin_config', sa.JSON(), nullable=False),
    sa.Column('kong_plugin_id', sa.String(length=64), nullable=True),
    sa.Column('state', sa.Enum('PROPOSED', 'JUDGED', 'APPLIED', 'REJECTED', 'REVERTED', 'FAILED', name='control_state_t', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('generator', sa.String(length=32), nullable=False),
    sa.Column('judge_run_id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), nullable=True),
    sa.Column('origin_stage', sa.SmallInteger(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('applied_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('reverted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('actor', sa.String(length=256), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['judge_run_id'], ['judge_run.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_control_endpoint_id'), 'control', ['endpoint_id'], unique=False)
    op.create_index('ix_control_ep_state', 'control', ['endpoint_id', 'state'], unique=False)
    op.create_table('change_request',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('endpoint_id', sa.String(length=32), nullable=False),
    sa.Column('control_id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), nullable=True),
    sa.Column('sys_id', sa.String(length=64), nullable=True),
    sa.Column('number', sa.String(length=32), nullable=True),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('stub', sa.Boolean(), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=False),
    sa.Column('response', sa.JSON(), nullable=True),
    sa.Column('submitted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['control_id'], ['control.id'], ),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_change_request_endpoint_id'), 'change_request', ['endpoint_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_change_request_endpoint_id'), table_name='change_request')
    op.drop_table('change_request')
    op.drop_index('ix_control_ep_state', table_name='control')
    op.drop_index(op.f('ix_control_endpoint_id'), table_name='control')
    op.drop_table('control')
    op.drop_table('resurrection_alert')
    op.drop_index(op.f('ix_probe_vday'), table_name='probe')
    op.drop_index(op.f('ix_probe_source_ip'), table_name='probe')
    op.drop_index(op.f('ix_probe_endpoint_id'), table_name='probe')
    op.drop_table('probe')
    op.drop_table('ownership')
    op.drop_index(op.f('ix_observation_vday'), table_name='observation')
    op.drop_index('ix_observation_unresolved', table_name='observation', postgresql_where=sa.text('endpoint_id IS NULL'))
    op.drop_index(op.f('ix_observation_synthetic'), table_name='observation')
    op.drop_index(op.f('ix_observation_peer_service'), table_name='observation')
    op.drop_index('ix_observation_ep_vday', table_name='observation')
    op.drop_index(op.f('ix_observation_endpoint_id'), table_name='observation')
    op.drop_index(op.f('ix_observation_direction'), table_name='observation')
    op.drop_table('observation')
    op.drop_index(op.f('ix_judge_run_endpoint_id'), table_name='judge_run')
    op.drop_table('judge_run')
    op.drop_table('forecast')
    op.drop_table('fingerprint')
    op.drop_index('ix_finding_ep_vday', table_name='finding')
    op.drop_index(op.f('ix_finding_endpoint_id'), table_name='finding')
    op.drop_table('finding')
    op.drop_table('endpoint_source')
    op.drop_index('ix_endpoint_daily_vday', table_name='endpoint_daily')
    op.drop_table('endpoint_daily')
    op.drop_table('decommission')
    op.drop_table('datastore_edge')
    op.drop_index('ix_classification_axes', table_name='classification')
    op.drop_table('classification')
    op.drop_table('certificate')
    op.drop_index(op.f('ix_cdri_tier'), table_name='cdri')
    op.drop_index(op.f('ix_cdri_score'), table_name='cdri')
    op.drop_table('cdri')
    op.drop_index(op.f('ix_call_edge_endpoint_id'), table_name='call_edge')
    op.drop_table('call_edge')
    op.drop_table('blast')
    op.drop_table('anomaly')
    op.drop_table('ai_decision')
    op.drop_table('stage_run')
    op.drop_index(op.f('ix_endpoint_service_id'), table_name='endpoint')
    op.drop_index(op.f('ix_endpoint_retired'), table_name='endpoint')
    op.drop_index(op.f('ix_endpoint_path_template'), table_name='endpoint')
    op.drop_index(op.f('ix_endpoint_last_call_vday'), table_name='endpoint')
    op.drop_table('endpoint')
    op.drop_table('vclock')
    op.drop_index(op.f('ix_service_team'), table_name='service')
    op.drop_table('service')
    op.drop_table('policy_weights')
    op.drop_table('policy_setting')
    op.drop_table('pipeline_run')
    op.drop_table('gate_event')
    op.drop_index(op.f('ix_audit_entry_target'), table_name='audit_entry')
    op.drop_index(op.f('ix_audit_entry_actor'), table_name='audit_entry')
    op.drop_table('audit_entry')
