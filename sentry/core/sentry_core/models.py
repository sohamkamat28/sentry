"""ORM models — the complete SENTRY schema.

Two conventions hold throughout and are enforced by tools/check_schema_writers.py:

1. One writer per column. Every column names exactly one stage that writes it.
   The single deliberate exception is ``Classification.pre_zombie``, written by
   stage 07, which is the one legal back-edge in the pipeline DAG.
2. Raw observations are immutable. ``Observation`` and ``Probe`` are append-only;
   engines derive from them and never edit them.

Portability note: enums are declared with ``native_enum=False`` so they compile to
VARCHAR + CHECK on both PostgreSQL and SQLite. PostgreSQL is the production
target; SQLite keeps the engine test suite runnable without a container.
Array columns use JSON for the same reason.
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .enums import (
    Auth,
    BlastTier,
    Confidence,
    ControlState,
    Criticality,
    Governance,
    Lifecycle,
    Phase,
    Source,
    Tier,
)


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


#: Timestamp columns carry a *server* default as well as the Python one.
#:
#: A Python-side default alone leaves the column NOT NULL with nothing to fill
#: it, so every writer that is not SQLAlchemy — the Go ingest and honeypot
#: services, a bulk load, a migration, a DBA at a psql prompt — hits a
#: constraint violation. The server default makes the schema usable by anything
#: that can speak SQL, which is what a shared database has to be.
_NOW_SQL = sa.func.now()


#: BigInteger on PostgreSQL, Integer on SQLite.
#:
#: SQLite aliases only ``INTEGER PRIMARY KEY`` to rowid, so a BIGINT primary key
#: never auto-increments there. The variant keeps 64-bit ids in production and a
#: working autoincrement in the test suite.
BigPK = sa.BigInteger().with_variant(sa.Integer, "sqlite")


def _enum(py_enum: type, name: str) -> sa.Enum:
    """Persist the enum *value*, not the Python member name.

    SQLAlchemy stores member names by default, so Source.EBPF becomes "EBPF" in
    the column while the Go services, the protobuf contract and the REST API all
    use "ebpf". Rows written by Go were then unreadable from Python — a schema
    shared across two languages cannot have two spellings of the same value, and
    the lowercase form is the one every other layer already agreed on.
    """
    return sa.Enum(py_enum, name=name, native_enum=False, validate_strings=True,
                   create_constraint=True,
                   values_callable=lambda e: [m.value for m in e])


# ─────────────────────────────────────────────────────────────────────────────
# Time base
# ─────────────────────────────────────────────────────────────────────────────
class VClock(Base):
    """The system's only time axis.

    ``scale_seconds`` is 86400 in production, making vday a calendar day. Lower
    values compress the timeline; the analysis code path is unchanged.

    Writer: api (admin routes).
    """

    __tablename__ = "vclock"

    # Not autoincrement. An integer primary key becomes a SERIAL on PostgreSQL
    # by default, which gives this table a sequence it can never use: the CHECK
    # below allows exactly one row, with id 1. The sequence was invisible until
    # the migration drift check compared the declared schema against the
    # generated one and found a server default the model never asked for.
    id: Mapped[int] = mapped_column(sa.SmallInteger, primary_key=True, default=1,
                                    autoincrement=False)
    epoch_wall: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    scale_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=30)
    paused_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    paused_vday: Mapped[int | None] = mapped_column(sa.Integer)

    __table_args__ = (
        sa.CheckConstraint("id = 1", name="ck_vclock_singleton"),
        sa.CheckConstraint("scale_seconds BETWEEN 1 AND 86400", name="ck_vclock_scale"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Estate
# ─────────────────────────────────────────────────────────────────────────────
class Service(Base):
    """Writers: stage 01 collectors, stage 03.

    Both write, and neither is redundant. A gateway route or a WSDL names a
    service that may never be seen on the wire, and a kernel capture names a
    service that may appear in no registry — which is the whole shadow case.
    They converge because both derive the id from the same name hash, so the
    row is created by whichever source observes it first.
    """

    __tablename__ = "service"

    id: Mapped[str] = mapped_column(sa.String(32), primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False, unique=True)
    team: Mapped[str | None] = mapped_column(sa.String(96), index=True)
    criticality: Mapped[Criticality] = mapped_column(
        _enum(Criticality, "criticality_t"), nullable=False, default=Criticality.INTERNAL
    )
    stack: Mapped[str | None] = mapped_column(sa.String(96))
    first_vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    last_vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)

    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="service")


class Endpoint(Base):
    """The aggregate row: identity and observed facts only.

    Engine verdicts live in their own tables so they can be recomputed and
    audited independently. Per-column writers:

    ==========================================  =========
    identity, host, port, first_vday            stage 03
    last_call_vday, total_calls                 stage 02
    auth, tls_version, rate_limited,
      data_classes                              stage 01 (observed);
                                                stage 10 actuator on apply
    request_schema                              stage 01 (openapi collector)
    deprecated                                  stage 03
    retired, honeypot_active                    stage 11
    internet_reachable                          stage 03
    ==========================================  =========
    """

    __tablename__ = "endpoint"

    id: Mapped[str] = mapped_column(sa.String(32), primary_key=True)
    method: Mapped[str] = mapped_column(sa.String(8), nullable=False)
    path_template: Mapped[str] = mapped_column(sa.String(512), nullable=False, index=True)
    service_id: Mapped[str] = mapped_column(
        sa.ForeignKey("service.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host: Mapped[str | None] = mapped_column(sa.String(128))
    port: Mapped[int | None] = mapped_column(sa.Integer)

    first_vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    last_call_vday: Mapped[int | None] = mapped_column(sa.Integer, index=True)
    total_calls: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)

    auth: Mapped[Auth] = mapped_column(_enum(Auth, "auth_t"), nullable=False, default=Auth.NONE)
    tls_version: Mapped[str | None] = mapped_column(sa.String(8))
    rate_limited: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    data_classes: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)

    # The JSON Schema a caller has to satisfy, as the service itself publishes it.
    #
    # Not a discovery signal, which is why it is an attribute here rather than a
    # fifth ``Source``: an OpenAPI document says what a caller must send, not
    # whether anything is calling. SHADOW stays a query over the four sources
    # that answer the existence question.
    #
    # NULL means no contract was readable, which is not the same as a contract
    # declaring no body. The Judge replays bodyless in the first case and counts
    # it; in the second it has a schema and synthesises from it.
    request_schema: Mapped[dict | None] = mapped_column(sa.JSON)

    deprecated: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    internet_reachable: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)

    retired: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False, index=True)
    honeypot_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)

    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=_now, onupdate=_now,
        server_default=_NOW_SQL, nullable=False
    )

    __table_args__ = (
        sa.UniqueConstraint("method", "path_template", "service_id", name="uq_endpoint_identity"),
    )

    service: Mapped[Service] = relationship(back_populates="endpoints")
    sources: Mapped[list["EndpointSource"]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan"
    )


class EndpointSource(Base):
    """Discovery provenance. Shadow status is a query over this, not a stored flag.

    Writer: stage 03.

    Stage 01 produces the evidence but does not write this table. Each collector
    emits observations carrying a ``source``; stage 03 is what resolves an
    observation to an endpoint, and provenance cannot be recorded before the
    endpoint it attaches to exists.
    """

    __tablename__ = "endpoint_source"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    source: Mapped[Source] = mapped_column(_enum(Source, "source_t"), primary_key=True)
    first_vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    last_vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    detail: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)

    endpoint: Mapped[Endpoint] = relationship(back_populates="sources")


# ─────────────────────────────────────────────────────────────────────────────
# Observations
# ─────────────────────────────────────────────────────────────────────────────
class Observation(Base):
    """One captured request. Append-only.

    There is no payload column. Bodies are matched against data-class patterns
    in kernel memory and discarded there; the class is recorded, the value has
    nowhere to be stored.

    Partitioned by vday in PostgreSQL (created at runtime by the maintenance
    task, not by a migration).

    Writers: ingest (insert), stage 01 collectors (insert), stage 03
    (endpoint_id backfill only). ``response_fields`` is written by ingest alone —
    only the kernel sensor can see a response body, so a gateway route or a
    source declaration carries an empty set rather than an unknown one.

    The collectors insert here deliberately. A gateway route, a route declared in
    source, and a WSDL operation are all evidence that a surface exists, and
    routing them through the same table as kernel captures is what lets stage 03
    correlate all four sources on one identity — and what makes SHADOW a query
    over which sources are present rather than a flag somebody sets. Collector
    rows are distinguished by ``source``; only ``Source.EBPF`` rows are counted
    as traffic, which is why a gateway route alone never resets a silence clock.
    """

    __tablename__ = "observation"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False, index=True)
    wall_ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    # SET NULL, not CASCADE.
    #
    # The endpoint is derived from these rows; these rows are not derived from
    # the endpoint. Cascading a delete from the aggregate down to the raw
    # evidence destroys the only record of what was actually observed and
    # contradicts the immutability this table is supposed to have. Dropping and
    # rebuilding the registry is a normal operation — re-running correlation
    # after an engine change does exactly that — and it must leave the
    # observations untouched for stage 03 to re-resolve.
    endpoint_id: Mapped[str | None] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="SET NULL"), index=True
    )
    source: Mapped[Source] = mapped_column(_enum(Source, "source_t"), nullable=False)

    method: Mapped[str] = mapped_column(sa.String(8), nullable=False)
    path_raw: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    host: Mapped[str | None] = mapped_column(sa.String(128))
    port: Mapped[int | None] = mapped_column(sa.Integer)
    status: Mapped[int | None] = mapped_column(sa.SmallInteger)
    latency_us: Mapped[int | None] = mapped_column(sa.Integer)
    req_bytes: Mapped[int | None] = mapped_column(sa.Integer)
    resp_bytes: Mapped[int | None] = mapped_column(sa.Integer)

    auth_present: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    auth_scheme: Mapped[str | None] = mapped_column(sa.String(32))
    tls_version: Mapped[str | None] = mapped_column(sa.String(8))
    data_classes: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)

    # The names of the JSON keys in the response body — schema, never content.
    #
    # ``data_classes`` says an Aadhaar number was present; this says the key was
    # called ``aadhaar``. Both are labels and neither is a value: the kernel
    # writes a key name into the outgoing record as it reads it and rewinds over
    # any token that turns out to be a value before the next byte, so a value has
    # no path to this column.
    #
    # Stage 12's fingerprint is specified to key on response schema and had none
    # to key on. Nine behavioural features carried the whole verdict, each worth
    # about a tenth of it, and the estate's own resurrection scored 0.80 against
    # a 0.85 threshold — real separation from the 0.58 nearest miss, but decided
    # by one bucket boundary.
    # No server_default, matching data_classes above. PostgreSQL's `json` type
    # has no equality operator, so a declared server default makes the migration
    # drift check compare `'[]'::json = '[]'` and fail outright — the column
    # would be unverifiable rather than merely undefaulted. Rows that predate
    # this column are backfilled by the migration instead, and every writer
    # supplies the value explicitly.
    response_fields: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)

    # Which half of the exchange this row is.
    #
    # A call between two instrumented workloads is captured twice: once as the
    # caller's SSL_write and once as the callee's SSL_read. Both are true
    # sightings and both are kept — the egress copy is the only one that can
    # name the caller, and the ingress copy is the only one present when the
    # client is outside the estate. Without this column the two are
    # indistinguishable and every call count is doubled, so stage 02 uses it to
    # count each exchange once.
    direction: Mapped[str | None] = mapped_column(sa.String(8), index=True)

    # Traffic SENTRY generated itself.
    #
    # The API Judge replays real request shapes through the gateway to the real
    # upstream, so the sensor sees them and cannot tell them from a caller. Left
    # unmarked they are counted as usage — and since stage 10 judges exactly the
    # endpoints under scrutiny, the system resets the silence clock on the
    # endpoint it is deciding about. A zombie stays alive because it is being
    # examined.
    synthetic: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false(), index=True)

    peer_service: Mapped[str | None] = mapped_column(sa.String(128), index=True)
    peer_ip: Mapped[str | None] = mapped_column(sa.String(64))
    pid: Mapped[int | None] = mapped_column(sa.Integer)
    cgroup_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    backfill: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)

    __table_args__ = (
        sa.Index("ix_observation_ep_vday", "endpoint_id", "vday"),
        sa.Index("ix_observation_unresolved", "vday", postgresql_where=sa.text("endpoint_id IS NULL")),
    )


class EndpointDaily(Base):
    """Per-vday rollup. Engines window over this, never over raw observations.

    Zero-call days are materialised: a series with missing days produces a
    different trend slope from one with explicit zeros, so gap filling happens
    here once rather than being re-derived by every consumer.

    Writer: stage 02.
    """

    __tablename__ = "endpoint_daily"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    vday: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    calls: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    distinct_peers: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    err_calls: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    p50_latency_us: Mapped[int | None] = mapped_column(sa.Integer)
    p95_latency_us: Mapped[int | None] = mapped_column(sa.Integer)
    mean_resp_bytes: Mapped[int | None] = mapped_column(sa.Integer)
    auth_missing: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    hour_histogram: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=lambda: [0] * 24)

    __table_args__ = (sa.Index("ix_endpoint_daily_vday", "vday"),)


# ─────────────────────────────────────────────────────────────────────────────
# Graph and ownership
# ─────────────────────────────────────────────────────────────────────────────
class CallEdge(Base):
    """Writer: stage 03."""

    __tablename__ = "call_edge"

    caller_service_id: Mapped[str] = mapped_column(
        sa.ForeignKey("service.id", ondelete="CASCADE"), primary_key=True
    )
    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    first_vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    last_vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    calls: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)


class DatastoreEdge(Base):
    """Which store an endpoint reads or writes.

    Writers: stage 01 legacy collector (from a core-banking registry export),
    stage 03 (from repository analysis, where that exists).

    ``source`` because the two are not equally strong. A registry export is the
    platform's own statement of where an interface's data lives; an inference
    from an ORM call is a reading of code. An operator deciding whether retiring
    an operation touches the general ledger needs to know which one they have.
    """

    __tablename__ = "datastore_edge"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    datastore: Mapped[str] = mapped_column(sa.String(128), primary_key=True)
    source: Mapped[Source] = mapped_column(
        _enum(Source, "datastore_source_t"), nullable=False, default=Source.LEGACY
    )
    first_vday: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)


class Ownership(Base):
    """Four-rung ladder result with the full trace.

    ``reachable=False`` with a named escalation is materially different from no
    owner at all: it routes to a department head rather than an inbox nobody
    reads.

    Writer: stage 03.
    """

    __tablename__ = "ownership"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    owner_email: Mapped[str | None] = mapped_column(sa.String(256))
    owner_team: Mapped[str | None] = mapped_column(sa.String(96))
    resolved_by: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(sa.Float, nullable=False, default=0.0)
    reachable: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    escalation: Mapped[str | None] = mapped_column(sa.String(256))
    ladder: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    resolved_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)

    __table_args__ = (
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_ownership_conf"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Engine outputs
# ─────────────────────────────────────────────────────────────────────────────
class Classification(Base):
    """Two axes plus a replayable rule trace.

    ``pre_zombie`` is written by **stage 07**, not stage 04. Stage 04's upsert
    deliberately omits it from its SET list so a re-classification cannot clear
    a forecast result.

    Writers: stage 04 (all columns except pre_zombie), stage 07 (pre_zombie).
    """

    __tablename__ = "classification"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    lifecycle: Mapped[Lifecycle] = mapped_column(_enum(Lifecycle, "lifecycle_t"), nullable=False)
    governance: Mapped[Governance] = mapped_column(_enum(Governance, "governance_t"), nullable=False)
    confidence: Mapped[Confidence] = mapped_column(_enum(Confidence, "confidence_t"), nullable=False)
    severity_bump: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    pre_zombie: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    trace: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    engine_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)

    __table_args__ = (sa.Index("ix_classification_axes", "lifecycle", "governance"),)


class Anomaly(Base):
    """Isolation Forest output. ``flag`` is r6, consumed by CDRI at weight 0.07.

    Writer: stage 05.
    """

    __tablename__ = "anomaly"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    flag: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    score: Mapped[float] = mapped_column(sa.Float, nullable=False, default=0.0)
    isolation_depth: Mapped[float] = mapped_column(sa.Float, nullable=False, default=0.0)
    patterns: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    features: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    engine_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)


class PolicyWeights(Base):
    """Versioned CDRI weights.

    The sum-to-one invariant is checked in the service layer and asserted in
    tests; it is what guarantees the maximum score is exactly 1.00 and that any
    two scores are comparable.

    Writer: api (analyst routes).
    """

    __tablename__ = "policy_weights"

    version: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    weights: Mapped[dict] = mapped_column(sa.JSON, nullable=False)
    note: Mapped[str | None] = mapped_column(sa.Text)
    created_by: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)


class Cdri(Base):
    """Writer: stage 06."""

    __tablename__ = "cdri"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    score: Mapped[float] = mapped_column(sa.Float, nullable=False, index=True)
    tier: Mapped[Tier] = mapped_column(_enum(Tier, "tier_t"), nullable=False, index=True)
    parts: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    weights_version: Mapped[int] = mapped_column(
        sa.ForeignKey("policy_weights.version"), nullable=False
    )
    time_to_breach_d: Mapped[int | None] = mapped_column(sa.Integer)
    ttb_factors: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    engine_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)

    __table_args__ = (sa.CheckConstraint("score >= 0 AND score <= 1", name="ck_cdri_range"),)


class Forecast(Base):
    """Writer: stage 07."""

    __tablename__ = "forecast"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    days_to_zombie: Mapped[int | None] = mapped_column(sa.Integer)
    slope: Mapped[float] = mapped_column(sa.Float, nullable=False, default=0.0)
    level: Mapped[float] = mapped_column(sa.Float, nullable=False, default=0.0)
    signals: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    observed: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    adjusted: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    projection: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    deseasonalised: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    engine_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)


class Blast(Base):
    """Writer: stage 09."""

    __tablename__ = "blast"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    tier: Mapped[BlastTier] = mapped_column(_enum(BlastTier, "blast_t"), nullable=False)
    direct_callers: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    hop2_callers: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    affected: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    datastores: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    touches_critical: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    in_graph: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    hop_limit: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=2)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    engine_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)


class Finding(Base):
    """Narrative plus regulatory citations.

    ``generator`` is a first-class column: a template narrative is never
    presented as model output.

    Writer: stage 08.
    """

    __tablename__ = "finding"

    id: Mapped[str] = mapped_column(sa.String(32), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), nullable=False, index=True
    )
    narrative: Mapped[dict] = mapped_column(sa.JSON, nullable=False)
    generator: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    model: Mapped[str | None] = mapped_column(sa.String(64))
    regulations: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    time_to_breach_d: Mapped[int | None] = mapped_column(sa.Integer)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    engine_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)

    __table_args__ = (sa.Index("ix_finding_ep_vday", "endpoint_id", "vday"),)


class PolicySetting(Base):
    """Writer: api (admin routes)."""

    __tablename__ = "policy_setting"

    key: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(sa.JSON, nullable=False)
    updated_by: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)


# ─────────────────────────────────────────────────────────────────────────────
# Action and governance
# ─────────────────────────────────────────────────────────────────────────────
class JudgeRun(Base):
    """Writer: stage 10."""

    __tablename__ = "judge_run"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requests: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    replay_exact: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    replay_synthesised: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    replay_bodyless: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    schema_score: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False, default=0)
    latency_score: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False, default=0)
    error_score: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False, default=0)
    exposure_score: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False, default=0)
    verdict: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(sa.String(64))
    latency_delta_us: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    budget_us: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    diff_summary: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)


class Control(Base):
    """A gateway control.

    The single writer of gateway state. Stages 11 and 13 delegate here rather
    than writing Kong directly, so ``APPLIED`` means "Kong confirmed it"
    everywhere in the system and there is one rollback path.

    Writer: stage 10 actuator only.
    """

    __tablename__ = "control"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(sa.String(48), nullable=False)
    plugin_config: Mapped[dict] = mapped_column(sa.JSON, nullable=False)
    kong_plugin_id: Mapped[str | None] = mapped_column(sa.String(64))
    state: Mapped[ControlState] = mapped_column(
        _enum(ControlState, "control_state_t"), nullable=False, default=ControlState.PROPOSED
    )
    generator: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="template")
    judge_run_id: Mapped[int | None] = mapped_column(sa.ForeignKey("judge_run.id"))
    origin_stage: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False, default=10)
    error: Mapped[str | None] = mapped_column(sa.Text)
    #: For a SUPERSEDED row, the control that actually holds the plugin.
    #:
    #: Without it "superseded" is an assertion an operator has to take on
    #: trust. With it the Remediation surface can send them to the row that is
    #: enforcing the policy — which, when a SOAP operation and its containing
    #: URL resolve to one gateway route, is a control on a *different*
    #: endpoint. That is the non-obvious part, so it is recorded rather than
    #: left to be re-derived.
    superseded_by: Mapped[int | None] = mapped_column(sa.ForeignKey("control.id"))
    applied_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    reverted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    actor: Mapped[str | None] = mapped_column(sa.String(256))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)

    __table_args__ = (sa.Index("ix_control_ep_state", "endpoint_id", "state"),)


class ChangeRequest(Base):
    """Writer: stage 10."""

    __tablename__ = "change_request"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[int | None] = mapped_column(sa.ForeignKey("control.id"))
    sys_id: Mapped[str | None] = mapped_column(sa.String(64))
    number: Mapped[str | None] = mapped_column(sa.String(32))
    state: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="DRAFT")
    stub: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    payload: Mapped[dict] = mapped_column(sa.JSON, nullable=False)
    response: Mapped[dict | None] = mapped_column(sa.JSON)
    submitted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=_now, onupdate=_now,
        server_default=_NOW_SQL, nullable=False
    )


class Decommission(Base):
    """Writer: stage 11."""

    __tablename__ = "decommission"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    phase: Mapped[Phase] = mapped_column(_enum(Phase, "phase_t"), nullable=False, default=Phase.NONE)
    express: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    canary: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    canary_split: Mapped[float | None] = mapped_column(sa.Float)
    entered_vday: Mapped[int | None] = mapped_column(sa.Integer)
    phase_vday: Mapped[int | None] = mapped_column(sa.Integer)
    hold: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    hold_reason: Mapped[str | None] = mapped_column(sa.Text)

    # Phase D is the only transition no timer makes.
    #
    # Archival and a 410 are irreversible in effect, so an approver has to have
    # looked at whatever the quarantine surfaced and released it by name. Without
    # this the runner would retire an endpoint on the clock, with the hidden
    # callers it found sitting unread.
    released_for_phase_d: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False)
    released_by: Mapped[str | None] = mapped_column(sa.String(256))
    released_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    hidden_callers: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    worm_object: Mapped[str | None] = mapped_column(sa.String(512))
    worm_retain_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    certificate_id: Mapped[str | None] = mapped_column(sa.String(32))
    reverted_reason: Mapped[str | None] = mapped_column(sa.Text)


class Certificate(Base):
    """Writer: stage 11."""

    __tablename__ = "certificate"

    id: Mapped[str] = mapped_column(sa.String(32), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), nullable=False
    )
    body: Mapped[dict] = mapped_column(sa.JSON, nullable=False)
    content_hash: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    worm_object: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    approved_by: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)


# ─────────────────────────────────────────────────────────────────────────────
# Threat
# ─────────────────────────────────────────────────────────────────────────────
class Fingerprint(Base):
    """Behavioural signature, captured at Phase D before behaviour changes.

    Keyed on what the endpoint does, never on where it lives: the path is the
    attacker's variable, so including path tokens would defeat the detection.

    Writers: stage 11 (capture), stage 12 (owns the schema and reads it).

    The second legal back-edge in the DAG, and it exists for the same kind of
    reason as ``Classification.pre_zombie``. Capture has to happen inside stage
    11's Phase D, in the window after the decision to retire and before the 410
    lands: once the termination plugin is applied the endpoint stops behaving
    like itself, so a signature taken by stage 12 on its own schedule would
    describe a retired endpoint and match every other retirement rather than the
    redeployment it exists to catch. Stage 12 owns the feature set, the
    threshold and the index; stage 11 owns only the moment.
    """

    __tablename__ = "fingerprint"

    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True
    )
    minhash: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    features: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    shingles: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    captured_vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    origin_path: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    origin_method: Mapped[str] = mapped_column(sa.String(8), nullable=False, default="GET")


class Probe(Base):
    """A request against a retired endpoint. Append-only.

    Bodies are hashed, never stored: probe payloads are attacker-supplied and
    the digest is enough to correlate repeat attempts.

    Writer: honeypot service.
    """

    __tablename__ = "probe"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False, index=True)
    wall_ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_ip: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    source_asn: Mapped[str | None] = mapped_column(sa.String(128))
    geo: Mapped[str | None] = mapped_column(sa.String(64))
    method: Mapped[str] = mapped_column(sa.String(8), nullable=False)
    path_raw: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    headers: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    body_sha256: Mapped[bytes | None] = mapped_column(sa.LargeBinary)
    watermark: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    session_fp: Mapped[str | None] = mapped_column(sa.String(64))


class ResurrectionAlert(Base):
    """Writer: stage 12."""

    __tablename__ = "resurrection_alert"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    new_endpoint_id: Mapped[str] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="CASCADE"), nullable=False
    )
    origin_endpoint_id: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    origin_path: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    similarity: Mapped[float] = mapped_column(sa.Float, nullable=False)
    threshold: Mapped[float] = mapped_column(sa.Float, nullable=False)
    lsh_hit: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("new_endpoint_id", "origin_endpoint_id", name="uq_resurrection_pair"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Audit and AI decision log
# ─────────────────────────────────────────────────────────────────────────────
class AuditEntry(Base):
    """Append-only, hash chained.

    Altering or removing any historical entry invalidates every entry after it.
    Never deleted: a hash chain with a hole is not a hash chain.

    Writer: api audit ledger.
    """

    __tablename__ = "audit_entry"

    seq: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    wall_ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    actor: Mapped[str] = mapped_column(sa.String(256), nullable=False, index=True)
    action: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    target: Mapped[str | None] = mapped_column(sa.String(256), index=True)
    detail: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    prev_hash: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    entry_hash: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)


class AiDecision(Base):
    """FS AI RMF decision log.

    Every model-influenced output in the system lands here regardless of which
    stage made the call, distinguished by ``purpose``. Prompt and output are
    stored as digests plus a reasoning summary, which is what reconstructability
    requires without retaining prompts by default.

    Writers: stages 08 and 10.
    """

    __tablename__ = "ai_decision"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    endpoint_id: Mapped[str | None] = mapped_column(
        sa.ForeignKey("endpoint.id", ondelete="SET NULL")
    )
    purpose: Mapped[str] = mapped_column(sa.String(48), nullable=False)
    model: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    prompt_sha256: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    output_sha256: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    confidence: Mapped[float | None] = mapped_column(sa.Float)
    reasoning: Mapped[str | None] = mapped_column(sa.Text)
    input_tokens: Mapped[int | None] = mapped_column(sa.Integer)
    output_tokens: Mapped[int | None] = mapped_column(sa.Integer)
    latency_ms: Mapped[int | None] = mapped_column(sa.Integer)
    ok: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    error: Mapped[str | None] = mapped_column(sa.Text)
    wall_ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────────────
class PipelineRun(Base):
    """Writer: worker orchestrator."""

    __tablename__ = "pipeline_run"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    trigger: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    actor: Mapped[str | None] = mapped_column(sa.String(256))
    started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    ok: Mapped[bool | None] = mapped_column(sa.Boolean)


class StageRun(Base):
    """Writer: worker orchestrator."""

    __tablename__ = "stage_run"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        sa.ForeignKey("pipeline_run.id", ondelete="CASCADE"), nullable=False
    )
    stage: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False)
    vday: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    records: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    duration_ms: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    ok: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(sa.Text)
    detail: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)

    __table_args__ = (sa.UniqueConstraint("run_id", "stage", name="uq_stage_run"),)


class GateEvent(Base):
    """Writer: stage 14."""

    __tablename__ = "gate_event"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)
    repo: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    pr_number: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    commit_sha: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    checks: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    passed: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    wall_ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_now,
        server_default=_NOW_SQL, nullable=False)
