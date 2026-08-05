"""Response models — the declared shape of every route's 200.

The design specifies that `console/src/lib/api.ts` is generated from the OpenAPI
contract, and it was hand-written instead. That divergence cost two defects in
one session: the Operations view declared `/pipeline` as `runs: [...]` on an
endpoint that returns one `run`, and the Audit view declared `message` where the
server sends `reason`. Neither failed — the fetch returned 200, the query
reported success, and `tsc` checked an assertion rather than a contract.

Generation was impossible before this file existed. Every handler returned a
plain `dict`, so FastAPI emitted `{"type": "object"}` with no properties for 47
of 53 operations, and a generator over that produces `Record<string, unknown>` —
strictly worse than the hand-written types it would replace.

**Declared, not enforced.** These are attached with
`responses={200: {"model": ...}}` rather than `response_model=`, and the
difference is not stylistic. `response_model` *filters* a response to its
declared fields: a model missing one key silently deletes that key from a live
response, and the first sign of it is a console surface going blank. The
`responses=` form documents the schema in OpenAPI and leaves the payload
untouched — verified in `api/tests/test_contracts.py`, which asserts both that
the schema carries properties and that an undeclared field still reaches the
client.

**Derived from observation.** These 53 handlers have been returning dicts since
they were written, and the only trustworthy account of what they return is what
they return. Each model was generated from a live payload and then corrected
where a field was observed only as `null` — a single sample proves a field is
nullable and says nothing about what it holds otherwise, so those types were
read off the handler and the ORM column rather than guessed at.

That makes this file a claim that has to be re-checked rather than trusted:
`test_every_declared_model_matches_a_live_payload` validates each route's real
response against its model, and `tools/check_console_contract.py` compares the
console's own declarations against the same payloads.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class _Contract(BaseModel):
    """Base for every response model.

    `extra="allow"` so a handler that returns more than is declared here is
    described incompletely rather than described wrongly — and, with the
    `responses=` attachment above, still returns everything it returned before.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class AuditItemsItem(_Contract):

    seq: int
    wall_ts: str
    vday: int
    actor: str
    action: str
    target: str | None = None
    detail: dict
    entry_hash: str


class Audit(_Contract):

    items: list[AuditItemsItem]
    next_cursor: int | None = None


class AuditVerify(_Contract):

    ok: bool
    entries: int
    broken_at: int | None = None
    reason: str | None = None


class BaselineConfidence(_Contract):

    PROVISIONAL: int
    CONFIRMED: int


class BaselineGrowthItem(_Contract):

    vday: int
    n: int


class Baseline(_Contract):

    vday: int
    registry_size: int
    confidence: BaselineConfidence
    growth: list[BaselineGrowthItem]
    verdicts_permitted: bool
    decommission_permitted: int


class BaselineEndpointIdSeriesSeriesItem(_Contract):

    vday: int
    calls: int
    errors: int
    p95_latency_us: int | None = None


class BaselineEndpointIdSeries(_Contract):

    endpoint_id: str
    series: list[BaselineEndpointIdSeriesSeriesItem]


class BehaviourPatterns(_Contract):

    INSUFFICIENT_HISTORY: int


class BehaviourItemsItem(_Contract):

    endpoint_id: str
    score: float
    isolation_depth: float | None = None
    patterns: list[str]


class Behaviour(_Contract):

    fitted: bool
    fitted_on: int
    min_fit_endpoints: int
    withheld: str | None = None
    flagged: int | None = None
    scored: int | None = None
    patterns: dict[str, int]
    excluded_insufficient_history: int
    items: list[BehaviourItemsItem]


class ClassificationMatrixItem(_Contract):

    lifecycle: str
    governance: str
    n: int


class Classification(_Contract):

    vday: int
    matrix: list[ClassificationMatrixItem]
    confidence: dict[str, int]
    shadow_reliable: bool


class ClassificationEndpointIdTraceQuestion(_Contract):

    q: int
    question: str
    answer: int | bool
    source: str


class ClassificationEndpointIdTraceRule(_Contract):

    rule: str
    applied: str
    result: str | bool


class ClassificationEndpointId(_Contract):

    endpoint_id: str
    lifecycle: str
    governance: str
    confidence: str
    severity_bump: bool
    pre_zombie: bool
    trace: list[ClassificationEndpointIdTraceQuestion | ClassificationEndpointIdTraceRule]
    vday: int
    engine_version: str


class Clock(_Contract):

    vday: int
    scale_seconds: int
    paused: bool
    epoch_wall: str
    real_time: bool


class CorrelationOwnership(_Contract):

    resolved_by: dict[str, int]
    unreachable: int


class Correlation(_Contract):

    sightings: int
    endpoints: int
    dedup_ratio: float
    ownership: CorrelationOwnership
    shadow_reliable: bool
    window_vdays: int


class CorrelationEndpointIdOwnershipLadderItem(_Contract):

    rung: str
    result: str


class CorrelationEndpointIdOwnership(_Contract):

    endpoint_id: str
    owner_email: str | None = None
    owner_team: str | None = None
    resolved_by: str
    confidence: float
    reachable: bool
    escalation: str | None = None
    ladder: list[CorrelationEndpointIdOwnershipLadderItem]


class DecommissionItemsItemHidden_CallersItem(_Contract):

    service: str
    ip: str
    first_vday: int
    calls: int


class DecommissionItemsItem(_Contract):

    endpoint_id: str
    method: str
    path: str
    phase: str
    express: bool
    canary: bool
    canary_split: float | None = None
    entered_vday: int
    phase_vday: int
    hold: bool
    hold_reason: str | None = None
    hidden_callers: list[DecommissionItemsItemHidden_CallersItem]
    worm_object: str | None = None
    worm_retain_until: str | None = None
    certificate_id: str | None = None


class Decommission(_Contract):

    vday: int
    by_phase: dict[str, int]
    items: list[DecommissionItemsItem]


class DecommissionEndpointIdWormVerify(_Contract):

    object: str
    version_id: str
    lock_mode: str
    retain_until: str
    verified: bool
    delete_refused_with: str
    detail: str


class DiscoverySourcesItem(_Contract):

    source: str
    endpoints: int
    observations_24v: int
    exclusive: int
    healthy: bool


class Discovery(_Contract):

    vday: int
    sources: list[DiscoverySourcesItem]
    shadow_reliable: bool
    shadow_count: int


class EstateItemsItem(_Contract):

    id: str
    method: str
    path: str
    service: str
    team: str | None = None
    criticality: str
    auth: str
    tls_version: str | None = None
    rate_limited: bool
    data_classes: list[str]
    last_call_vday: int | None = None
    retired: bool
    lifecycle: str | None = None
    governance: str | None = None
    confidence: str | None = None
    pre_zombie: bool
    cdri: float | None = None
    tier: str | None = None
    time_to_breach_d: int | None = None


class Estate(_Contract):

    items: list[EstateItemsItem]
    next_cursor: str | None = None


class EstateEndpointIdService(_Contract):

    id: str
    name: str
    team: str | None = None
    criticality: str


class EstateEndpointIdClassification(_Contract):

    lifecycle: str
    governance: str
    confidence: str
    pre_zombie: bool
    severity_bump: bool
    trace: list[ClassificationEndpointIdTraceQuestion | ClassificationEndpointIdTraceRule]


class EstateEndpointIdCdriPartsItem(_Contract):

    key: str
    label: str
    r: float
    w: float
    contribution: float


class EstateEndpointIdCdriTime_To_Breach(_Contract):

    days: int | None = None
    basis: str
    factors: list[str]


class EstateEndpointIdCdri(_Contract):

    score: float
    tier: str
    parts: list[EstateEndpointIdCdriPartsItem]
    weights_version: int
    time_to_breach: EstateEndpointIdCdriTime_To_Breach


class EstateEndpointIdAnomaly(_Contract):

    flag: bool
    score: float
    patterns: list
    features: dict[str, float]


class EstateEndpointIdForecast(_Contract):

    days_to_zombie: int | None = None
    slope: float
    signals: dict[str, float]
    deseasonalised: bool


class EstateEndpointIdBlastAffectedItem(_Contract):

    service_id: str
    name: str
    hop: int
    calls: int
    criticality: str


class EstateEndpointIdBlast(_Contract):

    tier: str
    direct_callers: int
    hop2_callers: int
    touches_critical: bool
    in_graph: bool
    hop_limit: int
    affected: list[EstateEndpointIdBlastAffectedItem]


class EstateEndpointIdOwnershipLadderItem(_Contract):

    rung: str
    result: str


class EstateEndpointIdOwnership(_Contract):

    owner_email: str | None = None
    reachable: bool
    confidence: float
    resolved_by: str
    escalation: str | None = None
    ladder: list[EstateEndpointIdOwnershipLadderItem]


class EstateEndpointId(_Contract):

    id: str
    method: str
    path: str
    service: EstateEndpointIdService | None = None
    auth: str
    tls_version: str | None = None
    rate_limited: bool
    data_classes: list[str]
    deprecated: bool
    internet_reachable: bool
    retired: bool
    honeypot_active: bool
    first_vday: int
    last_call_vday: int | None = None
    total_calls: int
    sources: list[str]
    classification: EstateEndpointIdClassification | None = None
    cdri: EstateEndpointIdCdri | None = None
    anomaly: EstateEndpointIdAnomaly | None = None
    forecast: EstateEndpointIdForecast | None = None
    blast: EstateEndpointIdBlast | None = None
    ownership: EstateEndpointIdOwnership | None = None


class FindingsGenerators(_Contract):

    template: int


class FindingsItemsItemNarrative(_Contract):

    summary: str
    technical: str
    action: str


class FindingsItemsItemRegulationsItem(_Contract):

    framework: str
    clause: str
    requirement: str
    status: str
    evidence: str


class FindingsItemsItem(_Contract):

    id: str
    endpoint_id: str
    method: str
    path: str
    generator: str
    model: str | None = None
    narrative: FindingsItemsItemNarrative
    regulations: list[FindingsItemsItemRegulationsItem]
    time_to_breach_d: int | None = None
    vday: int


class Findings(_Contract):

    generators: FindingsGenerators
    items: list[FindingsItemsItem]


class FindingsFrameworks(_Contract):

    frameworks: list[str]
    violations: dict


class ForecastItemsItem(_Contract):

    endpoint_id: str
    method: str
    path: str
    days_to_zombie: int
    slope: float
    signals: dict[str, float]
    deseasonalised: bool


class Forecast(_Contract):

    flagged: int
    active: int
    flagged_ratio: float
    items: list[ForecastItemsItem]


class ForecastEndpointId(_Contract):

    endpoint_id: str
    days_to_zombie: int | None = None
    slope: float
    level: float
    signals: dict[str, float]
    deseasonalised: bool
    observed: list[float]
    adjusted: list[float]
    projection: list[float]


class GateEventsEventsItemChecksItem(_Contract):

    name: str
    passed: bool
    severity: str
    file: str
    line: int


class GateEventsEventsItem(_Contract):

    id: int
    repo: str
    pr: int
    sha: str
    passed: bool
    checks: list[GateEventsEventsItemChecksItem]
    at: str


class GateEvents(_Contract):

    events: list[GateEventsEventsItem]


class ImpactEndpointIdAffectedItem(_Contract):

    service_id: str
    name: str
    hop: int
    calls: int
    criticality: str


class ImpactEndpointIdRetirement_Path(_Contract):

    express: bool
    canary: bool
    phases: list[str]
    estimated_vdays: int
    throttle_exempt: bool


class ImpactEndpointId(_Contract):

    endpoint_id: str
    tier: str
    hop_limit: int
    direct_callers: int
    hop2_callers: int
    touches_critical: bool
    in_graph: bool
    datastores: list
    affected: list[ImpactEndpointIdAffectedItem]
    retirement_path: ImpactEndpointIdRetirement_Path


class OperationsSiem(_Contract):

    host: str
    format: str
    configured: bool
    port: int
    sent: int
    spooled: int
    dropped: int
    failures: int
    recent: list


class OperationsGate_EventsItemChecksItem(_Contract):

    name: str
    passed: bool
    severity: str
    file: str
    line: int


class OperationsGate_EventsItem(_Contract):

    repo: str
    pr: int
    sha: str
    passed: bool
    checks: list[OperationsGate_EventsItemChecksItem]
    at: str


class OperationsSummarySiem(_Contract):

    host: str
    format: str
    configured: bool


class Operations(_Contract):

    vday: int
    scan_interval_vhours: int
    scheduler_enabled: bool
    siem: OperationsSummarySiem
    stages: dict
    gate_events: list[OperationsGate_EventsItem]


class OperationsLeaderboardTeamsItem(_Contract):

    team: str
    debt: float
    raw: float
    trend: str | None = None
    endpoints: int
    zombies: int
    orphaned: int
    pre_zombie: int
    critical_score: float
    ownership_confidence: float


class OperationsLeaderboard(_Contract):

    teams: list[OperationsLeaderboardTeamsItem]


class PipelineRun(_Contract):

    id: int
    trigger: str
    started_at: str
    finished_at: str | None = None
    ok: bool | None = None


class PipelineStagesItem(_Contract):

    stage: int
    name: str
    depends_on: list
    ok: bool | None = None
    records: int
    duration_ms: int
    error: str | None = None


class Pipeline(_Contract):

    vday: int
    run: PipelineRun | None = None
    stages: list[PipelineStagesItem]
    order: list[int]


class PolicySettingsSettingsResurrection_Threshold(_Contract):

    value: float


class PolicySettingsSettingsBlast_Hop_Limit(_Contract):

    value: int


class PolicySettingsSettingsScan_Interval_Vhours(_Contract):

    value: int


class PolicySettingsSettingsExpress_Sunset_Vdays(_Contract):

    value: int


class PolicySettingsSettingsAnomaly_Contamination(_Contract):

    value: float


class PolicySettingsSettingsHoneypot_Legal_Signoff(_Contract):

    reference: str
    signed: bool


class PolicySettingsSettings(_Contract):

    latency_budget_us: dict[str, int]
    tier_bounds: dict[str, float]
    resurrection_threshold: PolicySettingsSettingsResurrection_Threshold
    blast_hop_limit: PolicySettingsSettingsBlast_Hop_Limit
    scan_interval_vhours: PolicySettingsSettingsScan_Interval_Vhours
    express_sunset_vdays: PolicySettingsSettingsExpress_Sunset_Vdays
    anomaly_contamination: PolicySettingsSettingsAnomaly_Contamination
    honeypot_legal_signoff: PolicySettingsSettingsHoneypot_Legal_Signoff


class PolicySettings(_Contract):

    settings: PolicySettingsSettings
    warnings: list


class PolicyWeightsHistoryItem(_Contract):

    version: int
    weights: dict[str, float]
    note: str
    created_by: str
    created_at: str


class PolicyWeights(_Contract):

    version: int
    weights: dict[str, float]
    sum: float
    defaults: dict[str, float]
    history: list[PolicyWeightsHistoryItem]


class RemediationItemsItemControlsItem(_Contract):

    id: int
    kind: str
    state: str
    generator: str
    kong_plugin_id: str | None = None


class RemediationItemsItem(_Contract):

    endpoint_id: str
    method: str
    path: str
    score: float
    tier: str
    time_to_breach_d: int | None = None
    controls: list[RemediationItemsItemControlsItem]
    applied: int


class Remediation(_Contract):

    items: list[RemediationItemsItem]


class RemediationEndpointIdControlsItemPlugin_ConfigConfig(_Contract):

    status_code: int
    message: str


class RemediationEndpointIdControlsItemPlugin_Config(_Contract):

    name: str
    config: RemediationEndpointIdControlsItemPlugin_ConfigConfig


class RemediationEndpointIdControlsItem(_Contract):

    id: int
    kind: str
    state: str
    generator: str
    plugin_config: dict
    kong_plugin_id: str | None = None
    origin_stage: int
    error: str | None = None
    actor: str | None = None
    judge: dict | None = None


class RemediationEndpointIdChange_Request(_Contract):

    number: str | None = None
    state: str
    sys_id: str | None = None
    stub: bool


class RemediationEndpointId(_Contract):

    endpoint_id: str
    controls: list[RemediationEndpointIdControlsItem]
    change_request: RemediationEndpointIdChange_Request | None = None


class RiskItemsItemPartsItem(_Contract):

    key: str
    label: str
    r: float
    w: float
    contribution: float


class RiskItemsItemTime_To_Breach(_Contract):

    days: int | None = None
    basis: str
    factors: list[str]


class RiskItemsItem(_Contract):

    endpoint_id: str
    method: str
    path: str
    score: float
    tier: str
    parts: list[RiskItemsItemPartsItem]
    weights_version: int
    time_to_breach: RiskItemsItemTime_To_Breach


class Risk(_Contract):

    items: list[RiskItemsItem]


class SystemTiers(_Contract):

    HIGH: int
    CRITICAL: int


class System(_Contract):

    org: str
    vday: int
    endpoints: int
    retired: int
    lifecycle: dict[str, int]
    governance: dict[str, int]
    tiers: SystemTiers
    mean_cdri: float


class ThreatLegal_Signoff(_Contract):

    reference: str | None = None
    signed: bool


class ThreatProbesItem(_Contract):

    id: int
    at: str
    vday: int
    endpoint_id: str
    source_ip: str
    source_asn: str | None = None
    watermark: str


class ThreatAlertsItem(_Contract):

    new_endpoint_id: str
    origin_path: str
    similarity: float
    threshold: float
    lsh_hit: bool
    vday: int


class Threat(_Contract):

    honeypots_active: int
    probes_total: int
    unique_sources: int
    fingerprints: int
    threshold: float
    legal_signoff: ThreatLegal_Signoff
    probes: list[ThreatProbesItem]
    alerts: list[ThreatAlertsItem]


class ThreatFingerprintEndpointIdFeatures(_Contract):

    method: str
    response_fields: list
    data_classes: list[str]
    callers: list[str]
    hour_shape: list[int]
    auth: str
    auth_missing_band: str
    req_size_band: str
    resp_size_band: str
    observations: int
    has_schema: bool


class ThreatFingerprintEndpointId(_Contract):

    endpoint_id: str
    captured_vday: int
    origin_path: str
    origin_method: str
    features: ThreatFingerprintEndpointIdFeatures
    shingles: list[str]
    shingle_count: int


class ThreatProbesProbesItemHeaders(_Contract):

    Accept: str
    Connection: str
    User_Agent: str = Field(default=None, alias="User-Agent")
    Via: str
    X_Forwarded_For: str = Field(default=None, alias="X-Forwarded-For")
    X_Forwarded_Host: str = Field(default=None, alias="X-Forwarded-Host")
    X_Forwarded_Path: str = Field(default=None, alias="X-Forwarded-Path")
    X_Forwarded_Port: str = Field(default=None, alias="X-Forwarded-Port")
    X_Forwarded_Proto: str = Field(default=None, alias="X-Forwarded-Proto")
    X_Kong_Request_Id: str = Field(default=None, alias="X-Kong-Request-Id")
    X_Real_Ip: str = Field(default=None, alias="X-Real-Ip")


class ThreatProbesProbesItem(_Contract):

    id: int
    at: str
    vday: int
    endpoint_id: str
    method: str
    path_raw: str
    source_ip: str
    source_asn: str | None = None
    geo: str | None = None
    headers: ThreatProbesProbesItemHeaders
    watermark: str
    session_fp: str
    body_sha256: str | None = None


class ThreatProbes(_Contract):

    count: int
    probes: list[ThreatProbesProbesItem]


class ThreatResurrectionScanAlertsItem(_Contract):

    new_endpoint_id: str
    new_endpoint: str
    origin_endpoint_id: str
    origin_path: str
    similarity: float
    threshold: float
    lsh_hit: bool
    vday: int
    created_at: str


class ThreatResurrectionScan(_Contract):

    fingerprints: int
    threshold: float
    alerts: list[ThreatResurrectionScanAlertsItem]


class ZerotrustItemsItemControlsItem(_Contract):

    key: str
    ok: bool
    current: str | None = None
    remedy: str | None = None
    requires_migration: bool


class ZerotrustItemsItem(_Contract):

    endpoint_id: str
    method: str
    path: str
    satisfied: int
    of: int
    priority: float
    controls: list[ZerotrustItemsItemControlsItem]


class Zerotrust(_Contract):

    distribution: dict[str, int]
    gaps: dict[str, int]
    items: list[ZerotrustItemsItem]


class ZerotrustEndpointIdControlsItem(_Contract):

    key: str
    ok: bool
    current: str | None = None
    remedy: str | None = None
    requires_migration: bool


class ZerotrustEndpointId(_Contract):

    endpoint_id: str
    satisfied: int
    of: int
    priority: float
    controls: list[ZerotrustEndpointIdControlsItem]
    method: str
    path: str


# ── mutating routes ─────────────────────────────────────────────────────────
# Declared from the handlers' own return statements rather than from a sampled
# response. These routes change state — enrolling a decommission, applying a
# plugin, advancing a phase — and calling each one to observe its shape would
# have meant performing every one of those actions against a live estate to
# write down what they answer with.


class RemediationEndpointIdApply(_Contract):

    control_id: int
    state: str
    kong_plugin_id: str | None = None
    #: Set when the requested control was not the one applied: this policy was
    #: already enforced, so that row was closed out instead of duplicated.
    superseded_control_id: int | None = None


class RemediationControlControlIdRevert(_Contract):

    control_id: int
    state: str
    #: Other controls that claimed the same plugin. One plugin is one piece of
    #: enforcement, so removing it reverts all of them.
    also_reverted: list[int] = []


class DecommissionEndpointIdEnrol(_Contract):

    endpoint_id: str
    phase: str
    express: bool
    canary: bool


class DecommissionEndpointIdAdvance(_Contract):

    endpoint_id: str
    from_phase: str
    released_by: str
    note: str


class DecommissionEndpointIdHold(_Contract):

    endpoint_id: str
    hold: bool
    reason: str | None = None


class ThreatRescan(_Contract):
    """`{"vday", "alerts_raised", **outcome.detail}` — the stage's own detail is
    spread in, so the declared fields are the envelope and the rest arrives as
    extras."""

    vday: int
    alerts_raised: int


class ZerotrustHardenPreview(_Contract):
    """Preview and apply share one handler and differ in what it returns:
    a preview carries `would_apply`, an apply carries `controls`, and a run
    blocked before either carries `blocked`. All three are optional here for
    that reason."""

    endpoint_id: str
    posture: dict
    would_apply: list[dict] | None = None
    controls: list[dict] | None = None
    blocked: str | None = None


class ZerotrustEndpointIdHarden(ZerotrustHardenPreview):
    pass


class GateCheckResult(_Contract):

    passed: bool
    checks: list[dict]


class OperationsScanStagesItem(_Contract):

    stage: int
    records: int
    duration_ms: int
    error: str | None = None
    skipped: str | None = None


class OperationsScan(_Contract):

    run_id: int
    stages: list[OperationsScanStagesItem]


class ClockSet(_Contract):

    vday: int
    previous: int


class ClockPause(_Contract):

    vday: int
    paused: bool


class ClockResume(ClockPause):
    pass


class PolicyWeightsReset(_Contract):

    version: int
    weights: dict[str, float]


class PolicySettingsKey(_Contract):

    key: str
    value: object = None


# ── the live capture stream ─────────────────────────────────────────────────
class LiveHealthItem(_Contract):
    """One component, judged on evidence it produced rather than on a heartbeat.

    A sensor that reports healthy while capturing nothing is the exact failure
    this product exists to catch, so liveness is derived from the newest
    observation each source wrote — not from anything the component says about
    itself.
    """

    component: str
    state: str
    last_vday: int | None = None
    vdays_behind: int | None = None


class LivePipeline(_Contract):

    run_id: int | None = None
    trigger: str | None = None
    started_at: object = None
    ok: bool | None = None
    running: bool
    stages_done: int
    stages_total: int


class Live(_Contract):
    """Polled every couple of seconds; reads Redis, not a row count.

    `source` is load-bearing. `observed` carries zeros both when nothing was
    captured and when the cache could not be asked, and those are opposite
    facts about the estate — one is quiet, the other is blind. This field is how
    the console tells them apart, and dropping it would let a Redis outage
    render as a clean estate.
    """

    vday: int
    scale_seconds: int
    observed: dict[str, int]
    source: str
    counters: dict[str, int]
    health: list[LiveHealthItem]
    pipeline: LivePipeline
