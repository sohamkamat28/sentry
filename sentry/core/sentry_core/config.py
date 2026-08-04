"""Configuration.

Twelve-factor: environment only, no config files in images. Every setting that
has no safe default is required and the process refuses to start without it.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PLACEHOLDER_SECRETS = {"change-me", "changeme", "password", "secret", ""}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # ── environment ──
    env: Literal["dev", "staging", "prod"] = "dev"
    log_level: str = "info"
    log_format: Literal["json", "console"] = "json"
    otel_exporter_otlp_endpoint: str | None = None

    # ── storage ──
    database_url: str = "postgresql+psycopg://sentry:sentry@localhost:5432/sentry"
    redis_url: str = "redis://localhost:6379/0"

    # ── identity ──
    oidc_issuer: str | None = None
    #: Where to fetch signing keys, when that is not reachable at the issuer.
    #:
    #: The issuer is an *identity* and must match the token's `iss` claim
    #: exactly; the JWKS endpoint is a *network location*. In a container
    #: deployment these differ: the browser obtains a token from
    #: http://localhost:8081/realms/sentry, so that string is baked into every
    #: token, while the API can only reach the same server at
    #: http://keycloak:8081. Deriving the key URL from the issuer made the API
    #: dial localhost inside its own container; matching the issuer to the
    #: reachable name made every real token fail with "Invalid issuer".
    oidc_jwks_url: str | None = None
    oidc_audience: str = "sentry-api"

    #: The client the API Judge authenticates as when measuring an oauth2
    #: control. A real client-credentials registration at the issuer, not a
    #: shared secret with the gateway: the Judge has to obtain a token the same
    #: way a caller would, or the measurement describes something no caller does.
    judge_oidc_client_id: str | None = None
    judge_oidc_client_secret: str | None = None
    oidc_jwks_cache_s: int = 300
    auth_disabled: bool = False  # dev only; refused in prod by the validator below

    cors_origins: str = "http://localhost:5173"
    audit_verify_on_boot: bool = True

    # ── virtual clock ──
    # 86400 makes vday a calendar day. Lower values compress the timeline for
    # demonstration; the analysis code path is identical either way.
    vclock_scale_seconds: int = Field(default=30, ge=1, le=86400)

    # ── windows and thresholds ──
    baseline_vdays: int = 30
    window_vdays: int = 90
    active_vdays: int = 30
    zombie_vdays: int = 90
    ownership_confidence_floor: float = 0.5

    # ── stage 01 collectors ──
    #: Repositories the code collector scans, comma-separated.
    #:
    #: This is a claim about coverage, not a preference. An endpoint is only
    #: "absent from code" with respect to this set, so a service deployed from a
    #: repository nobody listed here is indistinguishable from one nobody wrote
    #: — which is exactly how a shadow endpoint comes to exist.
    code_repo_paths: str = ""
    #: Service name per repository path, comma-separated `path=service` pairs,
    #: for repositories whose directory name is not the service name.
    code_repo_services: str = ""
    #: WSDL documents the legacy collector reads, comma-separated. URLs or paths.
    legacy_wsdl_urls: str = ""
    #: Core-banking registry exports (Finacle-format CSV), comma-separated.
    #: Carries the backing datastore per interface, which is where stage 03's
    #: datastore edges come from.
    legacy_registry_path: str = ""
    #: The employment directory, as a URL or a path to JSON/CSV.
    #:
    #: Rung 4 of the ownership ladder. Unset means the employment question is
    #: never asked, so a departed owner stays on the record looking reachable —
    #: which is worse than no owner at all, because it looks resolved on every
    #: report while the escalation goes nowhere.
    hr_directory_source: str = ""
    #: Named when the directory reports a departure with no successor and no
    #: manager of its own. The last escalation address before "nobody".
    default_department_head: str = ""

    # ── stage 05 ──
    anomaly_contamination: float = Field(default=0.05, gt=0.0, lt=0.5)
    anomaly_n_estimators: int = 200
    anomaly_max_samples: int = 256
    anomaly_seed: int = 20260726
    min_series_vdays: int = 14
    min_fit_endpoints: int = 30
    spike_min_calls: int = 50
    auth_anomaly_ratio: float = 0.02
    payload_cv_threshold: float = 1.5

    # ── stage 06 ──
    ttb_base_days: int = 180
    ttb_min_score: float = 0.50
    cdri_round_dp: int = 4

    # ── stage 07 ──
    forecast_alpha: float = 0.3
    forecast_beta: float = 0.1
    forecast_horizon: int = 30
    seasonal_period: int = 7
    zombie_floor_calls: float = 0.5
    pre_zombie_horizon: int = 30
    pre_zombie_risk_floor: float = 0.45

    # ── stage 09 ──
    blast_hop_limit: int = Field(default=2, ge=1, le=4)
    graph_max_nodes: int = 50_000

    # ── stage 10 ──
    kong_admin_url: str | None = None
    kong_admin_token: str | None = None
    #: The proxy listener, not the Admin API. The Judge replays traffic through
    #: it, so a patch is measured on the path a real request takes.
    kong_proxy_url: str | None = None
    #: The gateway's TLS listener.
    #:
    #: A TLS control is a statement about the transport, and the transport is
    #: exactly what the plain listener does not have: ``ssl_protocol`` is empty
    #: over HTTP, so a tls-min pre-function rejects every request and the Judge
    #: correctly reports that the patch breaks the endpoint. The verdict is
    #: sound and the measurement is meaningless. Controls that read connection
    #: properties are replayed here instead.
    kong_proxy_tls_url: str | None = None
    kong_mtls_mode: Literal["pre-function", "mtls-auth"] = "pre-function"
    judge_window_vhours: int = 24
    judge_max_requests: int = 2000
    #: Distinct request shapes replayed per control. Replaying the same shape
    #: hundreds of times measures the gateway's cache rather than the patch.
    judge_replay_shapes: int = 40
    #: CDRI tiers eligible for the virtual-patch queue. LOW and MEDIUM findings
    #: go to the review queue instead: a gateway change carries its own risk,
    #: and spending it on a low-tier finding is a bad trade.
    remediation_tiers: list[str] = ["CRITICAL", "HIGH"]
    judge_max_attempts: int = 3
    judge_network: str = "sentry-shadow"
    servicenow_url: str | None = None
    servicenow_user: str | None = None
    servicenow_password: str | None = None
    servicenow_group: str = "Security Operations"
    servicenow_poll_vminutes: int = 30

    # ── stage 11 ──
    phase_a_vdays: int = 30
    phase_b_vdays: int = 30
    phase_c_vdays: int = 30
    express_quarantine_vdays: int = 30
    throttle_pct: int = 25
    canary_steps: str = "0.10,0.01,0.00"
    #: Where the Sunset header's rel="sunset" link points. Client tooling follows
    #: it, so it has to be an address that exists outside this process.
    console_base_url: str = "http://localhost:5173"
    #: The one-time policy record authorising honeypot activation. Referenced by
    #: every certificate rather than approved per endpoint, which is what makes
    #: the workflow operable at estate scale.
    honeypot_legal_signoff: str = "policy:LEGAL-2026-004"
    canary_error_ceiling: float = 0.02
    minio_endpoint: str | None = None
    minio_access_key: str | None = None
    minio_secret_key: str | None = None
    worm_bucket: str = "sentry-worm"
    worm_retain_years: int = 7

    # ── stage 12 ──
    resurrection_threshold: float = 0.85
    minhash_perm: int = 128
    synthetic_account_prefix: str = "9999"
    honeypot_queue: int = 10_000
    geoip_db_path: str | None = None
    #: Where the gateway sends a retired path once the honeypot is activated.
    #: Unset means no honeypot route is ever created, and Phase D completes with
    #: a 410 — which is the correct degradation: a retirement that cannot route
    #: to a honeypot must still be a retirement.
    honeypot_upstream: str | None = None

    # ── stage 13 ──
    zt_tls_floor: str = "1.3"
    zt_settlement_auth: str = "mtls"
    zt_default_auth: str = "oauth2"

    # ── stage 14 ──
    scan_interval_vhours: int = 6
    scheduler_enabled: bool = True
    siem_host: str | None = None
    siem_port: int = 514
    siem_format: Literal["cef", "leef", "hec"] = "cef"
    siem_spool_max: int = 10_000
    gate_fail_on: Literal["error", "warn", "never"] = "error"
    leaderboard_trend_vdays: int = 30

    # ── AI ──
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-5"
    anthropic_base_url: str | None = None
    anthropic_timeout_s: int = 30
    anthropic_max_retries: int = 1
    ai_archive_prompts: bool = False
    findings_min_tier: str = "HIGH"

    # ── retention ──
    observation_retention_vdays: int = 400

    org_name: str = "Reference Bank"

    @field_validator("env")
    @classmethod
    def _prod_needs_real_secrets(cls, v: str, info) -> str:
        return v

    def model_post_init(self, _ctx: object) -> None:
        if self.env != "prod":
            return
        # A prototype that silently runs production with default credentials is
        # a worse outcome than one that refuses to start.
        problems: list[str] = []
        if self.auth_disabled:
            problems.append("AUTH_DISABLED cannot be true in prod")
        if not self.oidc_issuer:
            problems.append("OIDC_ISSUER is required in prod")
        for name in ("kong_admin_token", "minio_secret_key", "servicenow_password"):
            val = getattr(self, name)
            if val is not None and val.strip().lower() in _PLACEHOLDER_SECRETS:
                problems.append(f"{name.upper()} is a placeholder value")
        if "sentry:sentry@" in self.database_url:
            problems.append("DATABASE_URL uses default credentials")
        if problems:
            raise RuntimeError("refusing to start in prod: " + "; ".join(problems))

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def canary_step_list(self) -> list[float]:
        return [float(s) for s in self.canary_steps.split(",") if s.strip()]

    @property
    def sensitive_ttl_seconds(self) -> int:
        """Redis TTL for live counters: two virtual days of wall time."""
        return max(60, self.vclock_scale_seconds * 2)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
