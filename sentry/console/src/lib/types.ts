/**
 * Response shapes, hand-written against the live control plane.
 *
 * The design calls for these to be generated from
 * contracts/openapi/sentry-api.yaml. They are not, and that is a divergence
 * worth stating rather than hiding: these were written by reading the router
 * source and the live responses, so a route whose shape changes will break a
 * surface at runtime instead of at build time. Only the fields the console
 * actually renders are declared, so a field added server-side is not a
 * compilation error here.
 */

export interface EstateItem {
  id: string;
  method: string;
  path: string;
  service: string;
  team: string | null;
  criticality: string;
  auth: string;
  tls_version: string | null;
  rate_limited: boolean;
  data_classes: string[];
  last_call_vday: number | null;
  retired: boolean;
  lifecycle: string | null;
  governance: string | null;
  confidence: string | null;
  pre_zombie: boolean;
  cdri: number | null;
  tier: string | null;
  time_to_breach_d: number | null;
}

export interface Estate {
  items: EstateItem[];
  next_cursor: string | null;
}

export interface Risk {
  items: {
    endpoint_id: string;
    method: string;
    path: string;
    score: number;
    tier: string;
    parts: { key: string; weight: number; value: number; contribution: number }[];
    weights_version: number;
    time_to_breach: { days: number | null; basis: string; factors: unknown };
  }[];
}

export interface Classification {
  vday: number;
  matrix: { lifecycle: string; governance: string; n: number }[];
  confidence: Record<string, number>;
  shadow_reliable: boolean;
}

export interface Discovery {
  vday: number;
  sources: {
    source: string;
    endpoints: number;
    observations_24v: number;
    exclusive: number;
    healthy: boolean;
  }[];
  shadow_reliable: boolean;
  shadow_count: number;
}

export interface Correlation {
  sightings: number;
  endpoints: number;
  dedup_ratio: number;
  ownership: { resolved_by: Record<string, number>; unreachable: number };
  shadow_reliable: boolean;
  window_vdays: number;
}

export interface Behaviour {
  fitted: boolean;
  fitted_on: number;
  min_fit_endpoints: number;
  /** Present when the model did not fit. Rendered instead of a zero verdict. */
  withheld: string | null;
  /** null when the model did not fit: nothing was scored, so nothing is zero. */
  flagged: number | null;
  scored: number | null;
  patterns: Record<string, number>;
  excluded_insufficient_history: number;
  items: {
    endpoint_id: string;
    score: number;
    isolation_depth: number | null;
    patterns: string[];
  }[];
}

export interface Forecast {
  flagged: number;
  active: number;
  flagged_ratio: number;
  items: {
    endpoint_id: string;
    method: string;
    path: string;
    days_to_zombie: number | null;
    slope: number | null;
    signals: string[];
    deseasonalised: boolean;
  }[];
}

export interface Findings {
  generators: Record<string, number>;
  items: {
    id: string;
    endpoint_id: string;
    method: string;
    path: string;
    generator: string;
    model: string | null;
    narrative: Record<string, unknown>;
    regulations: string[];
    time_to_breach_d: number | null;
    vday: number;
  }[];
}

export interface Threat {
  honeypots_active: number;
  probes_total: number;
  unique_sources: number;
  fingerprints: number;
  threshold: number;
  legal_signoff: { reference: string | null; signed: boolean };
  probes: {
    id: number;
    at: string;
    vday: number;
    endpoint_id: string;
    source_ip: string;
    source_asn: string | null;
    watermark: string;
  }[];
  alerts: {
    new_endpoint_id: string;
    origin_path: string;
    similarity: number;
    threshold: number;
    lsh_hit: boolean;
    vday: number;
  }[];
}

export interface ZeroTrust {
  distribution: Record<string, number>;
  gaps: Record<string, number>;
  items: {
    endpoint_id: string;
    method: string;
    path: string;
    satisfied: number;
    of: number;
    priority: number;
    controls: {
      key: string;
      ok: boolean;
      current: string | null;
      remedy: string | null;
      requires_migration: boolean;
    }[];
  }[];
}
