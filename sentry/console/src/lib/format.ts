/**
 * Formatting.
 *
 * The rule the whole console rests on: a value that is not known renders as an
 * em dash, never as zero. Zero is a measurement; absence is not. Collapsing the
 * two is how a sensor outage comes to look like an idle estate, and it is the
 * defect this system spends most of its code refusing to commit.
 */

export const ABSENT = "—";

export function num(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return ABSENT;
  return value.toLocaleString("en-GB");
}

export function score(value: number | null | undefined, dp = 3): string {
  if (value === null || value === undefined || Number.isNaN(value)) return ABSENT;
  return value.toFixed(dp);
}

export function pct(value: number | null | undefined, dp = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return ABSENT;
  return `${(value * 100).toFixed(dp)}%`;
}

export function vday(value: number | null | undefined): string {
  if (value === null || value === undefined) return ABSENT;
  return `v${value}`;
}

export function micros(value: number | null | undefined): string {
  if (value === null || value === undefined) return ABSENT;
  if (value < 1000) return `${value}µs`;
  if (value < 1_000_000) return `${(value / 1000).toFixed(1)}ms`;
  return `${(value / 1_000_000).toFixed(2)}s`;
}

export function when(iso: string | null | undefined): string {
  if (!iso) return ABSENT;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return ABSENT;
  return d.toISOString().replace("T", " ").slice(0, 19);
}

export function shortId(id: string | null | undefined, n = 10): string {
  if (!id) return ABSENT;
  return id.length <= n ? id : `${id.slice(0, n)}…`;
}

/**
 * Severity → colour lives in `severity.ts`, which owns the mapping outright.
 *
 * These four helpers used to return `text-critical`, `text-high`,
 * `text-medium`, `text-low`, `text-muted` and `text-ink`. Tailwind's config
 * defines none of those — only `ok`, `warn`, `crit`, `info` and `tx1`–`tx4` —
 * so every one compiled to no rule and severity was rendered in body text in
 * every table in the console. Kept as thin delegations so existing callers
 * carry on working, and so the mapping has exactly one home.
 */
import { governanceTone, lifecycleTone, tierTone, toneText } from "./severity";

export { confidenceClass } from "./severity";

export function tierClass(tier: string | null | undefined): string {
  return toneText(tierTone(tier));
}

export function lifecycleClass(lifecycle: string | null | undefined): string {
  return toneText(lifecycleTone(lifecycle));
}

export function governanceClass(governance: string | null | undefined): string {
  return toneText(governanceTone(governance));
}
