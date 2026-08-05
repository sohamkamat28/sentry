import type { ReactNode } from "react";

export type Tone = "ok" | "warn" | "crit" | "info" | "dim";

const TONE: Record<Tone, string> = {
  ok: "var(--ok)",
  warn: "var(--warn)",
  crit: "var(--crit)",
  info: "var(--info)",
  dim: "var(--tx3)",
};

interface Props {
  /** Undefined while in flight. See the loading contract below. */
  value?: number | string | null;
  label: string;
  sub?: string;
  tone?: Tone;
  loading?: boolean;
  /** A failed read withholds the value and says why; it never falls through to zero. */
  error?: unknown;
  /** Counts derived from a degraded source are marked rather than presented as complete. */
  degraded?: boolean;
  children?: ReactNode;
}

/**
 * A metric tile.
 *
 * Loading renders an em dash, never a zero. A resurrection-alert tile showing 0
 * during a scan reads as "none found", which is a claim the system has not yet
 * made — that shipped once and is the reason this component owns the rule rather
 * than leaving it to each caller.
 */
export function Metric({ value, label, sub, tone = "dim", loading, error, degraded, children }: Props) {
  const failed = error != null;
  const pending = loading || failed || value === undefined || value === null;
  const failure = error instanceof Error ? error.message : failed ? String(error) : null;

  return (
    <div className="rounded-sm border border-line bg-panel px-3 py-2.5">
      <div
        className="font-mono text-2xl leading-none tabular-nums"
        style={{ color: failed ? "var(--crit)" : pending ? "var(--tx3)" : TONE[tone] }}
        aria-busy={(loading && !failed) || undefined}
      >
        {pending ? "—" : value}
      </div>
      <div className="mt-1.5 text-[10.5px] uppercase tracking-wide text-tx3">{label}</div>
      {(sub || pending || degraded) && (
        <div className="mt-0.5 text-[10.5px] text-tx4">
          {failed
            ? `unavailable${failure ? ` — ${failure}` : ""}`
            : pending
              ? "loading…"
              : degraded
                ? "source degraded — may undercount"
                : sub}
        </div>
      )}
      {children}
    </div>
  );
}
