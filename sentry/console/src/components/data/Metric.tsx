import type { ReactNode } from "react";

export type Tone = "ok" | "warn" | "crit" | "info" | "dim";

// Wrapped in `rgb()`. The variables hold channel triplets — `--crit` is
// `255 92 92`, not a colour — so a bare `color: var(--crit)` is invalid CSS,
// silently dropped, and every tile rendered in the inherited text colour. The
// tone prop was plumbed through six call sites and had never once been visible.
const TONE: Record<Tone, string> = {
  ok: "rgb(var(--ok))",
  warn: "rgb(var(--warn))",
  crit: "rgb(var(--crit))",
  info: "rgb(var(--info))",
  dim: "rgb(var(--tx3))",
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
    <div className="panel px-4 py-3.5 transition-colors duration-200">
      {/* Label above figure. The reference leads with the number, but a bare
          `33` says nothing until you know what was counted — and these tiles sit
          six abreast, so the eye needs the noun before the digit. */}
      <div className="font-sans text-[11px] font-medium uppercase tracking-[0.08em] text-tx4">
        {label}
      </div>
      <div
        className="num mt-1.5 font-mono text-[28px] font-medium leading-none tracking-[-0.02em]"
        style={{ color: failed ? TONE.crit : pending ? TONE.dim : TONE[tone] }}
        aria-busy={(loading && !failed) || undefined}
      >
        {pending ? "—" : value}
      </div>
      {(sub || pending || degraded) && (
        <div className="mt-1.5 font-sans text-[11px] leading-4 text-tx4">
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
