import type { Tone } from "./Metric";

// `rgb()`-wrapped for the same reason as the metric tile: the variables are
// channel triplets, and an unwrapped `var(--crit)` is not a colour.
const TONE: Record<Tone, string> = {
  ok: "rgb(var(--ok))",
  warn: "rgb(var(--warn))",
  crit: "rgb(var(--crit))",
  info: "rgb(var(--info))",
  dim: "rgb(var(--accent))",
};

interface Props {
  /** 0…1. Undefined while in flight or after a failed read — never defaulted to 0. */
  value?: number | null;
  /** Rendered large in the middle. The caller formats it; this does not guess. */
  display?: string;
  caption?: string;
  tone?: Tone;
  legend?: { label: string; tone?: Tone }[];
  /**
   * Cap on the arc's width. The drawing is 120×104, so its height is about
   * 0.87× this — the knob to turn when the gauge has to fit a fixed row rather
   * than take the width its card happens to have.
   */
  maxWidth?: number;
}

/**
 * A 240° arc, for one bounded ratio.
 *
 * The arc is drawn with `pathLength="100"` so the dash length is the percentage
 * directly — no arc-length trigonometry to get wrong, and the track and the
 * fill are guaranteed to be the same curve.
 *
 * An absent value leaves the track empty and prints an em dash. A gauge sitting
 * at zero and a gauge that could not be read look nothing alike, which is the
 * same rule the metric tile enforces one level up.
 */
export function Gauge({ value, display, caption, tone = "dim", legend, maxWidth = 190 }: Props) {
  const known = value != null && Number.isFinite(value);
  const pct = known ? Math.max(0, Math.min(1, value)) * 100 : 0;

  // The readable width inside the arc is about 0.675× the gauge's own width —
  // the drawing is 120 units across with an 11-unit stroke on a radius of 46,
  // so the clear span is roughly 81 of those units. At `maxWidth` 118 that is
  // 80px, and `0.757` set in 28px mono wants about 84: the figure ran into the
  // arc it sits inside. Two steps off the console's scale rather than a
  // sliding size, so the number stays part of the same type system.
  const figure = maxWidth >= 150 ? "text-[28px]" : "text-[20px]";

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-full" style={{ maxWidth }}>
        <svg viewBox="0 0 120 104" className="w-full" role="img" aria-label={caption ?? "gauge"}>
          <path
            d="M20.2 83 A46 46 0 1 1 99.8 83"
            pathLength={100}
            fill="none"
            stroke="rgb(var(--line))"
            strokeWidth={11}
            strokeLinecap="round"
          />
          {known && (
            <path
              d="M20.2 83 A46 46 0 1 1 99.8 83"
              pathLength={100}
              fill="none"
              stroke={TONE[tone]}
              strokeWidth={11}
              strokeLinecap="round"
              strokeDasharray={`${pct} 100`}
              style={{ transition: "stroke-dasharray 700ms cubic-bezier(0.22,1,0.36,1)" }}
            />
          )}
        </svg>

        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pt-3">
          {caption && (
            <span className="font-sans text-[11px] uppercase tracking-[0.1em] text-tx4">
              {caption}
            </span>
          )}
          <span
            className={`num font-mono ${figure} leading-tight`}
            style={{ color: known ? TONE[tone] : "rgb(var(--tx3))" }}
          >
            {known ? (display ?? `${Math.round(pct)}%`) : "—"}
          </span>
        </div>
      </div>

      {legend && (
        <div className="mt-1 flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
          {legend.map((l) => (
            <span key={l.label} className="flex items-center gap-1.5 font-sans text-[11px] text-tx3">
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ background: l.tone ? TONE[l.tone] : "rgb(var(--line))" }}
              />
              {l.label}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
