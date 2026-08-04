import { toneText, type Tone } from "../../lib/severity";

/**
 * Direction, at a glance.
 *
 * A CDRI of 0.93 is a fact; 0.93 and climbing is a decision. The console shows
 * the first everywhere and the second nowhere, which leaves an operator ranking
 * a queue on a number that may be falling. This is the smallest thing that
 * carries the second.
 *
 * Inline SVG and no dependency: a charting library is several hundred kilobytes
 * to draw a polyline, and this has to render once per row.
 */
interface Props {
  values: number[];
  width?: number;
  height?: number;
  tone?: Tone;
  /** Fixes the vertical scale — for a bounded measure like CDRI, where a
   *  self-scaled sparkline would make a flat 0.9 look like violent movement. */
  min?: number;
  max?: number;
  title?: string;
}

export function Sparkline({
  values,
  width = 72,
  height = 16,
  tone = "dim",
  min,
  max,
  title,
}: Props) {
  const clean = values.filter((v) => Number.isFinite(v));

  // One point is not a trend, and drawing a flat line through it would assert
  // stability that has not been observed.
  if (clean.length < 2) {
    return (
      <span className="text-tx4" title={title ?? "not enough history to show a trend"}>
        —
      </span>
    );
  }

  const lo = min ?? Math.min(...clean);
  const hi = max ?? Math.max(...clean);
  const span = hi - lo || 1;

  const step = width / (clean.length - 1);
  const points = clean
    .map((v, i) => {
      const x = i * step;
      // SVG y grows downward; a rising series must rise on screen.
      const y = height - ((v - lo) / span) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className={`inline-block align-middle ${toneText(tone)}`}
      role="img"
      aria-label={title ?? "trend"}
    >
      {title && <title>{title}</title>}
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        strokeWidth="1"
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
