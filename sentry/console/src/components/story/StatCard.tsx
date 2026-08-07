import { useEffect, useState } from "react";

import { Term } from "../data/Term";

/**
 * One headline figure, in the reader's language.
 *
 * The old console led with `zombie 43 · shadow 33 · cdri 0.813` — true, and
 * meaningless to anyone who has not worked here. Each card now leads with the
 * plain sentence and keeps the domain word underneath, where it reads as a name
 * for something the reader has just understood rather than a prerequisite.
 */
export function StatCard({
  value,
  label,
  term,
  tone = "plain",
  loading,
}: {
  value: number | undefined;
  label: string;
  /** The domain word this figure is called, shown small and defined on hover. */
  term?: string;
  tone?: "plain" | "warn" | "crit";
  loading?: boolean;
}) {
  const shown = useCountUp(value);
  const colour =
    tone === "crit" ? "text-crit" : tone === "warn" ? "text-warn" : "text-tx1";

  return (
    <div className="panel px-4 py-4 sm:px-5 sm:py-5">
      <div className={`num text-[30px] font-semibold leading-none sm:text-[38px] ${colour}`}>
        {loading || value === undefined ? <span className="text-tx4">—</span> : shown}
      </div>
      <div className="mt-2 font-sans text-[13px] leading-5 text-tx2">{label}</div>
      {term && (
        <div className="mt-1 font-sans text-[11px] text-tx4">
          we call this <Term>{term}</Term>
        </div>
      )}
    </div>
  );
}

/**
 * Counts up once on arrival.
 *
 * Motion here earns its place: it draws the eye to the figures in the order
 * they should be read, on a screen whose whole job is to be understood in the
 * first few seconds. It runs once and never on update, so a number does not
 * animate every time a query refetches.
 */
function useCountUp(target: number | undefined) {
  const [n, setN] = useState(0);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (target === undefined || done) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setN(target);
      setDone(true);
      return;
    }
    const start = performance.now();
    const ms = 550;
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / ms);
      // Ease-out cubic: fast then settling, so the final value is legible
      // before the animation technically ends.
      setN(Math.round(target * (1 - Math.pow(1 - t, 3))));
      if (t < 1) raf = requestAnimationFrame(tick);
      else setDone(true);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, done]);

  return n;
}
