import { useEffect } from "react";

import { TOUR_STEPS, endTour, stepTo, useTourStep } from "../../lib/tour";

/**
 * The tour's panel.
 *
 * Anchored bottom-right rather than centred: it has to sit beside the surface
 * it is describing, and a centred modal would cover the table the step is
 * telling you to look at.
 */
export function Tour() {
  const index = useTourStep();
  const active = index !== null;

  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") endTour();
      if (e.key === "ArrowRight") stepTo(index + 1);
      if (e.key === "ArrowLeft") stepTo(index - 1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active, index]);

  if (index === null) return null;

  const step = TOUR_STEPS[index];
  const last = index === TOUR_STEPS.length - 1;

  return (
    <aside
      role="dialog"
      aria-label="Guided tour"
      aria-live="polite"
      className="fixed bottom-3 right-3 z-40 w-[min(27rem,calc(100vw-1.5rem))] rounded-[var(--radius-card)] border border-line bg-panel p-4 shadow-2xl sm:bottom-4 sm:right-4"
    >
      <div className="flex items-center justify-between gap-3">
        <span className="font-sans text-[11px] font-semibold uppercase tracking-[0.14em] text-tx4">
          Guided tour · {index + 1} of {TOUR_STEPS.length}
        </span>
        <button
          type="button"
          onClick={endTour}
          className="font-sans text-[11px] text-tx4 transition-colors hover:text-tx1"
        >
          Skip
        </button>
      </div>

      <h2 className="mt-2 font-sans text-[16px] font-semibold leading-snug tracking-[-0.01em] text-tx1">
        {step.title}
      </h2>
      <p className="mt-1.5 font-sans text-[12.5px] leading-5 text-tx2">{step.body}</p>

      <div className="mt-3.5 flex items-center gap-2">
        <div className="flex flex-1 items-center gap-1.5" aria-hidden="true">
          {TOUR_STEPS.map((s, i) => (
            <button
              key={s.path + i}
              type="button"
              onClick={() => stepTo(i)}
              title={s.title}
              className={`h-1.5 rounded-full transition-all ${
                i === index ? "w-5 bg-accent" : "w-1.5 bg-line hover:bg-tx4"
              }`}
            />
          ))}
        </div>
        <button
          type="button"
          className="btn"
          onClick={() => stepTo(index - 1)}
          disabled={index === 0}
        >
          Back
        </button>
        <button type="button" className="btn-primary" onClick={() => stepTo(index + 1)}>
          {last ? "Finish" : "Next"}
        </button>
      </div>
    </aside>
  );
}
