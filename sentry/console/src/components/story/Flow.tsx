/**
 * The pipeline, as five steps rather than fourteen.
 *
 * Fourteen numbered stages is how the system is built; it is not how anyone
 * arriving at it thinks. Presented as navigation it asked every reader to learn
 * an architecture before they could learn what the product does — and the
 * stages are internal machinery, so the learning bought them nothing.
 *
 * Five verbs cover the same ground: watch, identify, judge, score, act. The
 * counts under them are real, so the row doubles as a summary of the recording.
 */
export function Flow({
  captured,
  endpoints,
  classified,
  scored,
  acted,
}: {
  captured?: number;
  endpoints?: number;
  classified?: number;
  scored?: number;
  acted?: number;
}) {
  const steps = [
    // "seen by the kernel", not "calls seen": the figure is how many distinct
    // endpoints the probe observed, and labelling it as a call count would be a
    // wrong number on the first card of the site.
    { verb: "Watch", detail: "TLS traffic, read in the kernel", n: captured, unit: "seen by the probe" },
    { verb: "Identify", detail: "one record per real endpoint", n: endpoints, unit: "APIs found" },
    { verb: "Judge", detail: "alive or dead, owned or not", n: classified, unit: "classified" },
    { verb: "Score", detail: "six weighted risk factors", n: scored, unit: "scored" },
    { verb: "Act", detail: "protect, retire, or watch", n: acted, unit: "controls live" },
  ];

  return (
    <ol className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-5">
      {steps.map((s, i) => (
        <li key={s.verb} className="panel relative px-4 py-3.5">
          {/* The chevron is decoration and is hidden from assistive tech; the
              ordered list already carries the sequence. */}
          {i < steps.length - 1 && (
            <span
              aria-hidden
              className="absolute -right-[7px] top-1/2 z-10 hidden -translate-y-1/2 text-tx4 lg:block"
            >
              ›
            </span>
          )}
          <div className="font-sans text-[10px] font-medium uppercase tracking-[0.14em] text-tx4">
            step {i + 1}
          </div>
          <div className="mt-1 font-sans text-[15px] font-semibold text-tx1">{s.verb}</div>
          <div className="mt-0.5 font-sans text-[11.5px] leading-4 text-tx3">{s.detail}</div>
          <div className="mt-2.5 border-t border-line pt-2">
            <span className="num text-[15px] text-tx1">
              {s.n === undefined ? "—" : s.n.toLocaleString()}
            </span>{" "}
            <span className="font-sans text-[11px] text-tx4">{s.unit}</span>
          </div>
        </li>
      ))}
    </ol>
  );
}
