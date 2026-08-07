import { useState, type ReactNode } from "react";

/**
 * One idea, one screen.
 *
 * The walkthrough exists because the fourteen stages are a real sequence and
 * nobody was ever going to discover it by clicking fifteen navigation items in
 * the right order. Told as eight steps it becomes a story a stranger can follow
 * without a presenter — which is the difference between a link on a CV that gets
 * closed and one that gets finished.
 *
 * Each step holds a plain-English headline, the figure that answers it, and one
 * line saying how it is known. The raw payload sits behind a disclosure, because
 * the reader who wants it is not the reader the headline is for.
 */
export function Step({
  index,
  total,
  question,
  answer,
  evidence,
  children,
  raw,
}: {
  index: number;
  total: number;
  /** The plain question this step answers, as a headline. */
  question: string;
  /** The short answer, stated before any detail. */
  answer: ReactNode;
  /** One line on how it is known. */
  evidence: ReactNode;
  children?: ReactNode;
  raw?: unknown;
}) {
  return (
    <article className="min-w-0">
      <div className="font-sans text-[11px] font-medium uppercase tracking-[0.14em] text-info">
        Step {index + 1} of {total}
      </div>

      <h2 className="mt-2 max-w-[22ch] font-sans text-[26px] font-semibold leading-[1.15] tracking-[-0.02em] text-tx1 sm:text-[32px]">
        {question}
      </h2>

      <div className="mt-4 font-sans text-[15px] leading-6 text-tx2 sm:text-[16px] sm:leading-7">
        {answer}
      </div>

      <p className="mt-3 max-w-[62ch] border-l-2 border-line pl-3 font-sans text-[12.5px] leading-5 text-tx3">
        <span className="text-tx4">How we know: </span>
        {evidence}
      </p>

      {children ? <div className="mt-6">{children}</div> : null}

      {raw !== undefined ? <Raw payload={raw} /> : null}
    </article>
  );
}

/** The underlying payload, for the reader who wants to check the claim. */
function Raw({ payload }: { payload: unknown }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-6">
      <button
        type="button"
        className="font-sans text-[12px] text-tx4 underline-offset-4 hover:text-info hover:underline"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        {open ? "hide the raw data" : "show the raw data"}
      </button>
      {open && (
        <pre className="mt-2 max-h-72 overflow-auto rounded-sm border border-line bg-bg px-3 py-2.5 text-[11px] leading-5 text-tx3">
          {JSON.stringify(payload, null, 2)}
        </pre>
      )}
    </div>
  );
}

/** The step index, as a clickable rail. Doubles as a progress indicator. */
export function StepRail({
  titles,
  current,
  onSelect,
}: {
  titles: string[];
  current: number;
  onSelect: (i: number) => void;
}) {
  return (
    <nav aria-label="Walkthrough steps" className="min-w-0">
      <ol className="flex gap-1 overflow-x-auto pb-1 lg:block lg:space-y-0.5 lg:overflow-visible lg:pb-0">
        {titles.map((t, i) => {
          const active = i === current;
          const done = i < current;
          return (
            <li key={t} className="shrink-0 lg:shrink">
              <button
                type="button"
                aria-current={active ? "step" : undefined}
                onClick={() => onSelect(i)}
                className={`flex w-full items-center gap-2.5 rounded-sm border-l-2 px-2.5 py-2 text-left
                  font-sans text-[12px] transition-colors lg:w-full ${
                    active
                      ? "border-info bg-line/50 text-tx1"
                      : "border-transparent text-tx4 hover:bg-line/25 hover:text-tx2"
                  }`}
              >
                <span
                  aria-hidden
                  className={`grid h-5 w-5 shrink-0 place-items-center rounded-full border text-[10px] ${
                    active
                      ? "border-info text-info"
                      : done
                        ? "border-ok/60 text-ok"
                        : "border-line text-tx4"
                  }`}
                >
                  {done ? "✓" : i + 1}
                </span>
                <span className="hidden whitespace-nowrap lg:inline lg:whitespace-normal">{t}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
