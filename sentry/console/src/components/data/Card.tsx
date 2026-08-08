import type { ReactNode } from "react";

interface Props {
  title?: ReactNode;
  /** Small quiet line under the title. */
  sub?: ReactNode;
  /**
   * Where the card's `↗` leads. A card that shows a summary should say where
   * the full thing lives; one that is already complete gets no affordance
   * rather than a control that reloads the same screen.
   */
  href?: string;
  /** Replaces the `↗` — filters, toggles, a segmented control. */
  action?: ReactNode;
  /** Removes body padding, for a card whose child is a table or a chart. */
  flush?: boolean;
  className?: string;
  children: ReactNode;
}

/**
 * The one card.
 *
 * Every surface previously drew its own box out of `.panel` plus an `<h2>`, so
 * heading size, padding and the position of a "see more" link drifted from
 * screen to screen. Collecting it here is what makes a bento grid read as one
 * object instead of six unrelated frames.
 */
export function Card({ title, sub, href, action, flush, className = "", children }: Props) {
  const header = title || sub || href || action;
  return (
    <section
      className={`panel flex min-w-0 flex-col overflow-hidden transition-colors duration-200 hover:border-line ${className}`}
    >
      {header && (
        <div className="flex items-start justify-between gap-3 px-4 pb-3 pt-3.5">
          <div className="min-w-0">
            {title && (
              <h2 className="truncate font-sans text-[14px] font-semibold tracking-[-0.01em] text-tx1">
                {title}
              </h2>
            )}
            {sub && <p className="mt-0.5 font-sans text-[11.5px] leading-4 text-tx4">{sub}</p>}
          </div>
          {action ??
            (href && (
              <a
                href={href}
                className="grid h-7 w-7 shrink-0 place-items-center rounded-[var(--radius-control)] border border-line bg-raise text-tx3 transition-colors hover:border-accent hover:text-tx1"
                aria-label={typeof title === "string" ? `Open ${title}` : "Open"}
              >
                <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
                  <path
                    d="M5.5 10.5 10.5 5.5M10.5 5.5H6.25M10.5 5.5v4.25"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.4"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </a>
            ))}
        </div>
      )}
      <div className={`min-w-0 flex-1 ${flush ? "" : "px-4 pb-4"}`}>{children}</div>
    </section>
  );
}
