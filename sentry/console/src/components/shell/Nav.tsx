import { SURFACES } from "../../routes";
import { routePath } from "../../lib/router";

/**
 * A top bar with four links.
 *
 * The sidebar it replaces held fifteen, which is not navigation so much as a
 * table of contents for a system the reader has not agreed to learn yet. Four
 * fit across the top on a laptop and wrap to two rows on a phone, so the whole
 * of the product is visible at once and nothing is hidden behind a menu.
 */
export function Nav({ path, capturedAt }: { path: string; capturedAt?: string }) {
  const current = routePath(path);

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-panel/95 backdrop-blur">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2.5 sm:px-6">
        <a href="#/" className="flex shrink-0 items-baseline gap-2">
          <span className="font-sans text-[15px] font-semibold tracking-[0.18em] text-tx1">
            SENTRY
          </span>
          <span className="hidden font-sans text-[11px] text-tx4 sm:inline">
            API lifecycle security
          </span>
        </a>

        <nav aria-label="Primary" className="order-3 -mx-1 w-full sm:order-none sm:mx-0 sm:w-auto">
          <ul className="flex gap-0.5 overflow-x-auto">
            {SURFACES.map((s) => {
              const active = current === s.path;
              return (
                <li key={s.path}>
                  <a
                    href={`#${s.path}`}
                    aria-current={active ? "page" : undefined}
                    className={`block whitespace-nowrap rounded-sm px-3 py-1.5 font-sans text-[13px] transition-colors ${
                      active
                        ? "bg-line/70 font-medium text-tx1"
                        : "text-tx3 hover:bg-line/30 hover:text-tx1"
                    }`}
                  >
                    {s.label}
                  </a>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Says what this is before anyone has to work it out. A site that
            looked live and had a dead sensor would be worse than one that is
            honest about being a recording. */}
        {capturedAt && (
          <span
            className="ml-auto hidden shrink-0 items-center gap-1.5 font-sans text-[11px] text-tx4 md:flex"
            title={`Captured ${capturedAt}`}
          >
            <span aria-hidden className="inline-block h-1.5 w-1.5 rounded-full bg-ok" />
            recorded run · {capturedAt.slice(0, 10)}
          </span>
        )}
      </div>
    </header>
  );
}
