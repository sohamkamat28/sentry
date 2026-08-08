import { SURFACES } from "../../routes";
import { routePath } from "../../lib/router";
import { ThemeToggle } from "./ThemeToggle";

const NAV_SURFACES = SURFACES.filter((surface) => surface.path !== "/correlation");

/**
 * The rail.
 *
 * Deliberately one flat list. The surfaces carry a `group`, and rendering those
 * as headings was tried and removed: five headings over fifteen items reads as
 * a taxonomy to learn before the first click, and `Nav.test.tsx` pins the flat
 * set so it does not come back by accident.
 *
 * On a phone the rail becomes a horizontal scroller. Stacked, sixteen items ate
 * the entire first screen and pushed every surface below the fold.
 */
export function Nav({ path }: { path: string }) {
  const current = routePath(path);
  return (
    <nav
      aria-label="Primary"
      className="flex shrink-0 flex-col gap-3 border-b border-line bg-bg p-3 md:w-56 md:overflow-y-auto md:border-b-0 md:border-r"
    >
      <div className="flex items-center justify-between gap-2">
        <a href="#/" className="flex min-w-0 items-center gap-2.5">
          <span
            aria-hidden="true"
            className="grid h-8 w-8 shrink-0 place-items-center rounded-[var(--radius-control)] bg-accent"
          >
            <svg viewBox="0 0 20 20" className="h-4 w-4 text-[rgb(var(--accent-tx))]">
              <path
                d="M10 2.5 16.5 5v5.2c0 3.4-2.6 6.2-6.5 7.3-3.9-1.1-6.5-3.9-6.5-7.3V5L10 2.5Z"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinejoin="round"
              />
              <circle cx="10" cy="9.4" r="1.7" fill="currentColor" />
            </svg>
          </span>
          <span className="truncate font-sans text-[15px] font-semibold tracking-[0.14em] text-tx1">
            SENTRY
          </span>
        </a>
        <div className="md:hidden">
          <ThemeToggle />
        </div>
      </div>

      {/* The reference puts a profile card here. There is no signed-in identity
          on a published recording, so this carries what the product is instead
          of inventing a person to greet. */}
      <div className="hidden items-center justify-between gap-2 rounded-[var(--radius-card)] border border-line bg-panel px-3 py-2.5 md:flex">
        <span className="font-sans text-[11px] leading-4 text-tx4">
          API lifecycle
          <br />
          security
        </span>
        <ThemeToggle />
      </div>

      <div className="-mx-1 flex gap-1 overflow-x-auto px-1 md:mx-0 md:flex-col md:gap-0.5 md:rounded-[var(--radius-card)] md:border md:border-line md:bg-panel md:p-1.5">
        {NAV_SURFACES.map((surface) => {
          const active = current === surface.path;
          return (
            <a
              key={surface.path}
              href={`#${surface.path}`}
              aria-current={active ? "page" : undefined}
              className={`shrink-0 whitespace-nowrap rounded-[var(--radius-control)] px-3 py-2 font-sans text-[12.5px] transition-colors duration-150 md:shrink ${
                active
                  ? "bg-accent font-medium text-[rgb(var(--accent-tx))]"
                  : "text-tx3 hover:bg-raise hover:text-tx1"
              }`}
            >
              {surface.label}
            </a>
          );
        })}
      </div>
    </nav>
  );
}
