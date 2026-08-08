import { setTheme, useTheme } from "../../lib/theme";

/**
 * A two-state segmented control, not a switch.
 *
 * A single toggle leaves the reader working out whether the icon shows the
 * current theme or the one they would get by pressing it — a coin flip every
 * time. Both options are drawn, and the active one is marked, so there is
 * nothing to infer.
 */
export function ThemeToggle() {
  const theme = useTheme();

  return (
    <div
      className="flex items-center gap-0.5 rounded-[var(--radius-pill)] border border-line bg-raise p-0.5"
      role="group"
      aria-label="Colour theme"
    >
      {(["dark", "light"] as const).map((t) => {
        const active = theme === t;
        return (
          <button
            key={t}
            type="button"
            onClick={() => setTheme(t)}
            aria-pressed={active}
            title={t === "dark" ? "Dark theme" : "Light theme"}
            className={`grid h-6 w-6 place-items-center rounded-[var(--radius-pill)] transition-colors ${
              active ? "bg-panel text-tx1 shadow-sm" : "text-tx4 hover:text-tx2"
            }`}
          >
            <span className="sr-only">{t === "dark" ? "Dark theme" : "Light theme"}</span>
            {t === "dark" ? (
              <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
                <path
                  d="M13.5 9.6A5.8 5.8 0 0 1 6.4 2.5a5.8 5.8 0 1 0 7.1 7.1Z"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.3"
                  strokeLinejoin="round"
                />
              </svg>
            ) : (
              <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
                <circle cx="8" cy="8" r="3" fill="none" stroke="currentColor" strokeWidth="1.3" />
                <path
                  d="M8 1v1.6M8 13.4V15M15 8h-1.6M2.6 8H1m11-5-1.1 1.1M5.1 10.9 4 12m8 0-1.1-1.1M5.1 5.1 4 4"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.3"
                  strokeLinecap="round"
                />
              </svg>
            )}
          </button>
        );
      })}
    </div>
  );
}
