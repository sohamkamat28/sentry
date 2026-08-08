import { useEffect } from "react";

import { Nav } from "./components/shell/Nav";
import { LiveBar } from "./components/shell/LiveBar";
import { CommandPalette } from "./components/shell/CommandPalette";
import { Door } from "./components/shell/Door";
import { Tour } from "./components/shell/Tour";
import { useRoute, routePath } from "./lib/router";
import { areaForPath, SURFACES } from "./routes";

/**
 * The shell.
 *
 * Two strips sit above every surface and neither is decoration. The live bar
 * carries the figures with their age attached, because a count on an operations
 * screen with no indication of when it was read cannot be acted on. The health
 * strip answers "is the sensor alive", which previously required a trip to the
 * Sensor Grid — the trip nobody makes, because a blind console looks calm.
 *
 * Triage runs full-bleed: it manages its own three-pane height and a page
 * heading above it would only steal a row from the queue.
 */
export function App() {
  const [path] = useRoute();
  const surface = SURFACES.find((s) => s.path === routePath(path));
  const area = areaForPath(routePath(path));
  const View = surface?.view;
  // These two manage their own height and fill the viewport rather than
  // scrolling: Triage is a three-pane queue, Command Centre a bento that has to
  // be readable at a glance. On both, a page heading above would only repeat
  // the rail's active item and steal a row from the content. Below `md` they
  // scroll normally — six cards cannot share a phone screen.
  const fullBleed = surface?.path === "/triage" || surface?.path === "/";

  useEffect(() => {
    document.title = surface ? `${surface.label} · SENTRY` : "SENTRY";
  }, [surface]);

  return (
    <div className="flex min-h-dvh flex-col md:h-dvh md:flex-row">
      <a
        href="#main-content"
        className="fixed left-3 top-3 z-50 -translate-y-20 rounded-sm bg-info px-3 py-2 font-sans text-[12.5px] font-semibold text-bg transition-transform focus:translate-y-0"
      >
        Skip to content
      </a>
      <Nav path={path} />
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <LiveBar />
        {/* Where each surface stops scrolling and starts filling the viewport.
            Triage is two panes and manages it from `md`. Command Centre needs
            all four chart cards on one row before its bottom band has any
            height to claim — below `xl` they wrap to two rows, the band gets
            nothing, and the tables collapse to a couple of pixels. Written as
            whole literals because Tailwind cannot see a class name assembled at
            runtime. */}
        <main
          id="main-content"
          tabIndex={-1}
          className={`min-h-0 flex-1 ${
            surface?.path === "/triage"
              ? "overflow-y-auto p-2.5 md:overflow-hidden md:p-4"
              : surface?.path === "/"
                ? "overflow-y-auto p-2.5 xl:overflow-hidden xl:p-4"
                : "overflow-y-auto p-3.5 md:p-6"
          }`}
        >
          {View ? (
            fullBleed ? (
              <>
                <h1 className="sr-only">{surface.label}</h1>
                <View />
              </>
            ) : (
              <>
                {/* Five type steps, estate-wide: 28 / 20 / 14 / 12.5 / 11.
                    The header used to contribute three sizes of its own —
                    10.5, 13 and 26 — each appearing exactly once per screen,
                    which is how a four-step scale became eleven. */}
                <header className="mb-5 font-sans">
                  <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-accent">
                    {area?.label}
                  </div>
                  <h1 className="text-[28px] font-semibold leading-tight tracking-[-0.025em] text-tx1">
                    {surface.label}
                  </h1>
                  <p className="mt-1 max-w-[65ch] text-[12.5px] leading-5 text-tx3">
                    {surface.description}
                  </p>
                </header>
                <View />
              </>
            )
          ) : (
            <div className="panel max-w-lg p-5 font-sans">
              <h1 className="text-[18px] font-semibold text-tx1">View not found</h1>
              <p className="mt-1 text-[12.5px] text-tx3">There is no console view at {routePath(path)}.</p>
              <a className="mt-4 inline-block text-[12.5px] text-accent hover:underline" href="#/">
                Return to the work queue
              </a>
            </div>
          )}
        </main>
      </div>
      <CommandPalette />
      <Tour />
      <Door />
    </div>
  );
}
