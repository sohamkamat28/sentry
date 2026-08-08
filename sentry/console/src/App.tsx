import { useEffect } from "react";

import { Nav } from "./components/shell/Nav";
import { LiveBar } from "./components/shell/LiveBar";
import { HealthStrip } from "./components/shell/HealthStrip";
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
  // Triage manages its own three-pane height; a page heading above it would
  // only steal a row from the queue.
  const fullBleed = surface?.path === "/triage";

  useEffect(() => {
    document.title = surface ? `${surface.label} · SENTRY` : "SENTRY";
  }, [surface]);

  return (
    <div className="flex min-h-dvh flex-col md:h-dvh md:flex-row">
      <a
        href="#main-content"
        className="fixed left-3 top-3 z-50 -translate-y-20 rounded-sm bg-info px-3 py-2 font-sans text-[12px] font-semibold text-bg transition-transform focus:translate-y-0"
      >
        Skip to content
      </a>
      <Nav path={path} />
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <LiveBar />
        <HealthStrip />
        <main id="main-content" tabIndex={-1} className={`min-h-0 flex-1 ${fullBleed ? "overflow-y-auto p-2.5 md:overflow-hidden md:p-4" : "overflow-y-auto p-3.5 md:p-6"}`}>
          {View ? (
            fullBleed ? (
              <>
                <h1 className="sr-only">{surface.label}</h1>
                <View />
              </>
            ) : (
              <>
                <header className="mb-5 font-sans">
                  <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-[0.14em] text-accent">
                    {area?.label}
                  </div>
                  <h1 className="text-[26px] font-semibold leading-tight tracking-[-0.025em] text-tx1">
                    {surface.label}
                  </h1>
                  <p className="mt-1 max-w-[65ch] text-[13px] leading-5 text-tx3">
                    {surface.description}
                  </p>
                </header>
                <View />
              </>
            )
          ) : (
            <div className="panel max-w-lg p-5 font-sans">
              <h1 className="text-[18px] font-semibold text-tx1">View not found</h1>
              <p className="mt-1 text-[12px] text-tx3">There is no console view at {routePath(path)}.</p>
              <a className="mt-4 inline-block text-[12px] text-accent hover:underline" href="#/">
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
