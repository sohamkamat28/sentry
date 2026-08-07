import { useEffect, useState } from "react";

import { Nav } from "./components/shell/Nav";
import { useRoute, routePath } from "./lib/router";
import { SURFACES } from "./routes";
import { STATIC_MODE, capturedAt as loadCapturedAt } from "./lib/snapshot";

/**
 * The shell.
 *
 * What used to sit above every screen — a live counter strip, a sensor health
 * row, a role switcher, a command palette — served an operator watching an
 * estate in real time. This is published for someone who has never seen the
 * product before, and for them those strips were four rows of unexplained
 * numbers standing between them and the first sentence.
 *
 * So the chrome is one bar: who this is, four places to go, and an honest note
 * that the data is a recording.
 */
export function App() {
  const [path] = useRoute();
  const current = routePath(path);
  const surface = SURFACES.find((s) => s.path === current);
  const View = surface?.view;
  const [captured, setCaptured] = useState<string>();

  useEffect(() => {
    document.title = surface ? `${surface.label} · SENTRY` : "SENTRY";
  }, [surface]);

  useEffect(() => {
    if (STATIC_MODE) void loadCapturedAt().then(setCaptured).catch(() => undefined);
  }, []);

  // Each destination is its own page: land at the top of it, not halfway down
  // where the last one was scrolled to.
  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [current]);

  return (
    <div className="min-h-dvh bg-bg">
      <a
        href="#main"
        className="fixed left-3 top-3 z-50 -translate-y-20 rounded-sm bg-info px-3 py-2 font-sans text-[12px] font-semibold text-bg transition-transform focus:translate-y-0"
      >
        Skip to content
      </a>

      <Nav path={path} capturedAt={captured} />

      <main id="main" tabIndex={-1} className="px-4 py-6 sm:px-6 sm:py-8">
        {View ? (
          <View />
        ) : (
          <div className="mx-auto max-w-md panel px-5 py-6">
            <h1 className="font-sans text-[17px] font-semibold text-tx1">Nothing here</h1>
            <p className="mt-1 font-sans text-[13px] text-tx3">
              There is no page at {current}.
            </p>
            <a className="mt-4 inline-block font-sans text-[13px] text-info hover:underline" href="#/">
              Back to the overview
            </a>
          </div>
        )}
      </main>

      <footer className="border-t border-line px-4 py-5 sm:px-6">
        <p className="mx-auto max-w-6xl font-sans text-[11.5px] leading-5 text-tx4">
          SENTRY — API lifecycle security. Every figure on this site came out of a
          real captured run against twelve running banking services; there is no
          synthetic data anywhere in the project.
          {captured ? ` Recorded ${captured.slice(0, 10)}.` : ""}
        </p>
      </footer>
    </div>
  );
}
