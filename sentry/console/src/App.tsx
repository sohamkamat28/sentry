import { Nav } from "./components/shell/Nav";
import { LiveBar } from "./components/shell/LiveBar";
import { HealthStrip } from "./components/shell/HealthStrip";
import { CommandPalette } from "./components/shell/CommandPalette";
import { useRoute, routePath } from "./lib/router";
import { SURFACES } from "./routes";

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
  const View = surface?.view;
  const fullBleed = surface?.path === "/";

  return (
    <div className="flex h-screen">
      <Nav path={path} />
      <div className="flex min-w-0 flex-1 flex-col">
        <LiveBar />
        <HealthStrip />
        <main className={`min-h-0 flex-1 ${fullBleed ? "overflow-hidden p-3" : "overflow-y-auto p-4"}`}>
          {View ? (
            fullBleed ? (
              <View />
            ) : (
              <>
                <h1 className="mb-3 text-[15px] tracking-wide text-tx2">{surface!.label}</h1>
                <View />
              </>
            )
          ) : (
            <div className="text-tx4">no surface at {routePath(path)}</div>
          )}
        </main>
      </div>
      <CommandPalette />
    </div>
  );
}
