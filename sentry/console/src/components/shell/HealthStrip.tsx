import { healthTone, toneText } from "../../lib/severity";
import { LIVE_MS, useLive } from "../../lib/useLive";
import type { Live } from "../../lib/api-types";

/**
 * Is the sensor actually alive.
 *
 * The first question on an operations floor, and until now it took a trip to
 * the Sensor Grid to answer — which is exactly the trip nobody makes, because
 * the console looked calm. A quiet estate and a blind one present identically
 * on every other surface, so the distinction has to be somewhere permanent.
 *
 * Each component is judged on evidence it produced rather than on a heartbeat
 * it sent: `/live` derives the state from the newest observation each source
 * wrote. A sensor that reports healthy while capturing nothing is the failure
 * this product exists to catch, and it must not be able to hide behind its own
 * status field.
 */
export function HealthStrip() {
  const { data, error } = useLive<Live>("live", "/live", LIVE_MS);

  if (error) {
    return (
      <div className="flex items-center gap-2 border-b border-line bg-panel px-3 py-1 text-[11px] text-crit">
        control plane unreachable — component health unknown
      </div>
    );
  }

  return (
    <div className="flex items-center gap-1.5 overflow-x-auto border-b border-line bg-panel px-3 py-1 text-[11px]">
      {(data?.health ?? []).map((h) => (
        <Pill
          key={h.component}
          name={h.component}
          state={h.state}
          behind={h.vdays_behind ?? null}
        />
      ))}

      {data?.source && (
        <span className="ml-auto shrink-0 text-tx4" title="which store answered the capture counts">
          capture via {data.source}
        </span>
      )}
    </div>
  );
}

function Pill({
  name,
  state,
  behind,
}: {
  name: string;
  state: string;
  behind: number | null;
}) {
  const tone = healthTone(state);
  // The dot carries the state and the label carries the name, so the strip is
  // readable at a glance and still legible to anyone who cannot separate the
  // hues.
  const detail =
    state === "stale" && behind !== null
      ? `${name} last wrote ${behind} vdays ago`
      : `${name}: ${state}`;

  return (
    <span className="chip shrink-0 text-tx3" title={detail}>
      <span className={toneText(tone)}>●</span> {name}
      {state === "stale" && behind !== null && (
        <span className="ml-1 text-warn">+{behind}v</span>
      )}
      {state === "down" && <span className="ml-1 text-crit">down</span>}
    </span>
  );
}
