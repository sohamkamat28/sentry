import { useState } from "react";

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
 *
 * It used to own a second full-width band under the live bar, five pills wide,
 * on every screen — and four of those five were green almost always. Permanent
 * is not the same as loud. What is wrong stays named and in place; what is fine
 * collapses to a count that opens on click.
 */
export function Health() {
  const [open, setOpen] = useState(false);
  const { data, error } = useLive<Live>("live", "/live", LIVE_MS);

  if (error) {
    return <span className="shrink-0 text-crit">component health unknown</span>;
  }

  const all = data?.health ?? [];
  if (all.length === 0) return null;

  const degraded = all.filter((h) => h.state !== "ok");
  const healthy = all.length - degraded.length;
  // Anything not ok is always drawn. Only the green ones are ever folded away.
  const shown = open ? all : degraded;

  return (
    <span className="flex shrink-0 items-center gap-1.5">
      {shown.map((h) => (
        <Pill
          key={h.component}
          name={h.component}
          state={h.state}
          behind={h.vdays_behind ?? null}
        />
      ))}

      {healthy > 0 && (
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="chip shrink-0 text-tx3 transition-colors hover:text-tx1"
          title={
            open
              ? "collapse the healthy sources"
              : `${healthy} source(s) reporting fresh observations${
                  data?.source ? ` · capture via ${data.source}` : ""
                }`
          }
        >
          <span className={toneText("ok")}>●</span>
          {open ? "fewer" : `${healthy} ok`}
        </button>
      )}
    </span>
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
