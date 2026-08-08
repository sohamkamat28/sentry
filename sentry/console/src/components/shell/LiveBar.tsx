import { useEffect, useRef, useState } from "react";

import {
  DEV_TOKENS,
  getDevToken,
  logout,
  OIDC_ENABLED,
  setDevToken,
  useAuth,
} from "../../lib/auth";
import { num, score, vday } from "../../lib/format";
import { STATIC_MODE, capturedAt } from "../../lib/snapshot";
import { LIVE_MS, freshness, togglePaused, useLive, usePaused } from "../../lib/useLive";
import type { Live, System } from "../../lib/api-types";

/**
 * Always-visible state, and how old it is.
 *
 * The bar this replaces showed five counts refreshed every ten seconds with no
 * indication of when they were read. A number on an operations screen with no
 * age attached cannot be acted on: the operator cannot tell a quiet estate from
 * a dead feed, which is the same confusion the whole product is built to
 * refuse. Freshness is therefore rendered beside the figures, not in a tooltip.
 *
 * The capture rate is computed here from successive `/live` polls rather than
 * asked for, because the counter is monotonic and a rate is a difference over a
 * known interval. Deriving it in the console keeps the endpoint a plain read.
 */
export function LiveBar() {
  const paused = usePaused();
  const auth = useAuth();
  const live = useLive<Live>("live", "/live", LIVE_MS);
  const system = useLive<System>("system", "/system", 10_000);

  const rate = useCaptureRate(live.data?.observed?.total, live.dataUpdatedAt);
  const fresh = freshness(live.dataUpdatedAt, paused);

  // A cache that could not answer is not an idle estate. `/live` distinguishes
  // them and so does this: the figure is withheld rather than shown as zero.
  const blind = live.data?.source === "unavailable";

  return (
    <div className="flex shrink-0 items-center gap-4 overflow-x-auto border-b border-line bg-panel/60 px-4 py-2 text-[11px] backdrop-blur">
      <Item label="vday" value={vday(live.data?.vday ?? system.data?.vday)} />
      <Item label="endpoints" value={num(system.data?.endpoints)} />
      <Item
        label="captured"
        value={blind ? undefined : num(live.data?.observed?.total)}
        title={
          blind
            ? "the capture cache could not be read; this is not a count of zero"
            : `source: ${live.data?.source ?? "—"}`
        }
      />
      <Item
        label="rate"
        value={blind || rate === null ? undefined : `${rate.toFixed(1)}/s`}
      />
      <Item label="zombie" value={num(system.data?.lifecycle?.ZOMBIE ?? undefined)} />
      <Item label="shadow" value={num(system.data?.governance?.SHADOW ?? undefined)} />
      <Item label="cdri" value={score(system.data?.mean_cdri)} />

      {blind && (
        <span className="text-warn" title="Redis is configured but not answering">
          capture cache unreadable — counts withheld, not zero
        </span>
      )}
      {live.error && (
        <span className="text-crit">control plane unreachable — figures are stale</span>
      )}

      {/* Per-component health is no longer carried here. `live.error` above
          still reports a control plane that cannot be reached at all, and the
          per-source state — which sensor wrote what, and when it last did —
          is a column on the Sensor Grid. */}

      <span className="ml-auto flex items-center gap-3">
        {live.data?.pipeline?.running && (
          <span className="text-tx2" title="a pipeline cycle is in flight">
            ● scan {live.data.pipeline.stages_done}/{live.data.pipeline.stages_total}
          </span>
        )}

        {/*
          A recording must never present itself as a feed. `live` and a
          freshness counter are true statements about a polled control plane and
          false ones about a frozen capture — and on the published site the
          counter would climb into days while the bar still said `live`. The
          capture date replaces both, which is the same claim the rest of the
          console makes about its own data: say when it was read.
        */}
        {STATIC_MODE ? (
          <RecordedChip />
        ) : (
          <>
            <button
              className={`chip ${paused ? "border-warn text-warn" : "text-tx3"}`}
              type="button"
              onClick={togglePaused}
              title={
                paused
                  ? "resume polling"
                  : "pause polling — a table that reorders under the cursor cannot be read"
              }
            >
              {paused ? "paused" : "live"}
            </button>

            <span className={fresh.tone} title="age of the newest reading">
              {fresh.label}
            </span>
          </>
        )}

        {OIDC_ENABLED ? (
          <span className="flex shrink-0 items-center gap-1.5">
            <span className="text-tx4">identity</span>
            <span className="text-tx2" title={auth.roles.join(", ")}>
              {auth.subject ?? "operator"}
            </span>
            <button className="chip text-tx3" type="button" onClick={logout}>logout</button>
          </span>
        ) : (
          <span className="flex shrink-0 items-center gap-1.5">
            <span className="text-tx4">role</span>
            <select
              aria-label="development role"
              className="border border-line bg-bg px-1.5 py-0.5 text-[11px]"
              value={getDevToken()}
              onChange={(e) => {
                setDevToken(e.target.value);
                window.location.reload();
              }}
            >
              {DEV_TOKENS.map((t) => (
                <option key={t} value={t}>
                  {t.replace("dev-", "")}
                </option>
              ))}
            </select>
          </span>
        )}
      </span>
    </div>
  );
}

/**
 * Captures per wall second, from the change between two polls.
 *
 * Returns null rather than zero until a second reading exists, and discards a
 * negative delta: the counters carry a TTL and reset at a vday boundary, and a
 * reset rendered as a rate would read as the sensor having gone backwards.
 */
function useCaptureRate(total: number | undefined, updatedAt: number | undefined) {
  const [rate, setRate] = useState<number | null>(null);
  const previous = useRef<{ total: number; at: number } | null>(null);

  useEffect(() => {
    if (total === undefined || !updatedAt) return;
    const prev = previous.current;
    if (prev && updatedAt !== prev.at) {
      const dt = (updatedAt - prev.at) / 1000;
      const dv = total - prev.total;
      if (dt > 0 && dv >= 0) setRate(dv / dt);
      else if (dv < 0) setRate(null); // counter rolled at a vday boundary
    }
    if (!prev || updatedAt !== prev.at) previous.current = { total, at: updatedAt };
  }, [total, updatedAt]);

  return rate;
}

/**
 * Names the capture instead of implying a feed.
 *
 * The date comes out of the recording itself rather than the build, so it
 * cannot drift from the data beside it: re-record and this moves, edit the
 * console and it does not.
 */
function RecordedChip() {
  const [at, setAt] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    void capturedAt().then((iso) => {
      if (live) setAt(iso.slice(0, 10));
    });
    return () => {
      live = false;
    };
  }, []);

  return (
    <span
      className="chip border-line text-tx2"
      title="a frozen capture of a real run — the control plane is not being polled"
    >
      recorded {at ?? "…"}
    </span>
  );
}

function Item({
  label,
  value,
  title,
}: {
  label: string;
  value?: string;
  title?: string;
}) {
  return (
    <span className="flex items-baseline gap-1.5 whitespace-nowrap" title={title}>
      <span className="font-sans text-tx4">{label}</span>
      {/* Absent renders as an em dash, never as zero. */}
      <span className="num font-mono text-tx1">{value ?? "—"}</span>
    </span>
  );
}
