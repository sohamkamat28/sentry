/**
 * One clock for the whole console.
 *
 * Every surface used to fetch once on mount and then sit there. A pipeline
 * pass, a probe, a control landing — none of it appeared until the operator
 * reloaded, which means the console reported the estate as it was whenever they
 * last navigated rather than as it is. On an operations floor that is not a
 * stale view, it is a wrong one.
 *
 * Two properties this exists to give:
 *
 *   - **One interval.** Surfaces refresh together, so two panes on the same
 *     screen can never show figures from different moments and invite an
 *     operator to reconcile them.
 *   - **Pause is global and honest.** An operator reading a table does not want
 *     it reordering under the cursor. Pausing stops every query at once and the
 *     freshness readout keeps ageing, so paused never looks like live.
 */

import { useSyncExternalStore } from "react";
import { useQuery } from "@tanstack/react-query";

import { get } from "./api";

/** Fast enough to feel live, slow enough that a Redis GET is the whole cost. */
export const LIVE_MS = 2_000;
/** Derived state — a pipeline pass, a queue — changes at pass granularity. */
export const SLOW_MS = 10_000;

// ── the pause switch ────────────────────────────────────────────────────────
// A module-level store rather than context: the status bar toggles it and every
// surface reads it, and threading a provider through fifteen views to carry one
// boolean buys nothing.
let paused = false;
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((l) => l());
}

export function setPaused(next: boolean): void {
  paused = next;
  emit();
}

export function togglePaused(): void {
  setPaused(!paused);
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function usePaused(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => paused,
    () => false,
  );
}

/**
 * A polled query that respects the global pause.
 *
 * `dataUpdatedAt` is returned rather than hidden because the freshness of a
 * number is part of the number: a count with no indication of when it was read
 * cannot be acted on. Callers render it.
 */
export function useLive<T>(key: string, path: string, intervalMs: number = LIVE_MS) {
  const isPaused = usePaused();
  return useQuery<T>({
    // Include the resource path as well as the semantic prefix. This prevents
    // two variants of a surface (for example a filtered and unfiltered list)
    // from sharing one cache entry while preserving prefix invalidation by key.
    queryKey: [key, path],
    queryFn: () => get<T>(path),
    refetchInterval: isPaused ? false : intervalMs,
    // Keep showing the last good value while a refetch is in flight, so a live
    // surface does not blink through a loading state every two seconds.
    placeholderData: (prev) => prev,
    refetchOnWindowFocus: !isPaused,
  });
}

/**
 * How long ago, in whole seconds, and how alarmed to be about it.
 *
 * The thresholds are deliberately tight. At a 2s interval, fifteen seconds is
 * roughly seven missed polls — long past coincidence — and a minute means the
 * feed is gone rather than slow.
 */
export function freshness(updatedAt: number | undefined, isPaused: boolean) {
  if (!updatedAt) return { secs: null, tone: "text-tx4", label: "—" } as const;
  const secs = Math.max(0, Math.round((Date.now() - updatedAt) / 1000));
  if (isPaused) return { secs, tone: "text-warn", label: `paused ${secs}s` } as const;
  if (secs >= 60) return { secs, tone: "text-crit", label: `stale ${secs}s` } as const;
  if (secs >= 15) return { secs, tone: "text-warn", label: `${secs}s ago` } as const;
  return { secs, tone: "text-tx4", label: `${secs}s ago` } as const;
}
