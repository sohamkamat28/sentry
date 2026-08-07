/**
 * The published site's data source.
 *
 * `tools/snapshot.py` freezes a real run of the control plane into
 * `public/data/snapshot.json`, keyed by the exact route the console asks for.
 * In a static build `api.ts` resolves reads from here instead of `fetch`, so
 * every view keeps its existing query without knowing which mode it is in.
 *
 * The recording is deliberate rather than a compromise hidden in the plumbing.
 * The kernel agent needs a privileged Linux host with BTF and cannot run on a
 * managed one, so a site that claimed to be live would permanently report its
 * own sensor as down. `capturedAt` is rendered in the shell for that reason —
 * a reader is told they are looking at a recording and when it was taken.
 */

export interface Snapshot {
  captured_at: string;
  vday: number | null;
  routes: Record<string, unknown>;
}

export const STATIC_MODE: boolean = import.meta.env.VITE_STATIC === "1";

let cache: Promise<Snapshot> | null = null;

/** Loaded once and shared. Every view resolves against the same recording. */
export function load(): Promise<Snapshot> {
  if (cache === null) {
    cache = fetch(`${import.meta.env.BASE_URL}data/snapshot.json`).then((r) => {
      if (!r.ok) throw new Error(`snapshot unavailable (${r.status})`);
      return r.json() as Promise<Snapshot>;
    });
  }
  return cache;
}

/**
 * Resolve one route out of the recording.
 *
 * Throws when a route is absent rather than returning an empty object. A view
 * handed `{}` renders "no rows" and tells the reader the estate is clean — the
 * exact confusion this product exists to refuse, reproduced in its own console.
 */
export async function get<T>(path: string): Promise<T> {
  const snap = await load();
  if (!(path in snap.routes)) {
    throw new Error(`not in the recording: ${path}`);
  }
  return snap.routes[path] as T;
}

export async function capturedAt(): Promise<string> {
  return (await load()).captured_at;
}
