import { useSyncExternalStore } from "react";

import { navigate } from "./router";

/**
 * A guided read of the console, for someone who has never seen it.
 *
 * The tour drives the real surfaces rather than replacing them with a story.
 * An earlier attempt built four purpose-made narrative screens and deleted the
 * sixteen expert ones; that read well and threw away the thing worth showing.
 * Here every step navigates to a surface that already exists and says what to
 * look at, so a visitor finishes knowing how to use the console instead of
 * having been shown a substitute for it.
 *
 * The copy states no figures. The screen behind it already carries them, and a
 * number written here would drift the moment the estate was re-captured — the
 * one failure mode this project does not tolerate.
 */

export interface TourStep {
  path: string;
  title: string;
  body: string;
}

export const TOUR_STEPS: TourStep[] = [
  {
    path: "/",
    title: "A bank does not know what APIs it has",
    body: "Every tile above is an endpoint its own systems are serving right now. The four coloured figures are the problem: how many are dangerous, dead, unregistered, and unowned.",
  },
  {
    path: "/sensor",
    title: "Nothing was installed in the applications",
    body: "A probe runs inside the Linux kernel, attached to the function every TLS library calls to write a request. It reads traffic before encryption without the application knowing. The exclusive column counts endpoints only this probe found — no gateway or repository lists them.",
  },
  {
    path: "/estate",
    title: "Everything it found, in one register",
    body: "One row per endpoint, with what it returns. Sensitive fields were read by name from kernel memory; the values themselves were never captured, which is why you can see that an endpoint leaks an Aadhaar number without this console ever storing one.",
  },
  {
    path: "/classification",
    title: "Two questions, asked separately",
    body: "Is anyone calling it, and does anyone own it. They are independent: a heavily used API can have no owner, and a retired one can still be somebody's responsibility. The matrix is every combination — select a cell to open that slice.",
  },
  {
    path: "/risk",
    title: "How dangerous, and why",
    body: "CDRI scores each endpoint from 0 to 1. Expand any row and the six weighted factors are listed with their contributions, and they add to the total. A score an operator is asked to act on has to be decomposable, or it is just an assertion.",
  },
  {
    path: "/findings",
    title: "What it actually breaks",
    body: "Each control failure is mapped to the specific regulatory clause it violates, across five frameworks. Some clauses come back satisfied — a tool that only ever finds fault is not measuring anything.",
  },
  {
    path: "/zerotrust",
    title: "Fixing it without breaking the callers",
    body: "Controls are proposed, then replayed against real captured traffic and measured before anyone may apply them. Press preview on any row to see what a change would do. This is a recording, so the console refuses the write rather than pretending to act.",
  },
  {
    path: "/threat",
    title: "And when it comes back",
    body: "A retired API often reappears under a new path, which silently voids every control placed on the old one. Endpoints are fingerprinted so the return is caught and scored — that is what the resurrection entries here are.",
  },
];

const SEEN_KEY = "sentry.visited";

export function hasVisited(): boolean {
  try {
    return localStorage.getItem(SEEN_KEY) === "1";
  } catch {
    // Private-mode Safari throws rather than returning null. Treating that as
    // "already visited" is the kinder failure: no overlay on every load.
    return true;
  }
}

export function markVisited() {
  try {
    localStorage.setItem(SEEN_KEY, "1");
  } catch {
    /* Nothing to do; the overlay is dismissible either way. */
  }
}

let index: number | null = null;
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((fn) => fn());
}

function show(next: number) {
  index = next;
  navigate(TOUR_STEPS[next].path);
  emit();
}

export function startTour() {
  markVisited();
  show(0);
}

export function endTour() {
  index = null;
  emit();
}

export function stepTo(next: number) {
  if (next < 0) return;
  if (next >= TOUR_STEPS.length) {
    endTour();
    return;
  }
  show(next);
}

function subscribe(fn: () => void) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function snapshot() {
  return index;
}

/** The active step, or null when the tour is not running. */
export function useTourStep(): number | null {
  return useSyncExternalStore(subscribe, snapshot, () => null);
}
