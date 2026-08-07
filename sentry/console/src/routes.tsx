import type { ComponentType } from "react";

import { Overview } from "./views/Overview";
import { Walkthrough } from "./views/Walkthrough";
import { Explore } from "./views/Explore";
import { HowItWorks } from "./views/HowItWorks";

export interface Surface {
  path: string;
  label: string;
  /** Shown under the label in the mobile menu; also the document subtitle. */
  blurb: string;
  view: ComponentType;
}

/**
 * Four destinations.
 *
 * There were fifteen, named after the pipeline stage that produced each one —
 * Correlation, Classification, CDRI, Zero-Trust, Decommission. That is the
 * shape of the system, and it is the wrong shape for anyone arriving at it: it
 * asked a reader to learn an architecture before they could learn what the
 * product does, and the architecture bought them nothing.
 *
 * These four are the questions a visitor actually turns up with, in the order
 * they ask them. The fourteen stages are still there underneath; they are
 * simply no longer something anyone has to navigate.
 */
export const SURFACES: Surface[] = [
  {
    path: "/",
    label: "Overview",
    blurb: "What this is, in one screen",
    view: Overview,
  },
  {
    path: "/walkthrough",
    label: "Walkthrough",
    blurb: "Follow one API end to end",
    view: Walkthrough,
  },
  {
    path: "/explore",
    label: "Explore",
    blurb: "Every API we found",
    view: Explore,
  },
  {
    path: "/how",
    label: "How it works",
    blurb: "Architecture and engineering",
    view: HowItWorks,
  },
];
