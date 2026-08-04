import type { ComponentType } from "react";

import { Triage } from "./views/Triage";
import { CommandCentre } from "./views/CommandCentre";
import { EstateRegister } from "./views/EstateRegister";
import { Classification } from "./views/Classification";
import { SensorGrid } from "./views/SensorGrid";
import { Correlation } from "./views/Correlation";
import { Behaviour } from "./views/Behaviour";
import { RiskRegister } from "./views/RiskRegister";
import { Forecast } from "./views/Forecast";
import { Findings } from "./views/Findings";
import { Remediation } from "./views/Remediation";
import { Decommission } from "./views/Decommission";
import { ZeroTrust } from "./views/ZeroTrust";
import { Threat } from "./views/Threat";
import { Operations } from "./views/Operations";
import { Audit } from "./views/Audit";

export interface Surface {
  path: string;
  label: string;
  group: string;
  view: ComponentType;
}

/**
 * Grouped by what an operator is trying to do, not by pipeline stage number.
 *
 * Stage numbers appear in exactly one place — the pipeline readout on
 * Operations — where they carry operational meaning, namely which stage failed.
 * Navigating by them would require knowing the DAG to find anything.
 */
export const SURFACES: Surface[] = [
  // Triage is the landing surface because it is the only one that answers
  // "what needs me now". Command Centre remains as the estate-wide summary an
  // operator reads when nothing is on fire.
  { path: "/", label: "Triage", group: "Posture", view: Triage },
  { path: "/posture", label: "Command Centre", group: "Posture", view: CommandCentre },
  { path: "/estate", label: "Estate Register", group: "Posture", view: EstateRegister },
  { path: "/classification", label: "Classification", group: "Posture", view: Classification },

  { path: "/sensor", label: "Sensor Grid", group: "Detection", view: SensorGrid },
  { path: "/correlation", label: "Correlation", group: "Detection", view: Correlation },
  { path: "/behaviour", label: "Behaviour", group: "Detection", view: Behaviour },

  { path: "/risk", label: "Risk Register", group: "Assessment", view: RiskRegister },
  { path: "/forecast", label: "Forecast", group: "Assessment", view: Forecast },
  { path: "/findings", label: "Findings", group: "Assessment", view: Findings },

  { path: "/remediation", label: "Remediation", group: "Response", view: Remediation },
  { path: "/decommission", label: "Decommission", group: "Response", view: Decommission },
  { path: "/zerotrust", label: "Zero-Trust", group: "Response", view: ZeroTrust },

  { path: "/threat", label: "Threat", group: "Assurance", view: Threat },
  { path: "/operations", label: "Operations", group: "Assurance", view: Operations },
  { path: "/audit", label: "Audit", group: "Assurance", view: Audit },
];

export const GROUPS = ["Posture", "Detection", "Assessment", "Response", "Assurance"];
