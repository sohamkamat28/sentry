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
  description: string;
  aliases: string[];
  group: string;
  area: AreaId;
  view: ComponentType;
}

export type AreaId = "monitor" | "estate" | "risk" | "respond" | "system";

export interface Area {
  id: AreaId;
  label: string;
  description: string;
  landing: string;
}

/** Five operator tasks. Specialist views are disclosed only inside their task. */
export const AREAS: Area[] = [
  { id: "monitor", label: "Monitor", description: "What needs attention", landing: "/" },
  { id: "estate", label: "Estate", description: "Inventory and ownership", landing: "/estate" },
  { id: "risk", label: "Risk", description: "Priorities and evidence", landing: "/risk" },
  { id: "respond", label: "Respond", description: "Controls and retirement", landing: "/remediation" },
  { id: "system", label: "System", description: "Automation and audit", landing: "/operations" },
];

export const SURFACES: Surface[] = [
  { path: "/", label: "Triage", description: "Prioritised issues that need an operator", aliases: ["Work queue"], group: "Posture", area: "monitor", view: Triage },
  { path: "/posture", label: "Command Centre", description: "Estate-wide posture and capture coverage", aliases: ["Estate overview", "Posture"], group: "Posture", area: "monitor", view: CommandCentre },
  { path: "/estate", label: "Estate Register", description: "Every known endpoint and its current state", aliases: ["API inventory", "Endpoints"], group: "Posture", area: "estate", view: EstateRegister },
  { path: "/classification", label: "Classification", description: "Lifecycle and governance decisions", aliases: ["Lifecycle"], group: "Posture", area: "estate", view: Classification },

  { path: "/sensor", label: "Sensor Grid", description: "Coverage and health of discovery sources", aliases: ["Data sources", "Discovery"], group: "Detection", area: "monitor", view: SensorGrid },
  { path: "/correlation", label: "Correlation", description: "How endpoints are deduplicated and assigned", aliases: ["Ownership"], group: "Detection", area: "estate", view: Correlation },
  { path: "/behaviour", label: "Behaviour", description: "Behavioural outliers and model coverage", aliases: ["Anomalies"], group: "Detection", area: "risk", view: Behaviour },

  { path: "/risk", label: "Risk Register", description: "CDRI ranking and score evidence", aliases: ["CDRI"], group: "Assessment", area: "risk", view: RiskRegister },
  { path: "/forecast", label: "Forecast", description: "Endpoints trending towards inactivity", aliases: ["Retirement forecast"], group: "Assessment", area: "risk", view: Forecast },
  { path: "/findings", label: "Findings", description: "Control failures mapped to regulatory evidence", aliases: ["Compliance findings"], group: "Assessment", area: "risk", view: Findings },

  { path: "/remediation", label: "Remediation", description: "Proposed and applied gateway protections", aliases: ["Gateway controls"], group: "Response", area: "respond", view: Remediation },
  { path: "/decommission", label: "Decommission", description: "Controlled API sunset workflow", aliases: ["API retirement"], group: "Response", area: "respond", view: Decommission },
  { path: "/zerotrust", label: "Zero-Trust", description: "Authentication, TLS, rate limits, and data controls", aliases: ["Zero-trust posture"], group: "Response", area: "respond", view: ZeroTrust },

  { path: "/threat", label: "Threat", description: "Honeypots, probes, and resurrection signals", aliases: ["Threat signals"], group: "Assurance", area: "risk", view: Threat },
  { path: "/operations", label: "Operations", description: "Scan pipeline, build gate, and team debt", aliases: ["Pipeline & integrations"], group: "Assurance", area: "system", view: Operations },
  { path: "/audit", label: "Audit", description: "Tamper-evident operator activity", aliases: ["Audit log"], group: "Assurance", area: "system", view: Audit },
];

export const GROUPS = ["Posture", "Detection", "Assessment", "Response", "Assurance"];

export function surfacesForArea(area: AreaId): Surface[] {
  return SURFACES.filter((surface) => surface.area === area);
}

export function areaForPath(path: string): Area | undefined {
  const area = SURFACES.find((surface) => surface.path === path)?.area;
  return AREAS.find((candidate) => candidate.id === area);
}
