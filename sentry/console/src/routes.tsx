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

// `/` is Command Centre, not Triage. Triage is a three-pane work queue whose
// first screen is `resurrection 1.00`, `phase C held` and `DORMANT × SHADOW` —
// correct for an operator mid-shift, and unreadable as a first impression to
// anyone who has not worked here. Command Centre answers "what is this" with
// figures and plain labels, and Triage is one click away for the people who
// actually want it. The rail order is unchanged.
export const SURFACES: Surface[] = [
  { path: "/triage", label: "Triage", description: "What needs a decision right now", aliases: ["Work queue"], group: "Posture", area: "monitor", view: Triage },
  { path: "/", label: "Command Centre", description: "The whole estate in one screen", aliases: ["Estate overview", "Posture"], group: "Posture", area: "monitor", view: CommandCentre },
  { path: "/estate", label: "Estate Register", description: "Every API we found, and what it returns", aliases: ["API inventory", "Endpoints"], group: "Posture", area: "estate", view: EstateRegister },
  { path: "/classification", label: "Classification", description: "Which APIs are dead, and which have no owner", aliases: ["Lifecycle"], group: "Posture", area: "estate", view: Classification },

  { path: "/sensor", label: "Sensor Grid", description: "Where the evidence comes from, and is it healthy", aliases: ["Data sources", "Discovery"], group: "Detection", area: "monitor", view: SensorGrid },
  { path: "/correlation", label: "Correlation", description: "How duplicates are merged and owners resolved", aliases: ["Ownership"], group: "Detection", area: "estate", view: Correlation },
  { path: "/behaviour", label: "Behaviour", description: "APIs behaving unlike themselves", aliases: ["Anomalies"], group: "Detection", area: "risk", view: Behaviour },

  { path: "/risk", label: "Risk Register", description: "How dangerous each API is, and why", aliases: ["CDRI"], group: "Assessment", area: "risk", view: RiskRegister },
  { path: "/forecast", label: "Forecast", description: "Which APIs are dying, and how soon", aliases: ["Retirement forecast"], group: "Assessment", area: "risk", view: Forecast },
  { path: "/findings", label: "Findings", description: "What law each failure breaks", aliases: ["Compliance findings"], group: "Assessment", area: "risk", view: Findings },

  { path: "/remediation", label: "Remediation", description: "Protections proposed, measured, then applied", aliases: ["Gateway controls"], group: "Response", area: "respond", view: Remediation },
  { path: "/decommission", label: "Decommission", description: "Switching an API off without breaking its callers", aliases: ["API retirement"], group: "Response", area: "respond", view: Decommission },
  { path: "/zerotrust", label: "Zero-Trust", description: "What protection each API is missing", aliases: ["Zero-trust posture"], group: "Response", area: "respond", view: ZeroTrust },

  { path: "/threat", label: "Threat", description: "Retired APIs coming back, and who is probing them", aliases: ["Threat signals"], group: "Assurance", area: "risk", view: Threat },
  { path: "/operations", label: "Operations", description: "The scan pipeline, the build gate, and who owes what", aliases: ["Pipeline & integrations"], group: "Assurance", area: "system", view: Operations },
  { path: "/audit", label: "Audit", description: "Every action taken, in a chain that cannot be edited", aliases: ["Audit log"], group: "Assurance", area: "system", view: Audit },
];

export const GROUPS = ["Posture", "Detection", "Assessment", "Response", "Assurance"];

export function surfacesForArea(area: AreaId): Surface[] {
  return SURFACES.filter((surface) => surface.area === area);
}

export function areaForPath(path: string): Area | undefined {
  const area = SURFACES.find((surface) => surface.path === path)?.area;
  return AREAS.find((candidate) => candidate.id === area);
}
