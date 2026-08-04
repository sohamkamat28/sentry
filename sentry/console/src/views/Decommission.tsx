import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { get, post, ApiError } from "../lib/api";
import { Table } from "../components/data/Table";
import { num, vday, when } from "../lib/format";

interface Item {
  endpoint_id: string;
  method: string;
  path: string;
  phase: string;
  express: boolean;
  canary: boolean;
  canary_split: number | null;
  entered_vday: number;
  phase_vday: number | null;
  hold: boolean;
  hold_reason: string | null;
  hidden_callers: { service?: string }[];
  worm_object: string | null;
  worm_retain_until: string | null;
  certificate_id: string | null;
}

const PHASE_TONE: Record<string, string> = {
  NONE: "text-tx4",
  A: "text-info",
  B: "text-info",
  C: "text-warn",
  D: "text-warn",
  RETIRED: "text-tx3",
  REVERTED: "text-tx4",
};

/**
 * The sunset sequence.
 *
 * Phase D is the only transition with a button, because it is the only one that
 * does not happen on the clock. Archival and a 410 are irreversible in effect,
 * so the last step needs somebody to have read the hidden-caller column first —
 * which is why that column sits next to the button.
 */
export function Decommission() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["decommission"],
    queryFn: () => get<{ vday: number; by_phase: Record<string, number>; items: Item[] }>(
      "/decommission",
    ),
  });

  const release = useMutation({
    mutationFn: (id: string) =>
      post(`/decommission/${id}/advance`, { reason: "quarantine reviewed" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["decommission"] }),
  });

  const hold = useMutation({
    mutationFn: (id: string) => post(`/decommission/${id}/hold`, { hold: true, reason: "operator" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["decommission"] }),
  });

  const failure = (release.error ?? hold.error) as ApiError | null;

  return (
    <div className="space-y-3">
      <div className="flex gap-2 text-[11.5px]">
        {Object.entries(data?.by_phase ?? {}).map(([p, n]) => (
          <span key={p} className={`chip ${PHASE_TONE[p] ?? ""}`}>
            {p} {num(n)}
          </span>
        ))}
      </div>

      {failure && (
        <div
          className={`panel px-3 py-2 text-[12px] ${
            failure.forbidden ? "border-warn text-warn" : "border-crit text-crit"
          }`}
        >
          {failure.forbidden
            ? `${failure.message} — releasing into Phase D requires approver`
            : failure.message}
        </div>
      )}

      <Table
        columns={[
          { key: "ep", header: "endpoint", render: (i) => `${i.method} ${i.path}` },
          {
            key: "ph",
            header: "phase",
            render: (i) => (
              <span className={PHASE_TONE[i.phase] ?? ""}>
                {i.phase}
                {i.hold && <span className="text-warn"> ·held</span>}
              </span>
            ),
          },
          {
            key: "path",
            header: "path",
            render: (i) => (i.express ? "express" : i.canary ? "canary" : "standard"),
          },
          { key: "ent", header: "entered", align: "right", render: (i) => vday(i.entered_vday) },
          {
            key: "hc",
            header: "hidden callers",
            render: (i) =>
              i.hidden_callers?.length ? (
                <span className="text-crit">
                  {i.hidden_callers.map((c) => c.service ?? "?").join(" ")}
                </span>
              ) : (
                "none"
              ),
          },
          {
            key: "worm",
            header: "archive",
            render: (i) =>
              i.worm_object ? (
                <span className="text-ok" title={i.worm_object}>
                  retained to {when(i.worm_retain_until).slice(0, 10)}
                </span>
              ) : (
                "—"
              ),
          },
          {
            key: "cert",
            header: "certificate",
            render: (i) => (i.certificate_id ? i.certificate_id : "—"),
          },
          {
            key: "act",
            header: "",
            render: (i) =>
              i.phase === "RETIRED" ? null : (
                <span className="flex gap-1">
                  {i.phase === "C" && (
                    <button className="btn" onClick={() => release.mutate(i.endpoint_id)}>
                      release
                    </button>
                  )}
                  {!i.hold && (
                    <button className="btn" onClick={() => hold.mutate(i.endpoint_id)}>
                      hold
                    </button>
                  )}
                </span>
              ),
          },
        ]}
        rows={data?.items}
        rowKey={(i) => i.endpoint_id}
        loading={isLoading}
        error={error as Error | null}
        empty="nothing is enrolled"
      />
    </div>
  );
}
