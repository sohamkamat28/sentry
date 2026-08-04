import { useMutation, useQueryClient } from "@tanstack/react-query";

import { SLOW_MS, useLive } from "../lib/useLive";
import { post } from "../lib/api";
import { Confirm } from "../components/data/Confirm";
import { Table } from "../components/data/Table";
import { useRoute, routeQuery } from "../lib/router";
import { score, tierClass } from "../lib/format";

interface Control {
  id: number;
  kind: string;
  state: string;
  generator: string;
  kong_plugin_id: string | null;
}

interface Item {
  endpoint_id: string;
  method: string;
  path: string;
  score: number;
  tier: string;
  time_to_breach_d: number | null;
  controls: Control[];
  applied: number;
}

const STATE_TONE: Record<string, string> = {
  APPLIED: "text-ok",
  PROPOSED: "text-tx3",
  JUDGED: "text-info",
  REJECTED: "text-crit",
  REVERTED: "text-tx4",
  FAILED: "text-crit",
  // Dim, like REVERTED: the row is history, not a request. It is still shown
  // and still counted, because `tls-min superseded ×482` is the true account of
  // what this system did and hiding it would leave the surface tidier than the
  // record behind it.
  SUPERSEDED: "text-tx4",
};

/**
 * Proposed and applied gateway controls.
 *
 * Apply and revert are approver actions. An analyst sees the same plan and
 * receives 403 — the button is present and the refusal is shown, because
 * hiding it would teach an analyst the action does not exist rather than that
 * it is not theirs.
 */
export function Remediation() {
  const [path] = useRoute();
  const focus = routeQuery(path).get("endpoint");
  const qc = useQueryClient();

  const { data, isLoading, error } = useLive<{ items: Item[] }>("remediation", "/remediation", SLOW_MS);

  const revert = useMutation({
    mutationFn: (id: number) => post(`/remediation/control/${id}/revert`, { reason: "operator" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["remediation"] }),
  });

  const apply = useMutation({
    mutationFn: (endpointId: string) => post(`/remediation/${endpointId}/apply`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["remediation"] }),
  });

  const rows = (data?.items ?? []).filter((i) => !focus || i.endpoint_id === focus);

  return (
    <div className="space-y-3">
      <Table
        columns={[
          { key: "ep", header: "endpoint", render: (i) => `${i.method} ${i.path}` },
          {
            key: "s",
            header: "CDRI",
            align: "right",
            render: (i) => <span className={tierClass(i.tier)}>{score(i.score)}</span>,
          },
          {
            key: "ctl",
            header: "controls",
            render: (i) =>
              i.controls.length === 0 ? (
                "—"
              ) : (
                // Collapsed by kind and state, with a count.
                //
                // Stage 10 proposes a control per pass, so an endpoint that has
                // been failing to apply `tls-min` for a hundred cycles carried a
                // hundred identical chips. The column ran for several screens
                // and said nothing a single chip and a number does not — and it
                // buried the one `key-auth applied` that mattered.
                <span className="flex flex-wrap gap-1">
                  {Object.entries(
                    i.controls.reduce<Record<string, number>>((acc, c) => {
                      const k = `${c.kind}\u0000${c.state}`;
                      acc[k] = (acc[k] ?? 0) + 1;
                      return acc;
                    }, {}),
                  )
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([k, n]) => {
                      const [kind, state] = k.split("\u0000");
                      return (
                        <span key={k} className={`chip ${STATE_TONE[state] ?? ""}`}>
                          {kind} {state.toLowerCase()}
                          {n > 1 && <span className="ml-1 text-tx4">×{n}</span>}
                        </span>
                      );
                    })}
                </span>
              ),
          },
          {
            key: "act",
            header: "",
            // Behind a confirmation, and naming the endpoint.
            //
            // This was a bare `apply` button in a cell, and revert was an
            // unlabelled `×` inside a chip. Both wrote to a live gateway on one
            // click, and both identified their target by row position — the one
            // thing that moves when a live list refreshes under the cursor.
            render: (i) => (
              <span onClick={(e) => e.stopPropagation()}>
                <Confirm
                  label="apply"
                  disabled={i.controls.every((c) => c.state !== "JUDGED")}
                  question={
                    <>
                      Write the judged controls for <b>{i.method} {i.path}</b> to
                      the live gateway.
                    </>
                  }
                  pending={apply.isPending}
                  error={apply.error}
                  onConfirm={() => apply.mutate(i.endpoint_id)}
                />
              </span>
            ),
          },
          {
            key: "rev",
            header: "",
            render: (i) => {
              const live = i.controls.filter((c) => c.state === "APPLIED");
              if (live.length === 0) return null;
              return (
                <span onClick={(e) => e.stopPropagation()}>
                  <Confirm
                    label="revert"
                    destructive
                    question={
                      <>
                        Remove {live.map((c) => c.kind).join(", ")} from the live
                        gateway for <b>{i.method} {i.path}</b>. The route returns to
                        its unprotected behaviour immediately.
                      </>
                    }
                    pending={revert.isPending}
                    error={revert.error}
                    onConfirm={() => live.forEach((c) => revert.mutate(c.id))}
                  />
                </span>
              );
            },
          },
        ]}
        rows={rows}
        rowKey={(i) => i.endpoint_id}
        loading={isLoading}
        error={error as Error | null}
      />
    </div>
  );
}
