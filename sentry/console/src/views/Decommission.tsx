import { useMutation, useQueryClient } from "@tanstack/react-query";

import { post, ApiError } from "../lib/api";
import { Confirm } from "../components/data/Confirm";
import { Table } from "../components/data/Table";
import { num, vday, when } from "../lib/format";
import { SLOW_MS, useLive } from "../lib/useLive";
import type { Decommission as DecommissionResponse } from "../lib/api-types";

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
  const { data, isLoading, error } = useLive<DecommissionResponse>(
    "decommission",
    "/decommission",
    SLOW_MS,
  );

  const release = useMutation({
    mutationFn: (id: string) =>
      post(`/decommission/${id}/advance`, { reason: "quarantine reviewed" }),
    onSuccess: () => qc.invalidateQueries(),
  });

  const hold = useMutation({
    mutationFn: ({ id, value }: { id: string; value: boolean }) =>
      post(`/decommission/${id}/hold`, {
        hold: value,
        reason: value ? "operator hold" : "operator released hold",
      }),
    onSuccess: () => qc.invalidateQueries(),
  });

  const failure = (release.error ?? hold.error) as ApiError | null;

  return (
    <div className="space-y-3">
      <div className="flex gap-2 text-[11px]">
        {Object.entries(data?.by_phase ?? {}).map(([p, n]) => (
          <span key={p} className={`chip ${PHASE_TONE[p] ?? ""}`}>
            {p} {num(n)}
          </span>
        ))}
      </div>

      {failure && (
        <div
          className={`panel px-3 py-2 text-[12.5px] ${
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
            // The lane rides on the phase rather than taking a column of its
            // own: it qualifies where the endpoint sits in the sequence, and as
            // a column it printed "express" down every row of the table.
            key: "ph",
            header: "phase",
            render: (i) => (
              <span className={PHASE_TONE[i.phase] ?? ""}>
                {i.phase}
                {i.hold && <span className="text-warn"> ·held</span>}
                {(i.express || i.canary) && (
                  <span className="ml-1 text-[11px] text-tx4">
                    {i.express ? "express" : "canary"}
                  </span>
                )}
              </span>
            ),
          },
          { key: "ent", header: "entered", align: "right", render: (i) => vday(i.entered_vday) },
          {
            // Counted, not listed. These resolve to container ids, and printed
            // in full they wrapped to five lines — making one row as tall as
            // five and burying the endpoints with no callers, which are exactly
            // the ones that are safe to release.
            key: "hc",
            header: "hidden callers",
            align: "right",
            render: (i) => {
              const n = i.hidden_callers?.length ?? 0;
              if (n === 0) return <span className="text-tx4">none</span>;
              return (
                <span
                  className="text-crit"
                  title={i.hidden_callers.map((c) => c.service ?? "?").join("\n")}
                >
                  {n}
                </span>
              );
            },
          },
          {
            // One column for the retirement record. The WORM object and the
            // certificate arrive together at Phase D and are both an em dash
            // until then, so two columns spent width saying "not yet" twice.
            key: "worm",
            header: "archive",
            render: (i) =>
              i.worm_object ? (
                <span
                  className="whitespace-nowrap text-ok"
                  title={`${i.worm_object}${i.certificate_id ? `\ncertificate ${i.certificate_id}` : ""}`}
                >
                  retained to {when(i.worm_retain_until).slice(0, 10)}
                </span>
              ) : (
                <span className="text-tx4">—</span>
              ),
          },
          {
            key: "act",
            header: "",
            render: (i) =>
              i.phase === "RETIRED" ? null : (
                // `nowrap`, because the labels are two words. Left to wrap in a
                // narrow cell, "release hold" broke across two lines inside its
                // own border and read as a rendering fault rather than a button.
                <span
                  className="flex flex-nowrap gap-1 whitespace-nowrap"
                  onClick={(event) => event.stopPropagation()}
                >
                  {i.phase === "C" && (
                    <Confirm
                      label="release"
                      destructive
                      disabled={i.hold}
                      pending={release.isPending && release.variables === i.endpoint_id}
                      error={release.variables === i.endpoint_id ? release.error : null}
                      question={
                        <>
                          Release <b>{i.method} {i.path}</b> from quarantine into Phase D.
                          {i.hidden_callers.length > 0
                            ? ` ${i.hidden_callers.length} hidden caller(s) are still recorded; the server will refuse release until policy permits it.`
                            : " The route will be archived before retirement proceeds."}
                        </>
                      }
                      onConfirm={() => release.mutate(i.endpoint_id)}
                    />
                  )}
                  <Confirm
                    label={i.hold ? "release hold" : "hold"}
                    destructive={!i.hold}
                    pending={hold.isPending && hold.variables?.id === i.endpoint_id}
                    error={hold.variables?.id === i.endpoint_id ? hold.error : null}
                    question={
                      i.hold
                        ? <>Release the operator hold on <b>{i.method} {i.path}</b> so its sunset clock may continue.</>
                        : <>Pause the sunset clock for <b>{i.method} {i.path}</b>.</>
                    }
                    onConfirm={() => hold.mutate({ id: i.endpoint_id, value: !i.hold })}
                  />
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
