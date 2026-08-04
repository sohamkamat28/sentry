import { useMutation, useQueryClient } from "@tanstack/react-query";

import { SLOW_MS, useLive } from "../lib/useLive";
import { post, ApiError } from "../lib/api";
import type { Operations as Ops, OperationsLeaderboard as Leaderboard, Pipeline } from "../lib/api-types";
import { Metric } from "../components/data/Metric";
import { Table } from "../components/data/Table";
import { num, score, when } from "../lib/format";

/**
 * The loop: schedule, pipeline health, the build gate, and team debt.
 *
 * Stage numbers appear here and nowhere else in the navigation, because this is
 * the one place they carry operational meaning — namely which stage failed.
 */
export function Operations() {
  const qc = useQueryClient();
  const ops = useLive<Ops>("operations", "/operations", SLOW_MS);
  const board = useLive<Leaderboard>("leaderboard", "/operations/leaderboard", SLOW_MS);
  const pipe = useLive<Pipeline>("pipeline", "/pipeline", SLOW_MS);

  const scan = useMutation({
    mutationFn: () => post("/operations/scan", {}),
    onSuccess: () => {
      qc.invalidateQueries();
    },
  });

  const failure = scan.error as ApiError | null;
  const latest = pipe.data?.run ?? null;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Metric
          label="Scheduler"
          value={ops.isLoading ? undefined : ops.data?.scheduler_enabled ? "on" : "off"}
          tone={ops.data?.scheduler_enabled ? "ok" : "warn"}
          loading={ops.isLoading}
          sub={`every ${ops.data?.scan_interval_vhours ?? "—"} vhours`}
        />
        <Metric
          label="Last run"
          value={
            pipe.isLoading
              ? undefined
              : latest
                ? latest.ok === null
                  ? "running"
                  : latest.ok
                    ? "ok"
                    : "partial"
                : undefined
          }
          tone={latest?.ok === false ? "crit" : latest?.ok ? "ok" : "dim"}
          loading={pipe.isLoading}
          sub={latest ? when(latest.started_at) : undefined}
        />
        <Metric
          label="SIEM"
          value={ops.isLoading ? undefined : ops.data?.siem.configured ? ops.data.siem.format : "off"}
          tone={ops.data?.siem.configured ? "ok" : "dim"}
          loading={ops.isLoading}
          sub={ops.data?.siem.host ?? undefined}
        />
        <Metric
          label="Gate events"
          value={ops.isLoading ? undefined : ops.data?.gate_events.length}
          loading={ops.isLoading}
          sub={
            ops.data?.gate_events.filter((g) => !g.passed).length
              ? `${ops.data.gate_events.filter((g) => !g.passed).length} failed`
              : undefined
          }
        />
      </div>

      <div>
        <button className="btn" disabled={scan.isPending} onClick={() => scan.mutate()}>
          {scan.isPending ? "scanning…" : "run scan now"}
        </button>
        {failure && (
          <span className={`ml-2 text-[12px] ${failure.forbidden ? "text-warn" : "text-crit"}`}>
            {failure.forbidden ? `${failure.message} — scan requires analyst` : failure.message}
          </span>
        )}
      </div>

      {latest && (
        <section>
          <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">
            Pipeline — run {latest.id}
          </h2>
          <Table
            columns={[
              {
                key: "s",
                header: "stage",
                render: (s) =>
                  `${String(s.stage).padStart(2, "0")} ${s.name || (ops.data?.stages?.[String(s.stage)] ?? "")}`,
              },
              {
                key: "ok",
                header: "result",
                // Three states, not two. A stage the run has not reached yet
                // carries ok === null, and folding that into the falsy branch
                // labelled every unreached stage "failed" — a cycle caught
                // mid-flight would have read as a pipeline collapsing.
                render: (s) => (
                  <span
                    className={s.ok === null ? "text-tx3" : s.ok ? "text-ok" : "text-crit"}
                  >
                    {s.ok === null ? "—" : s.ok ? "ok" : (s.error ?? "failed")}
                  </span>
                ),
              },
              { key: "r", header: "records", align: "right", render: (s) => num(s.records) },
              { key: "d", header: "ms", align: "right", render: (s) => num(s.duration_ms) },
            ]}
            rows={pipe.data?.stages ?? []}
            rowKey={(s) => String(s.stage)}
            loading={pipe.isLoading}
          />
        </section>
      )}

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">Security debt</h2>
        <Table
          columns={[
            { key: "t", header: "team", render: (t) => t.team },
            { key: "d", header: "debt", align: "right", render: (t) => score(t.debt, 2) },
            { key: "e", header: "endpoints", align: "right", render: (t) => num(t.endpoints) },
            {
              key: "res",
              header: "ownership",
              render: (t) =>
                t.owner_resolved === false ? (
                  <span className="text-warn">unresolved</span>
                ) : (
                  <span className="text-ok">resolved</span>
                ),
            },
          ]}
          rows={board.data?.teams}
          rowKey={(t) => t.team}
          loading={board.isLoading}
          error={board.error as Error | null}
        />
      </section>

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">Build gate</h2>
        <Table
          columns={[
            { key: "r", header: "repo", render: (g) => g.repo },
            { key: "pr", header: "pr", align: "right", render: (g) => `#${g.pr}` },
            { key: "sha", header: "sha", render: (g) => g.sha },
            {
              key: "p",
              header: "result",
              render: (g) => (
                <span className={g.passed ? "text-ok" : "text-crit"}>
                  {g.passed ? "passed" : `${g.checks.filter((c) => !c.passed).length} failed`}
                </span>
              ),
            },
            { key: "at", header: "at", render: (g) => when(g.at) },
          ]}
          rows={ops.data?.gate_events}
          rowKey={(g) => `${g.repo}:${g.pr}:${g.sha}`}
          loading={ops.isLoading}
          error={ops.error as Error | null}
          empty="no builds have been submitted"
        />
      </section>
    </div>
  );
}
