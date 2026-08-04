
import { SLOW_MS, useLive } from "../lib/useLive";
import { Metric } from "../components/data/Metric";
import { Table } from "../components/data/Table";
import { num } from "../lib/format";
import type { Correlation as C } from "../lib/types";

const RUNG_LABEL: Record<string, string> = {
  codeowners: "CODEOWNERS",
  "git-blame": "git blame",
  "gateway-metadata": "gateway tag",
  unresolved: "unresolved",
};

const RUNG_CONFIDENCE: Record<string, string> = {
  codeowners: "1.00",
  "git-blame": "0.75",
  "gateway-metadata": "0.40",
  unresolved: "0.00",
};

/** Sightings collapsed to endpoints, and who owns them. */
export function Correlation() {
  const { data, isLoading, error } = useLive<C>("correlation", "/correlation", SLOW_MS);

  const rungs = Object.entries(data?.ownership.resolved_by ?? {}).map(([rung, n]) => ({
    rung,
    n,
  }));

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Metric label="Sightings" value={isLoading ? undefined : data?.sightings} loading={isLoading} />
        <Metric label="Endpoints" value={isLoading ? undefined : data?.endpoints} loading={isLoading} />
        <Metric
          label="Dedup ratio"
          value={isLoading ? undefined : data?.dedup_ratio}
          loading={isLoading}
          sub="sightings per endpoint"
        />
        <Metric
          label="Unreachable owners"
          value={isLoading ? undefined : data?.ownership.unreachable}
          tone={data?.ownership.unreachable ? "warn" : "ok"}
          loading={isLoading}
          sub="departed, escalated"
        />
      </div>

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">Ownership ladder</h2>
        <Table
          columns={[
            { key: "r", header: "rung", render: (r) => RUNG_LABEL[r.rung] ?? r.rung },
            {
              key: "c",
              header: "confidence",
              align: "right",
              render: (r) => RUNG_CONFIDENCE[r.rung] ?? "—",
            },
            { key: "n", header: "endpoints", align: "right", render: (r) => num(r.n) },
          ]}
          rows={rungs}
          rowKey={(r) => r.rung}
          loading={isLoading}
          error={error as Error | null}
        />
      </section>
    </div>
  );
}
