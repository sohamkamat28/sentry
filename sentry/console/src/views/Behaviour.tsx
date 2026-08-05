
import { SLOW_MS, useLive } from "../lib/useLive";
import { Metric } from "../components/data/Metric";
import { Table } from "../components/data/Table";
import { num, score } from "../lib/format";
import type { Behaviour as B } from "../lib/api-types";

/**
 * Anomaly scores, and the endpoints the model refused to score.
 *
 * `excluded_insufficient_history` is shown beside the flagged count because a
 * model that scored a fraction of the estate has not cleared the rest.
 */
export function Behaviour() {
  const { data, isLoading, error } = useLive<B>("behaviour", "/behaviour", SLOW_MS);

  const patterns = Object.entries(data?.patterns ?? {}).sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-4">
      {data && !data.fitted && (
        <div className="panel border-warn px-3 py-2 text-[12px] text-warn">
          {data.withheld}
        </div>
      )}

      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        {/* flagged and scored arrive as null when the model did not fit, so the
            tile renders the em dash rather than a zero that reads as "checked,
            none found". */}
        <Metric
          label="Flagged"
          value={isLoading || error ? undefined : data?.flagged}
          tone={data?.flagged ? "warn" : "ok"}
          loading={isLoading}
          error={error}
        />
        <Metric label="Scored" value={isLoading || error ? undefined : data?.scored} loading={isLoading} error={error} />
        <Metric
          label="Fitted on"
          value={isLoading || error ? undefined : data?.fitted_on}
          tone={data?.fitted ? "ok" : "warn"}
          loading={isLoading}
          error={error}
          sub={`needs ${data?.min_fit_endpoints ?? "—"}`}
        />
        <Metric
          label="Patterns"
          value={isLoading || error ? undefined : patterns.length}
          loading={isLoading}
          error={error}
        />
      </div>

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">Patterns</h2>
        <Table
          columns={[
            { key: "p", header: "pattern", render: (p) => p[0] },
            { key: "n", header: "endpoints", align: "right", render: (p) => num(p[1]) },
          ]}
          rows={patterns}
          rowKey={(p) => p[0]}
          loading={isLoading}
          error={error as Error | null}
        />
      </section>

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">Flagged</h2>
        <Table
          columns={[
            { key: "ep", header: "endpoint", render: (i) => i.endpoint_id },
            { key: "s", header: "score", align: "right", render: (i) => score(i.score) },
            {
              key: "d",
              header: "isolation depth",
              align: "right",
              render: (i) => score(i.isolation_depth, 1),
            },
            { key: "p", header: "patterns", render: (i) => i.patterns.join(" ") || "—" },
          ]}
          rows={data?.items}
          rowKey={(i) => i.endpoint_id}
          loading={isLoading}
          error={error as Error | null}
          empty="no endpoint scored above the contamination threshold"
        />
      </section>
    </div>
  );
}
