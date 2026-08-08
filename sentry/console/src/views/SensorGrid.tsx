import { SLOW_MS, useLive } from "../lib/useLive";
import { Metric } from "../components/data/Metric";
import { Table } from "../components/data/Table";
import { num, vday } from "../lib/format";
import type { Discovery } from "../lib/api-types";

/**
 * Where endpoints came from.
 *
 * `exclusive` is the column that matters: an endpoint only the kernel saw is
 * one no gateway route and no repository declares, which is the definition of
 * shadow rather than an inference about it.
 */
export function SensorGrid() {
  const { data, isLoading, error } = useLive<Discovery>("discovery", "/discovery", SLOW_MS);

  const unreachable = (data?.sources ?? []).filter((s) => !s.healthy);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Metric label="vday" value={isLoading || error ? undefined : vday(data?.vday)} loading={isLoading} error={error} />
        <Metric
          label="Sources"
          value={isLoading || error ? undefined : data?.sources.length}
          loading={isLoading}
          error={error}
        />
        <Metric
          label="Shadow"
          value={isLoading || error ? undefined : data?.shadow_count}
          tone={data?.shadow_count ? "crit" : "ok"}
          loading={isLoading}
          error={error}
          degraded={data ? !data.shadow_reliable : false}
        />
        <Metric
          label="Unreachable"
          value={isLoading || error ? undefined : unreachable.length}
          tone={unreachable.length ? "crit" : "ok"}
          loading={isLoading}
          error={error}
          sub={unreachable.map((s) => s.source).join(" ") || undefined}
        />
      </div>

      {data && !data.shadow_reliable && (
        <div className="panel border-crit px-3 py-2 text-[12px] text-crit">
          gateway unreachable — shadow is withheld, not zero
        </div>
      )}

      <Table
        columns={[
          { key: "src", header: "source", render: (s) => s.source.toUpperCase() },
          { key: "ep", header: "endpoints", align: "right", render: (s) => num(s.endpoints) },
          {
            key: "ex",
            header: "exclusive",
            align: "right",
            render: (s) => (
              <span className={s.exclusive ? "text-warn" : ""}>{num(s.exclusive)}</span>
            ),
          },
          {
            key: "obs",
            header: "observations 24v",
            align: "right",
            render: (s) => num(s.observations_24v),
          },
          {
            key: "h",
            header: "health",
            render: (s) => (
              <span className={s.healthy ? "text-ok" : "text-crit"}>
                {s.healthy ? "ok" : "unreachable"}
              </span>
            ),
          },
        ]}
        rows={data?.sources}
        rowKey={(s) => s.source}
        loading={isLoading}
        error={error as Error | null}
      />
    </div>
  );
}
