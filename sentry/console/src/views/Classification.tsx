
import { SLOW_MS, useLive } from "../lib/useLive";
import { Metric } from "../components/data/Metric";
import { Table } from "../components/data/Table";
import { navigate } from "../lib/router";
import { governanceClass, lifecycleClass, num } from "../lib/format";
import type { Classification as C } from "../lib/api-types";

export function Classification() {
  const { data, isLoading, error } = useLive<C>("classification", "/classification", SLOW_MS);

  const conf = data?.confidence ?? {};

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Metric
          label="Confirmed"
          value={isLoading || error ? undefined : conf.CONFIRMED ?? 0}
          loading={isLoading}
          error={error}
          sub="90 vdays observed"
        />
        <Metric
          label="Provisional"
          value={isLoading || error ? undefined : conf.PROVISIONAL ?? 0}
          loading={isLoading}
          error={error}
          tone="warn"
          sub="below 90 vdays"
        />
        <Metric
          label="None"
          value={isLoading || error ? undefined : conf.NONE ?? 0}
          loading={isLoading}
          error={error}
          sub="below baseline"
        />
        <Metric
          label="Shadow comparison"
          value={isLoading || error ? undefined : data?.shadow_reliable ? "live" : "degraded"}
          tone={data?.shadow_reliable ? "ok" : "crit"}
          loading={isLoading}
          error={error}
          sub={data?.shadow_reliable ? "gateway reachable" : "gateway unreachable"}
        />
      </div>

      <Table
        columns={[
          {
            key: "lc",
            header: "lifecycle",
            render: (m) => <span className={lifecycleClass(m.lifecycle)}>{m.lifecycle}</span>,
          },
          {
            key: "gov",
            header: "governance",
            render: (m) => (
              <span className={governanceClass(m.governance)}>{m.governance}</span>
            ),
          },
          { key: "n", header: "endpoints", align: "right", render: (m) => num(m.n) },
        ]}
        rows={data?.matrix}
        rowKey={(m) => `${m.lifecycle}:${m.governance}`}
        loading={isLoading}
        error={error as Error | null}
        onRowClick={(m) =>
          navigate(`/estate?lifecycle=${m.lifecycle}&governance=${m.governance}`)
        }
        rowLabel={(m) => `Show ${m.lifecycle} ${m.governance} endpoints`}
      />
    </div>
  );
}
