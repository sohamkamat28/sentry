import { SLOW_MS, useLive } from "../lib/useLive";
import { Metric } from "../components/data/Metric";
import { Table, type Column } from "../components/data/Table";
import { navigate } from "../lib/router";
import { num, score, tierClass, lifecycleClass, governanceClass } from "../lib/format";
import type {
  Classification,
  Discovery,
  Estate,
  EstateItemsItem,
  Risk,
} from "../lib/api-types";

const LIFECYCLES = ["ACTIVE", "DEPRECATED", "DORMANT", "ZOMBIE"];
const GOVERNANCE = ["OWNED", "ORPHANED", "SHADOW"];

/** The landing surface. What needs attention now, and nothing else. */
export function CommandCentre() {
  const risk = useLive<Risk>("risk", "/risk?limit=200", SLOW_MS);
  const cls = useLive<Classification>("classification", "/classification", SLOW_MS);
  const disc = useLive<Discovery>("discovery", "/discovery", SLOW_MS);
  const estate = useLive<Estate>("estate", "/estate?limit=500", SLOW_MS);

  const items = estate.data?.items ?? [];
  const cell = (lc: string, gov: string) =>
    cls.data?.matrix?.find((m) => m.lifecycle === lc && m.governance === gov)?.n ?? 0;

  const count = (pred: (e: EstateItemsItem) => boolean) =>
    estate.isLoading || estate.error ? undefined : items.filter(pred).length;

  // The only ranked list that matters: CRITICAL with no control applied,
  // soonest breach first.
  const queue = (risk.data?.items ?? [])
    .filter((r) => r.tier === "CRITICAL")
    .sort(
      (a, b) =>
        (a.time_to_breach?.days ?? Number.MAX_SAFE_INTEGER) -
        (b.time_to_breach?.days ?? Number.MAX_SAFE_INTEGER),
    );

  const byId = new Map(items.map((e) => [e.id, e]));

  const columns: Column<Risk["items"][number]>[] = [
    { key: "ep", header: "endpoint", render: (r) => `${r.method} ${r.path}` },
    {
      key: "svc",
      header: "service",
      render: (r) => byId.get(r.endpoint_id)?.service ?? "—",
    },
    {
      key: "score",
      header: "CDRI",
      align: "right",
      render: (r) => <span className={tierClass(r.tier)}>{score(r.score)}</span>,
    },
    {
      key: "ttb",
      header: "time to breach",
      align: "right",
      render: (r) => (r.time_to_breach?.days == null ? "—" : `${r.time_to_breach.days}d`),
    },
    {
      key: "lc",
      header: "lifecycle",
      render: (r) => {
        const lc = byId.get(r.endpoint_id)?.lifecycle;
        return <span className={lifecycleClass(lc)}>{lc ?? "—"}</span>;
      },
    },
    {
      key: "gov",
      header: "governance",
      render: (r) => {
        const g = byId.get(r.endpoint_id)?.governance;
        return <span className={governanceClass(g)}>{g ?? "—"}</span>;
      },
    },
  ];

  const degraded = disc.data ? !disc.data.shadow_reliable : false;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-6">
        <Metric
          label="Critical"
          value={risk.isLoading || risk.error ? undefined : queue.length}
          tone={queue.length ? "crit" : "ok"}
          loading={risk.isLoading}
          error={risk.error}
          sub="ranked below"
        />
        <Metric
          label="Zombies"
          value={count((e) => e.lifecycle === "ZOMBIE")}
          tone={count((e) => e.lifecycle === "ZOMBIE") ? "crit" : "ok"}
          loading={estate.isLoading}
          error={estate.error}
        />
        <Metric
          label="Shadow"
          value={disc.isLoading || disc.error ? undefined : disc.data?.shadow_count}
          tone={disc.data?.shadow_count ? "warn" : "ok"}
          loading={disc.isLoading}
          error={disc.error}
          degraded={degraded}
          sub={degraded ? undefined : "gateway compared"}
        />
        <Metric
          label="Orphaned"
          value={count((e) => e.governance === "ORPHANED")}
          tone="warn"
          loading={estate.isLoading}
          error={estate.error}
        />
        <Metric
          label="Retired"
          value={count((e) => e.retired)}
          tone="dim"
          loading={estate.isLoading}
          error={estate.error}
        />
        <Metric
          label="Confirmed"
          value={cls.isLoading || cls.error ? undefined : cls.data?.confidence?.CONFIRMED}
          tone="dim"
          loading={cls.isLoading}
          error={cls.error}
          sub="90 vdays observed"
        />
      </div>

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">Action queue</h2>
        <Table
          columns={columns}
          rows={queue}
          rowKey={(r) => r.endpoint_id}
          loading={risk.isLoading}
          error={risk.error as Error | null}
          empty="nothing scored critical"
          onRowClick={(r) => navigate(`/remediation?endpoint=${r.endpoint_id}`)}
          rowLabel={(r) => `Open remediation for ${r.method} ${r.path}`}
        />
      </section>

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">
          Lifecycle × governance
        </h2>
        <div className="panel overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className="th" />
                {GOVERNANCE.map((g) => (
                  <th key={g} className="th text-right">
                    {g}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {LIFECYCLES.map((lc) => (
                <tr key={lc}>
                  <td className={`cell ${lifecycleClass(lc)}`}>{lc}</td>
                  {GOVERNANCE.map((g) => (
                    <td key={g} className="cell num p-0 text-right">
                      <button
                        className="w-full px-3 py-1.5 text-right hover:bg-line/40 disabled:cursor-not-allowed"
                        type="button"
                        disabled={Boolean(cls.error)}
                        onClick={() => navigate(`/estate?lifecycle=${lc}&governance=${g}`)}
                      >
                        {cls.isLoading || cls.error ? "—" : num(cell(lc, g))}
                      </button>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">Capture by source</h2>
        <Table
          columns={[
            { key: "src", header: "source", render: (s) => s.source.toUpperCase() },
            { key: "ep", header: "endpoints", align: "right", render: (s) => num(s.endpoints) },
            {
              key: "excl",
              header: "exclusive",
              align: "right",
              render: (s) => num(s.exclusive),
            },
            {
              key: "obs",
              header: "observations 24v",
              align: "right",
              render: (s) => num(s.observations_24v),
            },
            {
              key: "health",
              header: "health",
              render: (s) => (
                <span className={s.healthy ? "text-ok" : "text-crit"}>
                  {s.healthy ? "ok" : "unreachable"}
                </span>
              ),
            },
          ]}
          rows={disc.data?.sources}
          rowKey={(s) => s.source}
          loading={disc.isLoading}
          error={disc.error as Error | null}
        />
      </section>
    </div>
  );
}
