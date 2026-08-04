
import { SLOW_MS, useLive } from "../lib/useLive";
import { Table, type Column } from "../components/data/Table";
import { useRoute, routeQuery, navigate } from "../lib/router";
import {
  governanceClass,
  lifecycleClass,
  confidenceClass,
  score,
  tierClass,
  vday,
} from "../lib/format";
import type { Estate, EstateItem } from "../lib/types";

/** Every endpoint the platform knows about, filterable by verdict. */
export function EstateRegister() {
  const [path] = useRoute();
  const q = routeQuery(path);
  const lifecycle = q.get("lifecycle");
  const governance = q.get("governance");

  const { data, isLoading, error } = useLive<Estate>("estate", "/estate?limit=500", SLOW_MS);

  const rows = (data?.items ?? []).filter(
    (e) =>
      (!lifecycle || e.lifecycle === lifecycle) &&
      (!governance || e.governance === governance),
  );

  const columns: Column<EstateItem>[] = [
    { key: "ep", header: "endpoint", render: (e) => `${e.method} ${e.path}` },
    { key: "svc", header: "service", render: (e) => e.service },
    { key: "team", header: "team", render: (e) => e.team ?? "—" },
    { key: "crit", header: "criticality", render: (e) => e.criticality },
    {
      key: "lc",
      header: "lifecycle",
      render: (e) => (
        <span className={lifecycleClass(e.lifecycle)}>
          {e.lifecycle ?? "—"}
          {e.pre_zombie && <span className="text-warn"> ·pre</span>}
        </span>
      ),
    },
    {
      key: "gov",
      header: "governance",
      render: (e) => (
        <span className={governanceClass(e.governance)}>{e.governance ?? "—"}</span>
      ),
    },
    {
      key: "conf",
      header: "confidence",
      render: (e) => (
        <span className={confidenceClass(e.confidence)}>{e.confidence ?? "—"}</span>
      ),
    },
    {
      key: "cdri",
      header: "CDRI",
      align: "right",
      render: (e) => <span className={tierClass(e.tier)}>{score(e.cdri)}</span>,
    },
    { key: "last", header: "last call", align: "right", render: (e) => vday(e.last_call_vday) },
    { key: "auth", header: "auth", render: (e) => e.auth },
    { key: "tls", header: "tls", render: (e) => e.tls_version ?? "—" },
    {
      key: "dc",
      header: "data classes",
      render: (e) =>
        e.data_classes.length ? (
          <span className="text-warn">{e.data_classes.join(" ")}</span>
        ) : (
          "—"
        ),
    },
  ];

  return (
    <div className="space-y-2">
      {(lifecycle || governance) && (
        <div className="flex items-center gap-2 text-[11.5px]">
          {lifecycle && <span className="chip">lifecycle {lifecycle}</span>}
          {governance && <span className="chip">governance {governance}</span>}
          <button className="btn" onClick={() => navigate("/estate")}>
            clear
          </button>
          <span className="text-tx4">
            {rows.length} of {data?.items.length ?? 0}
          </span>
        </div>
      )}
      <Table
        columns={columns}
        rows={rows}
        rowKey={(e) => e.id}
        loading={isLoading}
        error={error as Error | null}
        onRowClick={(e) => navigate(`/zerotrust?endpoint=${e.id}`)}
      />
    </div>
  );
}
