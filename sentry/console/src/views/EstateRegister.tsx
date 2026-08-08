import { useQuery } from "@tanstack/react-query";

import { SLOW_MS, useLive } from "../lib/useLive";
import { get } from "../lib/api";
import { Drawer, Field, Section } from "../components/data/Drawer";
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
import type { Estate, EstateEndpointId, EstateItemsItem } from "../lib/api-types";

/** Every endpoint the platform knows about, filterable by verdict. */
export function EstateRegister() {
  const [path] = useRoute();
  const q = routeQuery(path);
  const lifecycle = q.get("lifecycle");
  const governance = q.get("governance");
  const endpoint = q.get("endpoint");

  const { data, isLoading, error } = useLive<Estate>("estate", "/estate?limit=500", SLOW_MS);

  const detail = useQuery({
    queryKey: ["estate-detail", endpoint],
    queryFn: () => get<EstateEndpointId>(`/estate/${endpoint}`),
    enabled: endpoint !== null,
  });

  const rows = (data?.items ?? []).filter(
    (e) =>
      (!endpoint || e.id === endpoint) &&
      (!lifecycle || e.lifecycle === lifecycle) &&
      (!governance || e.governance === governance),
  );

  /**
   * Seven columns, from twelve — because the row is a summary, not the record.
   *
   * Listing every attribute as its own column ran the table off the right edge,
   * so `data classes` was clipped mid-word and CDRI — the figure that ranks the
   * row — sat outside the viewport. Two of those columns carried no information
   * at all: `confidence` reads CONFIRMED on every row of this estate, and `team`
   * wrapped to a second line in most of them, doubling the height of the table
   * to repeat one word.
   *
   * Nothing is lost. Every field removed here is in the drawer this row opens,
   * under `identity`, `classification` and `observed posture` — which is where a
   * full record belongs. What stays is what an operator scans on: who owns it,
   * what state it is in, how bad it is, and whether it is exposed.
   */
  const columns: Column<EstateItemsItem>[] = [
    { key: "ep", header: "endpoint", render: (e) => `${e.method} ${e.path}` },
    {
      key: "svc",
      header: "service",
      render: (e) => (
        <span className="block">
          {e.service}
          {e.team ? <span className="block text-[11px] text-tx4">{e.team}</span> : null}
        </span>
      ),
    },
    { key: "crit", header: "criticality", render: (e) => e.criticality },
    {
      // The two axes of one verdict, read together as the work queue reads them,
      // with confidence styling the pair rather than taking a column beside it.
      key: "state",
      header: "lifecycle × governance",
      width: "190px",
      render: (e) => (
        <span
          className={`${confidenceClass(e.confidence)} whitespace-nowrap`}
          title={`confidence ${e.confidence ?? "—"}`}
        >
          <span className={lifecycleClass(e.lifecycle)}>{e.lifecycle ?? "—"}</span>
          {e.pre_zombie && <span className="text-warn"> ·pre</span>}
          <span className="text-tx4"> × </span>
          <span className={governanceClass(e.governance)}>{e.governance ?? "—"}</span>
        </span>
      ),
    },
    {
      key: "cdri",
      header: "CDRI",
      align: "right",
      render: (e) => <span className={tierClass(e.tier)}>{score(e.cdri)}</span>,
    },
    { key: "last", header: "last call", align: "right", render: (e) => vday(e.last_call_vday) },
    {
      // The three things that make an endpoint dangerous, tone-coded so the row
      // says so at a glance. Data classes are named rather than counted — the
      // classifier found regulated identifiers in kernel space and that is the
      // point of the column — but only the first, because four of them is an
      // ordinary set here and listing all four wrapped every row to three lines.
      key: "posture",
      header: "posture",
      width: "250px",
      render: (e) => (
        <span className="block">
          <span className="flex flex-wrap gap-1">
            <span className={`chip ${e.auth === "none" ? "text-crit" : "text-tx3"}`}>{e.auth}</span>
            {e.tls_version ? (
              <span className={`chip ${e.tls_version < "1.3" ? "text-warn" : "text-tx3"}`}>
                tls {e.tls_version}
              </span>
            ) : null}
          </span>
          {e.data_classes.length > 0 ? (
            <span
              className="mt-0.5 block whitespace-nowrap text-[11px] leading-tight text-warn"
              title={e.data_classes.join(", ")}
            >
              {e.data_classes[0]}
              {e.data_classes.length > 1 ? (
                <span className="text-tx4"> +{e.data_classes.length - 1}</span>
              ) : null}
            </span>
          ) : null}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-2">
      {(lifecycle || governance || endpoint) && (
        <div className="flex items-center gap-2 text-[11px]">
          {lifecycle && <span className="chip">lifecycle {lifecycle}</span>}
          {governance && <span className="chip">governance {governance}</span>}
          {endpoint && <span className="chip">endpoint {endpoint}</span>}
          <button className="btn" type="button" onClick={() => navigate("/estate")}>
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
        onRowClick={(e) => navigate(`/estate?endpoint=${e.id}`)}
        rowLabel={(e) => `Open details for ${e.method} ${e.path}`}
      />

      <Drawer
        open={endpoint !== null}
        onClose={() => navigate("/estate")}
        title={detail.data ? `${detail.data.method} ${detail.data.path}` : endpoint ?? ""}
        subtitle={detail.data?.service?.name}
        footer={
          detail.data ? (
            <button className="btn" type="button" onClick={() => navigate(`/zerotrust?endpoint=${detail.data!.id}`)}>
              open zero-trust posture
            </button>
          ) : undefined
        }
      >
        {detail.isLoading ? <p className="text-[12.5px] text-tx4">loading…</p> : null}
        {detail.error ? <p className="text-[12.5px] text-crit">{detail.error.message}</p> : null}
        {detail.data ? <EstateDetail endpoint={detail.data} /> : null}
      </Drawer>
    </div>
  );
}

function EstateDetail({ endpoint }: { endpoint: EstateEndpointId }) {
  return (
    <>
      <Section title="identity">
        <Field label="service" value={endpoint.service?.name ?? "—"} />
        <Field label="team" value={endpoint.service?.team ?? "—"} />
        <Field label="criticality" value={endpoint.service?.criticality ?? "—"} />
        <Field label="sources" value={endpoint.sources.join(", ") || "—"} />
      </Section>
      <Section title="classification">
        <Field label="lifecycle" value={endpoint.classification?.lifecycle ?? "—"} />
        <Field label="governance" value={endpoint.classification?.governance ?? "—"} />
        <Field label="confidence" value={endpoint.classification?.confidence ?? "—"} />
        <Field label="pre-zombie" value={endpoint.classification?.pre_zombie ? "yes" : "no"} />
      </Section>
      <Section title="observed posture">
        <Field label="authentication" value={endpoint.auth} />
        <Field label="TLS" value={endpoint.tls_version ?? "—"} />
        <Field label="rate limited" value={endpoint.rate_limited ? "yes" : "no"} />
        <Field label="internet reachable" value={endpoint.internet_reachable ? "yes" : "no"} />
        <Field label="data classes" value={endpoint.data_classes.join(", ") || "—"} />
      </Section>
      <Section title="risk and impact">
        <Field label="CDRI" value={score(endpoint.cdri?.score)} />
        <Field label="tier" value={endpoint.cdri?.tier ?? "—"} />
        <Field label="blast radius" value={endpoint.blast?.tier ?? "—"} />
        <Field label="direct callers" value={endpoint.blast?.direct_callers ?? "—"} />
        <Field label="days to zombie" value={endpoint.forecast?.days_to_zombie ?? "—"} />
      </Section>
    </>
  );
}
