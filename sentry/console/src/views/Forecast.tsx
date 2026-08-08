import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { get } from "../lib/api";
import { Drawer, Field, Section } from "../components/data/Drawer";
import { Metric } from "../components/data/Metric";
import { Sparkline } from "../components/data/Sparkline";
import { Table } from "../components/data/Table";
import { num, pct, score } from "../lib/format";
import { SLOW_MS, useLive } from "../lib/useLive";
import type { Forecast as F, ForecastEndpointId, ForecastItemsItem } from "../lib/api-types";

/**
 * Endpoints trending toward silence.
 *
 * `deseasonalised` is a column rather than an implementation detail: a series
 * fitted without removing one weekly period forecasts a rising endpoint to
 * zero, so whether it was applied changes what the number means.
 *
 * The surface rendered a blank screen before this. `signals` is a map of named
 * factor scores — `{call_volume, commit_recency, owner_activity, composite}` —
 * and the view called `.join(" ")` on it, because `lib/types.ts` declared it as
 * `string[]`. The generated type had it right. Nothing here declares a response
 * shape locally any more.
 */

/** The blended pre-zombie score. The rest of the map are its inputs. */
const COMPOSITE = "composite";

/** Not a score. It says the commit signal was estimated rather than measured. */
const ESTIMATED = "commit_estimated";

export function Forecast() {
  const [open, setOpen] = useState<ForecastItemsItem | null>(null);
  const { data, isLoading, error } = useLive<F>("forecast", "/forecast", SLOW_MS);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Metric
          label="Pre-zombie"
          value={isLoading || error ? undefined : data?.flagged}
          tone={data?.flagged ? "warn" : "ok"}
          loading={isLoading}
          error={error}
          sub="stage 07 flagged"
        />
        <Metric
          label="Active endpoints"
          value={isLoading || error ? undefined : data?.active}
          loading={isLoading}
          error={error}
          sub="the ratio's denominator"
        />
        <Metric
          label="Flagged ratio"
          value={isLoading || error ? undefined : pct(data?.flagged_ratio, 1)}
          loading={isLoading}
          error={error}
        />
        {/* Named separately from `active` because the two differ and the
            difference invites a misreading: every endpoint carrying a forecast
            appears below, whatever its lifecycle, so a count of three ACTIVE
            beside twenty-nine rows looks like a contradiction until the table
            says what it is counting. */}
        <Metric
          label="Forecast series"
          value={isLoading || error ? undefined : num(data?.items?.length)}
          loading={isLoading}
          error={error}
          sub="endpoints with a fitted trend"
        />
      </div>

      <Table
        columns={[
          { key: "ep", header: "endpoint", render: (i) => `${i.method} ${i.path}` },
          {
            key: "d",
            header: "days to zombie",
            align: "right",
            render: (i) =>
              i.days_to_zombie == null ? (
                "—"
              ) : (
                <span className={i.days_to_zombie < 30 ? "text-warn" : ""}>
                  {i.days_to_zombie}
                </span>
              ),
          },
          {
            key: "c",
            header: "composite",
            align: "right",
            render: (i) => {
              const v = i.signals?.[COMPOSITE];
              if (typeof v !== "number") return "—";
              return <span className={v >= 0.5 ? "text-warn" : ""}>{score(v, 2)}</span>;
            },
          },
          {
            key: "sig",
            header: "signals",
            render: (i) => <Signals signals={i.signals} />,
          },
          { key: "s", header: "slope", align: "right", render: (i) => score(i.slope, 4) },
          {
            key: "ds",
            header: "deseasonalised",
            render: (i) => (
              <span className={i.deseasonalised ? "text-ok" : "text-warn"}>
                {i.deseasonalised ? "yes" : "no"}
              </span>
            ),
          },
        ]}
        rows={data?.items}
        rowKey={(i) => i.endpoint_id}
        loading={isLoading}
        error={error as Error | null}
        empty="no endpoint is trending toward silence"
        onRowClick={setOpen}
        rowLabel={(item) => `${item.method} ${item.path}`}
      />

      <Drawer
        open={open !== null}
        onClose={() => setOpen(null)}
        title={open ? `${open.method} ${open.path}` : ""}
        subtitle={
          open?.days_to_zombie != null ? `${open.days_to_zombie} days to zombie` : undefined
        }
      >
        {open && <Detail item={open} />}
      </Drawer>
    </div>
  );
}

/**
 * The factor scores behind the composite.
 *
 * Shown as labelled values rather than a joined string: they are a map, the
 * names carry the meaning, and an operator deciding whether to trust a forecast
 * wants to see which input drove it.
 */
function Signals({ signals }: { signals: Record<string, unknown> | undefined }) {
  const entries = Object.entries(signals ?? {}).filter(
    ([k]) => k !== COMPOSITE && k !== ESTIMATED,
  );
  const estimated = signals?.[ESTIMATED] === true;

  if (entries.length === 0 && !estimated) return <span className="text-tx4">—</span>;

  return (
    <span className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
      {entries.map(([k, v]) => (
        <span key={k} className="text-[11px] text-tx3">
          {k.replace(/_/g, " ")}{" "}
          <span className="num text-tx1">
            {typeof v === "number" ? score(v, 2) : String(v)}
          </span>
        </span>
      ))}
      {estimated && (
        // A caveat on the forecast, not a factor in it: the commit signal was
        // inferred rather than read from a repository, and an operator weighing
        // a retirement should know which.
        <span className="chip text-warn" title="commit recency was estimated, not measured">
          estimated
        </span>
      )}
    </span>
  );
}

/** Observed against deseasonalised against projected — the correction, shown. */
function Detail({ item }: { item: ForecastItemsItem }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["forecast", item.endpoint_id],
    queryFn: () => get<ForecastEndpointId>(`/forecast/${item.endpoint_id}`),
  });

  if (isLoading) return <p className="text-[12px] text-tx4">loading…</p>;
  if (error) return <p className="text-[12px] text-crit">{(error as Error).message}</p>;

  const observed = data?.observed ?? [];
  const adjusted = data?.adjusted ?? [];
  const projection = data?.projection ?? [];

  // One scale across all three, or the correction looks like a change in the
  // data rather than a change in how it was read.
  const all = [...observed, ...adjusted, ...projection].filter(Number.isFinite);
  const lo = Math.min(...all, 0);
  const hi = Math.max(...all, 1);

  return (
    <div>
      <Section title="the series">
        <Line label="observed" values={observed} lo={lo} hi={hi} tone="dim" />
        {/* The reason the column exists. Fitting without removing one weekly
            period reads a weekend trough as decline and forecasts a rising
            endpoint to zero. */}
        <Line label="deseasonalised" values={adjusted} lo={lo} hi={hi} tone="info" />
        <Line label="projection" values={projection} lo={lo} hi={hi} tone="warn" />
      </Section>

      <Section title="fit">
        <Field label="slope" value={score(data?.slope, 6)} />
        <Field label="level" value={score(data?.level, 2)} />
        <Field
          label="deseasonalised"
          value={
            data?.deseasonalised ? (
              <span className="text-ok">yes</span>
            ) : (
              <span className="text-warn">no — a weekly trough may read as decline</span>
            )
          }
        />
        <Field
          label="days to zombie"
          value={data?.days_to_zombie ?? "—"}
        />
      </Section>

      <Section title="signals">
        {Object.entries(data?.signals ?? {}).map(([k, v]) => (
          <Field
            key={k}
            label={k.replace(/_/g, " ")}
            value={typeof v === "number" ? score(v, 4) : String(v)}
          />
        ))}
      </Section>
    </div>
  );
}

function Line({
  label,
  values,
  lo,
  hi,
  tone,
}: {
  label: string;
  values: number[];
  lo: number;
  hi: number;
  tone: "dim" | "info" | "warn";
}) {
  return (
    <div className="flex items-center gap-3 py-1">
      <span className="w-32 shrink-0 text-[11.5px] text-tx3">{label}</span>
      <Sparkline values={values} width={220} height={26} min={lo} max={hi} tone={tone} />
      <span className="num ml-auto text-[11px] text-tx4">
        {values.length ? `${values.length} pts` : "—"}
      </span>
    </div>
  );
}
