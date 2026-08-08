import { SLOW_MS, useLive } from "../lib/useLive";
import { Card } from "../components/data/Card";
import { Gauge } from "../components/data/Gauge";
import { Metric } from "../components/data/Metric";
import { Table, type Column } from "../components/data/Table";
import { navigate } from "../lib/router";
import { num, score, tierClass, lifecycleClass } from "../lib/format";
import type {
  Classification,
  Discovery,
  Estate,
  EstateItemsItem,
  Risk,
  System,
} from "../lib/api-types";

const LIFECYCLES = ["ACTIVE", "DEPRECATED", "DORMANT", "ZOMBIE"];
const GOVERNANCE = ["OWNED", "ORPHANED", "SHADOW"];
const TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const TIER_TONE: Record<(typeof TIERS)[number], "crit" | "warn" | "info" | "ok"> = {
  CRITICAL: "crit",
  HIGH: "warn",
  MEDIUM: "info",
  LOW: "ok",
};

/**
 * The landing surface: estate-wide posture, on one screen.
 *
 * Laid out as a bento rather than a stack of full-width sections. The figures
 * here answer different questions — how much is dangerous, how much is
 * unowned, what is queued, where the evidence came from — and stacking them
 * made each look like a step in a sequence that has to be read in order.
 *
 * Every number is read from the API. Nothing on this screen is written into the
 * markup, so the copy cannot drift away from the estate it describes.
 */
export function CommandCentre() {
  const risk = useLive<Risk>("risk", "/risk?limit=200", SLOW_MS);
  const cls = useLive<Classification>("classification", "/classification", SLOW_MS);
  const disc = useLive<Discovery>("discovery", "/discovery", SLOW_MS);
  const estate = useLive<Estate>("estate", "/estate?limit=500", SLOW_MS);
  const system = useLive<System>("system", "/system", SLOW_MS);

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

  // Four columns, not six. This is a summary in a two-thirds card, and service
  // and governance were the two that pushed the row past the card's edge —
  // clipped, they read as a rendering fault rather than as more data. The full
  // six-column table is one click away in the risk register.
  const columns: Column<Risk["items"][number]>[] = [
    { key: "ep", header: "endpoint", render: (r) => `${r.method} ${r.path}` },
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
  ];

  const degraded = disc.data ? !disc.data.shadow_reliable : false;
  const riskRows = risk.data?.items ?? [];
  const tierCounts = TIERS.map((t) => ({
    tier: t,
    n: risk.error || risk.isLoading ? undefined : riskRows.filter((r) => r.tier === t).length,
  }));
  const tierMax = Math.max(1, ...tierCounts.map((t) => t.n ?? 0));

  const sources = disc.data?.sources ?? [];
  const sourceMax = Math.max(1, ...sources.map((s) => s.endpoints ?? 0));

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
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

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Spotlight
          endpoints={system.data?.endpoints}
          shadow={disc.data?.shadow_count}
          degraded={degraded}
        />

        <Card
          title="Risk distribution"
          sub="every scored endpoint, by tier"
          href="#/risk"
        >
          {/* `items-stretch`, not `items-end`: aligning to the end sizes each
              column to its content, leaving the bar track no height to fill. */}
          <div className="flex h-[132px] items-stretch gap-2.5">
            {tierCounts.map((t) => (
              <div key={t.tier} className="flex min-w-0 flex-1 flex-col items-center gap-2">
                <span className="num font-mono text-[12.5px] text-tx2">
                  {t.n === undefined ? "—" : t.n}
                </span>
                {/* The bar is positioned, not flowed. A percentage height
                    against a flex item whose own height is resolved by the
                    flex algorithm computes against `auto` and collapses to
                    nothing, which is what every bar here did. */}
                <div className="relative w-full flex-1">
                  <div
                    className="absolute inset-x-0 bottom-0 rounded-t-[6px] transition-[height] duration-500"
                    style={{
                      height: `${((t.n ?? 0) / tierMax) * 100}%`,
                      minHeight: t.n ? 4 : 0,
                      background: `rgb(var(--${TIER_TONE[t.tier]}))`,
                    }}
                  />
                </div>
                <span className="truncate font-sans text-[11px] uppercase tracking-[0.06em] text-tx4">
                  {t.tier}
                </span>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Mean CDRI" sub="composite danger across the estate" href="#/risk">
          <Gauge
            value={system.data?.mean_cdri}
            display={score(system.data?.mean_cdri)}
            caption="estate"
            tone={
              (system.data?.mean_cdri ?? 0) >= 0.7
                ? "crit"
                : (system.data?.mean_cdri ?? 0) >= 0.4
                  ? "warn"
                  : "ok"
            }
            legend={[
              { label: "scored", tone: "dim" },
              { label: "headroom" },
            ]}
          />
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Card
          title="Action queue"
          sub="critical, soonest breach first"
          href="#/risk"
          flush
          className="lg:col-span-2"
        >
          <Table
            columns={columns}
            rows={queue}
            rowKey={(r) => r.endpoint_id}
            loading={risk.isLoading}
            error={risk.error as Error | null}
            empty="nothing scored critical"
            onRowClick={(r) => navigate(`/remediation?endpoint=${r.endpoint_id}`)}
            rowLabel={(r) => `Open remediation for ${r.method} ${r.path}`}
            framed={false}
          />
        </Card>

        <Card title="Capture by source" sub="which sensor saw what" href="#/sensor">
          {disc.isLoading && <p className="font-sans text-[12.5px] text-tx4">loading…</p>}
          {disc.error && (
            <p className="font-sans text-[12.5px] text-crit">{(disc.error as Error).message}</p>
          )}
          {!disc.isLoading && !disc.error && (
            <ul className="space-y-2.5">
              {sources.map((s) => (
                <li key={s.source}>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="font-sans text-[12.5px] text-tx2">
                      {s.source.toUpperCase()}
                    </span>
                    <span className="flex items-baseline gap-2">
                      <span className="num font-mono text-[12.5px] text-tx1">
                        {num(s.endpoints)}
                      </span>
                      {!s.healthy && (
                        <span className="font-sans text-[11px] text-crit">unreachable</span>
                      )}
                    </span>
                  </div>
                  <div className="well mt-1.5 h-1.5 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-[width] duration-500"
                      style={{
                        width: `${((s.endpoints ?? 0) / sourceMax) * 100}%`,
                        background: s.healthy ? "rgb(var(--accent))" : "rgb(var(--crit))",
                      }}
                    />
                  </div>
                  <div className="mt-1 font-sans text-[11px] text-tx4">
                    {num(s.exclusive)} seen only here
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card
        title="Lifecycle × governance"
        sub="select a cell to open that slice of the register"
        flush
      >
        <div className="overflow-x-auto">
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
                        className="w-full px-3.5 py-2 text-right transition-colors hover:bg-raise disabled:cursor-not-allowed"
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
      </Card>
    </div>
  );
}

/**
 * The one sentence a reader should leave with, built from the figures rather
 * than written down. If the estate changes, this changes; there is no wording
 * here that can quietly become false.
 */
function Spotlight({
  endpoints,
  shadow,
  degraded,
}: {
  endpoints?: number;
  shadow?: number;
  degraded: boolean;
}) {
  const known = endpoints != null && shadow != null;
  return (
    <section className="panel relative isolate flex min-h-[180px] flex-col justify-end overflow-hidden p-5">
      <div
        aria-hidden="true"
        className="absolute inset-0 -z-10"
        style={{
          background:
            "radial-gradient(120% 90% at 78% 8%, rgb(var(--accent) / 0.30), transparent 62%)",
        }}
      />
      <div
        aria-hidden="true"
        className="absolute inset-0 -z-10 opacity-[0.35]"
        style={{
          backgroundImage:
            "linear-gradient(rgb(var(--line) / 0.9) 1px, transparent 1px), linear-gradient(90deg, rgb(var(--line) / 0.9) 1px, transparent 1px)",
          backgroundSize: "34px 34px",
          maskImage: "radial-gradient(120% 90% at 78% 8%, #000, transparent 68%)",
          WebkitMaskImage: "radial-gradient(120% 90% at 78% 8%, #000, transparent 68%)",
        }}
      />
      <span className="chip w-fit border-accent/40 text-accent">Estate</span>
      <p className="mt-3 font-sans text-[20px] font-semibold leading-[1.28] tracking-[-0.02em] text-tx1">
        {known ? (
          <>
            <span className="num font-mono">{shadow}</span> of{" "}
            <span className="num font-mono">{endpoints}</span> endpoints are in no gateway and
            no repository.
          </>
        ) : (
          "Reading the estate…"
        )}
      </p>
      <p className="mt-1.5 font-sans text-[11px] leading-4 text-tx4">
        {degraded
          ? "The gateway comparison is degraded — this may undercount."
          : "Seen in live traffic by the kernel probe, registered nowhere."}
      </p>
    </section>
  );
}
