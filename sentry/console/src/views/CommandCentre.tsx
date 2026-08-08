import { SLOW_MS, useLive } from "../lib/useLive";
import { Card } from "../components/data/Card";
import { Gauge } from "../components/data/Gauge";
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
  System,
} from "../lib/api-types";

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

  // Six columns again. They were cut to four when this table shared a row with
  // the lifecycle matrix and rows were clipping at the card's edge; the queue
  // now has the full width, and with the risk register gone it is the only
  // ranked view of CDRI in the console, so service and governance earn their
  // place back rather than leaving the table half empty.
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
  const riskRows = risk.data?.items ?? [];
  const tierCounts = TIERS.map((t) => ({
    tier: t,
    n: risk.error || risk.isLoading ? undefined : riskRows.filter((r) => r.tier === t).length,
  }));
  const tierMax = Math.max(1, ...tierCounts.map((t) => t.n ?? 0));

  const sources = disc.data?.sources ?? [];
  const sourceMax = Math.max(1, ...sources.map((s) => s.endpoints ?? 0));

  return (
    // Three bands that together fill the viewport exactly: the tiles and the
    // chart row take what they need, the tables take the rest. Nothing here
    // grows the page — the action queue had 23 rows and was 923px tall on its
    // own, so a screen meant to be read at a glance was two screens of
    // scrolling, and the estate matrix under it was never seen at all.
    //
    // `min-h-0` on the flex children is load-bearing: without it a flex item
    // refuses to shrink below its content, and every `overflow-auto` inside
    // silently does nothing.
    <div className="flex flex-col gap-3 xl:h-full xl:overflow-hidden">
      <div className="grid shrink-0 grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
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

      <div className="grid shrink-0 grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4 xl:h-[184px]">
        <Spotlight
          endpoints={system.data?.endpoints}
          shadow={disc.data?.shadow_count}
          degraded={degraded}
        />

        <Card
          title="Risk distribution"
          sub="every scored endpoint, by tier"
          href="#/estate"
        >
          {/* `items-stretch`, not `items-end`: aligning to the end sizes each
              column to its content, leaving the bar track no height to fill. */}
          <div className="flex h-[86px] items-stretch gap-2.5">
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

        {/* No `↗`: this is one number for the whole estate, and there is no
            screen that shows "the mean" in more detail to send anyone to. */}
        <Card title="Mean CDRI" sub="composite danger across the estate">
          {/* No legend: "scored / headroom" restates the arc it sits under, and
              in a fixed row those twenty pixels are the difference between the
              gauge fitting and the band growing. */}
          <Gauge
            maxWidth={118}
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
          />
        </Card>

        <Card title="Capture by source" sub="which sensor saw what" href="#/sensor">
          {disc.isLoading && <p className="font-sans text-[12.5px] text-tx4">loading…</p>}
          {disc.error && (
            <p className="font-sans text-[12.5px] text-crit">{(disc.error as Error).message}</p>
          )}
          {!disc.isLoading && !disc.error && (
            // One line per source: name, bar, count. Stacked over three lines
            // each — with the bar and an "N seen only here" caption beneath —
            // the fourth source fell outside the card and the reader had no
            // way to know a sensor was missing from a panel about sensors.
            // The exclusive count is on the row's title.
            <ul className="space-y-1.5">
              {sources.map((s) => (
                <li
                  key={s.source}
                  className="flex items-center gap-2.5"
                  title={`${num(s.exclusive)} endpoint(s) seen only by ${s.source}${
                    s.healthy ? "" : " — unreachable"
                  }`}
                >
                  <span className="w-[62px] shrink-0 truncate font-sans text-[11px] text-tx2">
                    {s.source.toUpperCase()}
                  </span>
                  <span className="well h-1.5 min-w-0 flex-1 overflow-hidden">
                    <span
                      className="block h-full rounded-full transition-[width] duration-500"
                      style={{
                        width: `${((s.endpoints ?? 0) / sourceMax) * 100}%`,
                        background: s.healthy ? "rgb(var(--accent))" : "rgb(var(--crit))",
                      }}
                    />
                  </span>
                  <span className="num w-7 shrink-0 text-right font-mono text-[12.5px] text-tx1">
                    {num(s.endpoints)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {/* The band that takes whatever is left, now given entirely to the queue.
          The lifecycle matrix used to share it; every cell it held is already a
          filter on the estate register, and beside a list of what to do next it
          read as a second thing to decide between. One table, full width, so
          the rows a reader is meant to act on get the space. */}
      <div className="flex min-h-[260px] flex-1 flex-col xl:min-h-0">
        <Card
          title="Action queue"
          sub="critical, soonest breach first — select a row to open its controls"
          href="#/triage"
          flush
          scroll
          className="min-h-0 flex-1"
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
      </div>
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
    // No `min-h`: the card takes the height of the row it shares, so a minimum
    // set here would push that row taller than the space budgeted for it.
    <section className="panel relative isolate flex min-h-[164px] flex-col justify-end overflow-hidden p-4">
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
      <p className="mt-2.5 font-sans text-[20px] font-semibold leading-[1.22] tracking-[-0.02em] text-tx1">
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
