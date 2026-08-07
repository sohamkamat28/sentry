import { useMemo, useState } from "react";

import { SLOW_MS, useLive } from "../lib/useLive";
import { Term } from "../components/data/Term";
import { score as fmtScore, vday } from "../lib/format";
import { governanceClass, lifecycleClass, tierClass } from "../lib/format";
import type { Estate, EstateItemsItem, Findings, Risk, Zerotrust } from "../lib/api-types";

/**
 * Every API, and everything known about one of them.
 *
 * This replaces fifteen screens. Those screens were organised by the stage that
 * produced the data — register, classification, risk, zero-trust, findings —
 * which meant answering one question about one endpoint took five navigations
 * and a good memory. Nobody outside the team was ever going to do that.
 *
 * Here the list is the only index, and selecting a row answers the questions a
 * reader actually arrives with, in their order: what is it, who owns it, how
 * dangerous is it, what is missing.
 */
export function Explore() {
  const [q, setQ] = useState("");
  const [only, setOnly] = useState<"all" | "risky" | "unowned" | "dead">("all");
  const [openId, setOpenId] = useState<string | null>(null);

  const estate = useLive<Estate>("estate", "/estate?limit=500", SLOW_MS);
  const risk = useLive<Risk>("risk", "/risk?limit=300", SLOW_MS);
  const findings = useLive<Findings>("findings", "/findings", SLOW_MS);
  const zt = useLive<Zerotrust>("zerotrust", "/zerotrust", SLOW_MS);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (estate.data?.items ?? [])
      .filter((e) => {
        if (needle && !`${e.method} ${e.path} ${e.service}`.toLowerCase().includes(needle))
          return false;
        if (only === "risky") return (e.cdri ?? 0) >= 0.7;
        if (only === "unowned") return e.governance === "SHADOW" || e.governance === "ORPHANED";
        if (only === "dead") return e.lifecycle === "ZOMBIE" || e.lifecycle === "DORMANT";
        return true;
      })
      .sort((a, b) => (b.cdri ?? 0) - (a.cdri ?? 0));
  }, [estate.data, q, only]);

  const open = rows.find((r) => r.id === openId) ?? null;

  const FILTERS = [
    ["all", "All APIs"],
    ["risky", "Dangerous"],
    ["unowned", "No owner"],
    ["dead", "Not in use"],
  ] as const;

  return (
    <div className="mx-auto max-w-6xl">
      <header className="mb-5">
        <h1 className="font-sans text-[26px] font-semibold tracking-[-0.02em] text-tx1 sm:text-[30px]">
          Every API we found
        </h1>
        <p className="mt-1.5 max-w-[62ch] font-sans text-[13.5px] leading-6 text-tx3">
          Sorted by danger. Select any row to see everything the system knows
          about it — in plain terms.
        </p>
      </header>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <input
          className="min-w-0 flex-1 rounded-sm border border-line bg-panel px-3 py-2 font-sans text-[13px] text-tx1 outline-none placeholder:text-tx4 focus:border-info sm:max-w-xs"
          placeholder="Search by path or service…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          aria-label="Search APIs"
        />
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map(([key, label]) => (
            <button
              key={key}
              type="button"
              aria-pressed={only === key}
              onClick={() => setOnly(key)}
              className={`rounded-sm border px-3 py-2 font-sans text-[12.5px] transition-colors ${
                only === key
                  ? "border-info bg-line/60 text-tx1"
                  : "border-line text-tx3 hover:text-tx1"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        <span className="ml-auto font-sans text-[12px] text-tx4">
          {rows.length} of {estate.data?.items.length ?? 0}
        </span>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,26rem)]">
        <ul className="panel min-w-0 divide-y divide-line overflow-hidden">
          {estate.isLoading && (
            <li className="px-4 py-3 font-sans text-[13px] text-tx4">loading…</li>
          )}
          {!estate.isLoading && rows.length === 0 && (
            <li className="px-4 py-3 font-sans text-[13px] text-tx4">nothing matches that search</li>
          )}
          {rows.map((e) => (
            <li key={e.id}>
              <button
                type="button"
                onClick={() => setOpenId(e.id === openId ? null : e.id)}
                aria-expanded={e.id === openId}
                className={`flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                  e.id === openId ? "bg-line/50" : "hover:bg-line/25"
                }`}
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-[12.5px] text-tx1">
                    {e.method} {e.path}
                  </span>
                  <span className="mt-0.5 block truncate font-sans text-[11.5px] text-tx4">
                    {e.service}
                    {e.data_classes.length > 0 && (
                      <span className="text-warn"> · {e.data_classes.length} sensitive field(s)</span>
                    )}
                  </span>
                </span>
                <span className={`num shrink-0 text-[13px] ${tierClass(e.tier)}`}>
                  {fmtScore(e.cdri)}
                </span>
              </button>
            </li>
          ))}
        </ul>

        <div className="min-w-0 lg:sticky lg:top-4 lg:self-start">
          {open ? (
            <Detail
              endpoint={open}
              risk={(risk.data?.items ?? []).find((r) => r.endpoint_id === open.id)}
              finding={(findings.data?.items ?? []).find((f) => f.endpoint_id === open.id)}
              posture={(zt.data?.items ?? []).find((z) => z.endpoint_id === open.id)}
            />
          ) : (
            <div className="panel px-5 py-6">
              <p className="font-sans text-[13.5px] leading-6 text-tx3">
                Select an API to see what it is, who owns it, how dangerous it is,
                and what protection it is missing.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** Organised by the reader's question, not by the stage that produced it. */
function Detail({
  endpoint,
  risk,
  finding,
  posture,
}: {
  endpoint: EstateItemsItem;
  risk?: Risk["items"][number];
  finding?: Findings["items"][number];
  posture?: Zerotrust["items"][number];
}) {
  const violated = finding?.regulations.filter((c) => c.status === "VIOLATED").length ?? 0;
  return (
    <div className="panel overflow-hidden">
      <div className="border-b border-line px-5 py-4">
        <div className="break-all font-mono text-[13px] text-tx1">
          {endpoint.method} {endpoint.path}
        </div>
        <div className="mt-1 font-sans text-[12px] text-tx4">
          {endpoint.service}
          {endpoint.team ? ` · ${endpoint.team}` : " · no team"}
        </div>
      </div>

      <Block title="What is it">
        <Row k="Business criticality" v={endpoint.criticality} />
        <Row
          k="Last called"
          v={endpoint.last_call_vday ? `${vday(endpoint.last_call_vday)} (virtual)` : "never observed"}
        />
        <Row
          k="Status"
          v={
            <span className={lifecycleClass(endpoint.lifecycle)}>
              <Term>{(endpoint.lifecycle ?? "—").toLowerCase()}</Term>
            </span>
          }
        />
      </Block>

      <Block title="Who owns it">
        <Row
          k="Governance"
          v={
            <span className={governanceClass(endpoint.governance)}>
              <Term>{(endpoint.governance ?? "—").toLowerCase()}</Term>
            </span>
          }
        />
        <Row k="Team" v={endpoint.team ?? "nobody could be resolved"} />
      </Block>

      <Block title="How dangerous">
        <Row
          k="Score"
          v={
            <span className={tierClass(endpoint.tier)}>
              {fmtScore(endpoint.cdri)} · {endpoint.tier ?? "—"}
            </span>
          }
        />
        {risk?.time_to_breach?.days != null && (
          <Row k="Estimated time to breach" v={`${risk.time_to_breach.days} days (heuristic)`} />
        )}
        {violated > 0 && <Row k="Regulatory clauses breached" v={String(violated)} />}
      </Block>

      <Block title="What is missing">
        <Row
          k="Authentication"
          v={
            <span className={endpoint.auth === "none" ? "text-crit" : "text-ok"}>
              {endpoint.auth}
            </span>
          }
        />
        <Row k="Transport" v={endpoint.tls_version ? `TLS ${endpoint.tls_version}` : "not observed"} />
        {posture && <Row k="Zero-trust controls" v={`${posture.satisfied} of ${posture.of} in place`} />}
        <Row
          k="Sensitive data returned"
          v={
            endpoint.data_classes.length > 0 ? (
              <span className="text-warn">{endpoint.data_classes.join(", ")}</span>
            ) : (
              "none detected"
            )
          }
        />
      </Block>
    </div>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-b border-line px-5 py-3.5 last:border-0">
      <h3 className="font-sans text-[10.5px] font-medium uppercase tracking-[0.12em] text-tx4">
        {title}
      </h3>
      <dl className="mt-2 space-y-1.5">{children}</dl>
    </section>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
      <dt className="min-w-0 flex-1 font-sans text-[12.5px] text-tx3">{k}</dt>
      <dd className="text-right font-sans text-[12.5px] text-tx1">{v}</dd>
    </div>
  );
}
