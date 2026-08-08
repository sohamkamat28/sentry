import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { get } from "../lib/api";
import { Field, Section } from "../components/data/Drawer";
import { num, pct, score } from "../lib/format";
import { navigate } from "../lib/router";
import {
  governanceTone,
  lifecycleTone,
  tierTone,
  toneText,
} from "../lib/severity";
import { SLOW_MS, useLive } from "../lib/useLive";
import type {
  ClassificationEndpointId,
  CorrelationEndpointIdOwnership,
  Decommission,
  ImpactEndpointId,
  Risk,
  Threat,
} from "../lib/api-types";

/**
 * What needs me now.
 *
 * The console had fifteen surfaces and no answer to the first question an
 * operations floor asks. Ranking the estate meant opening Risk Register,
 * Findings, Decommission and Threat, then holding the merged ordering in your
 * head — so in practice nobody ranked anything, they worked whichever list they
 * happened to open.
 *
 * This is that merge, done once and kept live. The queue never loses your
 * place, and the evidence arrives beside the item. Nothing here computes a new
 * verdict — every figure is already produced by a stage and served by an
 * existing route.
 */

type Kind = "risk" | "sunset" | "resurrection";

interface Row {
  key: string;
  kind: Kind;
  endpointId: string;
  method: string;
  path: string;
  /** Sole ordering key. Higher is more urgent. */
  weight: number;
  tier: string;
  headline: string;
  detail: string;
  breachDays: number | null;
}

/**
 * Response shapes come from the generated types, not from here.
 *
 * The first cut of this file declared its own `RiskItem` with
 * `time_to_breach: number | null`. The field is an object —
 * `{days, basis, factors}` — and the generated type had said so all along.
 * Rendering it as a number put an object where React expected a child and took
 * the whole console to a blank screen.
 *
 * That is precisely the failure `tools/generate_console_types.py` exists to
 * make impossible, bypassed by hand-writing the shape next to the code that
 * consumes it. Nothing local is declared for a payload the server describes.
 */
const KIND_LABEL: Record<Kind, string> = {
  risk: "risk",
  sunset: "sunset",
  resurrection: "resurrection",
};

export function Triage() {
  const [selected, setSelected] = useState<string | null>(null);
  const [kinds, setKinds] = useState<Set<Kind>>(
    () => new Set<Kind>(["risk", "sunset", "resurrection"]),
  );

  const risk = useLive<Risk>("risk", "/risk?limit=200", SLOW_MS);
  const sunset = useLive<Decommission>("decommission", "/decommission", SLOW_MS);
  const threat = useLive<Threat>("threat", "/threat", SLOW_MS);

  const rows = useMemo(() => {
    const out: Row[] = [];

    for (const r of risk.data?.items ?? []) {
      // Only what an operator would act on. MEDIUM and LOW belong on the Risk
      // Register, and putting them here would bury the ones that matter.
      if (r.tier !== "CRITICAL" && r.tier !== "HIGH") continue;
      // `time_to_breach` is `{days, basis, factors}`, not a number.
      const days = r.time_to_breach?.days ?? null;
      out.push({
        key: `risk:${r.endpoint_id}`,
        kind: "risk",
        endpointId: r.endpoint_id,
        method: r.method,
        path: r.path,
        // Time-to-breach outranks raw score: a 0.88 breaching in two days needs
        // attention before a 0.93 with three weeks of head-room.
        weight:
          r.score +
          (days !== null && days <= 7 ? 1 : 0) +
          (r.tier === "CRITICAL" ? 0.5 : 0),
        tier: r.tier,
        headline: `CDRI ${score(r.score)}`,
        detail:
          r.parts
            ?.slice()
            .sort((a, b) => b.contribution - a.contribution)
            .slice(0, 2)
            .map((p) => p.label)
            .join(", ") ?? "",
        breachDays: days,
      });
    }

    for (const d of sunset.data?.items ?? []) {
      // A phase running normally is not work. A hold is a person blocked, and a
      // caller found during quarantine is the workflow catching something.
      const callers = d.hidden_callers?.length ?? 0;
      if (!d.hold && callers === 0) continue;
      out.push({
        key: `sunset:${d.endpoint_id}`,
        kind: "sunset",
        endpointId: d.endpoint_id,
        method: d.method,
        path: d.path,
        weight: d.hold ? 2.4 : 2.0 + Math.min(callers, 9) / 100,
        tier: d.hold ? "HIGH" : "CRITICAL",
        headline: d.hold ? `phase ${d.phase} held` : `phase ${d.phase} — ${callers} caller(s)`,
        detail: d.hold ? (d.hold_reason ?? "held, no reason recorded") : "found during quarantine",
        breachDays: null,
      });
    }

    for (const a of threat.data?.alerts ?? []) {
      out.push({
        key: `res:${a.new_endpoint_id}:${a.vday}`,
        kind: "resurrection",
        endpointId: a.new_endpoint_id,
        method: "",
        path: a.origin_path,
        // A retired endpoint standing back up under a new path outranks
        // everything: it is a control that has already been defeated.
        weight: 3 + a.similarity,
        tier: "CRITICAL",
        headline: `resurrection ${score(a.similarity, 2)}`,
        detail: `matched ${a.origin_path} at v${a.vday}`,
        breachDays: null,
      });
    }

    return out.sort((a, b) => b.weight - a.weight);
  }, [risk.data, sunset.data, threat.data]);

  const visible = useMemo(() => rows.filter((r) => kinds.has(r.kind)), [rows, kinds]);

  // Selection survives a refresh: the list reorders underneath and the operator
  // stays on the item they were reading.
  const current = visible.find((r) => r.key === selected) ?? visible[0] ?? null;

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
      if (e.key !== "j" && e.key !== "k") return;
      e.preventDefault();
      const i = visible.findIndex((r) => r.key === current?.key);
      const next = e.key === "j" ? Math.min(i + 1, visible.length - 1) : Math.max(i - 1, 0);
      if (visible[next]) setSelected(visible[next].key);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [visible, current]);

  const loading = risk.isLoading || sunset.isLoading || threat.isLoading;
  const failed = risk.error ?? sunset.error ?? threat.error;

  return (
    <div className="grid min-h-0 grid-cols-1 gap-3 md:h-full lg:grid-cols-[minmax(320px,1fr)_minmax(0,1.2fr)]">
      {/* ── queue ─────────────────────────────────────────────────────── */}
      <div className="panel flex min-h-[300px] flex-col lg:min-h-0">
        <div className="flex items-center gap-1.5 border-b border-line px-2.5 py-1.5">
          <span className="text-[11px] uppercase tracking-wider text-tx3">queue</span>
          <span className="num text-[11px] text-tx4">{visible.length}</span>
          <span className="ml-auto flex gap-1">
            {(Object.keys(KIND_LABEL) as Kind[]).map((k) => (
              <button
                key={k}
                type="button"
                className={`chip ${kinds.has(k) ? "text-tx1" : "text-tx4 opacity-50"}`}
                onClick={() =>
                  setKinds((s) => {
                    const n = new Set(s);
                    n.has(k) ? n.delete(k) : n.add(k);
                    return n;
                  })
                }
              >
                {KIND_LABEL[k]}
              </button>
            ))}
          </span>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {loading && <p className="px-3 py-2 text-[12.5px] text-tx4">loading…</p>}
          {!loading && failed && (
            <p className="px-3 py-2 text-[12.5px] text-crit">{(failed as Error).message}</p>
          )}
          {!loading && !failed && visible.length === 0 && (
            <p className="px-3 py-2 text-[12.5px] text-tx4">
              nothing above the action threshold
            </p>
          )}

          {visible.map((r) => {
            const on = r.key === current?.key;
            return (
              <button
                key={r.key}
                type="button"
                onClick={() => setSelected(r.key)}
                className={`block w-full border-b border-line/60 px-2.5 py-1.5 text-left ${
                  on ? "bg-line/60" : "hover:bg-line/25"
                }`}
              >
                <div className="flex items-baseline gap-2">
                  <span className={`text-[11px] ${toneText(tierTone(r.tier))}`}>●</span>
                  <span className="truncate text-[12.5px] text-tx1">
                    {r.method} {r.path}
                  </span>
                  {r.breachDays !== null && (
                    <span
                      className={`num ml-auto shrink-0 text-[11px] ${
                        r.breachDays <= 7 ? "text-crit" : "text-tx4"
                      }`}
                      title="days until the risk threshold is breached"
                    >
                      {r.breachDays}d
                    </span>
                  )}
                </div>
                <div className="mt-0.5 flex items-baseline gap-2 pl-[18px]">
                  <span className="text-[11px] text-tx2">{r.headline}</span>
                  <span className="truncate text-[11px] text-tx4">{r.detail}</span>
                </div>
              </button>
            );
          })}
        </div>

        <div className="border-t border-line px-2.5 py-1 text-[11px] text-tx4">
          j / k to move · ⌘K to jump
        </div>
      </div>

      {/* ── evidence ──────────────────────────────────────────────────── */}
      <div className="panel min-h-[300px] overflow-y-auto lg:min-h-0">
        {current ? (
          <Evidence row={current} />
        ) : (
          <p className="px-3 py-2 text-[12.5px] text-tx4">select an item</p>
        )}
      </div>
    </div>
  );
}

/** Why this scores what it does, assembled from the stages that decided it. */
function Evidence({ row }: { row: Row }) {
  const cls = useQuery({
    queryKey: ["classification", row.endpointId],
    queryFn: () => get<ClassificationEndpointId>(`/classification/${row.endpointId}`),
  });
  const impact = useQuery({
    queryKey: ["impact", row.endpointId],
    queryFn: () => get<ImpactEndpointId>(`/impact/${row.endpointId}`),
  });
  const own = useQuery({
    queryKey: ["ownership", row.endpointId],
    queryFn: () => get<CorrelationEndpointIdOwnership>(`/correlation/${row.endpointId}/ownership`),
  });
  const risk = useQuery({
    queryKey: ["risk-one", row.endpointId],
    queryFn: () => get<Risk>("/risk?limit=200"),
    select: (d) => d.items.find((i) => i.endpoint_id === row.endpointId),
  });

  const parts = risk.data?.parts ?? [];
  // Scaled to the largest contributor rather than to 1.0: every CDRI term is
  // a fraction of a score that rarely exceeds 0.3, so an absolute scale draws
  // six near-invisible stubs and ranks nothing.
  const maxPart = Math.max(...parts.map((p) => p.contribution), 0.0001);

  return (
    <div className="px-3 py-2.5">
      {[cls.error, impact.error, own.error, risk.error].some(Boolean) ? (
        <div className="mb-3 space-y-1 panel border-crit px-3 py-2 text-[11px] text-crit">
          {([
            ["classification", cls.error],
            ["blast radius", impact.error],
            ["ownership", own.error],
            ["risk", risk.error],
          ] as const).map(([label, failure]) => failure ? (
            <div key={label}>{label} unavailable — {(failure as Error).message}</div>
          ) : null)}
        </div>
      ) : null}
      <div className="mb-3">
        <div className="text-[12.5px] text-tx1">
          {row.method} {row.path}
        </div>
        <div className="mt-0.5 flex items-center gap-2 text-[11px]">
          <span className={toneText(lifecycleTone(cls.data?.lifecycle))}>
            {cls.data?.lifecycle ?? "—"}
          </span>
          <span className="text-tx4">×</span>
          <span className={toneText(governanceTone(cls.data?.governance))}>
            {cls.data?.governance ?? "—"}
          </span>
          <span className="text-tx4">·</span>
          <span className="text-tx3">{cls.data?.confidence ?? "—"}</span>
          <button
            className="ml-auto text-[11px] text-tx2 hover:text-tx1 hover:underline"
            type="button"
            onClick={() => navigate(`/estate?endpoint=${row.endpointId}`)}
          >
            open in register →
          </button>
        </div>
      </div>

      {parts.length > 0 && (
        <Section title="what the score is made of">
          {parts
            .slice()
            .sort((a, b) => b.contribution - a.contribution)
            .map((p) => (
              <div key={p.key} className="flex items-baseline gap-2 py-0.5">
                <span className="w-44 shrink-0 truncate text-[11px] text-tx2">
                  {p.label}
                </span>
                {/* The bar is the contribution, so the eye ranks the causes in
                    the same order the score does. */}
                {/* No opacity modifier. `bg-crit/70` compiles to
                    `rgb(var(--crit) / 0.7)`, and --crit is a hex, so the fill
                    silently painted nothing and every bar read as empty. */}
                <span className="h-[6px] flex-1 bg-line">
                  <span
                    className="block h-full bg-crit"
                    style={{ width: `${Math.min(100, (p.contribution / maxPart) * 100)}%` }}
                  />
                </span>
                <span className="num w-14 shrink-0 text-right text-[11px] text-tx3">
                  {score(p.contribution)}
                </span>
                <span className="num w-12 shrink-0 text-right text-[11px] text-tx4">
                  ×{p.w}
                </span>
              </div>
            ))}
        </Section>
      )}

      <Section title="how it was classified">
        {(cls.data?.trace ?? []).length === 0 ? (
          <p className="text-[11px] text-tx4">no trace recorded</p>
        ) : (
          /* Two shapes, not one. The engine records the questions it asked
             (`q`/`question`/`answer`/`source`) and then the rules it applied
             (`rule`/`applied`/`result`) — and the rules are the half that
             actually produces the verdict. Rendering only the questions printed
             four rows of `undefined` where the reasoning should have been. */
          (cls.data?.trace ?? []).map((t, i) =>
            "rule" in t ? (
              <div
                key={i}
                className="flex items-baseline gap-2 border-t border-line/60 py-0.5 text-[11px] first:border-0"
              >
                <span className="w-6 shrink-0 text-tx4">→</span>
                <span className="shrink-0 text-tx3">{t.rule}</span>
                <span className="flex-1 truncate text-tx2" title={t.applied}>
                  {t.applied}
                </span>
                <span className="shrink-0 text-tx1">{String(t.result)}</span>
              </div>
            ) : (
              <div key={i} className="flex items-baseline gap-2 py-0.5 text-[11px]">
                <span className="w-6 shrink-0 text-tx4">{t.q}</span>
                <span className="flex-1 text-tx2">{t.question}</span>
                <span className="shrink-0 text-tx1">{String(t.answer)}</span>
                <span
                  className="w-28 shrink-0 truncate text-right text-[11px] text-tx4"
                  title={t.source}
                >
                  {t.source}
                </span>
              </div>
            ),
          )
        )}
      </Section>

      <Section title="blast radius">
        <Field label="tier" value={impact.data?.tier ?? "—"} />
        <Field label="direct callers" value={num(impact.data?.direct_callers)} />
        <Field label="second hop" value={num(impact.data?.hop2_callers)} />
        <Field
          label="datastores"
          value={(impact.data?.datastores ?? []).join(", ") || "—"}
        />
      </Section>

      <Section title="ownership">
        <Field label="owner" value={own.data?.owner_email ?? "unresolved"} />
        <Field label="resolved by" value={own.data?.resolved_by ?? "—"} />
        <Field
          label="confidence"
          value={own.data?.confidence !== undefined ? pct(own.data.confidence) : "—"}
        />
        <Field
          label="reachable"
          value={
            own.data?.reachable === false ? (
              <span className="text-warn">no — escalates to {own.data?.escalation}</span>
            ) : own.data?.reachable === true ? (
              "yes"
            ) : (
              "—"
            )
          }
        />
      </Section>
    </div>
  );
}
