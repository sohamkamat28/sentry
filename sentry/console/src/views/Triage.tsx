import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { get, post } from "../lib/api";
import { Confirm } from "../components/data/Confirm";
import { Field, Section } from "../components/data/Drawer";
import { micros, num, pct, score } from "../lib/format";
import { navigate } from "../lib/router";
import {
  controlTone,
  governanceTone,
  lifecycleTone,
  tierTone,
  toneText,
} from "../lib/severity";
import { SLOW_MS, useLive } from "../lib/useLive";
import type { Decommission, Risk, Threat } from "../lib/api-types";

/**
 * What needs me now.
 *
 * The console had fifteen surfaces and no answer to the first question an
 * operations floor asks. Ranking the estate meant opening Risk Register,
 * Findings, Decommission and Threat, then holding the merged ordering in your
 * head — so in practice nobody ranked anything, they worked whichever list they
 * happened to open.
 *
 * This is that merge, done once and kept live. Three panes, which is where
 * every real operations tool lands: the queue never loses your place, the
 * evidence arrives beside the item, and the action sits next to the evidence it
 * should be taken on. Nothing here computes a new verdict — every figure is
 * already produced by a stage and served by an existing route.
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
    <div className="grid h-full min-h-0 grid-cols-1 gap-3 lg:grid-cols-[minmax(320px,1fr)_minmax(0,1.2fr)_minmax(280px,0.9fr)]">
      {/* ── queue ─────────────────────────────────────────────────────── */}
      <div className="panel flex min-h-0 flex-col">
        <div className="flex items-center gap-1.5 border-b border-line px-2.5 py-1.5">
          <span className="text-[10.5px] uppercase tracking-wider text-tx3">queue</span>
          <span className="num text-[11px] text-tx4">{visible.length}</span>
          <span className="ml-auto flex gap-1">
            {(Object.keys(KIND_LABEL) as Kind[]).map((k) => (
              <button
                key={k}
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
          {loading && <p className="px-3 py-2 text-[12px] text-tx4">loading…</p>}
          {!loading && failed && (
            <p className="px-3 py-2 text-[12px] text-crit">{(failed as Error).message}</p>
          )}
          {!loading && !failed && visible.length === 0 && (
            <p className="px-3 py-2 text-[12px] text-tx4">
              nothing above the action threshold
            </p>
          )}

          {visible.map((r) => {
            const on = r.key === current?.key;
            return (
              <button
                key={r.key}
                onClick={() => setSelected(r.key)}
                className={`block w-full border-b border-line/60 px-2.5 py-1.5 text-left ${
                  on ? "bg-line/60" : "hover:bg-line/25"
                }`}
              >
                <div className="flex items-baseline gap-2">
                  <span className={`text-[11px] ${toneText(tierTone(r.tier))}`}>●</span>
                  <span className="truncate text-[12px] text-tx1">
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
                  <span className="truncate text-[10.5px] text-tx4">{r.detail}</span>
                </div>
              </button>
            );
          })}
        </div>

        <div className="border-t border-line px-2.5 py-1 text-[10.5px] text-tx4">
          j / k to move · ⌘K to jump
        </div>
      </div>

      {/* ── evidence ──────────────────────────────────────────────────── */}
      <div className="panel min-h-0 overflow-y-auto">
        {current ? (
          <Evidence row={current} />
        ) : (
          <p className="px-3 py-2 text-[12px] text-tx4">select an item</p>
        )}
      </div>

      {/* ── act ───────────────────────────────────────────────────────── */}
      <div className="panel min-h-0 overflow-y-auto">
        {current ? (
          <Act endpointId={current.endpointId} />
        ) : (
          <p className="px-3 py-2 text-[12px] text-tx4">—</p>
        )}
      </div>
    </div>
  );
}

/** Why this scores what it does, assembled from the stages that decided it. */
function Evidence({ row }: { row: Row }) {
  const cls = useQuery({
    queryKey: ["classification", row.endpointId],
    queryFn: () => get<any>(`/classification/${row.endpointId}`),
  });
  const impact = useQuery({
    queryKey: ["impact", row.endpointId],
    queryFn: () => get<any>(`/impact/${row.endpointId}`),
  });
  const own = useQuery({
    queryKey: ["ownership", row.endpointId],
    queryFn: () => get<any>(`/correlation/${row.endpointId}/ownership`),
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
      <div className="mb-3">
        <div className="text-[13px] text-tx1">
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
            className="ml-auto text-[10.5px] text-info hover:underline"
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
                <span className="w-44 shrink-0 truncate text-[11.5px] text-tx2">
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
                <span className="num w-12 shrink-0 text-right text-[10.5px] text-tx4">
                  ×{p.w}
                </span>
              </div>
            ))}
        </Section>
      )}

      <Section title="how it was classified">
        {(cls.data?.trace ?? []).length === 0 ? (
          <p className="text-[11.5px] text-tx4">no trace recorded</p>
        ) : (
          /* Two shapes, not one. The engine records the questions it asked
             (`q`/`question`/`answer`/`source`) and then the rules it applied
             (`rule`/`applied`/`result`) — and the rules are the half that
             actually produces the verdict. Rendering only the questions printed
             four rows of `undefined` where the reasoning should have been. */
          (cls.data?.trace ?? []).map((t: any, i: number) =>
            t.rule ? (
              <div
                key={i}
                className="flex items-baseline gap-2 border-t border-line/60 py-0.5 text-[11.5px] first:border-0"
              >
                <span className="w-6 shrink-0 text-tx4">→</span>
                <span className="shrink-0 text-tx3">{t.rule}</span>
                <span className="flex-1 truncate text-tx2" title={t.applied}>
                  {t.applied}
                </span>
                <span className="shrink-0 text-tx1">{String(t.result)}</span>
              </div>
            ) : (
              <div key={i} className="flex items-baseline gap-2 py-0.5 text-[11.5px]">
                <span className="w-6 shrink-0 text-tx4">{t.q}</span>
                <span className="flex-1 text-tx2">{t.question}</span>
                <span className="shrink-0 text-tx1">{String(t.answer)}</span>
                <span
                  className="w-28 shrink-0 truncate text-right text-[10.5px] text-tx4"
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

/** The controls, the evidence they were judged on, and the buttons. */
function Act({ endpointId }: { endpointId: string }) {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["remediation-detail", endpointId],
    queryFn: () => get<any>(`/remediation/${endpointId}`),
  });

  const apply = useMutation({
    mutationFn: (controlId: number) =>
      post(`/remediation/${endpointId}/apply`, { control_id: controlId }),
    onSuccess: () => qc.invalidateQueries(),
  });
  const revert = useMutation({
    mutationFn: (controlId: number) =>
      post(`/remediation/control/${controlId}/revert`, { reason: "operator" }),
    onSuccess: () => qc.invalidateQueries(),
  });

  const controls = data?.controls ?? [];

  return (
    <div className="px-3 py-2.5">
      <h3 className="mb-2 text-[10.5px] uppercase tracking-wider text-tx3">controls</h3>

      {isLoading && <p className="text-[12px] text-tx4">loading…</p>}
      {!isLoading && controls.length === 0 && (
        <p className="text-[12px] text-tx4">
          none proposed — stage 10 generates these on its next pass
        </p>
      )}

      <div className="space-y-3">
        {controls.map((c: any) => (
          <div key={c.id} className="panel px-2.5 py-2">
            <div className="flex items-baseline gap-2">
              <span className="text-[12px] text-tx1">{c.kind}</span>
              <span className={`chip ${toneText(controlTone(c.state))}`}>
                {c.state.toLowerCase()}
              </span>
            </div>

            {/* The verdict sits beside the button, not on another surface. An
                approver authorising a gateway write is entitled to see the
                measurement it rests on without navigating away from it. */}
            {c.judge ? (
              <div className="mt-1.5 space-y-0.5 text-[11px]">
                <div className="flex items-baseline gap-2">
                  <span className="text-tx4">judge</span>
                  <span className={c.judge.verdict === "PASS" ? "text-ok" : "text-warn"}>
                    {c.judge.verdict}
                  </span>
                  {c.judge.reason && <span className="text-tx3">{c.judge.reason}</span>}
                </div>
                <div className="flex flex-wrap gap-x-3 text-tx3">
                  <span>schema {c.judge.scores?.schema}</span>
                  <span>error {c.judge.scores?.error}</span>
                  <span>exposure {c.judge.scores?.exposure}</span>
                  <span
                    className={
                      c.judge.scores?.latency === 0 ? "text-warn" : undefined
                    }
                  >
                    latency {c.judge.scores?.latency}
                  </span>
                </div>
                <div className="text-tx4">
                  {micros(c.judge.latency_delta_us)} against a{" "}
                  {micros(c.judge.budget_us)} budget · {c.judge.replay?.requests} replayed
                  {c.judge.replay?.bodyless > 0 && (
                    <span className="text-warn"> · {c.judge.replay.bodyless} bodyless</span>
                  )}
                </div>
              </div>
            ) : (
              <p className="mt-1 text-[11px] text-tx4">not yet judged</p>
            )}

            <div className="mt-2">
              {c.state === "APPLIED" ? (
                <Confirm
                  label="revert"
                  destructive
                  question={
                    <>
                      Remove <b>{c.kind}</b> from the live gateway for this endpoint. The
                      route returns to its unprotected behaviour immediately.
                    </>
                  }
                  pending={revert.isPending}
                  error={revert.error}
                  onConfirm={() => revert.mutate(c.id)}
                />
              ) : c.state === "JUDGED" ? (
                <Confirm
                  label="apply"
                  question={
                    <>
                      Write <b>{c.kind}</b> to the live gateway for this endpoint.
                    </>
                  }
                  pending={apply.isPending}
                  error={apply.error}
                  onConfirm={() => apply.mutate(c.id)}
                />
              ) : (
                <span className="text-[11px] text-tx4">
                  {c.state === "REJECTED"
                    ? "refused by the Judge on measured evidence"
                    : "awaiting the Judge"}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {data?.change_request && (
        <Section title="change request">
          <Field label="number" value={data.change_request.number ?? "—"} />
          <Field label="state" value={data.change_request.state} />
          {data.change_request.stub && (
            <p className="mt-1 text-[11px] text-warn">
              stub — no live ServiceNow instance is configured
            </p>
          )}
        </Section>
      )}
    </div>
  );
}
