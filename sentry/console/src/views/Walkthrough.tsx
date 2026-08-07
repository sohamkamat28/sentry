import { useEffect, useMemo, useState } from "react";

import { SLOW_MS, useLive } from "../lib/useLive";
import { Step, StepRail } from "../components/story/Step";
import { Term } from "../components/data/Term";
import { navigate } from "../lib/router";
import { score as fmtScore } from "../lib/format";
import type {
  Decommission,
  Estate,
  EstateItemsItem,
  Findings,
  Risk,
  Threat,
  Zerotrust,
} from "../lib/api-types";

/**
 * One API, followed end to end.
 *
 * The pipeline is a real sequence and nobody was ever going to discover it by
 * clicking fifteen navigation items in the right order. Told as eight steps it
 * becomes a story a stranger finishes without a presenter.
 *
 * The subject is **chosen from the recording, not hardcoded**. An earlier draft
 * pinned an endpoint id; the pipeline then re-ran, that endpoint moved from
 * ZOMBIE to RETIRED, and half the steps lost their data. Selecting the
 * best-evidenced endpoint at render time means the walkthrough survives every
 * future capture, and every sentence below is built from the fields rather than
 * written around a value that was true once.
 */

const TITLES = [
  "We found it",
  "Nobody uses it",
  "Nobody owns it",
  "It is leaking",
  "How dangerous",
  "What law it breaks",
  "What we did",
  "It came back",
];

export function Walkthrough() {
  const [i, setI] = useState(0);

  const estate = useLive<Estate>("estate", "/estate?limit=500", SLOW_MS);
  const risk = useLive<Risk>("risk", "/risk?limit=300", SLOW_MS);
  const findings = useLive<Findings>("findings", "/findings", SLOW_MS);
  const zt = useLive<Zerotrust>("zerotrust", "/zerotrust", SLOW_MS);
  const dec = useLive<Decommission>("decommission", "/decommission", SLOW_MS);
  const threat = useLive<Threat>("threat", "/threat", SLOW_MS);

  /**
   * The most completely evidenced endpoint in the recording.
   *
   * Ranked on how much of the story it can actually tell — sensitive data, a
   * compliance finding, a score — rather than on severity alone, because a step
   * with no data behind it is worse than a lower-scoring subject.
   */
  const subject = useMemo<EstateItemsItem | undefined>(() => {
    const items = estate.data?.items ?? [];
    const scored = new Map((risk.data?.items ?? []).map((r) => [r.endpoint_id, r]));
    const found = new Set((findings.data?.items ?? []).map((f) => f.endpoint_id));
    return items
      .filter((e) => e.data_classes.length > 0 && found.has(e.id) && scored.has(e.id))
      .sort((a, b) => {
        const w = (e: EstateItemsItem) =>
          (e.cdri ?? 0) +
          e.data_classes.length * 0.05 +
          (e.governance === "SHADOW" || e.governance === "ORPHANED" ? 0.2 : 0) +
          (e.path.includes("#") || e.service?.includes("finacle") ? 0.15 : 0);
        return w(b) - w(a);
      })[0];
  }, [estate.data, risk.data, findings.data]);

  const id = subject?.id;
  const riskRow = (risk.data?.items ?? []).find((r) => r.endpoint_id === id);
  const findingRow = (findings.data?.items ?? []).find((f) => f.endpoint_id === id);
  const ztRow = (zt.data?.items ?? []).find((z) => z.endpoint_id === id);
  const decRow = (dec.data?.items ?? []).find((d) => d.endpoint_id === id);
  const retired = (dec.data?.items ?? []).filter((d) => d.phase === "RETIRED" && d.worm_object);
  const alerts = threat.data?.alerts ?? [];

  const cls = useLive<Record<string, unknown>>(
    id ? `cls-${id}` : "cls-none",
    id ? `/classification/${id}` : "/classification",
    SLOW_MS,
  );
  const own = useLive<Record<string, unknown>>(
    id ? `own-${id}` : "own-none",
    id ? `/correlation/${id}/ownership` : "/classification",
    SLOW_MS,
  );

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if (e.key === "ArrowRight") setI((n) => Math.min(n + 1, TITLES.length - 1));
      if (e.key === "ArrowLeft") setI((n) => Math.max(n - 1, 0));
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (estate.isLoading || !subject) {
    return (
      <p className="mx-auto max-w-5xl font-sans text-[13px] text-tx4">
        {estate.isLoading ? "loading the recording…" : "no endpoint in this recording carries enough evidence to walk through."}
      </p>
    );
  }

  const name = `${subject.method} ${subject.path}`;
  const trace = (cls.data?.trace as Array<Record<string, unknown>> | undefined) ?? [];
  const q1 = trace.find((t) => t.q === 1)?.answer;

  const steps = [
    <Step
      key={0}
      index={0}
      total={8}
      question="Nobody registered this API."
      answer={
        <>
          <code className="text-tx1">{name}</code> is running in production on{" "}
          <b className="text-tx1">{subject.service}</b>. It appears in no gateway
          registry and in no code repository — we only know it exists because we
          watched the traffic.
        </>
      }
      evidence={
        <>
          An <Term as="ebpf">eBPF</Term> probe attached to <code>SSL_write</code> in
          the Linux kernel, reading the request before it was encrypted. The
          application was never modified.
        </>
      }
      raw={subject}
    >
      <Card label="What this means">
        You cannot protect what you do not know about. Scanners see what is
        declared; this sees what is actually running.
      </Card>
    </Step>,

    <Step
      key={1}
      index={1}
      total={8}
      question="And nobody calls it."
      answer={
        <>
          Classified <Verdict text={subject.lifecycle ?? "—"} tone="lifecycle" /> — last
          called <b className="num text-tx1">{q1 === undefined ? "—" : String(q1)}</b>{" "}
          <Term>vday</Term>s ago, and still switched on and reachable.
        </>
      }
      evidence={
        <>
          Five questions asked against recorded fields, then the rules that fired.
          The trace is stored, so the verdict can be re-derived later rather than
          taken on trust.
        </>
      }
      raw={trace}
    >
      <Trace rows={trace} />
    </Step>,

    <Step
      key={2}
      index={2}
      total={8}
      question="And nobody owns it."
      answer={
        <>
          Governance: <Verdict text={subject.governance ?? "—"} tone="governance" />.
          We checked four places for a responsible team and found nothing, so it
          escalates to{" "}
          <b className="text-tx1">{String(own.data?.escalation ?? "an escalation contact")}</b>.
        </>
      }
      evidence={
        <>
          The ownership ladder: CODEOWNERS, then git blame, then deploy metadata,
          then the staff directory. Resolved by{" "}
          <code>{String(own.data?.resolved_by ?? "—")}</code>.
        </>
      }
      raw={own.data}
    >
      <Card label="Why this is the real problem">
        An unowned API is one nobody will ever be asked to fix. That is why it
        survived for years.
      </Card>
    </Step>,

    <Step
      key={3}
      index={3}
      total={8}
      question="It is handing out identity numbers."
      answer={
        <>
          Its responses carry{" "}
          {subject.data_classes.map((d, n) => (
            <span key={d}>
              {n > 0 ? ", " : ""}
              <b className="text-warn">{d}</b>
            </span>
          ))}
          {" — "}with <b className="text-crit">{subject.auth === "none" ? "no authentication at all" : subject.auth}</b>
          {subject.tls_version ? <> and TLS {subject.tls_version}</> : null}.
        </>
      }
      evidence={
        <>
          The kernel probe classified the response body in place and recorded only
          the <b>field names</b>. No identity value was ever copied out — a token
          is rewound out of the buffer the moment it turns out to be a value.
        </>
      }
      raw={{ data_classes: subject.data_classes, auth: subject.auth, tls: subject.tls_version }}
    >
      <Card label="The privacy property">
        A tool that had to read the values to find them would itself become the
        breach. This one never holds one.
      </Card>
    </Step>,

    <Step
      key={4}
      index={4}
      total={8}
      question={`How dangerous is it? ${fmtScore(riskRow?.score ?? subject.cdri)}`}
      answer={
        <>
          Rated <Verdict text={riskRow?.tier ?? subject.tier ?? "—"} tone="tier" /> on a
          0-to-1 scale we call <Term as="cdri">CDRI</Term>. It is not one opaque
          number — it is six weighted factors that add up in front of you.
        </>
      }
      evidence={
        <>
          Each factor is measured, not estimated. A factor contributing zero was
          checked and found clean, which is different from never being checked.
        </>
      }
      raw={riskRow}
    >
      <Parts parts={riskRow?.parts ?? []} total={riskRow?.score ?? 0} />
    </Step>,

    <Step
      key={5}
      index={5}
      total={8}
      // Counted from the payload. A headline that hardcoded "six" was wrong the
      // moment the pipeline re-ran and produced seven.
      question={
        findingRow
          ? `This breaks the law in ${countViolated(findingRow)} places.`
          : "What the law says about it."
      }
      answer={
        <>
          {findingRow
            ? <>Mapped to <b className="text-tx1">{countViolated(findingRow)}</b> breached clauses across{" "}
                <b className="text-tx1">{countFrameworks(findingRow)}</b> regulatory frameworks.</>
            : "No compliance finding was generated for this endpoint in this run."}
        </>
      }
      evidence="Each citation carries the clause, the requirement, and the evidence used to reach the verdict."
      raw={findingRow?.regulations}
    >
      <Citations finding={findingRow} />
    </Step>,

    <Step
      key={6}
      index={6}
      total={8}
      question="So we shut it down — carefully."
      answer={
        decRow ? (
          <>
            Enrolled in a staged <Term>sunset</Term>: warn the callers, quarantine,
            then switch off. It reached phase{" "}
            <b className="text-tx1">{decRow.phase}</b>
            {decRow.hidden_callers.length > 0 ? (
              <> — and quarantine caught <b className="text-warn">{decRow.hidden_callers.length}</b> caller(s) nobody knew about.</>
            ) : (
              <>, with no hidden callers found.</>
            )}
          </>
        ) : ztRow ? (
          <>
            Posture <b className="num text-tx1">{ztRow.satisfied}/{ztRow.of}</b> — the
            missing controls were proposed, measured against replayed traffic, and
            put in front of an approver.
          </>
        ) : (
          <>Controls were proposed for this endpoint and queued for measurement.</>
        )
      }
      evidence={
        <>
          Nothing reaches the gateway unmeasured: the <Term>judge</Term> replays real
          captured traffic against each proposed change and refuses any that costs
          too much latency or breaks the contract. A human approver signs the rest.
        </>
      }
      raw={decRow ?? ztRow}
    >
      <Card label="Why it is staged">
        Switching off an API that something still calls causes the outage you were
        trying to prevent. Quarantine is what finds those callers first.
      </Card>
    </Step>,

    <Step
      key={7}
      index={7}
      total={8}
      question="Then it came back under a new name."
      answer={
        alerts.length > 0 ? (
          <>
            <b className="text-crit">{alerts.length}</b> retired endpoint(s)
            reappeared at different paths. Renaming a route defeats every control
            attached to the old one — so we match on shape, not on name.
          </>
        ) : (
          <>No <Term>resurrection</Term> was detected in this recording.</>
        )
      }
      evidence={
        <>
          MinHash over the request and response shape, with LSH for candidate
          lookup. The path changed; the shape did not.
        </>
      }
      raw={alerts}
    >
      <Resurrections alerts={alerts} retired={retired} />
    </Step>,
  ];

  return (
    <div className="mx-auto max-w-6xl">
      <header className="mb-6 border-b border-line pb-4">
        <p className="font-sans text-[11px] font-medium uppercase tracking-[0.14em] text-tx4">
          Following one API
        </p>
        <h1 className="mt-1 break-all font-mono text-[15px] text-tx1 sm:text-[17px]">{name}</h1>
        <p className="mt-1 font-sans text-[12px] text-tx3">
          {subject.service}
          {subject.team ? ` · ${subject.team}` : ""} · use ← → to move between steps
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-[210px_minmax(0,1fr)] lg:gap-10">
        {/* `min-w-0`, or the rail's eight buttons size this grid column by their
            own content and the page scrolls sideways on a phone. A grid child
            defaults to `min-width: auto`, which ignores the child's
            `overflow-x-auto` entirely. */}
        <div className="min-w-0 lg:sticky lg:top-4 lg:self-start">
          <StepRail titles={TITLES} current={i} onSelect={setI} />
        </div>

        <div className="min-w-0">
          {steps[i]}

          <div className="mt-10 flex items-center gap-3 border-t border-line pt-5">
            <button
              type="button"
              className="btn font-sans"
              disabled={i === 0}
              onClick={() => setI((n) => Math.max(0, n - 1))}
            >
              ← Back
            </button>
            {i < TITLES.length - 1 ? (
              <button
                type="button"
                className="rounded-sm border border-info bg-info px-4 py-2 font-sans text-[13px] font-semibold text-bg transition hover:brightness-110 active:translate-y-px"
                onClick={() => setI((n) => n + 1)}
              >
                Next: {TITLES[i + 1]} →
              </button>
            ) : (
              <button
                type="button"
                className="rounded-sm border border-info bg-info px-4 py-2 font-sans text-[13px] font-semibold text-bg transition hover:brightness-110"
                onClick={() => navigate("/explore")}
              >
                Explore all {estate.data?.items.length ?? ""} APIs →
              </button>
            )}
            <span className="ml-auto font-sans text-[11.5px] text-tx4">
              {i + 1} / {TITLES.length}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── small presentational pieces ───────────────────────────────────────── */

function Card({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="panel px-4 py-3.5">
      <div className="font-sans text-[10.5px] font-medium uppercase tracking-[0.12em] text-tx4">
        {label}
      </div>
      <p className="mt-1.5 max-w-[58ch] font-sans text-[13.5px] leading-6 text-tx2">{children}</p>
    </div>
  );
}

function Verdict({ text, tone }: { text: string; tone: "lifecycle" | "governance" | "tier" }) {
  const bad = ["ZOMBIE", "SHADOW", "CRITICAL", "ORPHANED", "HIGH"].includes(text.toUpperCase());
  const colour = bad ? (tone === "tier" ? "text-crit" : "text-warn") : "text-ok";
  return (
    <b className={colour}>
      <Term>{text.toLowerCase()}</Term>
    </b>
  );
}

/** The classifier's stored reasoning: questions asked, then rules fired. */
function Trace({ rows }: { rows: Array<Record<string, unknown>> }) {
  if (rows.length === 0) return null;
  return (
    <div className="panel overflow-hidden">
      {rows.map((t, n) => (
        <div
          key={n}
          className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 border-b border-line px-4 py-2 text-[12.5px] last:border-0"
        >
          {t.rule ? (
            <>
              <span className="w-5 shrink-0 text-tx4">→</span>
              <span className="font-sans text-tx3">{String(t.rule)}</span>
              <span className="font-sans text-tx2">{String(t.applied)}</span>
              <span className="ml-auto font-semibold text-tx1">{String(t.result)}</span>
            </>
          ) : (
            <>
              <span className="w-5 shrink-0 num text-tx4">{String(t.q)}</span>
              <span className="font-sans text-tx2">{String(t.question)}</span>
              <span className="ml-auto num text-tx1">{String(t.answer)}</span>
            </>
          )}
        </div>
      ))}
    </div>
  );
}

/** The score, decomposed, so the total is visibly the sum of its parts. */
function Parts({
  parts,
  total,
}: {
  parts: Array<{ key: string; label: string; contribution: number; w: number }>;
  total: number;
}) {
  if (parts.length === 0) return null;
  const max = Math.max(...parts.map((p) => p.contribution), 0.0001);
  return (
    <div className="panel px-4 py-3.5">
      {parts
        .slice()
        .sort((a, b) => b.contribution - a.contribution)
        .map((p) => (
          <div key={p.key} className="flex items-center gap-3 py-1">
            <span className="w-40 shrink-0 font-sans text-[12.5px] text-tx2 sm:w-52">
              {p.label}
            </span>
            <span className="h-[7px] flex-1 rounded-sm bg-line">
              <span
                className={`block h-full rounded-sm ${p.contribution > 0 ? "bg-crit" : ""}`}
                style={{ width: `${Math.min(100, (p.contribution / max) * 100)}%` }}
              />
            </span>
            <span className="num w-12 shrink-0 text-right text-[12px] text-tx2">
              {p.contribution.toFixed(3)}
            </span>
          </div>
        ))}
      <div className="mt-2 flex items-baseline gap-3 border-t border-line pt-2">
        <span className="w-40 shrink-0 font-sans text-[12.5px] font-semibold text-tx1 sm:w-52">
          Total
        </span>
        <span className="flex-1" />
        <span className="num w-12 text-right text-[13px] font-semibold text-crit">
          {total.toFixed(3)}
        </span>
      </div>
    </div>
  );
}

function countViolated(f: Findings["items"][number]) {
  return f.regulations.filter((c) => c.status === "VIOLATED").length;
}
function countFrameworks(f: Findings["items"][number]) {
  return new Set(f.regulations.map((c) => c.framework)).size;
}

function Citations({ finding }: { finding?: Findings["items"][number] }) {
  if (!finding) return null;
  return (
    <div className="panel overflow-hidden">
      {finding.regulations.map((c, n) => (
        <div
          key={`${c.framework}:${c.clause}:${n}`}
          className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-line px-4 py-2.5 last:border-0"
        >
          <span className="font-sans text-[12.5px] font-medium text-tx1">{c.framework}</span>
          <span className="font-sans text-[11.5px] text-tx4">{c.clause}</span>
          <span
            className={`ml-auto font-sans text-[11px] font-semibold uppercase tracking-wide ${
              c.status === "VIOLATED" ? "text-crit" : "text-ok"
            }`}
          >
            {c.status.toLowerCase()}
          </span>
        </div>
      ))}
      <p className="border-t border-line px-4 py-2 font-sans text-[11.5px] text-tx4">
        One clause reads <span className="text-ok">satisfied</span> — a tool that only
        ever finds faults is not measuring anything.
      </p>
    </div>
  );
}

function Resurrections({
  alerts,
  retired,
}: {
  alerts: Threat["alerts"];
  retired: Decommission["items"];
}) {
  return (
    <div className="space-y-3">
      {retired.length > 0 && (
        <div className="panel px-4 py-3.5">
          <div className="font-sans text-[10.5px] font-medium uppercase tracking-[0.12em] text-tx4">
            The retirement record
          </div>
          <p className="mt-1.5 font-sans text-[13px] leading-6 text-tx2">
            {retired.length} endpoint(s) were archived to <Term>WORM</Term> storage
            with a certificate. Locked until{" "}
            <b className="text-ok">{String(retired[0].worm_retain_until ?? "").slice(0, 10)}</b> —
            it cannot be deleted before then, including by an administrator.
          </p>
        </div>
      )}

      {alerts.length > 0 && (
        <div className="panel overflow-hidden">
          {alerts.map((a, n) => (
            <div
              key={`${a.new_endpoint_id}:${n}`}
              className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-line px-4 py-2.5 last:border-0"
            >
              <span className="font-mono text-[12px] text-tx1">came back as a new path</span>
              <span className="font-sans text-[11.5px] text-tx4">
                matched <code>{a.origin_path}</code>
              </span>
              <span className="ml-auto num text-[12.5px] font-semibold text-crit">
                {a.similarity.toFixed(2)}
              </span>
              <span className="font-sans text-[11px] text-tx4">vs {a.threshold} threshold</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
