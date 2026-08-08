
import { useState } from "react";

import { SLOW_MS, useLive } from "../lib/useLive";
import { Drawer, Field, Section } from "../components/data/Drawer";
import { Table } from "../components/data/Table";
import { num, vday } from "../lib/format";
import type { Findings as F, FindingsItemsItem } from "../lib/api-types";

/**
 * Generated findings.
 *
 * Which generator wrote a narrative is not decoration: a template and a model
 * are different artefacts with different reliability, and the console labels
 * which it is rather than presenting both as analysis. That claim is kept, but
 * it does not need a column — the distribution is in the chips above the table,
 * and a column reading "template" down all forty-seven rows states it forty-six
 * times too often. It is now a marker on the endpoint, shown only when the
 * narrative came from something other than the template — which is the only
 * case where it changes how the row should be read.
 */
/**
 * Strip the lead clause that restates the column beside it.
 *
 * Every generated summary opens "Estimated 14 days before active exploitation
 * (heuristic)." — all forty-eight of them — and that number is already the
 * `time to breach` column two along. Forty-eight identical openings pushed the
 * only varying half of each sentence past the clamp, so the table showed the
 * repeated part and hid the part worth reading.
 *
 * Only removed when the estimate really is rendered elsewhere. With no
 * `time_to_breach_d` the sentence is the sole carrier of that figure and stays.
 */
const ESTIMATE_LEAD = /^Estimated\s+\d+\s+days?\s+before\s+active\s+exploitation\s*\(heuristic\)\.\s*/i;

function summaryFor(f: FindingsItemsItem): string {
  const full = f.narrative.summary;
  if (f.time_to_breach_d == null) return full;
  const trimmed = full.replace(ESTIMATE_LEAD, "");
  // Never return an empty cell: if the estimate was the whole summary, the
  // sentence is all there is and it stays.
  return trimmed.trim().length > 0 ? trimmed : full;
}

export function Findings() {
  const [open, setOpen] = useState<FindingsItemsItem | null>(null);
  const { data, isLoading, error } = useLive<F>("findings", "/findings", SLOW_MS);

  const gens = Object.entries(data?.generators ?? {});
  const vdays = (data?.items ?? []).map((f) => f.vday).filter((v): v is number => v != null);
  const span = vdays.length
    ? { lo: Math.min(...vdays), hi: Math.max(...vdays) }
    : null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-[11px]">
        {gens.length === 0 && !isLoading && !error ? <span className="chip text-tx4">no findings</span> : null}
        {gens.map(([g, n]) => (
          <span key={g} className="chip">
            {g} {num(n)}
          </span>
        ))}
        {/* The vday column held five distinct values across forty-eight rows and
            read as constant. Stated once as a range, it says the same thing and
            gives the table its width back. Per-finding vday is in the drawer. */}
        {span && (
          <span className="font-sans text-tx4">
            generated {span.lo === span.hi ? vday(span.lo) : `${vday(span.lo)}–${vday(span.hi)}`}
          </span>
        )}
      </div>

      <Table
        columns={[
          {
            key: "ep",
            header: "endpoint",
            render: (f) => (
              <span className="block">
                <span className="block whitespace-nowrap">{`${f.method} ${f.path}`}</span>
                {f.generator !== "template" ? (
                  <span className="mt-0.5 inline-block text-[11px] text-info">
                    {f.generator}
                    {f.model ? ` ${f.model}` : ""}
                  </span>
                ) : null}
              </span>
            ),
          },
          {
            // Two lines, with the whole narrative in the drawer this row opens.
            //
            // Each summary is a five-line paragraph that restates the endpoint
            // already in the first column, so forty-seven of them made the table
            // a wall of prose with nothing scannable in it. Clamped, the first
            // clause — the estimate and the reason — is what the eye lands on,
            // and the full text is one click away rather than one screen tall.
            key: "sum",
            header: "summary",
            render: (f) => (
              <span className="line-clamp-2 max-w-[68ch]" title={f.narrative.summary}>
                {summaryFor(f)}
              </span>
            ),
          },
          {
            // Two numbers instead of a truncated list.
            //
            // The framework names took seven distinct values across forty-eight
            // rows and were clamped in every one, so no reader could finish a
            // single list — the column cost a fifth of the table's width and
            // delivered a prefix. How many clauses were breached, and out of
            // how many checked, varies per row and is the thing being asked.
            // The named clauses with their evidence are in the drawer.
            key: "reg",
            header: "clauses breached",
            align: "right",
            width: "140px",
            render: (f) => {
              const total = f.regulations.length;
              if (total === 0) return <span className="text-tx4">—</span>;
              const violated = f.regulations.filter((c) => c.status === "VIOLATED").length;
              const names = [...new Set(f.regulations.map((c) => c.framework))];
              return (
                <span title={`${names.length} framework(s): ${names.join(", ")}`}>
                  <span className={violated > 0 ? "text-crit" : "text-ok"}>{violated}</span>
                  <span className="text-tx4"> of {total}</span>
                </span>
              );
            },
          },
          {
            key: "ttb",
            header: "time to breach",
            align: "right",
            render: (f) => (f.time_to_breach_d == null ? "—" : `${f.time_to_breach_d}d`),
          },
        ]}
        rows={data?.items}
        rowKey={(f) => f.id}
        loading={isLoading}
        error={error as Error | null}
        onRowClick={setOpen}
        rowLabel={(finding) => `Open finding for ${finding.method} ${finding.path}`}
      />

      <Drawer
        open={open !== null}
        onClose={() => setOpen(null)}
        title={open ? `${open.method} ${open.path}` : ""}
        subtitle={open ? `finding ${open.id}` : undefined}
      >
        {open ? <FindingDetail finding={open} /> : null}
      </Drawer>
    </div>
  );
}

function FindingDetail({ finding }: { finding: FindingsItemsItem }) {
  return (
    <>
      <Section title="narrative">
        <Field label="summary" value={finding.narrative.summary} />
        <Field label="technical" value={finding.narrative.technical} />
        <Field label="action" value={finding.narrative.action} />
      </Section>
      <Section title="provenance">
        <Field label="generator" value={finding.generator} />
        <Field label="model" value={finding.model ?? "—"} />
        <Field label="time to breach" value={finding.time_to_breach_d == null ? "—" : `${finding.time_to_breach_d}d`} />
        <Field label="vday" value={vday(finding.vday)} />
      </Section>
      <Section title="regulatory mapping">
        <div className="space-y-2">
          {finding.regulations.map((citation, index) => (
            <div key={`${citation.framework}:${citation.clause}:${index}`} className="panel px-2.5 py-2 text-[11px]">
              <div className="flex items-baseline gap-2">
                <span className="text-tx1">{citation.framework}</span>
                <span className="text-tx4">{citation.clause}</span>
                <span className={`ml-auto ${citation.status === "VIOLATED" ? "text-crit" : "text-ok"}`}>
                  {citation.status.toLowerCase()}
                </span>
              </div>
              <p className="mt-1 text-tx2">{citation.requirement}</p>
              <p className="mt-0.5 text-tx4">{citation.evidence}</p>
            </div>
          ))}
        </div>
      </Section>
    </>
  );
}
