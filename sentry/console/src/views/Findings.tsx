
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
export function Findings() {
  const [open, setOpen] = useState<FindingsItemsItem | null>(null);
  const { data, isLoading, error } = useLive<F>("findings", "/findings", SLOW_MS);

  const gens = Object.entries(data?.generators ?? {});

  return (
    <div className="space-y-4">
      <div className="flex gap-2 text-[11.5px]">
        {gens.length === 0 && !isLoading && !error ? <span className="chip text-tx4">no findings</span> : null}
        {gens.map(([g, n]) => (
          <span key={g} className="chip">
            {g} {num(n)}
          </span>
        ))}
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
                  <span className="mt-0.5 inline-block text-[10.5px] text-info">
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
                {f.narrative.summary}
              </span>
            ),
          },
          {
            // Clamped like the summary beside it. Four framework names is an
            // ordinary mapping here, and at a narrow width they wrapped to four
            // lines — so having shortened the prose, the citation list became
            // the thing setting the row height instead.
            key: "reg",
            header: "frameworks",
            width: "210px",
            render: (f) => {
              const names = [...new Set(f.regulations.map((c) => c.framework))];
              if (names.length === 0) return <span className="text-tx4">—</span>;
              return (
                <span className="line-clamp-2 leading-tight" title={names.join(", ")}>
                  {names.join(", ")}
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
          { key: "v", header: "vday", align: "right", render: (f) => vday(f.vday) },
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
            <div key={`${citation.framework}:${citation.clause}:${index}`} className="panel px-2.5 py-2 text-[11.5px]">
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
