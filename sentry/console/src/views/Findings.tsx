
import { SLOW_MS, useLive } from "../lib/useLive";
import { Table } from "../components/data/Table";
import { num, vday } from "../lib/format";
import type { Findings as F } from "../lib/types";

/**
 * Generated findings.
 *
 * The generator column is not decoration. A narrative written by a template and
 * one written by a model are different artefacts with different reliability,
 * and the console labels which it is rather than presenting both as analysis.
 */
export function Findings() {
  const { data, isLoading, error } = useLive<F>("findings", "/findings", SLOW_MS);

  const gens = Object.entries(data?.generators ?? {});

  return (
    <div className="space-y-4">
      <div className="flex gap-2 text-[11.5px]">
        {gens.length === 0 && !isLoading && <span className="chip text-tx4">no findings</span>}
        {gens.map(([g, n]) => (
          <span key={g} className="chip">
            {g} {num(n)}
          </span>
        ))}
      </div>

      <Table
        columns={[
          { key: "ep", header: "endpoint", render: (f) => `${f.method} ${f.path}` },
          {
            key: "gen",
            header: "generator",
            render: (f) => (
              <span className={f.generator === "template" ? "text-tx4" : "text-info"}>
                {f.generator}
                {f.model ? ` ${f.model}` : ""}
              </span>
            ),
          },
          {
            key: "sum",
            header: "summary",
            render: (f) => String((f.narrative as Record<string, unknown>)?.summary ?? "—"),
          },
          { key: "reg", header: "frameworks", render: (f) => f.regulations.join(" ") || "—" },
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
      />
    </div>
  );
}
