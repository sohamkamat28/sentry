import { useState } from "react";

import { SLOW_MS, useLive } from "../lib/useLive";
import { Table } from "../components/data/Table";
import { navigate } from "../lib/router";
import { score, tierClass } from "../lib/format";
import type { Risk } from "../lib/types";

const TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/**
 * CDRI, and what produced it.
 *
 * Expanding a row shows the six weighted terms and their contributions. A score
 * an operator is asked to act on has to be decomposable, or it is an assertion.
 */
export function RiskRegister() {
  const [open, setOpen] = useState<string | null>(null);
  const { data, isLoading, error } = useLive<Risk>("risk", "/risk?limit=200", SLOW_MS);

  const rows = data?.items ?? [];
  const counts = TIERS.map((t) => ({ tier: t, n: rows.filter((r) => r.tier === t).length }));

  return (
    <div className="space-y-4">
      <div className="flex gap-2 text-[11.5px]">
        {counts.map((c) => (
          <span key={c.tier} className={`chip ${tierClass(c.tier)}`}>
            {c.tier} {c.n}
          </span>
        ))}
        {rows[0] && (
          <span className="chip text-tx4">weights v{rows[0].weights_version}</span>
        )}
      </div>

      <Table
        columns={[
          { key: "ep", header: "endpoint", render: (r) => `${r.method} ${r.path}` },
          {
            key: "s",
            header: "CDRI",
            align: "right",
            render: (r) => <span className={tierClass(r.tier)}>{score(r.score)}</span>,
          },
          { key: "t", header: "tier", render: (r) => <span className={tierClass(r.tier)}>{r.tier}</span> },
          {
            key: "ttb",
            header: "time to breach",
            align: "right",
            render: (r) => (r.time_to_breach?.days == null ? "—" : `${r.time_to_breach.days}d`),
          },
          {
            key: "parts",
            header: "terms",
            render: (r) => (
              <button
                className="text-info"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpen(open === r.endpoint_id ? null : r.endpoint_id);
                }}
              >
                {open === r.endpoint_id ? "hide" : `${r.parts?.length ?? 0} terms`}
              </button>
            ),
          },
        ]}
        rows={rows}
        rowKey={(r) => r.endpoint_id}
        loading={isLoading}
        error={error as Error | null}
        onRowClick={(r) => navigate(`/remediation?endpoint=${r.endpoint_id}`)}
      />

      {open && (
        <section>
          <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">
            Score composition
          </h2>
          <Table
            columns={[
              { key: "k", header: "term", render: (p) => p.key },
              { key: "w", header: "weight", align: "right", render: (p) => score(p.weight, 2) },
              { key: "v", header: "value", align: "right", render: (p) => score(p.value) },
              {
                key: "c",
                header: "contribution",
                align: "right",
                render: (p) => score(p.contribution),
              },
            ]}
            rows={rows.find((r) => r.endpoint_id === open)?.parts}
            rowKey={(p) => p.key}
          />
        </section>
      )}
    </div>
  );
}
