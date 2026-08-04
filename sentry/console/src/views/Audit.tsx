import { useQuery } from "@tanstack/react-query";

import { SLOW_MS, useLive } from "../lib/useLive";
import { get } from "../lib/api";
import type { AuditVerify as Verify } from "../lib/api-types";
import { Metric } from "../components/data/Metric";
import { Table } from "../components/data/Table";
import { num, shortId, vday, when } from "../lib/format";

interface Entry {
  seq: number;
  wall_ts: string;
  vday: number;
  actor: string;
  action: string;
  target: string | null;
  detail: Record<string, unknown>;
  entry_hash?: string;
}

/**
 * The hash-chained ledger, and its verification.
 *
 * The verify result is a metric rather than a page an operator has to seek out:
 * a tamper-evident log nobody checks is a log, and the whole value of the chain
 * is in the check having been run.
 */
export function Audit() {
  const entries = useLive<{ items: Entry[] }>("audit", "/audit?limit=200", SLOW_MS);
  const verify = useQuery({
    queryKey: ["audit", "verify"],
    queryFn: () => get<Verify>("/audit/verify"),
  });

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
        <Metric
          label="Chain"
          value={verify.isLoading ? undefined : verify.data?.ok ? "intact" : "broken"}
          tone={verify.data?.ok ? "ok" : "crit"}
          loading={verify.isLoading}
          sub={
            verify.data?.ok
              ? undefined
              : verify.data?.broken_at != null
                ? `first bad entry ${verify.data.broken_at}`
                : (verify.data?.reason ?? undefined)
          }
        />
        <Metric
          label="Entries verified"
          value={verify.isLoading ? undefined : verify.data?.entries}
          loading={verify.isLoading}
        />
        <Metric
          label="Shown"
          value={entries.isLoading ? undefined : entries.data?.items.length}
          loading={entries.isLoading}
          sub="most recent first"
        />
      </div>

      <Table
        columns={[
          { key: "seq", header: "seq", align: "right", render: (e) => num(e.seq) },
          { key: "at", header: "at", render: (e) => when(e.wall_ts) },
          { key: "v", header: "vday", align: "right", render: (e) => vday(e.vday) },
          { key: "actor", header: "actor", render: (e) => e.actor },
          { key: "action", header: "action", render: (e) => e.action },
          { key: "target", header: "target", render: (e) => e.target ?? "—" },
          {
            key: "hash",
            header: "hash",
            render: (e) => <span className="text-tx4">{shortId(e.entry_hash, 12)}</span>,
          },
        ]}
        rows={entries.data?.items}
        rowKey={(e) => String(e.seq)}
        loading={entries.isLoading}
        error={entries.error as Error | null}
      />
    </div>
  );
}
