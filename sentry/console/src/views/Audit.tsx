import { useState } from "react";

import { SLOW_MS, useLive } from "../lib/useLive";
import type {
  Audit as AuditResponse,
  AuditItemsItem as Entry,
  AuditVerify as Verify,
} from "../lib/api-types";
import { Metric } from "../components/data/Metric";
import { Table } from "../components/data/Table";
import { Drawer, Field, Section } from "../components/data/Drawer";
import { num, shortId, vday, when } from "../lib/format";

/**
 * The hash-chained ledger, and its verification.
 *
 * The verify result is a metric rather than a page an operator has to seek out:
 * a tamper-evident log nobody checks is a log, and the whole value of the chain
 * is in the check having been run.
 */
/**
 * How many rows arrive before the reader asks for more.
 *
 * The ledger returns two hundred and the table rendered all of them, so the
 * screen was a two-hundred-row scroll with no control over it. The chain's
 * integrity is asserted by the verify metric above, which covers every entry
 * whether or not it is drawn; the table is for reading recent activity, and
 * nobody reads the two-hundredth row on the way there.
 */
const PAGE = 25;

export function Audit() {
  const [open, setOpen] = useState<Entry | null>(null);
  const [shown, setShown] = useState(PAGE);
  const entries = useLive<AuditResponse>("audit", "/audit?limit=200", SLOW_MS);
  const verify = useLive<Verify>("audit-verify", "/audit/verify", SLOW_MS);

  const all = entries.data?.items ?? [];
  const page = all.slice(0, shown);
  const more = all.length - page.length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
        <Metric
          label="Chain"
          value={verify.isLoading || verify.error ? undefined : verify.data?.ok ? "intact" : "broken"}
          tone={verify.error ? "dim" : verify.data?.ok ? "ok" : "crit"}
          loading={verify.isLoading}
          error={verify.error}
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
          error={verify.error}
        />
        <Metric
          label="Shown"
          value={entries.isLoading || entries.error ? undefined : page.length}
          loading={entries.isLoading}
          error={entries.error}
          sub={more > 0 ? `most recent of ${num(all.length)} read` : "most recent first"}
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
        rows={entries.isLoading ? undefined : page}
        rowKey={(e) => String(e.seq)}
        loading={entries.isLoading}
        error={entries.error as Error | null}
        onRowClick={setOpen}
        rowLabel={(entry) => `audit entry ${entry.seq}: ${entry.action}`}
      />

      {more > 0 && (
        <button
          type="button"
          className="btn w-full justify-center"
          onClick={() => setShown((n) => n + PAGE)}
        >
          Show {Math.min(PAGE, more)} more · {num(more)} older {more === 1 ? "entry" : "entries"} read
        </button>
      )}

      <Drawer
        open={open !== null}
        onClose={() => setOpen(null)}
        title={open ? `Audit entry ${open.seq}` : "Audit entry"}
        subtitle={open?.action}
      >
        {open ? (
          <div>
            <Section title="event">
              <Field label="timestamp" value={when(open.wall_ts)} />
              <Field label="virtual day" value={vday(open.vday)} />
              <Field label="actor" value={open.actor} />
              <Field label="target" value={open.target ?? "—"} />
              <Field label="entry hash" value={<span className="break-all num">{open.entry_hash}</span>} />
            </Section>
            <Section title="detail">
              {Object.keys(open.detail).length === 0 ? (
                <p className="text-[12.5px] text-tx4">no additional detail</p>
              ) : (
                <pre className="overflow-x-auto whitespace-pre-wrap break-words text-[11px] text-tx2">
                  {JSON.stringify(open.detail, null, 2)}
                </pre>
              )}
            </Section>
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
