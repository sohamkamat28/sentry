import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { SLOW_MS, useLive } from "../lib/useLive";
import { post, ApiError } from "../lib/api";
import { Table } from "../components/data/Table";
import { Confirm } from "../components/data/Confirm";
import { Drawer, Field, Section } from "../components/data/Drawer";
import { useRoute, routeQuery } from "../lib/router";
import { num, score } from "../lib/format";
import type {
  Zerotrust as ZT,
  ZerotrustEndpointIdHarden,
  ZerotrustHardenPreview,
  ZerotrustItemsItem,
} from "../lib/api-types";

const CONTROL_ORDER = ["ratelimit", "tls", "response", "auth", "binding"];

/**
 * Posture per endpoint, and the gaps.
 *
 * `requires_migration` is shown on the control rather than folded into the
 * verdict. A control that would break callers who hold no credential is not the
 * same as one that breaks the contract, and the two need different decisions.
 */
export function ZeroTrust() {
  const [selected, setSelected] = useState<ZerotrustItemsItem | null>(null);
  const [path] = useRoute();
  const focus = routeQuery(path).get("endpoint");
  const qc = useQueryClient();

  const { data, isLoading, error } = useLive<ZT>("zerotrust", "/zerotrust", SLOW_MS);

  const preview = useMutation({
    mutationFn: (id: string) =>
      post<ZerotrustHardenPreview>("/zerotrust/harden-preview", { endpoint_id: id }),
  });

  const harden = useMutation({
    mutationFn: (id: string) => post<ZerotrustEndpointIdHarden>(`/zerotrust/${id}/harden`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["zerotrust"] }),
  });

  const rows = (data?.items ?? []).filter((i) => !focus || i.endpoint_id === focus);
  const failure = (preview.error ?? harden.error) as ApiError | null;
  const dist = data?.distribution ?? {};

  return (
    <div className="space-y-4">
      <Distribution dist={dist} loading={isLoading} failed={Boolean(error)} />

      <div className="flex flex-wrap gap-2 text-[11.5px]">
        {CONTROL_ORDER.map((k) => (
          <span key={k} className="chip">
            {k} gap {num(data?.gaps?.[k])}
          </span>
        ))}
      </div>

      {failure && (
        <div
          className={`panel px-3 py-2 text-[12px] ${
            failure.forbidden ? "border-warn text-warn" : "border-crit text-crit"
          }`}
        >
          {failure.forbidden
            ? `${failure.message} — hardening writes to the gateway and requires approver`
            : failure.message}
        </div>
      )}

      <Table
        columns={[
          { key: "ep", header: "endpoint", render: (i) => `${i.method} ${i.path}` },
          {
            key: "p",
            header: "posture",
            align: "right",
            render: (i) => (
              <span className={i.satisfied === i.of ? "text-ok" : i.satisfied <= 1 ? "text-crit" : "text-warn"}>
                {i.satisfied}/{i.of}
              </span>
            ),
          },
          { key: "pri", header: "priority", align: "right", render: (i) => score(i.priority) },
          {
            key: "ctl",
            header: "controls",
            render: (i) => (
              <span className="flex flex-wrap gap-1">
                {i.controls.map((c) => (
                  <span
                    key={c.key}
                    className={`chip ${c.ok ? "text-ok" : "text-tx3"}`}
                    title={c.current ? `current: ${c.current}` : undefined}
                  >
                    {c.key}
                    {!c.ok && c.remedy ? ` → ${c.remedy}` : ""}
                    {c.requires_migration && <span className="text-warn"> ·migration</span>}
                  </span>
                ))}
              </span>
            ),
          },
          {
            key: "act",
            header: "",
            render: (i) => (
              <button
                className="btn"
                type="button"
                disabled={preview.isPending || i.satisfied === i.of}
                onClick={() => {
                  setSelected(i);
                  preview.mutate(i.endpoint_id);
                }}
              >
                preview
              </button>
            ),
          },
        ]}
        rows={rows}
        rowKey={(i) => i.endpoint_id}
        loading={isLoading}
        error={error as Error | null}
        rowLabel={(i) => `${i.method} ${i.path}`}
      />

      <Drawer
        open={selected !== null}
        onClose={() => {
          setSelected(null);
          preview.reset();
          harden.reset();
        }}
        title={selected ? `${selected.method} ${selected.path}` : "Hardening preview"}
        subtitle="proposed zero-trust controls — no changes have been made"
        footer={
          selected && preview.data ? (
            <Confirm
              label="harden"
              question={
                <>
                  Generate, judge, and apply the listed controls for <b>{selected.method} {selected.path}</b>.
                  Only controls that pass measured replay will reach the gateway.
                </>
              }
              pending={harden.isPending}
              error={harden.error}
              disabled={Boolean(harden.data) || Boolean(preview.data.blocked) || (preview.data.would_apply?.length ?? 0) === 0}
              onConfirm={() => harden.mutate(selected.endpoint_id)}
            />
          ) : undefined
        }
      >
        {preview.isPending ? (
          <p className="text-[12px] text-tx4">building a no-write plan…</p>
        ) : preview.error ? (
          <p className="text-[12px] text-crit">{(preview.error as Error).message}</p>
        ) : preview.data ? (
          <HardeningPlan data={preview.data} result={harden.data} />
        ) : null}
      </Drawer>
    </div>
  );
}

function HardeningPlan({
  data,
  result,
}: {
  data: ZerotrustHardenPreview;
  result?: ZerotrustEndpointIdHarden;
}) {
  const posture = data.posture as { satisfied?: unknown; of?: unknown };
  const proposed = data.would_apply ?? [];
  return (
    <div>
      <Section title="current posture">
        <Field label="satisfied" value={`${String(posture.satisfied ?? "—")}/${String(posture.of ?? "—")}`} />
        <Field label="endpoint id" value={data.endpoint_id} />
      </Section>

      <Section title="controls that would be judged">
        {proposed.length === 0 ? (
          <p className="text-[12px] text-ok">no control gaps remain</p>
        ) : (
          <div className="space-y-2">
            {proposed.map((item, index) => (
              <div className="panel px-3 py-2" key={`${String(item.control)}:${index}`}>
                <div className="text-[12px] text-tx1">{String(item.control ?? "control")}</div>
                <div className="mt-0.5 text-[11px] text-tx3">{String(item.remedy ?? "—")}</div>
                {item.requires_migration === true ? (
                  <div className="mt-1 text-[11px] text-warn">caller migration required</div>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </Section>

      {data.blocked ? <p className="panel border-warn px-3 py-2 text-[12px] text-warn">{data.blocked}</p> : null}
      {result ? (
        <Section title="apply result">
          {result.blocked ? <p className="text-[12px] text-warn">{result.blocked}</p> : null}
          {(result.controls ?? []).map((control, index) => (
            <Field
              key={index}
              label={String(control.control ?? control.remedy ?? `control ${index + 1}`)}
              value={String(control.state ?? control.reason ?? "complete")}
            />
          ))}
        </Section>
      ) : null}
    </div>
  );
}

/**
 * How many endpoints hold how many of the five controls.
 *
 * This was six metric tiles, each reading a count over a label — `13` above
 * `0 of 5`. Those are different kinds of number: one counts endpoints, the
 * other names a position on a scale. Stacked in identical tiles they invite
 * being read as a fraction, and "13 / 0 of 5" means nothing.
 *
 * It is a distribution, so it is drawn as one. Width is the count, the order is
 * worst to best, and the shape of the estate arrives in a single glance instead
 * of six separate readings.
 */
function Distribution({
  dist,
  loading,
  failed,
}: {
  dist: Record<string, number>;
  loading: boolean;
  failed: boolean;
}) {
  const steps = [0, 1, 2, 3, 4, 5].map((n) => ({ n, count: dist[String(n)] ?? 0 }));
  const total = steps.reduce((sum, s) => sum + s.count, 0);
  const tone = (n: number) => (n === 5 ? "bg-ok" : n <= 1 ? "bg-crit" : "bg-warn");

  if (loading) return <p className="text-[12px] text-tx4">loading…</p>;
  // A failed read is not an estate with no controls.
  if (failed) return <p className="text-[12px] text-crit">posture distribution unavailable</p>;
  if (total === 0) return <p className="text-[12px] text-tx4">no endpoint is scored yet</p>;

  return (
    <section aria-label="Controls held across the estate">
      <div className="mb-1.5 flex items-baseline gap-2 font-sans">
        <h2 className="text-[10.5px] font-medium uppercase tracking-[0.12em] text-tx3">
          Controls held
        </h2>
        <span className="num text-[11px] text-tx4">{total} endpoints</span>
      </div>

      <div className="flex h-5 w-full overflow-hidden rounded-sm border border-line">
        {steps
          .filter((s) => s.count > 0)
          .map((s) => (
            <span
              key={s.n}
              className={tone(s.n)}
              style={{ width: `${(s.count / total) * 100}%` }}
              title={`${s.count} endpoint(s) hold ${s.n} of 5 controls`}
            />
          ))}
      </div>

      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px]">
        {steps.map((s) => (
          <span key={s.n} className="flex items-baseline gap-1.5">
            <span className={`inline-block h-2 w-2 rounded-[1px] ${tone(s.n)}`} />
            <span className="text-tx3">{s.n} of 5</span>
            <span className="num text-tx1">{s.count}</span>
          </span>
        ))}
      </div>
    </section>
  );
}
