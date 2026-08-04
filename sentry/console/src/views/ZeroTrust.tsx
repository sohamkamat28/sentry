import { useMutation, useQueryClient } from "@tanstack/react-query";

import { SLOW_MS, useLive } from "../lib/useLive";
import { post, ApiError } from "../lib/api";
import { Table } from "../components/data/Table";
import { Metric } from "../components/data/Metric";
import { useRoute, routeQuery } from "../lib/router";
import { num, score } from "../lib/format";
import type { ZeroTrust as ZT } from "../lib/types";

const CONTROL_ORDER = ["ratelimit", "tls", "response", "auth", "binding"];

/**
 * Posture per endpoint, and the gaps.
 *
 * `requires_migration` is shown on the control rather than folded into the
 * verdict. A control that would break callers who hold no credential is not the
 * same as one that breaks the contract, and the two need different decisions.
 */
export function ZeroTrust() {
  const [path] = useRoute();
  const focus = routeQuery(path).get("endpoint");
  const qc = useQueryClient();

  const { data, isLoading, error } = useLive<ZT>("zerotrust", "/zerotrust", SLOW_MS);

  const harden = useMutation({
    mutationFn: (id: string) => post(`/zerotrust/${id}/harden`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["zerotrust"] }),
  });

  const rows = (data?.items ?? []).filter((i) => !focus || i.endpoint_id === focus);
  const failure = harden.error as ApiError | null;
  const dist = data?.distribution ?? {};

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-2 md:grid-cols-6">
        {[0, 1, 2, 3, 4, 5].map((n) => (
          <Metric
            key={n}
            label={`${n} of 5`}
            value={isLoading ? undefined : dist[String(n)] ?? 0}
            tone={n === 5 ? "ok" : n <= 1 ? "crit" : "warn"}
            loading={isLoading}
          />
        ))}
      </div>

      <div className="flex gap-2 text-[11.5px]">
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
                disabled={harden.isPending || i.satisfied === i.of}
                onClick={() => harden.mutate(i.endpoint_id)}
              >
                harden
              </button>
            ),
          },
        ]}
        rows={rows}
        rowKey={(i) => i.endpoint_id}
        loading={isLoading}
        error={error as Error | null}
      />
    </div>
  );
}
