import { useMutation, useQueryClient } from "@tanstack/react-query";

import { SLOW_MS, useLive } from "../lib/useLive";
import { post, ApiError } from "../lib/api";
import { Metric } from "../components/data/Metric";
import { Table } from "../components/data/Table";
import { score, vday, when } from "../lib/format";
import type { Threat as T } from "../lib/api-types";

/**
 * Honeypots, probes, and resurrection alerts.
 *
 * `fingerprints` sits beside the alert count deliberately: zero alerts against
 * zero fingerprints is an unarmed detector, and zero against seventeen is a
 * clean scan. Without the second number the first is uninterpretable.
 */
export function Threat() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useLive<T>("threat", "/threat", SLOW_MS);

  const rescan = useMutation({
    mutationFn: () => post("/threat/rescan", {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["threat"] }),
  });

  const failure = rescan.error as ApiError | null;
  const signed = data?.legal_signoff?.signed;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-5">
        <Metric
          label="Honeypots"
          value={isLoading || error ? undefined : data?.honeypots_active}
          tone={data?.honeypots_active ? "warn" : "dim"}
          loading={isLoading}
          error={error}
        />
        <Metric
          label="Fingerprints"
          value={isLoading || error ? undefined : data?.fingerprints}
          loading={isLoading}
          error={error}
          sub={`threshold ${data?.threshold ?? "—"}`}
        />
        <Metric
          label="Alerts"
          value={isLoading || rescan.isPending || error ? undefined : data?.alerts.length}
          tone={data?.alerts.length ? "crit" : "ok"}
          loading={isLoading || rescan.isPending}
          error={error}
        />
        <Metric
          label="Probes"
          value={isLoading || error ? undefined : data?.probes_total}
          loading={isLoading}
          error={error}
          sub={`${data?.unique_sources ?? "—"} sources`}
        />
        <Metric
          label="Legal sign-off"
          value={isLoading || error ? undefined : signed ? "signed" : "absent"}
          tone={signed ? "ok" : "warn"}
          loading={isLoading}
          error={error}
          sub={data?.legal_signoff?.reference ?? undefined}
        />
      </div>

      <div>
        <button className="btn" type="button" disabled={rescan.isPending} onClick={() => rescan.mutate()}>
          {rescan.isPending ? "scanning…" : "rescan"}
        </button>
        {failure && (
          <span className={`ml-2 text-[12px] ${failure.forbidden ? "text-warn" : "text-crit"}`}>
            {failure.forbidden ? `${failure.message} — rescan requires analyst` : failure.message}
          </span>
        )}
      </div>

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">
          Resurrection alerts
        </h2>
        <Table
          columns={[
            { key: "new", header: "resurrected as", render: (a) => a.new_endpoint_id },
            { key: "orig", header: "origin path", render: (a) => a.origin_path },
            {
              key: "sim",
              header: "similarity",
              align: "right",
              render: (a) => <span className="text-crit">{score(a.similarity, 4)}</span>,
            },
            { key: "th", header: "threshold", align: "right", render: (a) => score(a.threshold, 2) },
            { key: "lsh", header: "lsh", render: (a) => (a.lsh_hit ? "hit" : "scan") },
            { key: "v", header: "vday", align: "right", render: (a) => vday(a.vday) },
          ]}
          rows={data?.alerts}
          rowKey={(a) => `${a.new_endpoint_id}:${a.origin_path}`}
          loading={isLoading}
          error={error as Error | null}
          empty={
            data?.fingerprints
              ? "no live endpoint matches a retired one"
              : "no fingerprints captured — nothing to match against"
          }
        />
      </section>

      <section>
        <h2 className="mb-1 text-[11px] uppercase tracking-wider text-tx3">Probes</h2>
        <Table
          columns={[
            { key: "at", header: "at", render: (p) => when(p.at) },
            { key: "v", header: "vday", align: "right", render: (p) => vday(p.vday) },
            { key: "ip", header: "source", render: (p) => p.source_ip },
            { key: "asn", header: "asn", render: (p) => p.source_asn ?? "—" },
            { key: "ep", header: "endpoint", render: (p) => p.endpoint_id },
            { key: "wm", header: "watermark", render: (p) => p.watermark },
          ]}
          rows={data?.probes}
          rowKey={(p) => String(p.id)}
          loading={isLoading}
          error={error as Error | null}
          empty="no requests have reached a retired endpoint"
        />
      </section>
    </div>
  );
}
