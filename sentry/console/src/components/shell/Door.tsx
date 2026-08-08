import { useState } from "react";

import { SLOW_MS, useLive } from "../../lib/useLive";
import { STATIC_MODE } from "../../lib/snapshot";
import { Term } from "../data/Term";
import { hasVisited, markVisited, startTour } from "../../lib/tour";
import type { System } from "../../lib/api-types";

/**
 * What a first-time visitor meets before the console.
 *
 * Only on the published recording. An operator opening this at the start of a
 * shift does not need to be told what the product is, and a marketing card in
 * front of a live security console would be an obstacle rather than an
 * introduction — so it is gated on `STATIC_MODE` rather than shown to everyone.
 *
 * The figures are read from the same API the console uses. Nothing here is
 * written into the markup, so the pitch cannot outlive the data behind it.
 */
export function Door() {
  const [open, setOpen] = useState(() => STATIC_MODE && !hasVisited());

  const system = useLive<System>("system", "/system", SLOW_MS);

  if (!open) return null;

  const s = system.data;

  // All four are read from one payload, and the two axes are partitions —
  // governance is OWNED | ORPHANED | SHADOW, lifecycle is ACTIVE | DEPRECATED |
  // DORMANT | ZOMBIE — so these figures do not overlap and none of them can be
  // counted twice. An earlier draft added SHADOW into an "orphaned" total that
  // already had its own tile, and called DORMANT endpoints zombies; both read
  // as bigger numbers and both were wrong.
  const quiet = (s?.lifecycle?.DORMANT ?? 0) + (s?.lifecycle?.ZOMBIE ?? 0);

  const dismiss = () => {
    markVisited();
    setOpen(false);
  };

  const stats: { value?: number; label: string; term?: string; tone: string }[] = [
    { value: s?.endpoints, label: "live APIs found across 12 banking services", tone: "text-tx1" },
    {
      value: s?.governance?.SHADOW,
      label: "— in no gateway and no repository",
      term: "shadow",
      tone: "text-crit",
    },
    {
      value: quiet,
      label: "— gone quiet, still switched on and reachable",
      term: "dormant",
      tone: "text-warn",
    },
    {
      value: s?.governance?.ORPHANED,
      label: "— registered, but no team owns them",
      term: "orphaned",
      tone: "text-warn",
    },
  ];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-bg/80 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="What this is"
    >
      <div className="panel relative my-auto w-full max-w-2xl overflow-hidden p-6 shadow-2xl sm:p-8">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              "radial-gradient(90% 70% at 85% -10%, rgb(var(--accent) / 0.22), transparent 60%)",
          }}
        />

        <div className="relative">
          <span className="chip border-accent/40 text-accent">API lifecycle security</span>
          <h1 className="mt-3.5 font-sans text-[26px] font-semibold leading-[1.15] tracking-[-0.025em] text-tx1 sm:text-[32px]">
            Banks lose track of their own APIs.
          </h1>
          <p className="mt-2.5 max-w-[54ch] font-sans text-[13.5px] leading-6 text-tx2">
            SENTRY watches live traffic from inside the kernel, finds the endpoints nobody
            registered, proves which are dangerous, and shuts them down without breaking the
            callers that still depend on them.
          </p>

          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {stats.map((stat) => (
              <div key={stat.label}>
                <div className={`num font-mono text-[26px] leading-none ${stat.tone}`}>
                  {stat.value ?? "—"}
                </div>
                <div className="mt-1.5 font-sans text-[11px] leading-4 text-tx4">
                  {stat.term ? (
                    <>
                      <Term>{stat.term}</Term> {stat.label}
                    </>
                  ) : (
                    stat.label
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 flex flex-col gap-2.5 sm:flex-row sm:items-center">
            <button
              type="button"
              className="btn-primary justify-center px-5 py-2.5 text-[12.5px]"
              onClick={() => {
                setOpen(false);
                startTour();
              }}
            >
              Show me around — 2 minutes
            </button>
            <button
              type="button"
              className="btn justify-center px-5 py-2.5 text-[12.5px]"
              onClick={dismiss}
            >
              I&rsquo;ll look around myself
            </button>
          </div>

          <p className="mt-4 font-sans text-[11px] leading-4 text-tx4">
            This is a recording of a real run against twelve running banking services — real
            HTTP over real TLS, read by a kernel probe. The clock is accelerated (see{" "}
            <Term>vday</Term>) so 90-day windows elapse in minutes. Actions are read-only here.
          </p>
        </div>
      </div>
    </div>
  );
}
