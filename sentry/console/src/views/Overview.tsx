import { SLOW_MS, useLive } from "../lib/useLive";
import { Flow } from "../components/story/Flow";
import { StatCard } from "../components/story/StatCard";
import { Term } from "../components/data/Term";
import { navigate } from "../lib/router";
import type { Classification, Discovery, Remediation, System } from "../lib/api-types";

/**
 * The landing screen, and the only one most visitors will read.
 *
 * Its whole job is to answer "what is this" before the reader decides to leave.
 * Everything here is therefore a sentence first and a figure second: the old
 * status bar led with `zombie 43 · shadow 33 · cdri 0.813`, which is precise,
 * true, and unreadable to anyone who has not worked in this domain.
 *
 * The numbers are read from the recording rather than written into the markup,
 * so this screen cannot drift away from the data it describes.
 */
export function Overview() {
  const system = useLive<System>("system", "/system", SLOW_MS);
  const discovery = useLive<Discovery>("discovery", "/discovery", SLOW_MS);
  const cls = useLive<Classification>("classification", "/classification", SLOW_MS);
  const rem = useLive<Remediation>("remediation", "/remediation", SLOW_MS);

  const s = system.data;
  const loading = system.isLoading;

  const shadow = s?.governance?.SHADOW;
  const unowned = (s?.governance?.ORPHANED ?? 0) + (shadow ?? 0);
  const dead = (s?.lifecycle?.ZOMBIE ?? 0) + (s?.lifecycle?.DORMANT ?? 0);

  const ebpf = discovery.data?.sources?.find((x) => x.source === "ebpf");
  const applied = (rem.data?.items ?? []).reduce(
    (n, i) => n + i.controls.filter((c) => c.state === "APPLIED").length,
    0,
  );

  return (
    <div className="mx-auto max-w-6xl">
      <section className="pt-2 sm:pt-6">
        <p className="font-sans text-[12px] font-medium uppercase tracking-[0.16em] text-info">
          API lifecycle security
        </p>
        <h1 className="mt-3 max-w-[19ch] font-sans text-[32px] font-semibold leading-[1.08] tracking-[-0.03em] text-tx1 sm:max-w-[24ch] sm:text-[46px]">
          Banks lose track of their own APIs.
        </h1>
        <p className="mt-4 max-w-[58ch] font-sans text-[15px] leading-7 text-tx2 sm:text-[17px]">
          SENTRY watches live traffic inside the kernel, finds the endpoints nobody
          registered, proves which ones are dangerous, and shuts them down without
          breaking the callers that still depend on them.
        </p>
      </section>

      <section className="mt-8 grid grid-cols-2 gap-2 lg:grid-cols-4" aria-label="Headline figures">
        <StatCard
          value={s?.endpoints}
          label="live APIs discovered across 12 banking services"
          loading={loading}
        />
        <StatCard
          value={shadow}
          label="that no team ever registered — in no gateway, in no repository"
          term="shadow"
          tone="crit"
          loading={loading}
        />
        <StatCard
          value={dead}
          label="nobody calls any more, still switched on and reachable"
          term="zombie"
          tone="warn"
          loading={loading}
        />
        <StatCard
          value={unowned}
          label="with no owner, so no team would ever be asked to fix them"
          term="orphaned"
          tone="warn"
          loading={loading}
        />
      </section>

      <section className="mt-10">
        <h2 className="font-sans text-[13px] font-semibold uppercase tracking-[0.12em] text-tx3">
          How it works
        </h2>
        <p className="mt-1.5 max-w-[62ch] font-sans text-[13px] leading-6 text-tx3">
          Five steps run continuously against the estate. Every number below came
          out of the recorded run — nothing here is illustrative.
        </p>
        <div className="mt-4">
          <Flow
            captured={ebpf?.endpoints}
            endpoints={s?.endpoints}
            classified={cls.data?.confidence?.CONFIRMED}
            scored={s?.endpoints}
            acted={applied}
          />
        </div>
      </section>

      <section className="mt-10">
        <div className="panel flex flex-col gap-4 px-5 py-6 sm:flex-row sm:items-center sm:justify-between sm:px-7 sm:py-7">
          <div className="min-w-0">
            <h2 className="font-sans text-[19px] font-semibold tracking-[-0.01em] text-tx1 sm:text-[22px]">
              Follow one API through the whole system
            </h2>
            <p className="mt-1.5 max-w-[54ch] font-sans text-[13.5px] leading-6 text-tx3">
              Eight steps, about two minutes. A forgotten SOAP endpoint that was
              still returning Aadhaar and PAN numbers — found, scored, shut down,
              and then caught coming back under a new name.
            </p>
          </div>
          <button
            type="button"
            className="shrink-0 rounded-sm border border-info bg-info px-5 py-3 font-sans text-[14px] font-semibold text-bg transition hover:brightness-110 active:translate-y-px"
            onClick={() => navigate("/walkthrough")}
          >
            Start the walkthrough →
          </button>
        </div>
      </section>

      <section className="mt-8 pb-4">
        <p className="max-w-[70ch] font-sans text-[12.5px] leading-6 text-tx4">
          The traffic was real HTTP over real TLS against twelve running banking
          services. It was read by an <Term as="ebpf">eBPF</Term> probe attached to{" "}
          <code className="text-tx3">SSL_write</code> in the kernel, so the
          applications were never modified and no plaintext left the host. The
          clock is accelerated — see <Term>vday</Term> — so that 90-day windows
          elapse in minutes. Only the clock is sped up.
        </p>
      </section>
    </div>
  );
}
