import { Term } from "../components/data/Term";

/**
 * The screen for the reader who wants to know whether this is real.
 *
 * A recruiter stops after the walkthrough. An engineer keeps going, and what
 * convinces them is not a feature list — it is the constraints that were hit and
 * what was done about them. So this page leads with the decisions that were
 * forced, including the ones that went badly, because a project with no failures
 * on record reads as a project nobody actually ran.
 */
export function HowItWorks() {
  return (
    <div className="mx-auto max-w-3xl">
      <header className="mb-8">
        <h1 className="font-sans text-[26px] font-semibold tracking-[-0.02em] text-tx1 sm:text-[30px]">
          How it works
        </h1>
        <p className="mt-1.5 font-sans text-[13.5px] leading-6 text-tx3">
          Six services, three languages, and the reasons for each.
        </p>
      </header>

      <Section title="The path a request takes">
        <ol className="space-y-3">
          {[
            ["The kernel sees it first", <>An <Term as="ebpf">eBPF</Term> program attached to <code>SSL_write</code> and <code>SSL_read</code> reads the request <em>before</em> TLS encrypts it and the response before it leaves. The application is never modified and no plaintext is written to disk. Filtering and data-class classification happen in kernel space, so only a small structured event crosses into user space.</>],
            ["A Go agent ships it", <>Written in Go because it runs on every host: one static binary, no interpreter to install. <code>cilium/ebpf</code> loads and attaches the program.</>],
            ["Ingest writes it in bulk", <>PostgreSQL's COPY protocol via <code>pgx</code>, because this is the hot path — one row per observed call.</>],
            ["Python does the thinking", <>Fourteen analysis stages: deduplication, classification, an isolation forest for behavioural outliers, MinHash and LSH for <Term>resurrection</Term> matching, a weighted risk index. Python because scikit-learn, datasketch, networkx and tree-sitter exist there and have no equal elsewhere.</>],
            ["Kong enforces it", <>Approved controls are written to a live API gateway as real plugins — authentication, rate limits, response masking, TLS minimums.</>],
          ].map(([h, body], i) => (
            <li key={i} className="panel px-4 py-3.5">
              <div className="font-sans text-[13.5px] font-semibold text-tx1">{h}</div>
              <p className="mt-1 font-sans text-[13px] leading-6 text-tx2">{body}</p>
            </li>
          ))}
        </ol>
      </Section>

      <Section title="Three decisions that were forced">
        <Forced
          q="Why is Kong run database-backed rather than declarative?"
          a={<>Because in declarative mode Kong's Admin API is <b className="text-tx1">read-only</b> — and writing plugins through that API is the entire product. Declarative config would have made the core feature impossible.</>}
        />
        <Forced
          q="Why MinIO with Object Lock in COMPLIANCE mode?"
          a={<>It is the only configuration in which a retirement certificate cannot be deleted before its retention date — including by an administrator, including by root. Any weaker mode makes the certificate worthless as evidence.</>}
        />
        <Forced
          q="Why does the classifier record field names and never values?"
          a={<>Because a tool that had to read an Aadhaar number to detect one would itself become the breach. The BPF program rewinds a token out of its buffer the instant it turns out to be a value, so no identity number is ever held.</>}
        />
      </Section>

      <Section title="Things that went wrong, and what they cost">
        <ul className="space-y-2.5">
          {[
            ["The BPF verifier rejected the program", "The in-kernel parser exceeded the 1,000,001-instruction limit. Rewritten around bpf_loop with bounded iteration."],
            ["636 gateway writes failed with HTTP 409", "The actuator was not idempotent — it re-created plugins that already existed. The failures are still on the record rather than cleaned up."],
            ["A hand-written type contradicted the server, twice", "Both times the request returned 200, the type-checker passed, and a panel silently rendered nothing. Console types are now generated from the OpenAPI schema, and a contract check fails the build if they drift."],
            ["Shadow endpoint count inflated from 2 to 33", "Caused by how the reference estate was wired, not by the detector. Recorded as open rather than quietly corrected."],
          ].map(([h, body]) => (
            <li key={h} className="panel px-4 py-3">
              <div className="font-sans text-[13px] font-semibold text-warn">{h}</div>
              <p className="mt-0.5 font-sans text-[12.5px] leading-6 text-tx3">{body}</p>
            </li>
          ))}
        </ul>
      </Section>

      <Section title="About this recording">
        <p className="font-sans text-[13px] leading-6 text-tx2">
          What you are reading is a captured run, not a live system. The kernel
          probe needs a privileged Linux host with BTF and cannot run on managed
          hosting, so a deployment that claimed to be live would sit here
          reporting its own sensor as down.
        </p>
        <p className="mt-3 font-sans text-[13px] leading-6 text-tx2">
          Every figure came out of a real run: real HTTP over real TLS against
          twelve running banking services, read by the kernel probe, analysed by
          the same code path that would run in production. There is no seed data
          anywhere in the repository. The clock is accelerated — see{" "}
          <Term>vday</Term> — so 90-day windows elapse in minutes; only the clock
          is sped up.
        </p>
        <p className="mt-3 font-sans text-[13px] leading-6 text-tx3">
          To run the whole thing yourself, including the live gateway writes:{" "}
          <code className="text-tx2">docker compose up</code> in the repository.
        </p>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-9">
      <h2 className="mb-3 font-sans text-[12px] font-semibold uppercase tracking-[0.12em] text-tx3">
        {title}
      </h2>
      {children}
    </section>
  );
}

function Forced({ q, a }: { q: string; a: React.ReactNode }) {
  return (
    <div className="panel mb-2.5 px-4 py-3.5">
      <div className="font-sans text-[13.5px] font-semibold text-tx1">{q}</div>
      <p className="mt-1 font-sans text-[13px] leading-6 text-tx2">{a}</p>
    </div>
  );
}
