import { useId, useState } from "react";

/**
 * A domain word, with its meaning attached.
 *
 * Every layout fix this console has had addressed density. None of them
 * addressed the actual barrier: a reader meets "zombie", "shadow", "CDRI" or
 * "vday" in the first ten seconds, and those words carry nothing unless you have
 * already spent a week here. So they stop reading — not because the screen is
 * crowded, but because it is in a language they do not have.
 *
 * The words are kept. They are the real vocabulary of the domain and replacing
 * them with approximations would make the product sound less serious than it is.
 * What changes is that no reader has to already know one: every term explains
 * itself in place, on hover and on focus, without leaving the sentence.
 */

const GLOSSARY: Record<string, string> = {
  zombie:
    "An API nobody has called in over 90 days that is still switched on and still reachable.",
  dormant: "Quiet for 31–90 days. Might be a quarterly job, so not yet treated as dead.",
  shadow:
    "Running in production, but registered in no gateway and found in no code repository. Nobody declared it.",
  orphaned: "No owner could be found for it, so no team would ever be asked to fix it.",
  owned: "A responsible team was resolved for it.",
  cdri:
    "Composite Dormancy Risk Index — a 0-to-1 danger score built from six weighted factors that add up to the total.",
  vday:
    "Virtual day. The demo clock runs about 8,600× faster than real time so that 90-day windows actually elapse while you watch. Only the clock is accelerated; the traffic and the analysis are real.",
  "blast radius":
    "How much breaks if this API is switched off — who calls it, and who calls them.",
  worm:
    "Write Once Read Many. The retirement record is locked in object storage and cannot be deleted before its retention date, including by an administrator.",
  ebpf:
    "A way to run a small sandboxed program inside the Linux kernel. It lets us watch what an application sends without changing the application.",
  resurrection:
    "An API that was retired reappearing under a different path — so every control placed on the old one no longer applies.",
  honeypot:
    "A decoy left where a retired API used to be, so anything still calling it is recorded instead of silently failing.",
  sunset:
    "The staged shutdown of an API: warn its callers, quarantine it, then switch it off.",
  judge:
    "The component that replays real captured traffic against a proposed change and measures the effect before anyone is allowed to apply it.",
  "zero-trust":
    "Assume nothing is safe by default. Every request must prove who it is, over encryption, within limits.",
};

/** Wrap a domain word. `as` overrides which glossary entry to use. */
export function Term({ children, as }: { children: string; as?: string }) {
  const key = (as ?? children).toLowerCase();
  const definition = GLOSSARY[key];
  const [open, setOpen] = useState(false);
  const id = useId();

  // An unknown word renders as plain text rather than a dead affordance: a
  // dotted underline that explains nothing is worse than no underline.
  if (!definition) return <>{children}</>;

  return (
    <span className="relative inline-block">
      <button
        type="button"
        aria-describedby={open ? id : undefined}
        className="cursor-help border-b border-dotted border-tx4 text-left hover:border-info hover:text-tx1"
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={() => setOpen((v) => !v)}
      >
        {children}
      </button>
      {open && (
        <span
          id={id}
          role="tooltip"
          className="absolute bottom-full left-0 z-30 mb-1.5 block w-[min(19rem,70vw)]
                     rounded-sm border border-line bg-panel px-3 py-2 text-left
                     font-sans text-[12px] font-normal normal-case leading-5
                     tracking-normal text-tx2 shadow-xl"
        >
          {definition}
        </span>
      )}
    </span>
  );
}
