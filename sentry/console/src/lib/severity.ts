/**
 * The one place a severity becomes a colour.
 *
 * The palette in `index.css` carries four hues and the rule that colour encodes
 * *only* severity, so a red cell means the same thing everywhere. That rule was
 * being enforced by convention, and convention lost: `format.ts` returned
 * `text-critical`, `text-high`, `text-medium`, `text-low`, `text-muted` and
 * `text-ink` — six class names, none of which exist. Tailwind's config defines
 * `ok`, `warn`, `crit`, `info` and `tx1`–`tx4` and nothing else, so every one of
 * those was generated as no rule at all.
 *
 * The effect was silent and total. Tier, lifecycle, governance and confidence
 * rendered in body text across every table in the console; only the metric
 * tiles, which reach for `text-crit` directly, were ever coloured. Severity —
 * the single thing this palette is reserved for — was the one thing not being
 * communicated by it.
 *
 * Nothing here is exported as a raw string. Callers get a token from a closed
 * set, so a seventh invented class name cannot be typed without the compiler
 * objecting.
 */

/** The four hues, and the two neutral weights. Nothing else. */
export type Tone = "crit" | "warn" | "info" | "ok" | "dim" | "plain";

const TEXT: Record<Tone, string> = {
  crit: "text-crit",
  warn: "text-warn",
  info: "text-info",
  ok: "text-ok",
  dim: "text-tx4",
  plain: "text-tx1",
};

const BORDER: Record<Tone, string> = {
  crit: "border-crit",
  warn: "border-warn",
  info: "border-info",
  ok: "border-ok",
  dim: "border-line",
  plain: "border-line",
};

export function toneText(tone: Tone): string {
  return TEXT[tone];
}

export function toneBorder(tone: Tone): string {
  return BORDER[tone];
}

/** CDRI tier. The product's own severity scale. */
export function tierTone(tier: string | null | undefined): Tone {
  switch ((tier ?? "").toUpperCase()) {
    case "CRITICAL":
      return "crit";
    case "HIGH":
      return "warn";
    case "MEDIUM":
      return "info";
    case "LOW":
      return "ok";
    default:
      return "dim";
  }
}

/**
 * Lifecycle. ZOMBIE is the finding; ACTIVE is the healthy state.
 *
 * DORMANT is amber rather than red on purpose — days 31–89 is the window where
 * a quarterly batch endpoint lives, and colouring it as a fault would train an
 * operator to dismiss the colour.
 */
export function lifecycleTone(lifecycle: string | null | undefined): Tone {
  switch ((lifecycle ?? "").toUpperCase()) {
    case "ZOMBIE":
      return "crit";
    case "DORMANT":
      return "warn";
    case "DEPRECATED":
      return "info";
    case "ACTIVE":
      return "ok";
    default:
      return "dim";
  }
}

export function governanceTone(governance: string | null | undefined): Tone {
  switch ((governance ?? "").toUpperCase()) {
    case "SHADOW":
      return "crit";
    case "ORPHANED":
      return "warn";
    case "OWNED":
      return "ok";
    default:
      return "dim";
  }
}

/**
 * Control state. APPLIED is enforcing, REJECTED is a measured refusal.
 *
 * REJECTED is amber, not red: the Judge refusing a control on evidence is the
 * system working. Red is reserved for FAILED, where the gateway write itself
 * did not land and the operator has something to fix.
 */
export function controlTone(state: string | null | undefined): Tone {
  switch ((state ?? "").toUpperCase()) {
    case "APPLIED":
      return "ok";
    case "JUDGED":
      return "info";
    case "REJECTED":
      return "warn";
    case "FAILED":
      return "crit";
    case "REVERTED":
      return "dim";
    // Not red. A superseded control asks nothing of an operator: the policy it
    // states is enforced at the gateway by another control, verified against
    // Kong. Colouring it as failure is what put 636 unactionable rows on this
    // surface in the first place.
    case "SUPERSEDED":
      return "dim";
    default:
      return "dim";
  }
}

/**
 * Component liveness, as `/live` reports it.
 *
 * `unknown` is dim rather than red. A source that has never written a row is
 * not necessarily broken — the legacy collector has nothing to say about an
 * estate with no SOAP in it — and colouring absence as failure would fill the
 * strip with alarms nobody can act on.
 */
export function healthTone(state: string | null | undefined): Tone {
  switch ((state ?? "").toLowerCase()) {
    case "ok":
      return "ok";
    case "stale":
      return "warn";
    case "down":
      return "crit";
    case "off":
    case "unknown":
      return "dim";
    default:
      return "dim";
  }
}

/**
 * Confidence is a weight on a verdict, not a severity of its own.
 *
 * PROVISIONAL renders dim and italic so it reads as a hedge next to the
 * lifecycle it qualifies, without competing with it for the operator's eye.
 */
export function confidenceClass(confidence: string | null | undefined): string {
  switch ((confidence ?? "").toUpperCase()) {
    case "CONFIRMED":
      return "text-tx1";
    case "PROVISIONAL":
      return "text-tx3 italic";
    default:
      return "text-tx4";
  }
}
