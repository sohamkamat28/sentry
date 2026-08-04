import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  controlTone,
  governanceTone,
  healthTone,
  lifecycleTone,
  tierTone,
  toneBorder,
  toneText,
} from "./severity";

/**
 * The defect this file exists to stop recurring.
 *
 * `format.ts` returned `text-critical`, `text-high`, `text-medium`, `text-low`,
 * `text-muted` and `text-ink`. Tailwind's config defines `ok`, `warn`, `crit`,
 * `info` and `tx1`–`tx4` and nothing else, so all six compiled to no rule at
 * all — severity, the one thing this palette is reserved for, rendered in body
 * text in every table in the console. Nothing failed: the classes were valid
 * strings, `tsc` was happy, and the page looked deliberate.
 */
function paletteColours(): Set<string> {
  const cfg = readFileSync(join(__dirname, "../../tailwind.config.js"), "utf8");
  const block = cfg.slice(cfg.indexOf("colors: {"), cfg.indexOf("fontFamily"));
  return new Set([...block.matchAll(/^\s*([a-z0-9]+):/gm)].map((m) => m[1]));
}

const TONES = ["crit", "warn", "info", "ok", "dim", "plain"] as const;

describe("severity classes exist in the palette", () => {
  const colours = paletteColours();

  it("the palette parsed", () => {
    expect(colours.size).toBeGreaterThan(4);
    expect(colours.has("crit")).toBe(true);
  });

  it.each(TONES)("text class for %s is a real Tailwind colour", (tone) => {
    const cls = toneText(tone);
    const colour = cls.replace(/^text-/, "");
    expect(colours.has(colour)).toBe(true);
  });

  it.each(TONES)("border class for %s is a real Tailwind colour", (tone) => {
    const colour = toneBorder(tone).replace(/^border-/, "");
    expect(colours.has(colour)).toBe(true);
  });
});

describe("severity mappings", () => {
  it("CRITICAL and ZOMBIE and SHADOW are the critical hue", () => {
    expect(toneText(tierTone("CRITICAL"))).toBe("text-crit");
    expect(toneText(lifecycleTone("ZOMBIE"))).toBe("text-crit");
    expect(toneText(governanceTone("SHADOW"))).toBe("text-crit");
  });

  it("an unknown value is dim rather than alarming", () => {
    expect(toneText(tierTone(undefined))).toBe("text-tx4");
    expect(toneText(lifecycleTone("something-new"))).toBe("text-tx4");
  });

  it("a Judge refusal is amber, a failed gateway write is red", () => {
    // REJECTED is the system working — the Judge declining a control on
    // measured evidence. FAILED is the operator's problem.
    expect(toneText(controlTone("REJECTED"))).toBe("text-warn");
    expect(toneText(controlTone("FAILED"))).toBe("text-crit");
    expect(toneText(controlTone("APPLIED"))).toBe("text-ok");
  });

  it("a superseded control is dim, not red", () => {
    // 636 rows carried a Kong 409 for policies that were live at the gateway.
    // The reconciler files the 483 that were genuinely enforced as SUPERSEDED,
    // and they must stop reading as work an operator has to do — the whole
    // point was that they never were.
    expect(toneText(controlTone("SUPERSEDED"))).toBe("text-tx4");
  });

  it("a source that never wrote a row is dim, not failed", () => {
    // The legacy collector has nothing to say about an estate with no SOAP in
    // it. Colouring absence as failure fills the strip with unactionable alarms.
    expect(toneText(healthTone("unknown"))).toBe("text-tx4");
    expect(toneText(healthTone("down"))).toBe("text-crit");
    expect(toneText(healthTone("stale"))).toBe("text-warn");
  });
});

describe("the palette supports opacity modifiers", () => {
  /**
   * The second silent-colour defect, and the one with no symptom at all.
   *
   * Tailwind compiles `bg-line/40` to `rgb(var(--line) / 0.4)`. When the
   * variable held a hex that expression was not a colour, so Tailwind emitted
   * no rule — `.bg-line\/40` and `.bg-bg\/60` were absent from the stylesheet
   * entirely. The selected row in a list had no highlight and the drawer and
   * command-palette scrims dimmed nothing, and no build step objected.
   *
   * The fix is `<alpha-value>` in the config over channel triplets in the CSS.
   * This asserts both halves stay in place.
   */
  const css = readFileSync(join(__dirname, "../index.css"), "utf8");
  const cfg = readFileSync(join(__dirname, "../../tailwind.config.js"), "utf8");

  it("variables hold channel triplets, not hex", () => {
    const root = css.slice(css.indexOf(":root {"), css.indexOf("@layer base"));
    const decls = [...root.matchAll(/--([a-z0-9]+):\s*([^;]+);/g)];
    expect(decls.length).toBeGreaterThan(8);
    for (const [, name, value] of decls) {
      expect(value.trim(), `--${name} must be "R G B"`).toMatch(/^\d+ \d+ \d+$/);
    }
  });

  it("every palette colour carries the alpha placeholder", () => {
    const block = cfg.slice(cfg.indexOf("colors: {"), cfg.indexOf("fontFamily"));
    const entries = [...block.matchAll(/^\s*([a-z0-9]+):\s*"([^"]+)"/gm)];
    expect(entries.length).toBeGreaterThan(8);
    for (const [, name, value] of entries) {
      expect(value, `${name} needs <alpha-value> or /40 compiles to nothing`).toContain(
        "<alpha-value>",
      );
    }
  });
});
