import { useEffect, useId, useMemo, useRef, useState } from "react";

import { navigate } from "../../lib/router";
import { AREAS, SURFACES } from "../../routes";
import { togglePaused } from "../../lib/useLive";

/**
 * Reach anything without leaving the keyboard.
 *
 * Fifteen surfaces in five groups is a nav an operator has to read. Under load
 * they should not have to: `Cmd/Ctrl-K`, type three letters, enter. This is the
 * one navigation affordance that stays constant while the rest of the screen is
 * about the incident in front of them.
 *
 * Deliberately not a fuzzy matcher. Subsequence matching on a small, known set
 * of names produces confident-looking wrong answers — an operator hitting enter
 * on the wrong surface mid-incident is worse than one who has to type another
 * character.
 */
interface Command {
  id: string;
  label: string;
  hint: string;
  description: string;
  keywords: string[];
  run: () => void;
}

const OPEN_EVENT = "sentry:open-command-palette";

export function requestCommandPalette(): void {
  window.dispatchEvent(new Event(OPEN_EVENT));
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);
  const listId = useId();

  const commands = useMemo<Command[]>(
    () => [
      ...SURFACES.map((s) => ({
        id: `go:${s.path}`,
        label: s.label,
        description: s.description,
        keywords: s.aliases,
        hint: AREAS.find((area) => area.id === s.area)?.label ?? "View",
        run: () => navigate(s.path),
      })),
      {
        id: "live:toggle",
        label: "Pause / resume live polling",
        description: "Freeze or resume every auto-refreshing view",
        keywords: ["live", "refresh"],
        hint: "live",
        run: togglePaused,
      },
    ],
    [],
  );

  const matches = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return commands;
    return commands.filter(
      (c) =>
        c.label.toLowerCase().includes(needle) ||
        c.description.toLowerCase().includes(needle) ||
        c.keywords.some((keyword) => keyword.toLowerCase().includes(needle)) ||
        c.hint.toLowerCase().includes(needle),
    );
  }, [q, commands]);

  useEffect(() => {
    const show = () => {
      setOpen(true);
      setQ("");
      setCursor(0);
    };
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((current) => !current);
        setQ("");
        setCursor(0);
      }
      if (e.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKey);
    window.addEventListener(OPEN_EVENT, show);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener(OPEN_EVENT, show);
    };
  }, []);

  useEffect(() => {
    if (!open) return;
    previousFocus.current = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    const trap = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(
        'input:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", trap);
    return () => {
      window.removeEventListener("keydown", trap);
      previousFocus.current?.focus();
    };
  }, [open]);

  if (!open) return null;

  const choose = (c: Command) => {
    c.run();
    setOpen(false);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-bg/70 pt-[12vh]"
      onClick={() => setOpen(false)}
      role="presentation"
    >
      <div
        ref={dialogRef}
        className="panel w-[540px] max-w-[92vw] overflow-hidden"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
      >
        <input
          ref={inputRef}
          className="w-full border-b border-line bg-panel px-3 py-2 text-[12.5px] outline-none placeholder:text-tx4"
          placeholder="Search all views…"
          value={q}
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={matches[cursor] ? `${listId}-${cursor}` : undefined}
          onChange={(e) => {
            setQ(e.target.value);
            setCursor(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown" || (e.ctrlKey && e.key === "n")) {
              e.preventDefault();
              setCursor((i) => Math.min(i + 1, matches.length - 1));
            } else if (e.key === "ArrowUp" || (e.ctrlKey && e.key === "p")) {
              e.preventDefault();
              setCursor((i) => Math.max(i - 1, 0));
            } else if (e.key === "Enter" && matches[cursor]) {
              e.preventDefault();
              choose(matches[cursor]);
            }
          }}
        />

        <div id={listId} className="max-h-[52vh] overflow-y-auto" role="listbox">
          {matches.length === 0 && (
            <div className="px-3 py-2 text-[12.5px] text-tx4">nothing matches</div>
          )}
          {matches.map((c, i) => (
            <button
              key={c.id}
              id={`${listId}-${i}`}
              type="button"
              role="option"
              aria-selected={i === cursor}
              className={`flex w-full items-start gap-3 px-3 py-2 text-left font-sans ${
                i === cursor ? "bg-line/60 text-tx1" : "text-tx2 hover:bg-line/30"
              }`}
              onMouseEnter={() => setCursor(i)}
              onClick={() => choose(c)}
            >
              <span className="min-w-0">
                <span className="block text-[12.5px] font-medium">{c.label}</span>
                <span className="block truncate text-[11px] text-tx4">{c.description}</span>
              </span>
              <span className="ml-auto text-[11px] uppercase tracking-wide text-tx4">
                {c.hint}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
