import { useEffect, useMemo, useRef, useState } from "react";

import { navigate } from "../../lib/router";
import { SURFACES } from "../../routes";
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
  run: () => void;
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands = useMemo<Command[]>(
    () => [
      ...SURFACES.map((s) => ({
        id: `go:${s.path}`,
        label: s.label,
        hint: s.group,
        run: () => navigate(s.path),
      })),
      {
        id: "live:toggle",
        label: "Pause / resume live polling",
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
        c.label.toLowerCase().includes(needle) || c.hint.toLowerCase().includes(needle),
    );
  }, [q, commands]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
        setQ("");
        setCursor(0);
      }
      if (e.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) inputRef.current?.focus();
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
    >
      <div
        className="panel w-[540px] max-w-[92vw] overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          className="w-full border-b border-line bg-panel px-3 py-2 text-[13px] outline-none placeholder:text-tx4"
          placeholder="go to a surface…"
          value={q}
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

        <div className="max-h-[52vh] overflow-y-auto">
          {matches.length === 0 && (
            <div className="px-3 py-2 text-[12px] text-tx4">nothing matches</div>
          )}
          {matches.map((c, i) => (
            <button
              key={c.id}
              className={`flex w-full items-baseline gap-2 px-3 py-1.5 text-left text-[12.5px] ${
                i === cursor ? "bg-line/60 text-tx1" : "text-tx2 hover:bg-line/30"
              }`}
              onMouseEnter={() => setCursor(i)}
              onClick={() => choose(c)}
            >
              <span>{c.label}</span>
              <span className="ml-auto text-[10.5px] uppercase tracking-wide text-tx4">
                {c.hint}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
