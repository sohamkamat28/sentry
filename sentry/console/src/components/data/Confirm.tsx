import { useState, type ReactNode } from "react";

import { ApiError } from "../../lib/api";

/**
 * A gate in front of anything that changes the gateway.
 *
 * Apply wrote a plugin to a live gateway from a button in a table cell, and
 * revert was an unlabelled `×` inside a chip. Both are one mis-click from an
 * estate-wide change, and neither said which endpoint it was about to act on —
 * the row was identified by position, which is the thing that moves when a live
 * list refreshes underneath the cursor.
 *
 * This states the action, names the target, and requires a second, deliberate
 * press. A 403 is rendered as a permission boundary rather than as a failure,
 * because an analyst being refused a gateway write is the governance
 * requirement working and should read that way.
 */
interface Props {
  /** Rendered on the trigger. */
  label: string;
  /** What is about to happen, in a sentence. Shown before the second press. */
  question: ReactNode;
  onConfirm: () => void;
  pending?: boolean;
  error?: unknown;
  /** Destructive actions get the critical hue on the confirm step only. */
  destructive?: boolean;
  disabled?: boolean;
}

export function Confirm({
  label,
  question,
  onConfirm,
  pending,
  error,
  destructive,
  disabled,
}: Props) {
  const [armed, setArmed] = useState(false);
  const api = error instanceof ApiError ? error : null;

  return (
    <div className="space-y-1.5">
      {!armed ? (
        <button
          className="btn"
          type="button"
          aria-expanded={armed}
          disabled={disabled || pending}
          onClick={() => setArmed(true)}
        >
          {label}
        </button>
      ) : (
        <div
          className={`panel px-3 py-2 ${destructive ? "border-crit" : "border-warn"}`}
        >
          <div className="mb-2 text-[12.5px] text-tx1">{question}</div>
          <div className="flex items-center gap-2">
            <button
              className={`btn ${destructive ? "text-crit" : "text-warn"}`}
              type="button"
              disabled={pending}
              onClick={() => {
                setArmed(false);
                onConfirm();
              }}
            >
              {pending ? "working…" : `yes, ${label}`}
            </button>
            <button className="btn text-tx3" type="button" disabled={pending} onClick={() => setArmed(false)}>
              cancel
            </button>
          </div>
        </div>
      )}

      {api && (
        <div className={`text-[11px] ${api.forbidden ? "text-warn" : "text-crit"}`}>
          {api.forbidden
            ? `${api.message} — gateway writes require the approver role`
            : api.message}
        </div>
      )}
      {/* A ternary, not `&&`: `error` is `unknown`, and an `&&` chain leaves the
          whole expression `unknown` rather than narrowing to an element. */}
      {error != null && !api ? (
        <div className="text-[11px] text-crit">
          {error instanceof Error ? error.message : String(error)}
        </div>
      ) : null}
    </div>
  );
}
