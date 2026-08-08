import { useEffect, useId, useRef, type ReactNode } from "react";

/**
 * Detail without navigation.
 *
 * Every list surface used to answer "tell me more" by routing elsewhere with a
 * query parameter, which discards the operator's place in the list, their
 * filter and their scroll position. Under load that cost is paid on every
 * single item, and the effect is that nobody looks — they act on the row.
 *
 * A slide-over keeps the list underneath and alive: it is still polling, and
 * closing returns to exactly where they were.
 */
interface Props {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  /** Rendered pinned at the foot — where the actions go. */
  footer?: ReactNode;
  width?: string;
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  width = "min(680px, 92vw)",
}: Props) {
  const titleId = useId();
  const panelRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    previousFocus.current = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key !== "Tab") return;
      const focusable = panelRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      previousFocus.current?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      {/* The scrim dims the list without hiding it — the operator keeps the
          context they selected from. */}
      <button
        className="flex-1 cursor-default bg-bg/60"
        type="button"
        tabIndex={-1}
        aria-label="Close details"
        onClick={onClose}
      />

      <aside
        ref={panelRef}
        className="flex h-full flex-col border-l border-line bg-panel shadow-2xl"
        style={{ width }}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <header className="flex items-start gap-3 border-b border-line px-4 py-2.5">
          <div className="min-w-0">
            <div id={titleId} className="truncate text-[12.5px] text-tx1">{title}</div>
            {subtitle && <div className="mt-0.5 text-[11px] text-tx3">{subtitle}</div>}
          </div>
          <button
            ref={closeRef}
            className="ml-auto shrink-0 text-tx4 hover:text-tx1"
            type="button"
            onClick={onClose}
            title="close (Esc)"
            aria-label="Close details"
          >
            esc ✕
          </button>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">{children}</div>

        {footer && (
          <footer className="border-t border-line bg-panel px-4 py-2.5">{footer}</footer>
        )}
      </aside>
    </div>
  );
}

/** A labelled block inside a drawer. Consistent spacing across every surface. */
export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mb-4">
      <h3 className="mb-1.5 text-[11px] uppercase tracking-wider text-tx3">{title}</h3>
      {children}
    </section>
  );
}

/** A key/value row. Absent values render as an em dash, never as blank. */
export function Field({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-baseline gap-3 border-b border-line/60 py-1 last:border-0">
      <span className="w-40 shrink-0 text-[11px] text-tx4">{label}</span>
      <span className="min-w-0 flex-1 text-[12.5px] text-tx1">{value ?? "—"}</span>
    </div>
  );
}
