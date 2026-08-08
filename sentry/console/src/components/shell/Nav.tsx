import { SURFACES } from "../../routes";
import { routePath } from "../../lib/router";

const NAV_SURFACES = SURFACES.filter((surface) => surface.path !== "/correlation");

export function Nav({ path }: { path: string }) {
  const current = routePath(path);
  return (
    <nav
      aria-label="Primary"
      className="w-48 shrink-0 overflow-y-auto border-r border-line bg-panel"
    >
      <a href="#/" className="block border-b border-line px-3 py-3">
        <span className="text-[15px] tracking-[0.2em] text-tx1">SENTRY</span>
      </a>

      <div className="py-2">
        {NAV_SURFACES.map((surface) => {
          const active = current === surface.path;
          return (
            <a
              key={surface.path}
              href={`#${surface.path}`}
              aria-current={active ? "page" : undefined}
              className={`block border-l-2 px-3 py-1.5 text-[12px] ${
                active
                  ? "border-info bg-line/40 text-tx1"
                  : "border-transparent text-tx3 hover:text-tx1"
              }`}
            >
              {surface.label}
            </a>
          );
        })}
      </div>
    </nav>
  );
}
