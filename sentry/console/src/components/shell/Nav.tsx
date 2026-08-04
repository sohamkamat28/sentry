import { GROUPS, SURFACES } from "../../routes";
import { routePath } from "../../lib/router";

export function Nav({ path }: { path: string }) {
  const current = routePath(path);
  return (
    <nav className="w-48 shrink-0 border-r border-line bg-panel overflow-y-auto">
      <a href="#/" className="block px-3 py-3 border-b border-line">
        <span className="text-[15px] tracking-[0.2em] text-tx1">SENTRY</span>
      </a>

      {GROUPS.map((group) => (
        <div key={group} className="py-2">
          <div className="px-3 pb-1 text-[10px] uppercase tracking-wider text-tx4">
            {group}
          </div>
          {SURFACES.filter((s) => s.group === group).map((s) => {
            const active = current === s.path;
            return (
              <a
                key={s.path}
                href={`#${s.path}`}
                className={`block px-3 py-1 text-[12px] border-l-2 ${
                  active
                    ? "border-info text-tx1 bg-line/40"
                    : "border-transparent text-tx3 hover:text-tx1"
                }`}
              >
                {s.label}
              </a>
            );
          })}
        </div>
      ))}
    </nav>
  );
}
