import { useQuery } from "@tanstack/react-query";

import { DEV_TOKENS, get, getToken, setToken } from "../../lib/api";
import { num, score, vday } from "../../lib/format";

interface SystemStatus {
  org: string;
  vday: number;
  endpoints: number;
  retired: number;
  lifecycle: Record<string, number>;
  governance: Record<string, number>;
  tiers: Record<string, number>;
  mean_cdri: number;
}

/**
 * Always-visible state.
 *
 * The virtual day is here rather than on a settings page because every window
 * in this system is measured in vdays: a figure on any other surface is only
 * interpretable against it.
 */
export function StatusBar() {
  const { data, error, isLoading } = useQuery<SystemStatus>({
    queryKey: ["system"],
    queryFn: () => get<SystemStatus>("/system"),
    refetchInterval: 10_000,
  });

  const token = getToken();

  return (
    <div className="flex items-center gap-4 border-b border-line bg-panel px-3 py-1.5 text-[11.5px]">
      <Item label="vday" value={isLoading ? undefined : vday(data?.vday)} />
      <Item label="endpoints" value={isLoading ? undefined : num(data?.endpoints)} />
      <Item label="zombie" value={isLoading ? undefined : num(data?.lifecycle?.ZOMBIE ?? 0)} />
      <Item label="shadow" value={isLoading ? undefined : num(data?.governance?.SHADOW ?? 0)} />
      <Item label="mean cdri" value={isLoading ? undefined : score(data?.mean_cdri)} />

      {error && (
        <span className="text-crit">
          control plane unreachable — figures below are stale
        </span>
      )}

      <span className="ml-auto flex items-center gap-2">
        <span className="text-tx4">role</span>
        <select
          className="border border-line bg-bg px-1.5 py-0.5 text-[11.5px]"
          value={token}
          onChange={(e) => {
            setToken(e.target.value);
            window.location.reload();
          }}
        >
          {DEV_TOKENS.map((t) => (
            <option key={t} value={t}>
              {t.replace("dev-", "")}
            </option>
          ))}
        </select>
      </span>
    </div>
  );
}

function Item({ label, value }: { label: string; value?: string }) {
  return (
    <span className="flex items-baseline gap-1.5">
      <span className="text-tx4">{label}</span>
      <span className="num text-tx1">{value ?? "—"}</span>
    </span>
  );
}
