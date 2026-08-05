import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../lib/useLive", () => ({
  SLOW_MS: 10_000,
  useLive: (key: string) => {
    const values: Record<string, unknown> = {
      operations: {
        vday: 10,
        scan_interval_vhours: 6,
        scheduler_enabled: true,
        siem: { host: "", format: "json", configured: false },
        stages: {},
        gate_events: [],
      },
      leaderboard: {
        teams: [
          { team: "payments", debt: 0.4, raw: 4, endpoints: 3, zombies: 0, orphaned: 0, pre_zombie: 0, critical_score: 0, ownership_confidence: 0.82 },
          { team: "(unattributed)", debt: 0.8, raw: 8, endpoints: 2, zombies: 1, orphaned: 1, pre_zombie: 0, critical_score: 0.5, ownership_confidence: 0 },
        ],
      },
      pipeline: { vday: 10, run: null, stages: [], order: [] },
    };
    return { data: values[key], isLoading: false, error: null };
  },
}));

import { Operations } from "./Operations";

describe("Operations", () => {
  it("shows real attribution confidence and identifies unassigned debt", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Operations />
      </QueryClientProvider>,
    );
    expect(screen.getByText("82% confidence")).toBeTruthy();
    expect(screen.getByText("unassigned")).toBeTruthy();
    expect(screen.queryByText("resolved")).toBeNull();
  });
});
