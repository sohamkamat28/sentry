import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../lib/useLive", () => ({
  SLOW_MS: 10_000,
  useLive: () => ({
    data: {
      generators: { template: 1 },
      items: [{
        id: "finding-1",
        endpoint_id: "ep_1",
        method: "GET",
        path: "/orders",
        generator: "template",
        narrative: { summary: "Sensitive response", technical: "detail", action: "mask" },
        regulations: [
          { framework: "SOC 2", clause: "CC6", requirement: "control", status: "VIOLATED", evidence: "email" },
          { framework: "ISO 27001", clause: "A.8", requirement: "control", status: "VIOLATED", evidence: "email" },
        ],
        vday: 7,
      }],
    },
    isLoading: false,
    error: null,
  }),
}));

import { Findings } from "./Findings";

describe("Findings", () => {
  // The framework names moved out of the cell and into its title: seven
  // distinct values across forty-eight rows, clamped in every one, cost a fifth
  // of the table's width to show a prefix. The column now carries how many
  // clauses were breached out of how many checked, which varies per row.
  //
  // The original point of this test survives the move — the citations are
  // objects, and rendering the array anywhere would print `[object Object]`.
  it("names frameworks rather than coercing the citation objects", () => {
    render(<Findings />);
    const cell = screen.getByTitle("2 framework(s): SOC 2, ISO 27001");
    expect(cell).toBeTruthy();
    expect(cell.textContent).toBe("2 of 2");
    expect(screen.queryByText(/\[object Object\]/)).toBeNull();
  });

  it("keeps the estimate sentence when no time-to-breach column carries it", () => {
    // `time_to_breach_d` is absent in this fixture, so the lead clause is the
    // only place the figure appears and must not be stripped.
    render(<Findings />);
    expect(screen.getByTitle("Sensitive response")).toBeTruthy();
  });
});
