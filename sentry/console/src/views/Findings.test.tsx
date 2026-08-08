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
  it("renders framework names rather than object coercions", () => {
    render(<Findings />);
    expect(screen.getByText("SOC 2, ISO 27001")).toBeTruthy();
    expect(screen.queryByText(/\[object Object\]/)).toBeNull();
  });
});
