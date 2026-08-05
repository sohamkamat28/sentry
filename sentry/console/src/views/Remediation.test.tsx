import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const postMock = vi.hoisted(() => vi.fn());

vi.mock("../lib/api", async (load) => ({
  ...await load<typeof import("../lib/api")>(),
  post: postMock,
}));
vi.mock("../lib/useLive", () => ({
  SLOW_MS: 10_000,
  useLive: () => ({
    data: {
      items: [{
        endpoint_id: "ep_1",
        method: "GET",
        path: "/orders",
        score: 0.9,
        tier: "CRITICAL",
        time_to_breach_d: 2,
        controls: [
          { id: 11, kind: "tls-min", state: "JUDGED", generator: "test", kong_plugin_id: null },
          { id: 12, kind: "key-auth", state: "JUDGED", generator: "test", kong_plugin_id: null },
        ],
        applied: 0,
      }],
    },
    isLoading: false,
    error: null,
  }),
}));

import { Remediation } from "./Remediation";

describe("Remediation", () => {
  beforeEach(() => postMock.mockReset().mockResolvedValue({ state: "APPLIED" }));

  it("applies each judged control with the required control_id body", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Remediation />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "apply 2" }));
    fireEvent.click(screen.getByRole("button", { name: "yes, apply 2" }));

    await waitFor(() => expect(postMock).toHaveBeenCalledTimes(2));
    expect(postMock).toHaveBeenNthCalledWith(1, "/remediation/ep_1/apply", { control_id: 11 });
    expect(postMock).toHaveBeenNthCalledWith(2, "/remediation/ep_1/apply", { control_id: 12 });
  });
});
