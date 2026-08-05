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
      distribution: { "3": 1 },
      gaps: { ratelimit: 1 },
      items: [{
        endpoint_id: "ep_1",
        method: "GET",
        path: "/orders",
        satisfied: 3,
        of: 5,
        priority: 0.8,
        controls: [],
      }],
    },
    isLoading: false,
    error: null,
  }),
}));

import { ZeroTrust } from "./ZeroTrust";

describe("ZeroTrust", () => {
  beforeEach(() => {
    postMock.mockReset().mockImplementation((path: string) => path === "/zerotrust/harden-preview"
      ? Promise.resolve({ endpoint_id: "ep_1", posture: { satisfied: 3, of: 5 }, would_apply: [{ control: "auth", remedy: "key-auth", requires_migration: true }] })
      : Promise.resolve({ endpoint_id: "ep_1", posture: {}, controls: [{ control: "auth", state: "APPLIED" }] }));
  });

  it("requires a preview and explicit confirmation before hardening", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <ZeroTrust />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "preview" }));
    await screen.findByText("caller migration required");
    expect(postMock).toHaveBeenCalledWith("/zerotrust/harden-preview", { endpoint_id: "ep_1" });
    expect(postMock).not.toHaveBeenCalledWith("/zerotrust/ep_1/harden", {});

    fireEvent.click(screen.getByRole("button", { name: "harden" }));
    fireEvent.click(screen.getByRole("button", { name: "yes, harden" }));
    await waitFor(() => expect(postMock).toHaveBeenCalledWith("/zerotrust/ep_1/harden", {}));
  });
});
