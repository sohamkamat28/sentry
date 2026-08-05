import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, post } from "./api";

describe("API errors", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("keeps FastAPI validation arrays out of Error.message", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ detail: [{ loc: ["body", "control_id"], msg: "Field required" }] }),
      { status: 422, statusText: "Unprocessable Entity", headers: { "Content-Type": "application/json" } },
    )));

    const failure = await post("/remediation/ep_1/apply", {}).catch((error) => error);
    expect(failure).toBeInstanceOf(ApiError);
    if (!(failure instanceof ApiError)) throw new Error("expected ApiError");
    expect(failure.message).toBe("Unprocessable Entity");
    expect(failure.detail).toMatchObject({ detail: [{ msg: "Field required" }] });
  });
});
