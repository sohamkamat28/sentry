/**
 * The control plane client.
 *
 * One place that knows the base URL, the bearer token and what an error looks
 * like. Every surface goes through `get` or `post`, so a 401 is handled once
 * and a failed request can never be rendered as an empty result — which is the
 * distinction this console exists to preserve.
 */

import { expireAuth, getAccessToken } from "./auth";
import { STATIC_MODE, get as fromSnapshot } from "./snapshot";

export const API_BASE: string =
  (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:8080";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly detail?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** A permission boundary, not a fault. Rendered differently. */
  get forbidden(): boolean {
    return this.status === 403;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await getAccessToken();
  if (!token) throw new ApiError(401, "AUTH_REQUIRED", "sign in is required");
  let resp: Response;
  try {
    resp = await fetch(`${API_BASE}/api/v1${path}`, {
      ...init,
      headers: {
        ...(init?.body !== undefined ? { "Content-Type": "application/json" } : {}),
        Authorization: `Bearer ${token}`,
        ...(init?.headers ?? {}),
      },
    });
  } catch (cause) {
    // Unreachable is not empty. A surface that rendered this as "no rows" would
    // report an outage as a clean estate.
    throw new ApiError(0, "UNREACHABLE", `cannot reach ${API_BASE}`, cause);
  }

  if (!resp.ok) {
    let code = String(resp.status);
    let message = resp.statusText;
    let detail: unknown;
    try {
      const body = await resp.json();
      code = body?.error?.code ?? body?.code ?? code;
      const candidate = body?.error?.message ?? body?.detail;
      // FastAPI validation errors put an array in `detail`. Error.message must
      // stay a string or React renders an object/array where copy is expected.
      if (typeof candidate === "string") message = candidate;
      detail = body?.error?.detail ?? body;
    } catch {
      /* a non-JSON error body is still an error */
    }
    if (resp.status === 401) expireAuth();
    throw new ApiError(resp.status, code, message, detail);
  }

  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

/**
 * A read. In a static build this resolves from the frozen recording instead of
 * the network, so every view keeps the query it already had and none of them
 * need to know which mode they are running in.
 */
export function get<T>(path: string): Promise<T> {
  return STATIC_MODE ? fromSnapshot<T>(path) : request<T>(path);
}

export function post<T>(path: string, body?: unknown): Promise<T> {
  // There is no control plane behind a static build, and a write that silently
  // resolved would be the console lying about having done something. Callers
  // render this as a plain refusal.
  if (STATIC_MODE) {
    return Promise.reject(
      new ApiError(0, "RECORDING", "this is a recorded run — actions are read-only here"),
    );
  }
  return request<T>(path, {
    method: "POST",
    body: body === undefined ? "{}" : JSON.stringify(body),
  });
}

export function put<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: "PUT",
    body: JSON.stringify(body ?? {}),
  });
}
