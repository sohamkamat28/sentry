/**
 * The control plane client.
 *
 * One place that knows the base URL, the bearer token and what an error looks
 * like. Every surface goes through `get` or `post`, so a 401 is handled once
 * and a failed request can never be rendered as an empty result — which is the
 * distinction this console exists to preserve.
 */

export const API_BASE: string =
  (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:8080";

const TOKEN_KEY = "sentry.token";

/**
 * Dev identities the control plane accepts when AUTH_DISABLED is set. Listed so
 * an operator can switch role and see the permission boundary behave — an
 * analyst receiving 403 on apply is the governance requirement working, and it
 * should be demonstrable without editing a token by hand.
 */
export const DEV_TOKENS = [
  "dev-viewer",
  "dev-analyst",
  "dev-approver",
  "dev-admin",
] as const;

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "dev-admin";
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

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
  let resp: Response;
  try {
    resp = await fetch(`${API_BASE}/api/v1${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${getToken()}`,
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
      message = body?.error?.message ?? body?.detail ?? message;
      detail = body?.error?.detail ?? body;
    } catch {
      /* a non-JSON error body is still an error */
    }
    throw new ApiError(resp.status, code, message, detail);
  }

  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

export function get<T>(path: string): Promise<T> {
  return request<T>(path);
}

export function post<T>(path: string, body?: unknown): Promise<T> {
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
