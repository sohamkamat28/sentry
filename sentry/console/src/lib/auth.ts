import { useSyncExternalStore } from "react";

const DEV_TOKEN_KEY = "sentry.dev-token.v1";
const LEGACY_DEV_TOKEN_KEY = "sentry.token";
const SESSION_KEY = "sentry.oidc.session.v1";
const ATTEMPT_KEY = "sentry.oidc.attempt.v1";

export const DEV_TOKENS = [
  "dev-viewer",
  "dev-analyst",
  "dev-approver",
  "dev-admin",
] as const;

export const OIDC_ISSUER = (import.meta.env.VITE_OIDC_ISSUER ?? "").replace(/\/$/, "");
export const OIDC_CLIENT_ID = import.meta.env.VITE_OIDC_CLIENT_ID ?? "sentry-console";
export const OIDC_ENABLED = OIDC_ISSUER.length > 0;

interface TokenSession {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
}

interface LoginAttempt {
  state: string;
  verifier: string;
  returnTo: string;
}

export interface AuthState {
  status: "loading" | "dev" | "authenticated" | "unauthenticated" | "error";
  subject?: string;
  roles: string[];
  error?: string;
}

let snapshot: AuthState = {
  status: OIDC_ENABLED ? "loading" : "dev",
  roles: [],
};
const listeners = new Set<() => void>();
let initialising: Promise<void> | null = null;
let refreshing: Promise<TokenSession | null> | null = null;

function emit(next: AuthState): void {
  snapshot = next;
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useAuth(): AuthState {
  return useSyncExternalStore(subscribe, () => snapshot, () => snapshot);
}

export function getDevToken(): string {
  const current = localStorage.getItem(DEV_TOKEN_KEY);
  if (current) return current;
  const legacy = localStorage.getItem(LEGACY_DEV_TOKEN_KEY);
  if (legacy) {
    localStorage.setItem(DEV_TOKEN_KEY, legacy);
    localStorage.removeItem(LEGACY_DEV_TOKEN_KEY);
    return legacy;
  }
  return "dev-admin";
}

export function setDevToken(token: string): void {
  if (!DEV_TOKENS.includes(token as (typeof DEV_TOKENS)[number])) return;
  localStorage.setItem(DEV_TOKEN_KEY, token);
}

function readSession(): TokenSession | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const value = JSON.parse(raw) as TokenSession;
    return value.accessToken && Number.isFinite(value.expiresAt) ? value : null;
  } catch {
    return null;
  }
}

function saveSession(value: TokenSession): void {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(value));
}

function clearSession(): void {
  sessionStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(ATTEMPT_KEY);
}

function decodeClaims(token: string): Record<string, unknown> {
  try {
    const payload = token.split(".")[1];
    if (!payload) return {};
    const normalised = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalised.padEnd(Math.ceil(normalised.length / 4) * 4, "=");
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function stateFor(session: TokenSession): AuthState {
  const claims = decodeClaims(session.accessToken);
  const realm = claims.realm_access as { roles?: unknown } | undefined;
  const roles = Array.isArray(realm?.roles)
    ? realm.roles.filter((role): role is string => typeof role === "string")
    : [];
  const subject = [claims.preferred_username, claims.email, claims.sub].find(
    (value): value is string => typeof value === "string" && value.length > 0,
  );
  return { status: "authenticated", subject, roles };
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomValue(bytes = 32): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return base64url(value);
}

async function challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

function redirectUri(): string {
  return `${window.location.origin}${window.location.pathname}`;
}

async function tokenRequest(body: URLSearchParams): Promise<TokenSession> {
  const response = await fetch(`${OIDC_ISSUER}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!response.ok) throw new Error(`identity provider returned ${response.status}`);
  const payload = await response.json() as {
    access_token?: string;
    refresh_token?: string;
    id_token?: string;
    expires_in?: number;
  };
  if (!payload.access_token) throw new Error("identity provider returned no access token");
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    idToken: payload.id_token,
    expiresAt: Date.now() + Math.max(1, payload.expires_in ?? 300) * 1000,
  };
}

async function exchangeCallback(): Promise<boolean> {
  const url = new URL(window.location.href);
  const providerError = url.searchParams.get("error");
  if (providerError) {
    throw new Error(url.searchParams.get("error_description") ?? providerError);
  }
  const code = url.searchParams.get("code");
  if (!code) return false;

  const raw = sessionStorage.getItem(ATTEMPT_KEY);
  const attempt = raw ? JSON.parse(raw) as LoginAttempt : null;
  if (!attempt || url.searchParams.get("state") !== attempt.state) {
    throw new Error("login response state did not match the request");
  }

  const session = await tokenRequest(new URLSearchParams({
    grant_type: "authorization_code",
    client_id: OIDC_CLIENT_ID,
    code,
    code_verifier: attempt.verifier,
    redirect_uri: redirectUri(),
  }));
  saveSession(session);
  sessionStorage.removeItem(ATTEMPT_KEY);
  history.replaceState(null, "", `${window.location.pathname}${attempt.returnTo}`);
  emit(stateFor(session));
  return true;
}

async function refreshSession(session: TokenSession): Promise<TokenSession | null> {
  if (!session.refreshToken) return null;
  try {
    const next = await tokenRequest(new URLSearchParams({
      grant_type: "refresh_token",
      client_id: OIDC_CLIENT_ID,
      refresh_token: session.refreshToken,
    }));
    next.refreshToken ??= session.refreshToken;
    next.idToken ??= session.idToken;
    saveSession(next);
    emit(stateFor(next));
    return next;
  } catch {
    clearSession();
    emit({ status: "unauthenticated", roles: [] });
    return null;
  }
}

export function initialiseAuth(): Promise<void> {
  if (initialising) return initialising;
  initialising = (async () => {
    if (!OIDC_ENABLED) {
      emit({ status: "dev", roles: [getDevToken().replace("dev-", "")] });
      return;
    }
    try {
      if (await exchangeCallback()) return;
      const session = readSession();
      if (!session) {
        emit({ status: "unauthenticated", roles: [] });
      } else if (session.expiresAt > Date.now() + 30_000) {
        emit(stateFor(session));
      } else {
        await refreshSession(session);
      }
    } catch (error) {
      clearSession();
      emit({
        status: "error",
        roles: [],
        error: error instanceof Error ? error.message : String(error),
      });
    }
  })();
  return initialising;
}

export async function beginLogin(): Promise<void> {
  if (!OIDC_ENABLED) return;
  const verifier = randomValue(48);
  const state = randomValue();
  const attempt: LoginAttempt = {
    state,
    verifier,
    returnTo: window.location.hash || "#/",
  };
  sessionStorage.setItem(ATTEMPT_KEY, JSON.stringify(attempt));
  const url = new URL(`${OIDC_ISSUER}/protocol/openid-connect/auth`);
  url.search = new URLSearchParams({
    client_id: OIDC_CLIENT_ID,
    redirect_uri: redirectUri(),
    response_type: "code",
    scope: "openid profile email",
    state,
    code_challenge: await challenge(verifier),
    code_challenge_method: "S256",
  }).toString();
  window.location.assign(url);
}

export async function getAccessToken(): Promise<string | null> {
  if (!OIDC_ENABLED) return getDevToken();
  let session = readSession();
  if (!session) return null;
  if (session.expiresAt <= Date.now() + 30_000) {
    refreshing ??= refreshSession(session).finally(() => { refreshing = null; });
    session = await refreshing;
  }
  return session?.accessToken ?? null;
}

export function expireAuth(): void {
  if (!OIDC_ENABLED) return;
  clearSession();
  emit({ status: "unauthenticated", roles: [] });
}

export function logout(): void {
  const session = readSession();
  clearSession();
  emit({ status: "unauthenticated", roles: [] });
  if (!OIDC_ENABLED) return;
  const url = new URL(`${OIDC_ISSUER}/protocol/openid-connect/logout`);
  url.searchParams.set("client_id", OIDC_CLIENT_ID);
  url.searchParams.set("post_logout_redirect_uri", redirectUri());
  if (session?.idToken) url.searchParams.set("id_token_hint", session.idToken);
  window.location.assign(url);
}
