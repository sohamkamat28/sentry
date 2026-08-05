/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Control plane base URL, substituted at build time.
   *
   * 8080 is the API's published port. 8000 is Kong's proxy listener — pointing
   * a console there sends every control-plane call to the gateway under test.
   */
  readonly VITE_API_BASE?: string;
  /** Enables OIDC authorization-code + PKCE. Omit for local dev-token mode. */
  readonly VITE_OIDC_ISSUER?: string;
  readonly VITE_OIDC_CLIENT_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
