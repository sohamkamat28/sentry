import { useEffect, type ReactNode } from "react";

import { beginLogin, initialiseAuth, useAuth } from "../../lib/auth";

export function AuthGate({ children }: { children: ReactNode }) {
  const auth = useAuth();

  useEffect(() => {
    void initialiseAuth();
  }, []);

  if (auth.status === "dev" || auth.status === "authenticated") return children;

  return (
    <main className="grid min-h-dvh place-items-center bg-bg p-6">
      <section className="panel w-full max-w-md p-5" aria-live="polite">
        <div className="text-[15px] tracking-[0.2em] text-tx1">SENTRY</div>
        {auth.status === "loading" ? (
          <p className="mt-4 text-[12px] text-tx3">completing secure sign-in…</p>
        ) : (
          <>
            <h1 className="mt-4 text-[14px] text-tx1">Operator sign-in</h1>
            <p className="mt-1 text-[12px] leading-5 text-tx3">
              Authenticate with the configured identity provider to access the control plane.
            </p>
            {auth.error ? <p className="mt-3 text-[12px] text-crit">{auth.error}</p> : null}
            <button className="btn mt-4 text-info" type="button" onClick={() => void beginLogin()}>
              sign in
            </button>
          </>
        )}
      </section>
    </main>
  );
}
