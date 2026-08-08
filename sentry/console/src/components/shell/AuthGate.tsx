import { useEffect, type ReactNode } from "react";

import { beginLogin, initialiseAuth, useAuth } from "../../lib/auth";
import { STATIC_MODE } from "../../lib/snapshot";

export function AuthGate({ children }: { children: ReactNode }) {
  const auth = useAuth();

  useEffect(() => {
    if (!STATIC_MODE) void initialiseAuth();
  }, []);

  // The published site is a recording with no control plane behind it, so there
  // is nothing to authenticate against and nothing a session could protect.
  // Asking a first-time visitor to sign in to read a recording would lose them
  // at the door.
  if (STATIC_MODE) return children;

  if (auth.status === "dev" || auth.status === "authenticated") return children;

  return (
    <main className="grid min-h-dvh place-items-center bg-bg p-6">
      <section className="panel w-full max-w-md p-5" aria-live="polite">
        <div className="text-[15px] tracking-[0.2em] text-tx1">SENTRY</div>
        {auth.status === "loading" ? (
          <p className="mt-4 text-[12.5px] text-tx3">completing secure sign-in…</p>
        ) : (
          <>
            <h1 className="mt-4 text-[14px] text-tx1">Operator sign-in</h1>
            <p className="mt-1 text-[12.5px] leading-5 text-tx3">
              Authenticate with the configured identity provider to access the control plane.
            </p>
            {auth.error ? <p className="mt-3 text-[12.5px] text-crit">{auth.error}</p> : null}
            <button className="btn mt-4 text-info" type="button" onClick={() => void beginLogin()}>
              sign in
            </button>
          </>
        )}
      </section>
    </main>
  );
}
