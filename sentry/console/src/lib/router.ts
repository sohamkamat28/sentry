import { useEffect, useState } from "react";

/**
 * Hash routing, deliberately.
 *
 * The console is served as static files by nginx. History routing would need
 * the server to rewrite every unknown path to index.html, and getting that
 * wrong produces a console that works until somebody refreshes or follows a
 * link — the failure appears in normal use and not in any build step. A hash
 * never reaches the server.
 */
export function useRoute(): [string, (to: string) => void] {
  const [path, setPath] = useState(() => window.location.hash.slice(1) || "/");

  useEffect(() => {
    const onChange = () => setPath(window.location.hash.slice(1) || "/");
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  return [path, (to: string) => { window.location.hash = to; }];
}

export function navigate(to: string): void {
  window.location.hash = to;
}

/** Query parameters carried after the route, e.g. #/estate?lifecycle=ZOMBIE */
export function routeQuery(path: string): URLSearchParams {
  const i = path.indexOf("?");
  return new URLSearchParams(i === -1 ? "" : path.slice(i + 1));
}

export function routePath(path: string): string {
  const i = path.indexOf("?");
  return i === -1 ? path : path.slice(0, i);
}
