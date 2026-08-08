#!/usr/bin/env python3
"""Freeze a live run of the control plane into a static JSON snapshot.

The console is published as a static site. The eBPF agent needs a privileged
Linux host with BTF and cannot run on any managed host, so a deployment that
tried to stay live would sit there reporting `agent down` — which reads as a
broken product to the one person the published site exists for.

So the site ships a recording instead. Every figure in it was captured from a
real run against the reference estate: real HTTP over real TLS, read by a real
kernel probe. Nothing here synthesises a number, and the console labels the
capture date rather than implying it is live.

Run with the stack up:

    python tools/snapshot.py

Writes `console/public/data/snapshot.json`, keyed by API route, which
`console/src/lib/snapshot.ts` serves in place of `fetch`.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = os.environ.get("SENTRY_API", "http://localhost:8080") + "/api/v1"
TOKEN = os.environ.get("SENTRY_TOKEN", "dev-admin")
OUT = Path(__file__).resolve().parent.parent / "console" / "public" / "data" / "snapshot.json"

#: Collection routes. The key is the path the console asks for, verbatim, so the
#: static resolver is an exact dictionary lookup with no path normalisation.
ROUTES = [
    "/system",
    "/live",
    "/discovery",
    "/classification",
    "/correlation",
    "/behaviour",
    "/forecast",
    "/findings",
    "/decommission",
    "/zerotrust",
    "/threat",
    "/operations",
    "/pipeline",
    "/estate?limit=500",
    "/risk?limit=300",
    "/remediation",
    "/audit?limit=200",
    # The console asks for these verbatim. The resolver is an exact dictionary
    # lookup, so a route the UI requests but the capture omits renders as
    # `not in the recording` on the surface that needs it — which is how the
    # risk register, the operations leaderboard and the audit chain check were
    # all silently lost the first time round. Any path a view reads belongs
    # here; `tools/check_snapshot_routes.py` fails the build when one drifts.
    "/risk?limit=200",
    "/operations/leaderboard",
    "/audit/verify",
]

#: Per-endpoint detail, fetched for every endpoint in the register.
DETAIL = [
    "/estate/{id}",
    "/classification/{id}",
    "/impact/{id}",
    "/correlation/{id}/ownership",
    "/forecast/{id}",
]

#: Control states worth carrying per endpoint. Stage 10 proposes a control on
#: every pass, so PROPOSED runs to several thousand rows estate-wide and would
#: dominate the payload while telling a reader nothing a count does not. The
#: states that describe what actually happened are kept in full.
KEEP_CONTROL_STATES = {"APPLIED", "JUDGED", "REJECTED", "FAILED", "REVERTED"}


def fetch(path: str):
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def thin_remediation(payload: dict) -> dict:
    """Collapse PROPOSED controls to a count, keep the rest verbatim.

    The console renders control history grouped by kind and state with a count,
    so a thousand identical PROPOSED rows and the number 1000 render the same.
    The distinction is preserved rather than dropped: `proposed_count` carries
    what was removed, so the surface can still say how many are queued.
    """
    for item in payload.get("items", []):
        controls = item.get("controls", [])
        kept = [c for c in controls if c.get("state") in KEEP_CONTROL_STATES]
        item["proposed_count"] = len(controls) - len(kept)
        item["controls"] = kept
    return payload


def main() -> int:
    snapshot: dict[str, object] = {}
    failed: list[str] = []

    for route in ROUTES:
        try:
            payload = fetch(route)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"  !! {route}: {exc}", file=sys.stderr)
            failed.append(route)
            continue
        if route == "/remediation":
            payload = thin_remediation(payload)
        snapshot[route] = payload
        print(f"  ok {route}")

    if failed:
        # A snapshot missing a route would publish a site whose pages fail with
        # no indication why, so this refuses rather than shipping a hole.
        print(f"\nFAILED — {len(failed)} route(s) unreachable: {', '.join(failed)}",
              file=sys.stderr)
        print("Is the stack up?  docker compose -f deploy/compose/compose.yaml up -d",
              file=sys.stderr)
        return 1

    estate = snapshot.get("/estate?limit=500", {})
    ids = [e["id"] for e in estate.get("items", [])]  # type: ignore[union-attr]
    print(f"\n  fetching detail for {len(ids)} endpoints…")
    for endpoint_id in ids:
        for template in DETAIL:
            route = template.replace("{id}", endpoint_id)
            try:
                snapshot[route] = fetch(route)
            except Exception:
                # A per-endpoint 404 is legitimate — a retired endpoint carries
                # no blast radius, an unowned one no ownership record. The
                # console already renders an absent detail as "—".
                pass

    OUT.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "vday": (snapshot.get("/system") or {}).get("vday"),  # type: ignore[union-attr]
        "routes": snapshot,
    }
    OUT.write_text(json.dumps(body, separators=(",", ":")))
    size = OUT.stat().st_size
    print(f"\nwrote {OUT.relative_to(OUT.parent.parent.parent.parent)} "
          f"— {len(snapshot)} routes, {size/1024:.0f} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
