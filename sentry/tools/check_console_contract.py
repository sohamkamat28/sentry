"""Console type declarations, checked against what the control plane actually sends.

`console/src/lib/api.ts` is hand-written rather than generated from the OpenAPI
contract — a divergence the README records under "what has not been run". This
is what that divergence costs, and this script is how it is caught.

The Operations view declared the `/pipeline` payload as `runs: [...]`. The
endpoint returns one run, under `run`. `runs?.[0]` was therefore permanently
undefined and the Last-run tile sat on its loading dash forever — on a query
that had *succeeded*. Nothing anywhere reported a fault: the fetch returned 200,
TanStack Query reported success, and `tsc` checked the declaration rather than
the contract. The Audit view had the same fault on `/audit/verify`, declaring
`message` where the server sends `reason`, so a broken chain would have said
"broken" and nothing else.

Both are the same shape of defect and neither is visible offline, so this check
needs a running control plane and is not part of `make verify`:

    python tools/check_console_contract.py [--base-url URL] [--token TOKEN]

Exit 0 clean, 1 on a mismatch, 2 when the control plane is unreachable — never
silently passing on an API that failed to answer, which is the failure mode that
would let this check certify a console it never compared against anything.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

SRC = pathlib.Path(__file__).resolve().parent.parent / "console" / "src"
VIEWS = SRC / "views"
SHARED = SRC / "lib" / "types.ts"
#: Generated from the control plane's own schema. Checked here too: a
#: generated file can still be stale, and a stale one is a claim about the
#: server exactly like a hand-written one.
GENERATED = SRC / "lib" / "api-types.ts"

#: `get<Type>("/route")`, query string included — several surfaces page with
#: `?limit=`, and dropping the query would compare against a different response.
#: Routes carrying a template parameter need an id the check cannot invent and
#: are reported as skipped rather than guessed at.
#: Two shapes reach the control plane: a one-shot `get<T>("/route")` and the
#: polled `useLive<T>("key", "/route")` that most surfaces now use. Matching only
#: the first silently dropped this check from seventeen calls to three while
#: still reporting OK — which is the exact failure the coverage line exists to
#: make visible, and it did.
CALL = re.compile(
    r'(?:get|useLive)<(\w+)>\(\s*(?:[`"][a-z0-9-]+[`"]\s*,\s*)?[`"](/[a-z0-9/_?=&,-]+)[`"]')

#: A top-level property of an interface body: two spaces of indentation, a name,
#: an optional `?`, a colon. Nested object properties are indented further and
#: are deliberately not compared — this checks the envelope, which is where a
#: rename goes unnoticed.
PROP = re.compile(r"^ {2}(\w+)\??:", re.M)

#: `import type { Behaviour as B, Risk } from "../lib/types";`
IMPORT = re.compile(r"import type \{([^}]*)\} from", re.S)


def aliases(src: str) -> dict[str, str]:
    """Local name → declared name, for the shared types a view renames on import.

    Seven of the seventeen surfaces import their response type under a one-letter
    alias. Matching on the local name alone found no interface for any of them,
    and the check reported them as skipped — which is honest but useless, since
    those seven are half the console.
    """
    out: dict[str, str] = {}
    for block in IMPORT.findall(src):
        for spec in block.split(","):
            spec = spec.strip()
            if not spec:
                continue
            if " as " in spec:
                declared, _, local = spec.partition(" as ")
                out[local.strip()] = declared.strip()
            else:
                out[spec] = spec
    return out


def interface_body(src: str, name: str) -> str | None:
    """The interface's own body, from the view file or the shared declarations.

    A view may declare its response shape locally or import it from
    `lib/types.ts`; both are hand-written and both can drift, so looking only in
    the view file would leave the shared ones unchecked while still printing OK.
    """
    sources = [src]
    for extra in (SHARED, GENERATED):
        sources.append(extra.read_text() if extra.exists() else "")
    for text in sources:
        m = re.search(r"(?:export )?interface %s \{(.*?)\n\}" % re.escape(name),
                      text, re.S)
        if m:
            return m.group(1)
    return None


def fetch(base: str, route: str, token: str) -> dict | None:
    req = urllib.request.Request(base.rstrip("/") + route,
                                 headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = json.loads(r.read().decode())
    return body if isinstance(body, dict) else None


def check(base: str, token: str) -> int:
    try:
        fetch(base, "/system", token)
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        print(f"UNREACHABLE  {base} — {exc}", file=sys.stderr)
        print("The check made no comparison. This is not a pass.", file=sys.stderr)
        return 2

    findings: list[str] = []
    skipped: list[str] = []
    compared = 0
    calls = 0

    for f in sorted(VIEWS.glob("*.tsx")):
        src = f.read_text()
        alias = aliases(src)
        for typ, route in CALL.findall(src):
            calls += 1
            declared_name = alias.get(typ, typ)
            body = interface_body(src, declared_name)
            if body is None:
                skipped.append(f"{f.name}: {declared_name} on {route} — no interface found")
                continue
            try:
                payload = fetch(base, route, token)
            except urllib.error.HTTPError as exc:
                findings.append(f"{f.name}: {typ} reads {route}, which answered "
                                f"{exc.code}")
                continue
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                findings.append(f"{f.name}: {typ} reads {route}, unreachable — {exc}")
                continue
            if payload is None:
                skipped.append(f"{f.name}: {typ} on {route} — response is not an object")
                continue

            compared += 1
            declared = set(PROP.findall(body))
            missing = sorted(declared - set(payload))
            if missing:
                findings.append(
                    f"{f.name}: interface {declared_name} on {route}\n"
                    f"    declared, never sent: {missing}\n"
                    f"    server sends:         {sorted(payload)}")

    for line in findings:
        print(f"FAIL  {line}")

    # Coverage is reported whatever the outcome. A check that compared four of
    # seventeen surfaces and printed OK would certify thirteen it never looked
    # at — the same shape of claim this whole system exists to refuse.
    for line in skipped:
        print(f"SKIP  {line}")
    print(f"\n{compared} of {calls} typed calls compared, {len(skipped)} skipped.")

    if findings:
        print(f"{len(findings)} declaration(s) the server does not honour.")
        return 1

    print("OK  every compared declaration matches the payload the control plane sends.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", default="http://localhost:8080/api/v1")
    p.add_argument("--token", default="dev-admin")
    a = p.parse_args()
    return check(a.base_url, a.token)


if __name__ == "__main__":
    raise SystemExit(main())
