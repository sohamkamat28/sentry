#!/usr/bin/env python3
"""Fail when the console reads a route the recording does not carry.

The published site resolves reads out of `console/public/data/snapshot.json` by
exact dictionary lookup. A view that asks for a path the capture omitted does
not degrade quietly — it renders `not in the recording: /risk?limit=200` where
the register should be, and only on the deployed site, because a developer with
the stack up never sees it.

That is exactly how the risk register, the operations leaderboard and the audit
chain check were lost: `tools/snapshot.py` listed the routes by hand, a view
asked for `?limit=200` while the capture took `?limit=300`, and nothing
connected the two. This closes that loop — it reads the routes back out of the
source rather than trusting the list.

    python tools/check_snapshot_routes.py

Exits non-zero with the missing routes named. Run in CI before the static build.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "console" / "src"
SNAPSHOT = ROOT / "console" / "public" / "data" / "snapshot.json"

#: `get<T>("/path")` and `useLive<T>("key", "/path", ms)` — the two read paths.
#: `post` is deliberately excluded: a static build refuses writes by design, so
#: an unrecorded POST route is correct rather than a gap.
LITERAL = re.compile(r'(?:\bget|\buseLive)\s*<[^>]*>\s*\(\s*(?:"[^"]*"\s*,\s*)?"(/[^"]*)"')
TEMPLATE = re.compile(r'(?:\bget|\buseLive)\s*<[^>]*>\s*\(\s*(?:"[^"]*"\s*,\s*)?`(/[^`]*)`')

#: `${expr}` stands in for an endpoint id. The capture cannot hold every id a
#: future estate might mint, so a templated route is satisfied by any one
#: recorded instance — it proves the template was captured at all.
INTERPOLATION = re.compile(r"\$\{[^}]*\}")


def sources() -> list[Path]:
    return sorted(p for p in SRC.rglob("*") if p.suffix in {".ts", ".tsx"} and ".test." not in p.name)


def main() -> int:
    if not SNAPSHOT.exists():
        print(f"no recording at {SNAPSHOT.relative_to(ROOT)}", file=sys.stderr)
        print("capture one first:  python tools/snapshot.py", file=sys.stderr)
        return 1

    recorded = set(json.loads(SNAPSHOT.read_text())["routes"])

    literals: dict[str, Path] = {}
    templates: dict[str, Path] = {}
    for path in sources():
        text = path.read_text()
        for route in LITERAL.findall(text):
            literals.setdefault(route, path)
        for route in TEMPLATE.findall(text):
            if INTERPOLATION.search(route):
                templates.setdefault(route, path)
            else:
                literals.setdefault(route, path)

    missing: list[tuple[str, Path]] = []

    for route, path in sorted(literals.items()):
        if route not in recorded:
            missing.append((route, path))

    for route, path in sorted(templates.items()):
        # `/forecast/${id}` -> `^/forecast/[^/]+$`, matched against the capture.
        # The placeholder is substituted before escaping so the literal parts
        # stay quoted and only the interpolation becomes a wildcard.
        pattern = re.compile("^" + re.escape(INTERPOLATION.sub("\x00", route)).replace("\x00", "[^/]+") + "$")
        if not any(pattern.match(r) for r in recorded):
            missing.append((route, path))

    checked = len(literals) + len(templates)
    if missing:
        print(f"{len(missing)} of {checked} console reads are not in the recording:\n", file=sys.stderr)
        for route, path in missing:
            print(f"  {route}\n      read by {path.relative_to(ROOT)}", file=sys.stderr)
        print(
            "\nAdd them to ROUTES or DETAIL in tools/snapshot.py, bring the stack up,\n"
            "and re-capture:  python tools/snapshot.py",
            file=sys.stderr,
        )
        return 1

    print(f"all {checked} console reads are present in the recording")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
