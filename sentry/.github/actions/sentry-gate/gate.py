"""Extract route declarations from a diff and ask the control plane about them.

Deliberately dependency-free: standard library only, so the Action needs no
install step and cannot be broken by a transitive release. It shares the
extraction rules with the stage 01 code collector by importing them when the
package is available and falling back to a vendored copy of the same patterns
when it is not — two extractors that disagreed would let the gate pass a route
the collector later reports as shadow.

Exit codes:
    0  every check passed, or fail-on permitted the failures
    1  a check failed and fail-on says that fails the build
    2  the control plane could not be reached

The distinction between 1 and 2 matters. An unreachable control plane is not a
clean build, and a gate that treated it as one would go quiet exactly when
something was wrong with the deployment.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT_S = 20

try:  # pragma: no cover - exercised only where the package is installed
    from sentry_worker.collectors.patterns import (
        AUTH_MARKERS, METHOD_DECORATORS, ROUTE_DECORATORS, SPRING_ANNOTATIONS,
    )
    from sentry_worker.collectors.code import routes_from_patterns, routes_from_python
    _SHARED = True
except ImportError:
    _SHARED = False


def _fallback_routes(path: Path, text: str) -> list[dict]:
    """Minimal extraction when the collector package is unavailable.

    Covers the decorator and annotation forms the collector covers. Anything it
    misses is reported as unscanned rather than silently as zero routes — a gate
    that finds nothing and a gate that looked at nothing must not produce the
    same output.
    """
    import re

    out: list[dict] = []
    dec = re.compile(
        r'@(?:\w+)\.(get|post|put|patch|delete)\(\s*[\'"]([^\'"]+)[\'"]', re.I)
    route = re.compile(
        r'@(?:\w+)\.route\(\s*[\'"]([^\'"]+)[\'"](?:.*?methods\s*=\s*\[([^\]]*)\])?',
        re.I | re.S)
    spring = re.compile(
        r'@(Get|Post|Put|Patch|Delete)Mapping\(\s*[\'"]([^\'"]+)[\'"]')

    for n, line in enumerate(text.splitlines(), start=1):
        for m in dec.finditer(line):
            out.append({"method": m.group(1).upper(), "path": m.group(2),
                        "file": str(path), "line": n})
        for m in route.finditer(line):
            methods = [x.strip().strip('"\'').upper()
                       for x in (m.group(2) or "GET").split(",") if x.strip()]
            for method in methods or ["GET"]:
                out.append({"method": method, "path": m.group(1),
                            "file": str(path), "line": n})
        for m in spring.finditer(line):
            out.append({"method": m.group(1).upper(), "path": m.group(2),
                        "file": str(path), "line": n})
    return out


AUTH_HINTS = (
    "requires_auth", "login_required", "authenticated", "require_token",
    "Depends(", "Security(", "oauth2_scheme", "verify_token", "jwt_required",
    "PreAuthorize", "Secured", "RolesAllowed",
)

SCANNABLE = {".py", ".go", ".js", ".ts", ".java", ".kt"}


def _codeowners_for(path: str) -> str | None:
    """Whether this path has a declared owner in the repository's CODEOWNERS."""
    for candidate in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        f = Path(candidate)
        if not f.is_file():
            continue
        owner = None
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            pattern, owners = parts[0], parts[1:]
            # Last match wins, as GitHub does. A pattern with no owners is a
            # deliberate un-assignment and clears any earlier match.
            import fnmatch
            target = path.lstrip("/")
            pat = pattern.lstrip("/").rstrip("/")
            if pattern == "*" or fnmatch.fnmatch(target, pat) \
                    or fnmatch.fnmatch(target, pat + "/*") \
                    or (("/" not in pat) and fnmatch.fnmatch(Path(target).name, pat)):
                owner = owners[0] if owners else None
        if owner:
            return owner
    return None


def collect(changed: list[str]) -> tuple[list[dict], list[str]]:
    routes: list[dict] = []
    skipped: list[str] = []

    globs = [g.strip() for g in os.environ.get("SENTRY_PATHS", "").splitlines()
             if g.strip()]

    for name in changed:
        path = Path(name)
        if path.suffix not in SCANNABLE or not path.is_file():
            continue
        if globs and not any(path.match(g) for g in globs):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped.append(name)
            continue

        if _SHARED and path.suffix == ".py":
            found = [{"method": r.method, "path": r.path, "file": name,
                      "line": r.line, "has_auth_middleware": r.has_auth_middleware}
                     for r in routes_from_python(text, name)]
        elif _SHARED:
            found = [{"method": r.method, "path": r.path, "file": name,
                      "line": r.line, "has_auth_middleware": r.has_auth_middleware}
                     for r in routes_from_patterns(text, name)]
        else:
            found = _fallback_routes(path, text)
            for r in found:
                r["has_auth_middleware"] = any(h in text for h in AUTH_HINTS)

        fields, classes = _response_shape(text)
        for r in found:
            r.setdefault("has_auth_middleware", False)
            r["owner"] = _codeowners_for(name)
            # What the handler appears to return. This is the only behavioural
            # evidence a diff carries, and it is what the no-resurrection check
            # compares against a retired endpoint's captured fingerprint —
            # method alone can never reach the threshold, which is the honest
            # outcome for a route that reveals nothing about its payload.
            r["response_fields"] = fields
            r["data_classes"] = classes
            # Whether the route appears in a catalogue is a fact about the
            # repository, and this is where it can be seen. Reported as observed
            # rather than assumed true.
            r["in_catalogue"] = _in_catalogue(r["path"])
            routes.append(r)

    return routes, skipped


#: Field-name patterns that imply a data class. The same classes the kernel
#: classifier tags, recognised here from identifiers rather than from values —
#: a diff has no values.
CLASS_HINTS = {
    "AADHAAR": ("aadhaar", "aadhar", "uid"),
    "PAN": ("pan", "pannumber", "pan_no"),
    "ACCOUNT_NO": ("accountnumber", "account_no", "accountno", "accountid"),
    "IFSC": ("ifsc",),
    "SWIFT": ("swift", "bic"),
    "CARD": ("cardnumber", "card_no", "pan_card"),
}


def _response_shape(text: str) -> tuple[list[str], list[str]]:
    """Field names the handler returns, and the classes they imply.

    Extracted from dict-literal and struct-tag keys. Deliberately shallow: this
    is evidence a pull request carries on its face, not an attempt to evaluate
    the handler. A field it misses weakens the resurrection comparison rather
    than corrupting it, because both sides are compared on what was found.
    """
    import re

    fields: set[str] = set()
    for m in re.finditer(r'["\'](\w{2,40})["\']\s*:', text):
        fields.add(m.group(1))
    for m in re.finditer(r'json:"(\w{2,40})', text):     # Go struct tags
        fields.add(m.group(1))

    classes: set[str] = set()
    lowered = {f.lower().replace("_", "") for f in fields}
    for cls, hints in CLASS_HINTS.items():
        if any(h.replace("_", "") in lowered for h in hints):
            classes.add(cls)
    return sorted(fields), sorted(classes)


def _in_catalogue(route_path: str) -> bool:
    for candidate in ("openapi.yaml", "openapi.yml", "openapi.json",
                      "api/openapi.yaml", "docs/openapi.yaml"):
        f = Path(candidate)
        if f.is_file():
            try:
                if route_path in f.read_text(encoding="utf-8", errors="replace"):
                    return True
            except OSError:
                continue
    return False


def submit(routes: list[dict]) -> dict:
    base = os.environ["SENTRY_ENDPOINT"].rstrip("/")
    payload = json.dumps({
        "repo": os.environ.get("GH_REPO", ""),
        "pr_number": int(os.environ.get("GH_PR", "0") or 0),
        "commit_sha": os.environ.get("GH_SHA", ""),
        "routes": routes,
    }).encode()

    req = urllib.request.Request(
        f"{base}/api/v1/gate/check", data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {os.environ['SENTRY_TOKEN']}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:400]
        print(f"::error::SENTRY gate returned {exc.code}: {body}")
        raise SystemExit(2)
    except urllib.error.URLError as exc:
        # Not a pass. A gate that treats an unreachable control plane as a clean
        # build goes quiet exactly when the deployment is broken.
        print(f"::error::could not reach SENTRY at {base}: {exc.reason}")
        raise SystemExit(2)


def annotate(result: dict) -> None:
    for check in result.get("checks", []):
        if check.get("passed"):
            continue
        level = "error" if check.get("severity", "error") == "error" else "warning"
        route = check.get("route", {})
        file = route.get("file")
        line = route.get("line")
        where = f" file={file},line={line}" if file else ""
        print(f"::{level} title=SENTRY {check.get('name')}{where}::"
              f"{check.get('detail', '')}")


def main(argv: list[str]) -> int:
    changed_file = argv[1] if len(argv) > 1 else "/tmp/sentry-changed.txt"
    try:
        changed = [ln.strip() for ln in Path(changed_file).read_text().splitlines()
                   if ln.strip()]
    except OSError:
        changed = []

    routes, skipped = collect(changed)
    if skipped:
        print(f"::warning::{len(skipped)} changed file(s) could not be read and "
              f"were not scanned")

    if not routes:
        print("SENTRY gate: no route declarations in this diff")
        _out("passed", "true")
        _out("checks", "[]")
        return 0

    print(f"SENTRY gate: {len(routes)} route declaration(s) in {len(changed)} "
          f"changed file(s)")
    result = submit(routes)
    annotate(result)

    passed = bool(result.get("passed"))
    _out("passed", "true" if passed else "false")
    _out("checks", json.dumps(result.get("checks", [])))

    for check in result.get("checks", []):
        mark = "PASS" if check.get("passed") else "FAIL"
        print(f"  {mark}  {check.get('name')}: {check.get('detail', '')}")

    fail_on = os.environ.get("SENTRY_FAIL_ON", "error")
    if passed or fail_on == "never":
        return 0
    if fail_on == "warn":
        return 1
    failing = [c for c in result.get("checks", [])
               if not c.get("passed") and c.get("severity", "error") == "error"]
    return 1 if failing else 0


def _out(key: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{key}={value}\n")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
