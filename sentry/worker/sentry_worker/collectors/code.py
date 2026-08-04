"""Repository collector — what the institution's source declares.

The third of stage 01's four sources. The sensor reports what the estate *does*;
the gateway reports what it *publishes*; this reports what somebody *wrote*.

Three-way disagreement is the product. An endpoint in code and in the gateway
and in traffic is documented and healthy. One in code and in traffic but not the
gateway is bypassing the front door. One in traffic and in neither is shadow —
nobody can say where it came from. And one in code with no traffic at all is not
a zombie: it is unreleased, and stage 04 tells them apart by
``last_call_vday IS NULL``.

**Which repositories are scanned is the whole meaning of "absent from code".**
An endpoint is only code-absent with respect to the set SENTRY was pointed at,
so ``CODE_REPO_PATHS`` is a claim about coverage and is reported as one. A
service deployed from a repository nobody registered is exactly how a shadow
endpoint comes to exist.

Four languages, four real parses. Python uses the standard library's ``ast``,
which is exact and needs no grammar bundle; Go, JavaScript and Java use
tree-sitter, as the design specifies. Every route records the parser that found
it, because an exact parse and a line-wise guess are not the same evidence.

Those three were matched by regular expression until recently, and the cost was
not theoretical. A regex reads one line, so ``router.HandleFunc(`` with its path
on the next line was invisible, and ``r.Get(base+"/deposits/{id}")`` was
invisible whether wrapped or not. Both are ordinary code. A route this collector
cannot see is a route absent from the ``code`` source, and SHADOW is defined as
traffic present with gateway *and* code absent — so a parser that quietly misses
declarations manufactures shadow findings, which is the failure mode that
generates work for people.

The pattern matcher is kept as the fallback for a host where a grammar fails to
load, and says so in the ``framework`` label rather than passing itself off as a
parse.
"""

from __future__ import annotations

import ast
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from sentry_core.config import settings

from . import treesitter
from .patterns import (
    AUTH_MARKERS,
    METHOD_DECORATORS,
    ROUTE_DECORATORS,
    SPRING_ANNOTATIONS,
    FoundRoute,
    join_prefix,
    normalise_declared_path,
)

log = logging.getLogger(__name__)

VERSION = "code-1.0.0"

#: Directories never worth walking. Site-packages contains every route in every
#: dependency, and reporting those as the institution's API surface would bury
#: the ones that are.
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build", "target", ".tox", "site-packages",
    ".idea", ".vscode",
}

PY_SUFFIXES = {".py"}
PATTERN_SUFFIXES = {".go": "go", ".js": "javascript", ".ts": "javascript",
                    ".mjs": "javascript", ".java": "java", ".kt": "java"}


@dataclass
class RepoScan:
    """One repository's declared surface."""

    repo: str
    routes: list[FoundRoute] = field(default_factory=list)
    files_scanned: int = 0
    parse_errors: list[dict] = field(default_factory=list)
    #: False when the path does not exist. A repository that could not be read
    #: contributes no evidence either way, and saying so is what stops its
    #: endpoints being reported as code-absent.
    readable: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Python
# ─────────────────────────────────────────────────────────────────────────────
def _string_arg(node: ast.Call) -> str | None:
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    for kw in node.keywords:
        if kw.arg in ("path", "rule") and isinstance(kw.value, ast.Constant):
            if isinstance(kw.value.value, str):
                return kw.value.value
    return None


def _methods_kwarg(node: ast.Call) -> list[str]:
    for kw in node.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            out = [e.value.upper() for e in kw.value.elts
                   if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if out:
                return out
    return []


def _router_prefixes(tree: ast.AST) -> dict[str, str]:
    """Router variable -> prefix, from ``APIRouter(prefix="/api/v1")``.

    Without this a relative path reaches the registry as ``/accounts`` where the
    service serves ``/api/v1/accounts``, and the declared and observed sightings
    of one endpoint never correlate.
    """
    prefixes: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        name = call.func.attr if isinstance(call.func, ast.Attribute) else \
            getattr(call.func, "id", "")
        if name not in ("APIRouter", "Blueprint", "Router"):
            continue
        prefix = ""
        for kw in call.keywords:
            if kw.arg in ("prefix", "url_prefix") and isinstance(kw.value, ast.Constant):
                prefix = str(kw.value.value)
        if not prefix:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                prefixes[target.id] = prefix
    return prefixes


def _has_auth(source_lines: list[str], node: ast.FunctionDef) -> bool:
    """Whether the handler declares authentication.

    Reads the decorators and the signature — a FastAPI dependency appears in the
    parameter list, a Flask guard as another decorator. This recognises that
    authentication was declared, not that it is correct; stage 13 assesses the
    latter from what the gateway enforces.
    """
    start = max(0, node.lineno - 1 - len(node.decorator_list) - 1)
    end = min(len(source_lines), (node.body[0].lineno if node.body else node.lineno))
    window = "\n".join(source_lines[start:end])
    return any(marker in window for marker in AUTH_MARKERS)


def routes_from_python(source: str, rel_path: str) -> list[FoundRoute]:
    """Every route a Python module declares, from its AST.

    Exact rather than approximate: a decorator is a decorator, and a string
    inside one is unambiguous. The pattern matching used for the other languages
    cannot say the same.
    """
    tree = ast.parse(source)
    lines = source.splitlines()
    prefixes = _router_prefixes(tree)
    found: list[FoundRoute] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue

            attr = dec.func.attr
            owner = getattr(dec.func.value, "id", "")
            path = _string_arg(dec)
            if path is None:
                continue

            if attr in METHOD_DECORATORS:
                methods = [METHOD_DECORATORS[attr]]
            elif attr in ROUTE_DECORATORS:
                # Flask defaults to GET when no methods list is given, and so
                # does this. Assuming every verb would put five endpoints in the
                # registry where the service declares one.
                methods = _methods_kwarg(dec) or ["GET"]
            else:
                continue

            full = join_prefix(prefixes.get(owner, ""), path)
            for method in methods:
                found.append(FoundRoute(
                    method=method,
                    path=normalise_declared_path(full),
                    file=rel_path,
                    line=dec.lineno,
                    handler=node.name,
                    has_auth_middleware=_has_auth(lines, node),
                    framework="python-ast",
                ))
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Go, JavaScript, Java — pattern matched
# ─────────────────────────────────────────────────────────────────────────────
_GO_HANDLEFUNC = re.compile(
    r"""\.\s*HandleFunc\s*\(\s*["`]([^"`]+)["`]""", re.X)
_GO_METHOD = re.compile(
    r"""\.\s*(Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*["`]([^"`]+)["`]""")
_GO_MUX_METHOD = re.compile(
    r"""["`](GET|POST|PUT|PATCH|DELETE)\s+(/[^"`]*)["`]""")
_JS_METHOD = re.compile(
    r"""\.\s*(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]""")
_JAVA_MAPPING = re.compile(
    r"""@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)"""
    r"""\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']""")


def routes_from_source(source: str, rel_path: str, language: str) -> list[FoundRoute]:
    """Route declarations, parsed from a syntax tree where a grammar exists.

    tree-sitter for Go, JavaScript and Java, matching the exactness Python
    already has from `ast`. The pattern matcher below remains as the fallback for
    a host where a grammar failed to load, and the ``framework`` field records
    which one found each route — an exact parse and a line-wise guess are not the
    same evidence and are not labelled as though they were.

    The fallback is a fallback, not a silent equivalent. A missed route makes an
    endpoint absent from the `code` source, and SHADOW is defined as traffic
    present with gateway and code both absent — so a parser that quietly misses
    declarations manufactures shadow findings, which is the failure mode that
    generates work.
    """
    try:
        parsed, unparsed = treesitter.routes(source, language)
    except treesitter.GrammarUnavailable:
        return routes_from_patterns(source, rel_path, language)

    has_auth = any(m in source for m in AUTH_MARKERS)
    out = [
        FoundRoute(method=method, path=normalise_declared_path(path),
                   file=rel_path, line=line,
                   framework=f"{language}-treesitter",
                   has_auth_middleware=has_auth)
        for method, path, line in parsed
    ]
    if unparsed:
        log.info("%s: %d route registration(s) whose path is not a literal in "
                 "this file; not guessed at", rel_path, unparsed)
    return out


def routes_from_patterns(source: str, rel_path: str, language: str) -> list[FoundRoute]:
    """Route declarations matched by pattern.

    Weaker than a parse and labelled as such: a declaration split across lines,
    or one whose path is a constant rather than a literal, is missed. The
    ``framework`` field carries which parser found each route so a reader knows
    which guarantee applies to it.

    Retained as the fallback for a host without the grammars rather than as the
    primary path.
    """
    found: list[FoundRoute] = []

    def add(method: str, path: str, line_no: int) -> None:
        found.append(FoundRoute(
            method=method.upper(), path=normalise_declared_path(path),
            file=rel_path, line=line_no, framework=f"{language}-pattern",
            has_auth_middleware=any(m in source for m in AUTH_MARKERS)))

    for line_no, line in enumerate(source.splitlines(), start=1):
        if language == "go":
            for m in _GO_MUX_METHOD.finditer(line):
                add(m.group(1), m.group(2), line_no)
            for m in _GO_METHOD.finditer(line):
                add(m.group(1), m.group(2), line_no)
            for m in _GO_HANDLEFUNC.finditer(line):
                # net/http's HandleFunc takes no method. Recorded as GET
                # because that is what the overwhelming majority are, and a
                # wrong method is recoverable where a missing route is not.
                add("GET", m.group(1), line_no)
        elif language == "javascript":
            for m in _JS_METHOD.finditer(line):
                verb = "GET" if m.group(1) == "all" else m.group(1)
                add(verb, m.group(2), line_no)
        elif language == "java":
            for m in _JAVA_MAPPING.finditer(line):
                verb = SPRING_ANNOTATIONS.get(m.group(1), "GET")
                add(verb, m.group(2), line_no)

    return found


# ─────────────────────────────────────────────────────────────────────────────
# git blame — rung 2 of the ownership ladder
# ─────────────────────────────────────────────────────────────────────────────
def blame(repo: Path, rel_path: str, line: int) -> dict:
    """Who last touched the line that declares this route.

    Rung 2 of the ownership ladder: below a CODEOWNERS entry, above nothing. The
    person who last edited a route declaration is a far better lead than an
    empty ownership field, and it is evidence rather than a guess — which is why
    stage 03 records it with a confidence below a declared owner's.

    Silent on failure. Not every checkout is a git repository, and a missing
    blame is an absent rung rather than an error.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "blame", "-L", f"{line},{line}",
             "--porcelain", "--", rel_path],
            capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return {}
    if out.returncode != 0:
        return {}

    info: dict = {}
    for row in out.stdout.splitlines():
        if row.startswith("author "):
            info["last_author"] = row[len("author "):].strip()
        elif row.startswith("author-mail "):
            info["last_author_email"] = row[len("author-mail "):].strip("<> ")
        elif row.startswith("author-time "):
            info["last_commit_epoch"] = int(row[len("author-time "):].strip())
    return info


# ─────────────────────────────────────────────────────────────────────────────
# Walking a repository
# ─────────────────────────────────────────────────────────────────────────────
def scan_repo(path: str | Path, *, with_blame: bool = True) -> RepoScan:
    """Every route declared anywhere under a path."""
    root = Path(path).expanduser()
    scan = RepoScan(repo=root.name or str(root))

    if not root.exists():
        # A path that is not there is not an empty repository. Reporting zero
        # routes would make every endpoint in it look code-absent, which is the
        # difference between "documented" and "shadow".
        scan.readable = False
        return scan

    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        if any(part in SKIP_DIRS for part in file.parts):
            continue

        rel = str(file.relative_to(root))
        try:
            source = file.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            continue

        try:
            if file.suffix in PY_SUFFIXES:
                routes = routes_from_python(source, rel)
            elif file.suffix in PATTERN_SUFFIXES:
                routes = routes_from_source(source, rel, PATTERN_SUFFIXES[file.suffix])
            else:
                continue
        except SyntaxError as exc:
            # A file that will not parse is recorded, not swallowed. Its routes
            # are missing from the registry and somebody has to know why.
            scan.parse_errors.append({"file": rel, "error": str(exc)[:200]})
            scan.files_scanned += 1
            continue

        scan.files_scanned += 1
        for route in routes:
            if with_blame:
                info = blame(root, rel, route.line)
                route.last_author = info.get("last_author")
                route.last_author_email = info.get("last_author_email")
                if info.get("last_commit_epoch"):
                    from datetime import datetime, timezone
                    route.last_commit_iso = datetime.fromtimestamp(
                        info["last_commit_epoch"], tz=timezone.utc).isoformat()
            scan.routes.append(route)

    return scan


@dataclass
class CodeSnapshot:
    scans: list[RepoScan] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        """True when every configured repository could be read.

        Stage 04 needs this the way it needs the gateway's: absence from a
        repository nobody could read is not evidence of absence.
        """
        return bool(self.scans) and all(s.readable for s in self.scans)

    @property
    def routes(self) -> list[FoundRoute]:
        return [r for s in self.scans for r in s.routes]

    @property
    def unreadable(self) -> list[str]:
        return [s.repo for s in self.scans if not s.readable]


def repo_paths() -> list[str]:
    return [p.strip() for p in (settings.code_repo_paths or "").split(",") if p.strip()]


def collect(paths: list[str] | None = None, *, with_blame: bool = True) -> CodeSnapshot:
    """Scan every configured repository.

    Never raises on an unreadable path: an unhealthy snapshot is a valid answer
    that stage 04 knows how to handle, and an exception would abort a pipeline
    run over one misconfigured directory.
    """
    return CodeSnapshot(scans=[scan_repo(p, with_blame=with_blame)
                               for p in (paths if paths is not None else repo_paths())])
