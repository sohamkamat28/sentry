"""Rung 1 of the ownership ladder — the declared owner.

A CODEOWNERS file is the only ownership source in this system that somebody
wrote down on purpose. Everything below it on the ladder is inference: git blame
says who last touched a line, which is a lead rather than a statement of
accountability, and gateway metadata says whatever a tag happened to be set to.
That is why a match here carries confidence 1.00 and the others do not.

Matching follows the GitHub rule set, and the two properties that matter are:

* **Last match wins**, not first and not most-specific. A file that ends with
  ``* @bank/platform`` assigns every unclaimed path to the platform team, and
  reading top-down-first-match would instead assign *everything* to them and
  silently discard every specific rule above it.
* **A pattern with no owners un-assigns.** ``/vendor/`` on its own is a
  deliberate statement that nobody owns that tree, and treating it as "no match"
  would fall through to the catch-all and attribute vendored code to whoever
  owns the repository.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

#: Where the file is allowed to live, in GitHub's precedence order.
SEARCH_PATHS = ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")

_TEAM_RE = re.compile(r"^@[\w.-]+/([\w.-]+)$")
_USER_RE = re.compile(r"^@([\w.-]+)$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(frozen=True)
class Rule:
    pattern: str
    owners: tuple[str, ...]
    line: int


@dataclass
class Owners:
    """What a CODEOWNERS file says about one path."""

    email: str | None = None
    team: str | None = None
    pattern: str | None = None
    line: int | None = None
    raw: tuple[str, ...] = ()

    @property
    def matched(self) -> bool:
        return self.pattern is not None


def parse(text: str) -> list[Rule]:
    rules: list[Rule] = []
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        # A pattern with no owners is legal and meaningful — see the module
        # docstring. It is kept as a rule with an empty owner tuple.
        rules.append(Rule(pattern=parts[0], owners=tuple(parts[1:]), line=n))
    return rules


def _matches(pattern: str, path: str) -> bool:
    """GitHub's CODEOWNERS pattern semantics, which are gitignore's.

    ``path`` is repository-relative with no leading slash.
    """
    path = path.lstrip("/")

    if pattern == "*":
        return True

    anchored = pattern.startswith("/")
    pat = pattern.lstrip("/")

    # A trailing slash means a directory and everything under it.
    if pat.endswith("/"):
        pat = pat + "**"

    # An unanchored pattern with no slash matches at any depth: `*.py` matches
    # `services/a/main.py`. An anchored one is rooted at the repository top.
    if not anchored and "/" not in pat.rstrip("*").rstrip("/"):
        candidates = [path] + [path[i + 1:] for i, c in enumerate(path) if c == "/"]
    else:
        candidates = [path]

    for cand in candidates:
        if fnmatch.fnmatch(cand, pat):
            return True
        # `dir/**` should match `dir/a` as well as `dir/a/b`; fnmatch's `**` is
        # not recursive on its own, so the bare-directory case is tried too.
        if pat.endswith("/**") and fnmatch.fnmatch(cand, pat[:-3]):
            return True
        if pat.endswith("/**") and cand.startswith(pat[:-3].rstrip("/") + "/"):
            return True
    return False


def owners_for(rules: list[Rule], path: str) -> Owners:
    """The owning entry for a repository-relative path.

    Iterated in reverse because the last matching rule wins.
    """
    for rule in reversed(rules):
        if not _matches(rule.pattern, path):
            continue
        if not rule.owners:
            # A deliberate un-assignment. Stop here rather than continuing to a
            # broader rule, which is the whole point of writing it.
            return Owners(pattern=rule.pattern, line=rule.line, raw=())

        email, team = None, None
        for token in rule.owners:
            if _EMAIL_RE.match(token):
                email = email or token
            elif m := _TEAM_RE.match(token):
                team = team or m.group(1)
            elif m := _USER_RE.match(token):
                # A bare @handle is a person, not an address. Recorded as the
                # team only if nothing better is present — inventing
                # `handle@example.com` would produce an address that does not
                # exist and route escalations into a void.
                team = team or m.group(1)
        return Owners(email=email, team=team, pattern=rule.pattern,
                      line=rule.line, raw=rule.owners)
    return Owners()


def load(repo_path: str) -> list[Rule] | None:
    """Read a repository's CODEOWNERS, or None if it has none.

    None and an empty rule list are different: no file means the repository
    never declared ownership, an empty file means it declared none. The ladder
    treats both as a miss, but the scan detail says which.
    """
    root = Path(repo_path)
    for rel in SEARCH_PATHS:
        candidate = root / rel
        if candidate.is_file():
            try:
                return parse(candidate.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                return None
    return None


def collect(repo_path: str) -> dict:
    """Everything one repository declares, for the scan report."""
    rules = load(repo_path)
    if rules is None:
        return {"repo": repo_path, "present": False, "rules": 0}
    return {"repo": repo_path, "present": True, "rules": len(rules),
            "patterns": [r.pattern for r in rules]}
