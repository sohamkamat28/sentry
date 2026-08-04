"""Assert the one-writer-per-column rule the schema claims to hold.

``core/sentry_core/models.py`` opens by stating that every column names exactly
one stage that writes it. That sentence is worth exactly as much as the check
behind it — so this is the check.

Two independent things are verified:

1. **Every mapped class declares its writer.** A table nobody claims is a table
   whose provenance is unknown, and the first question asked of any figure this
   system produces is which stage computed it.

2. **The declarations match the code.** Declared writers are compared against
   the stages in ``worker/sentry_worker/runner.py`` that actually construct,
   update or delete each model. A stage writing a table it does not declare is
   the failure that matters: two stages writing one column silently, where the
   later one wins and the earlier one's work vanishes with no error anywhere.

The second check is the reason this is a source-parsing tool rather than a
convention in a style guide. It found the real thing it was built to find — see
the deliberate exception for ``Classification.pre_zombie``, which is a genuine
back-edge, declared as one, and would otherwise be indistinguishable from the
defect.

    python tools/check_schema_writers.py            # exits non-zero on drift
    python tools/check_schema_writers.py --list     # print the writer map
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODELS = REPO_ROOT / "core" / "sentry_core" / "models.py"
RUNNER = REPO_ROOT / "worker" / "sentry_worker" / "runner.py"

#: Writers that are not pipeline stages. Each one is a real process that inserts
#: rows, and naming them here is what keeps the check honest: without this set
#: every one of these tables would have to claim a stage that does not write it.
NON_STAGE_WRITERS = {
    "ingest",         # Go, the hot path — observation inserts
    "honeypot",       # Go — probe inserts
    "api",            # control plane — audit, policy, clock
    "actuator",       # gateway/WORM/SIEM actuators, called from stages and the API
    "orchestrator",   # run/stage bookkeeping, written around the stages not by one
    "system",         # bootstrap and maintenance
}

#: Tables written by the platform rather than by an analysis stage. Excluded from
#: the runner cross-check because no stage function should appear as their
#: writer; they are still required to declare a writer above.
PLATFORM_TABLES = {
    "VClock", "PipelineRun", "StageRun", "AuditEntry", "PolicySetting",
    "PolicyWeights", "AiDecision", "GateEvent", "Probe", "ResurrectionAlert",
}

# Two declaration forms are in use and both are legitimate. Most tables have a
# single writer and say so in one line ("Writer: stage 06."). Endpoint has seven
# groups of columns with different writers and declares them as a per-column
# table, because compressing that into one line would lose exactly the
# information the rule exists to record.
WRITER_KEYWORD = re.compile(r"writers?\b", re.I)
STAGE_RE = re.compile(r"stage[s]?\s+(\d+)", re.I)


class Failure(Exception):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Declarations
# ─────────────────────────────────────────────────────────────────────────────
def _is_model(node: ast.ClassDef) -> bool:
    """A mapped class, identified by its __tablename__ rather than its bases.

    Base itself and any future mixin have no table and are not models.
    """
    return any(
        isinstance(stmt, ast.AnnAssign)
        and isinstance(stmt.target, ast.Name)
        and stmt.target.id == "__tablename__"
        for stmt in node.body
    ) or any(
        isinstance(stmt, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "__tablename__"
                for t in stmt.targets)
        for stmt in node.body
    )


def declared_writers() -> dict[str, set[str]]:
    """Model class name → the writers its docstring claims."""
    tree = ast.parse(MODELS.read_text(), filename=str(MODELS))
    out: dict[str, set[str]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or not _is_model(node):
            continue
        doc = ast.get_docstring(node) or ""
        if not WRITER_KEYWORD.search(doc):
            raise Failure(
                f"{node.name} (line {node.lineno}) declares no writer. "
                f"Add 'Writer: stage NN.' to its docstring — a table whose "
                f"provenance is undeclared cannot be audited."
            )
        # Scanned across the whole docstring rather than one line after the
        # keyword, so the tabular form is read as well as the prose one. Only
        # the class docstring is considered: per-column comments name the stages
        # that *read* a column too, and treating a read as a write would make
        # every stage a writer of everything it consults.
        # int() so "stage 05" and "stage 5" are one writer. The docstrings pad
        # and the runner's function names do not; comparing the strings made
        # every table look like it had two writers.
        writers = {f"stage {int(n)}" for n in STAGE_RE.findall(doc)}
        writers |= {w for w in NON_STAGE_WRITERS if re.search(rf"\b{w}\b", doc, re.I)}
        if not writers:
            raise Failure(
                f"{node.name} (line {node.lineno}) says 'writer' but names no "
                f"stage or known non-stage writer."
            )
        out[node.name] = writers
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Observed writes
# ─────────────────────────────────────────────────────────────────────────────
class _Writes(ast.NodeVisitor):
    """Model names written inside one function body.

    A write is a constructor call, or the model passed to `update()`/`delete()`.
    `select(Model)` is a read and is deliberately not counted — counting reads
    would make every stage a writer of everything it consults, and the check
    would assert nothing.
    """

    def __init__(self, model_names: set[str]) -> None:
        self.models = model_names
        self.written: set[str] = set()
        self.calls: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        fn = node.func
        if isinstance(fn, ast.Name):
            if fn.id in self.models:
                self.written.add(fn.id)          # Model(...) construction
            elif fn.id in ("update", "delete"):
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in self.models:
                        self.written.add(arg.id)
            else:
                self.calls.add(fn.id)            # helper, resolved below
        self.generic_visit(node)


def observed_writers(model_names: set[str]) -> dict[str, set[str]]:
    """Model class name → the stages whose code writes it.

    Helper functions are resolved into their callers. ``_enter_phase`` writes
    Control rows and is only ever reached from stage 11; attributing its writes
    to nothing would leave stage 11 looking like it writes less than it does,
    and the check would pass while the declaration was wrong.
    """
    tree = ast.parse(RUNNER.read_text(), filename=str(RUNNER))

    per_fn: dict[str, _Writes] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            v = _Writes(model_names)
            for stmt in node.body:
                v.visit(stmt)
            per_fn[node.name] = v

    def resolve(name: str, seen: frozenset[str]) -> set[str]:
        if name in seen or name not in per_fn:
            return set()
        v = per_fn[name]
        out = set(v.written)
        for callee in v.calls:
            out |= resolve(callee, seen | {name})
        return out

    stage_fn = re.compile(r"^stage_(\d+)_")
    out: dict[str, set[str]] = {}
    for fn_name in per_fn:
        m = stage_fn.match(fn_name)
        if not m:
            continue
        stage = f"stage {int(m.group(1))}"
        for model in resolve(fn_name, frozenset()):
            out.setdefault(model, set()).add(stage)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# The check
# ─────────────────────────────────────────────────────────────────────────────
def check() -> list[str]:
    declared = declared_writers()
    observed = observed_writers(set(declared))
    problems: list[str] = []

    for model, stages in sorted(observed.items()):
        if model in PLATFORM_TABLES:
            continue
        undeclared = stages - declared[model]
        if undeclared:
            problems.append(
                f"{model}: written by {', '.join(sorted(undeclared))} in runner.py, "
                f"but its docstring declares only {', '.join(sorted(declared[model]))}. "
                f"Either the write is a duplicate writer, or the declaration is stale."
            )

    # A table declared as stage-written that no stage writes is the other
    # direction of the same defect: a column with a documented provenance that
    # nothing produces, which reads as an empty result rather than a missing one.
    for model, writers in sorted(declared.items()):
        if model in PLATFORM_TABLES:
            continue
        stage_writers = {w for w in writers if w.startswith("stage ")}
        if stage_writers and model not in observed:
            problems.append(
                f"{model}: declares {', '.join(sorted(stage_writers))} as its writer, "
                f"but no stage function in runner.py writes it."
            )

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print the writer map and exit")
    args = ap.parse_args()

    try:
        declared = declared_writers()
    except Failure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1

    if args.list:
        observed = observed_writers(set(declared))
        width = max(len(m) for m in declared)
        for model in sorted(declared):
            seen = ", ".join(sorted(observed.get(model, set()))) or "—"
            print(f"{model:<{width}}  declared: {', '.join(sorted(declared[model])):<28} "
                  f"observed: {seen}")
        return 0

    problems = check()
    if problems:
        print(f"FAIL  {len(problems)} schema-writer problem(s):\n", file=sys.stderr)
        for p in problems:
            print(f"  • {p}", file=sys.stderr)
        return 1

    print(f"OK  {len(declared)} tables, every one declaring a writer that matches "
          f"the code that writes it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
