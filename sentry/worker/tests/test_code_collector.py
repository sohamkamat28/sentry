"""Stage 01 — the repository collector.

What it finds decides whether an endpoint is DOCUMENTED or SHADOW, and that is
the highest-consequence verdict this system produces. A missed route reads as
shadow; a fabricated one reads as documented. Both are wrong in the direction
that costs somebody a day.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sentry_worker.collectors import code
from sentry_worker.collectors.patterns import join_prefix, normalise_declared_path


def write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body))
    return path


def src(body: str) -> str:
    """Dedent an inline source fixture. `ast.parse` refuses leading indent."""
    return textwrap.dedent(body)


def paths_of(routes) -> set[tuple[str, str]]:
    return {(r.method, r.path) for r in routes}


# ─────────────────────────────────────────────────────────────────────────────
# Path normalisation
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("declared,expected", [
    ("/api/v1/accounts/<account_id>", "/api/v1/accounts/{id}"),   # Flask
    ("/api/v1/accounts/<int:id>", "/api/v1/accounts/{id}"),       # Flask, typed
    ("/api/v1/accounts/{account_id}", "/api/v1/accounts/{id}"),   # FastAPI
    ("/api/v1/accounts/:id", "/api/v1/accounts/{id}"),            # Express
    ("api/v1/accounts", "/api/v1/accounts"),                      # leading slash
    ("/api/v1/accounts/", "/api/v1/accounts"),                    # trailing slash
])
def test_every_frameworks_placeholder_becomes_the_same_template(declared, expected):
    """The registry's identity function keys on the template.

    A route written `<id>` in Flask and `{id}` in FastAPI is one endpoint. Left
    alone they arrive as two strings, and the same endpoint appears twice while
    neither copy correlates with the traffic.
    """
    assert normalise_declared_path(declared) == expected


def test_literal_segments_are_never_guessed_at():
    """A declared path is the institution's own statement of its surface.
    Collapsing a literal would put a route in the register no repository
    contains."""
    assert normalise_declared_path("/api/v1/legacy-balance") == "/api/v1/legacy-balance"
    assert normalise_declared_path("/internal/fx/rate") == "/internal/fx/rate"


def test_a_router_prefix_is_joined():
    assert join_prefix("/api/v1", "/accounts") == "/api/v1/accounts"
    assert join_prefix("", "/accounts") == "/accounts"


# ─────────────────────────────────────────────────────────────────────────────
# Python, by AST
# ─────────────────────────────────────────────────────────────────────────────
def test_method_decorators_are_found_with_their_verb():
    routes = code.routes_from_python(src('''
        @app.get("/api/v1/accounts/<id>")
        def get_account(id): ...

        @app.post("/api/v1/payments")
        def make_payment(): ...

        @router.delete("/api/v1/sessions/{sid}")
        def drop(sid): ...
    '''), "routes.py")

    assert paths_of(routes) == {
        ("GET", "/api/v1/accounts/{id}"),
        ("POST", "/api/v1/payments"),
        ("DELETE", "/api/v1/sessions/{id}"),
    }


def test_route_decorator_defaults_to_get_like_flask():
    """Assuming every verb would put five endpoints in the register where the
    service declares one."""
    routes = code.routes_from_python(src('''
        @app.route("/api/v1/accounts")
        def accounts(): ...
    '''), "routes.py")
    assert paths_of(routes) == {("GET", "/api/v1/accounts")}


def test_a_methods_list_produces_one_route_per_verb():
    routes = code.routes_from_python(src('''
        @app.route("/api/v1/transfer", methods=["POST", "PUT"])
        def transfer(): ...
    '''), "routes.py")
    assert paths_of(routes) == {("POST", "/api/v1/transfer"),
                                ("PUT", "/api/v1/transfer")}


def test_an_apirouter_prefix_is_applied():
    """Ignoring it records /accounts where the service serves
    /api/v1/accounts, and the declared and observed sightings never meet."""
    routes = code.routes_from_python(src('''
        router = APIRouter(prefix="/api/v1")

        @router.get("/accounts/{id}")
        def get_account(id): ...
    '''), "routes.py")
    assert paths_of(routes) == {("GET", "/api/v1/accounts/{id}")}


def test_a_blueprint_url_prefix_is_applied():
    routes = code.routes_from_python(src('''
        bp = Blueprint("kyc", __name__, url_prefix="/api/v1/kyc")

        @bp.get("/<customer_id>")
        def get_kyc(customer_id): ...
    '''), "routes.py")
    assert paths_of(routes) == {("GET", "/api/v1/kyc/{id}")}


def test_the_declaring_line_is_recorded():
    """git blame needs the line, and the CI gate annotates the diff at it."""
    routes = code.routes_from_python(
        '\n\n@app.get("/api/v1/accounts")\ndef accounts(): ...\n', "svc/routes.py")

    assert routes[0].line == 3
    assert routes[0].file == "svc/routes.py"
    assert routes[0].handler == "accounts"


def test_declared_authentication_is_recorded():
    routes = code.routes_from_python(src('''
        @app.get("/api/v1/open")
        def open_route(): ...

        @app.get("/api/v1/guarded")
        @login_required
        def guarded(): ...

        @app.get("/api/v1/dependency")
        def dependency(user = Depends(oauth2_scheme)): ...
    '''), "routes.py")

    by_path = {r.path: r for r in routes}
    assert not by_path["/api/v1/open"].has_auth_middleware
    assert by_path["/api/v1/guarded"].has_auth_middleware
    assert by_path["/api/v1/dependency"].has_auth_middleware


def test_a_decorator_with_no_path_is_not_a_route():
    """`@app.get` is a route; `@staticmethod` and `@lru_cache()` are not."""
    routes = code.routes_from_python(src('''
        @lru_cache()
        def cached(): ...

        @app.on_event("startup")
        def boot(): ...
    '''), "routes.py")
    # on_event is a decorator with a string argument and is not a route verb.
    assert routes == []


def test_async_handlers_are_found():
    routes = code.routes_from_python(src('''
        @app.get("/api/v1/accounts")
        async def accounts(): ...
    '''), "routes.py")
    assert paths_of(routes) == {("GET", "/api/v1/accounts")}


# ─────────────────────────────────────────────────────────────────────────────
# Other languages, by pattern
# ─────────────────────────────────────────────────────────────────────────────
def test_go_routes_are_found():
    routes = code.routes_from_patterns(src('''
        mux.HandleFunc("/api/v1/accounts", handleAccounts)
        r.Get("/api/v1/balance/{id}", handleBalance)
        mux.HandleFunc("POST /api/v1/transfer", handleTransfer)
    '''), "main.go", "go")

    found = paths_of(routes)
    assert ("GET", "/api/v1/accounts") in found
    assert ("GET", "/api/v1/balance/{id}") in found
    assert ("POST", "/api/v1/transfer") in found


def test_express_routes_are_found():
    routes = code.routes_from_patterns(
        'app.get("/api/v1/accounts/:id", handler);\n'
        "app.post('/api/v1/payments', handler);\n", "server.js", "javascript")
    assert paths_of(routes) == {("GET", "/api/v1/accounts/{id}"),
                                ("POST", "/api/v1/payments")}


def test_spring_annotations_are_found():
    routes = code.routes_from_patterns(
        '@GetMapping("/api/v1/accounts/{id}")\n'
        '@PostMapping(value = "/api/v1/transfer")\n', "Controller.java", "java")
    assert paths_of(routes) == {("GET", "/api/v1/accounts/{id}"),
                                ("POST", "/api/v1/transfer")}


def test_the_parser_that_found_a_route_is_recorded():
    """A pattern match is weaker than a parse and says so, because a reader has
    to know which guarantee applies to which row."""
    py = code.routes_from_python('@app.get("/x")\ndef x(): ...\n', "a.py")
    go = code.routes_from_patterns('r.Get("/x", h)', "a.go", "go")

    assert py[0].framework == "python-ast"
    assert go[0].framework == "go-pattern"


# ─────────────────────────────────────────────────────────────────────────────
# Walking a repository
# ─────────────────────────────────────────────────────────────────────────────
def test_a_repository_scan_finds_routes_across_files(tmp_path):
    write(tmp_path, "svc/routes.py", '@app.get("/api/v1/a")\ndef a(): ...\n')
    write(tmp_path, "svc/more.py", '@app.post("/api/v1/b")\ndef b(): ...\n')

    scan = code.scan_repo(tmp_path, with_blame=False)

    assert scan.readable
    assert paths_of(scan.routes) == {("GET", "/api/v1/a"), ("POST", "/api/v1/b")}


def test_dependency_directories_are_skipped(tmp_path):
    """site-packages contains every route in every dependency. Reporting those
    as the institution's API surface would bury the ones that are."""
    write(tmp_path, "app/routes.py", '@app.get("/api/v1/mine")\ndef m(): ...\n')
    write(tmp_path, ".venv/lib/site-packages/flask/app.py",
          '@app.get("/api/v1/theirs")\ndef t(): ...\n')
    write(tmp_path, "node_modules/express/index.js", 'app.get("/nope", h)')

    scan = code.scan_repo(tmp_path, with_blame=False)
    assert paths_of(scan.routes) == {("GET", "/api/v1/mine")}


def test_a_file_that_will_not_parse_is_reported_not_swallowed(tmp_path):
    """Its routes are missing from the register and somebody has to know why."""
    write(tmp_path, "good.py", '@app.get("/api/v1/ok")\ndef ok(): ...\n')
    write(tmp_path, "broken.py", "def unclosed(:\n")

    scan = code.scan_repo(tmp_path, with_blame=False)

    assert paths_of(scan.routes) == {("GET", "/api/v1/ok")}
    assert len(scan.parse_errors) == 1
    assert scan.parse_errors[0]["file"] == "broken.py"


def test_a_path_that_does_not_exist_is_unreadable_not_empty(tmp_path):
    """An absent repository is not an empty one.

    Reporting zero routes would make every endpoint it describes look
    code-absent — which is the difference between DOCUMENTED and SHADOW, the
    highest-urgency cell in the matrix.
    """
    scan = code.scan_repo(tmp_path / "nope", with_blame=False)

    assert scan.readable is False
    assert scan.routes == []


def test_a_snapshot_is_unhealthy_when_any_repository_is_unreadable(tmp_path):
    write(tmp_path, "a/routes.py", '@app.get("/api/v1/a")\ndef a(): ...\n')

    snapshot = code.collect([str(tmp_path / "a"), str(tmp_path / "missing")],
                            with_blame=False)

    assert snapshot.healthy is False
    assert snapshot.unreadable == ["missing"]
    # The routes it *did* find are still reported.
    assert paths_of(snapshot.routes) == {("GET", "/api/v1/a")}


def test_an_empty_configured_set_is_unhealthy():
    """Scanning nothing is not the same as finding nothing, and if it were
    treated as such the whole estate would read as shadow."""
    assert code.collect([], with_blame=False).healthy is False


# ─────────────────────────────────────────────────────────────────────────────
# git blame — rung 2 of the ownership ladder
# ─────────────────────────────────────────────────────────────────────────────
def _git(repo: Path, *args: str) -> None:
    import subprocess
    subprocess.run(["git", "-C", str(repo), *args],
                   check=True, capture_output=True, text=True)


def test_blame_names_whoever_last_touched_the_declaring_line(tmp_path):
    """Rung 2 of the ownership ladder.

    The person who last edited a route declaration is a far better lead than an
    empty ownership field, and it is evidence rather than a guess — which is why
    the ladder records it below a declared CODEOWNERS entry rather than beside
    one.
    """
    import shutil
    if shutil.which("git") is None:
        pytest.skip("no git on this host")

    write(tmp_path, "routes.py", '@app.get("/api/v1/accounts")\ndef a(): ...\n')
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "asha@bank.example")
    _git(tmp_path, "config", "user.name", "Asha Rao")
    _git(tmp_path, "add", "routes.py")
    _git(tmp_path, "commit", "-q", "-m", "add accounts route")

    scan = code.scan_repo(tmp_path, with_blame=True)

    assert len(scan.routes) == 1
    assert scan.routes[0].last_author == "Asha Rao"
    assert scan.routes[0].last_author_email == "asha@bank.example"
    assert scan.routes[0].last_commit_iso is not None


def test_a_checkout_that_is_not_a_repository_yields_no_blame_and_no_error(tmp_path):
    """A missing blame is an absent rung, not a failure. Not every deployment
    scans a git checkout, and raising here would take out the whole collector
    over an optional ownership signal."""
    write(tmp_path, "routes.py", '@app.get("/api/v1/accounts")\ndef a(): ...\n')

    scan = code.scan_repo(tmp_path, with_blame=True)

    assert len(scan.routes) == 1
    assert scan.routes[0].last_author is None
    assert scan.readable is True
