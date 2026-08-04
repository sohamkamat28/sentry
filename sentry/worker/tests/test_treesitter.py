"""Go, JavaScript and Java parsed rather than pattern-matched.

The regular expressions these replace read one line at a time. A route wrapped
across two lines was invisible; a path built from a constant was invisible
whether wrapped or not. Both are ordinary code, and a route the collector cannot
see is a route absent from the `code` source — which, with the gateway also
absent, is the definition of SHADOW. A missed declaration manufactures a finding.
"""

from __future__ import annotations

import pytest

from sentry_worker.collectors import code

GO = '''package main

func main() {
    // Wrapped across lines: invisible to a line-wise matcher.
    router.HandleFunc(
        "/api/v1/accounts/{id}", handler)

    // Path assembled from a constant.
    const base = "/api/v1"
    r.Get(base+"/deposits/{id}", h)

    // Go 1.22 puts the method inside the pattern.
    mux.HandleFunc("POST /api/v1/transfer", h)

    // Not resolvable to a literal in this file. Must not be guessed at.
    r.Post(dynamicPath, h)
}
'''

JS = '''const base = "/api/v1";
app.get(
  base + "/cards/:id",
  handler);
router.post("/api/v1/pay", h);
app.get(`${prefix}/interpolated`, h);
'''

JAVA = '''class C {
  @GetMapping(
     "/api/v1/accounts/{id}")
  public X get() {}

  @PostMapping(value = "/api/v1/transfer")
  public X post() {}
}
'''


def routes(source, lang):
    return {(r.method, r.path) for r in code.routes_from_source(source, "f", lang)}


def test_go_route_wrapped_across_lines_is_found():
    assert ("GET", "/api/v1/accounts/{id}") in routes(GO, "go")


def test_go_path_built_from_a_constant_is_resolved():
    assert ("GET", "/api/v1/deposits/{id}") in routes(GO, "go")


def test_go_method_inside_the_pattern_is_split_out():
    """`"POST /api/v1/transfer"` is one string carrying both. The pattern matcher
    read it twice — once correctly and once as a GET on a path beginning
    `/POST` — so the registry gained an endpoint that does not exist."""
    found = routes(GO, "go")
    assert ("POST", "/api/v1/transfer") in found
    assert not any(p.startswith("/post") or p.startswith("/POST") for _, p in found)


def test_an_unresolvable_path_is_not_invented():
    """`r.Post(dynamicPath, h)` names a value this file does not define. Emitting
    a route for it would put a path in the registry that no line declares."""
    assert not any("dynamic" in p.lower() for _, p in routes(GO, "go"))


def test_javascript_concatenation_and_wrapping():
    found = routes(JS, "javascript")
    assert ("GET", "/api/v1/cards/{id}") in found
    assert ("POST", "/api/v1/pay") in found


def test_an_interpolated_template_is_not_a_literal():
    assert not any("interpolated" in p for _, p in routes(JS, "javascript"))


def test_java_annotation_wrapped_and_with_value_kwarg():
    found = routes(JAVA, "java")
    assert ("GET", "/api/v1/accounts/{id}") in found
    assert ("POST", "/api/v1/transfer") in found


def test_routes_record_the_parser_that_found_them():
    """An exact parse and a line-wise guess are different evidence and are
    labelled differently."""
    for r in code.routes_from_source(GO, "main.go", "go"):
        assert r.framework == "go-treesitter"


def test_the_pattern_matcher_misses_what_the_parser_catches():
    """The regression this replaces, stated as a comparison rather than a claim."""
    parsed = routes(GO, "go")
    patterned = {(r.method, r.path)
                 for r in code.routes_from_patterns(GO, "f", "go")}

    assert ("GET", "/api/v1/accounts/{id}") in parsed
    assert ("GET", "/api/v1/accounts/{id}") not in patterned, (
        "the pattern matcher now finds the wrapped route; this test is comparing "
        "against something that no longer differs")


def test_a_missing_grammar_falls_back_rather_than_reporting_an_empty_file(monkeypatch):
    """A host without the grammars must not report a repository with routes as a
    repository with none — that is the input SHADOW is computed from."""
    from sentry_worker.collectors import treesitter

    def unavailable(*_a, **_k):
        raise treesitter.GrammarUnavailable("grammar missing")

    monkeypatch.setattr(treesitter, "routes", unavailable)
    found = code.routes_from_source(GO, "main.go", "go")

    assert found, "fell back to nothing instead of to the pattern matcher"
    assert all(r.framework == "go-pattern" for r in found)
