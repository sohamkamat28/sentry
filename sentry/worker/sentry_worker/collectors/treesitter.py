"""Route declarations parsed from a syntax tree, for Go, JavaScript and Java.

Python has always been exact here — the standard library's `ast` gives a real
parse and costs nothing. The other three languages were matched line by line
with regular expressions, and the design specifies tree-sitter for all four.

What the patterns actually miss is not exotic. A regex reads one line, so a
declaration wrapped across two is invisible:

    router.HandleFunc(
        "/api/v1/accounts/{id}", handler)

and a path assembled from a constant is invisible whether or not it is wrapped:

    const base = "/api/v1"
    r.Get(base+"/accounts/{id}", handler)

Both are ordinary code, and both make an endpoint absent from the `code` source.
That absence is not inert: SHADOW is defined as traffic present, gateway absent
and code absent, so a route this collector fails to see is a route the estate
can be told it is hiding. A false shadow generates work, which is the failure
mode with the worst consequences.

Concatenation is resolved where its parts are literals in the same file, and
left alone where they are not — an unresolvable path is reported as unparsed
rather than guessed at. Every route still records which parser found it, so a
reader can tell an exact parse from a pattern match.
"""

from __future__ import annotations

import functools
import re

#: Go's chi/gorilla/echo verb methods, and Java's Spring annotations.
_GO_VERBS = {"Get", "Post", "Put", "Patch", "Delete", "Head", "Options"}
_JS_VERBS = {"get", "post", "put", "patch", "delete", "all"}
_SPRING = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "PatchMapping": "PATCH", "DeleteMapping": "DELETE", "RequestMapping": "GET",
}

#: `"GET /api/v1/thing"` — Go 1.22's net/http pattern syntax.
_METHOD_IN_PATTERN = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/.*)$")


class GrammarUnavailable(RuntimeError):
    """tree-sitter or a grammar is not installed. The caller falls back and says
    so, rather than reporting an empty repository."""


@functools.lru_cache(maxsize=8)
def _parser(language: str):
    try:
        from tree_sitter import Language, Parser
    except ImportError as exc:  # pragma: no cover - dependency is pinned
        raise GrammarUnavailable(f"tree_sitter is not installed: {exc}") from exc

    try:
        if language == "go":
            import tree_sitter_go as mod
        elif language == "javascript":
            import tree_sitter_javascript as mod
        elif language == "java":
            import tree_sitter_java as mod
        else:
            raise GrammarUnavailable(f"no grammar bundled for {language}")
    except ImportError as exc:
        raise GrammarUnavailable(f"grammar for {language} is not installed: {exc}") from exc

    return Parser(Language(mod.language()))


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf8", "replace")


def _unquote(raw: str) -> str:
    if len(raw) >= 2 and raw[0] in "\"'`" and raw[-1] == raw[0]:
        return raw[1:-1]
    return raw


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _constants(root, src: bytes, language: str) -> dict[str, str]:
    """Literal string constants in this file, for resolving a concatenated path.

    Only same-file literals. A constant imported from elsewhere is not resolved
    and the route is reported unparsed — inventing a value for it would put a
    path into the registry that no line of this repository actually declares.
    """
    out: dict[str, str] = {}
    for n in _walk(root):
        if language == "go" and n.type in ("const_spec", "var_spec"):
            # `const base = "/api/v1"` parses as
            # const_spec[identifier, '=', expression_list[literal]] — the value
            # is one level down, not a sibling of the name.
            names = [c for c in n.children if c.type == "identifier"]
            values = n.child_by_field_name("value")
            lits = []
            if values is not None:
                lits = [c for c in values.children
                        if c.type in ("interpreted_string_literal", "raw_string_literal")]
            if not lits:
                lits = [c for c in n.children
                        if c.type in ("interpreted_string_literal", "raw_string_literal")]
            for name, lit in zip(names, lits):
                out[_text(name, src)] = _unquote(_text(lit, src))
        elif language == "javascript" and n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            value = n.child_by_field_name("value")
            if name is not None and value is not None and value.type == "string":
                out[_text(name, src)] = _unquote(_text(value, src))
    return out


def _literal_of(node, src: bytes, consts: dict[str, str]) -> str | None:
    """A node's string value, following one level of `+` concatenation."""
    if node is None:
        return None
    t = node.type

    if t in ("interpreted_string_literal", "raw_string_literal", "string",
             "string_literal", "template_string"):
        inner = _text(node, src)
        # A template string carrying an interpolation is not a literal.
        if "${" in inner:
            return None
        return _unquote(inner)

    if t == "identifier":
        return consts.get(_text(node, src))

    if t in ("binary_expression", "additive_expression"):
        left = _literal_of(node.child_by_field_name("left"), src, consts)
        right = _literal_of(node.child_by_field_name("right"), src, consts)
        if left is None or right is None:
            return None
        return left + right

    return None


def _call_parts(node, src: bytes):
    """(receiver-method-name, argument list) for a call node, or (None, None)."""
    fn = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments")
    if fn is None or args is None:
        return None, None
    if fn.type in ("selector_expression", "member_expression", "field_expression"):
        field = fn.child_by_field_name("field") or fn.child_by_field_name("property")
        if field is None:
            return None, None
        return _text(field, src), args
    return None, None


def _arg_nodes(args):
    return [c for c in args.children if c.type not in (",", "(", ")")]


def routes(source: str, language: str) -> tuple[list[tuple[str, str, int]], int]:
    """Every route declaration in one file.

    Returns `([(method, path, line)], unparsed)`. `unparsed` counts calls that
    are recognisably route registrations whose path could not be resolved to a
    literal — reported rather than dropped, because a route this cannot read is
    exactly the case that would otherwise be indistinguishable from a file with
    no routes in it.
    """
    parser = _parser(language)
    src = source.encode("utf8")
    root = parser.parse(src).root_node
    consts = _constants(root, src, language)

    found: list[tuple[str, str, int]] = []
    unparsed = 0

    for node in _walk(root):
        if language == "java":
            if node.type not in ("annotation", "marker_annotation"):
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            name = _text(name_node, src)
            if name not in _SPRING:
                continue
            args = node.child_by_field_name("arguments")
            path = None
            if args is not None:
                for a in _walk(args):
                    if a.type == "string_literal":
                        path = _unquote(_text(a, src))
                        break
            if path is None:
                unparsed += 1
                continue
            found.append((_SPRING[name], path, node.start_point[0] + 1))
            continue

        if node.type != "call_expression":
            continue
        method_name, args = _call_parts(node, src)
        if method_name is None:
            continue

        argv = _arg_nodes(args)
        if not argv:
            continue

        if language == "go":
            if method_name == "HandleFunc":
                lit = _literal_of(argv[0], src, consts)
                if lit is None:
                    unparsed += 1
                    continue
                # Go 1.22 puts the method inside the pattern; earlier
                # net/http has none, and GET is what the majority are.
                m = _METHOD_IN_PATTERN.match(lit)
                if m:
                    found.append((m.group(1), m.group(2), node.start_point[0] + 1))
                else:
                    found.append(("GET", lit, node.start_point[0] + 1))
            elif method_name in _GO_VERBS:
                lit = _literal_of(argv[0], src, consts)
                if lit is None:
                    unparsed += 1
                    continue
                found.append((method_name.upper(), lit, node.start_point[0] + 1))

        elif language == "javascript":
            if method_name not in _JS_VERBS:
                continue
            lit = _literal_of(argv[0], src, consts)
            if lit is None:
                unparsed += 1
                continue
            verb = "GET" if method_name == "all" else method_name.upper()
            found.append((verb, lit, node.start_point[0] + 1))

    return found, unparsed
