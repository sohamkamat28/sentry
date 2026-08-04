"""Route-declaration patterns, per framework.

Kept apart from the walker so that adding a framework is one entry here rather
than a change to the traversal, and so the CI gate at stage 14 can extract routes
from a diff with exactly the same rules the collector uses on a repository. Two
extractors that disagree would let the gate pass a route the collector then
reports as shadow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Decorator attributes that declare a route and carry the method in the name.
#:
#: Flask, FastAPI, Starlette and every ``APIRouter`` in between. The object the
#: decorator hangs off is irrelevant — ``app``, ``router``, ``bp``, ``api`` — so
#: only the attribute is matched.
METHOD_DECORATORS = {
    "get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH",
    "delete": "DELETE", "head": "HEAD", "options": "OPTIONS",
}

#: Decorators that take the method as a keyword instead of in the name:
#: ``@app.route("/x", methods=["POST"])``. Absent a methods list, Flask defaults
#: to GET, and so does this.
ROUTE_DECORATORS = {"route", "add_url_rule", "api_route"}

#: Java / Spring annotations.
SPRING_ANNOTATIONS = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "PatchMapping": "PATCH", "DeleteMapping": "DELETE",
}

#: Middleware whose presence in a handler's chain satisfies the CI gate's
#: auth-middleware check. Names, not semantics: this recognises that a service
#: declared authentication, not that the authentication is correct — stage 13
#: assesses that from what the gateway actually enforces.
AUTH_MARKERS = (
    "requires_auth", "login_required", "authenticated", "require_token",
    "Depends(", "Security(", "oauth2_scheme", "verify_token", "jwt_required",
    "PreAuthorize", "Secured", "RolesAllowed",
)


@dataclass
class FoundRoute:
    """One route declaration, as it appears in source."""

    method: str
    path: str
    file: str
    line: int
    handler: str | None = None
    has_auth_middleware: bool = False
    #: Populated by the collector from git blame, not by the parser.
    last_author: str | None = None
    last_author_email: str | None = None
    last_commit_iso: str | None = None
    framework: str = "unknown"
    extra: dict = field(default_factory=dict)


#: Path placeholders, by framework, normalised to SENTRY's ``{id}``.
#:
#: The registry's identity function keys on the normalised template, so a route
#: written ``/accounts/<id>`` in Flask and ``/accounts/{id}`` in FastAPI has to
#: reach it as one string. Left alone they would be two endpoints, and the same
#: endpoint would look like two.
_PLACEHOLDER_FORMS = [
    re.compile(r"<[^>:]*:?[^>]*>"),      # Flask   /a/<int:id>
    re.compile(r"\{[^}]*\}"),            # FastAPI /a/{id}
    re.compile(r":[A-Za-z_]\w*"),        # Express /a/:id
    re.compile(r"\*\*?"),                # wildcards
]


def normalise_declared_path(path: str) -> str:
    """Collapse a framework's placeholder syntax to ``{id}``.

    Only placeholders are touched. A literal segment stays literal, because a
    declared path is the institution's own statement of its API surface and
    guessing at it here would put a route in the registry that no repository
    contains.
    """
    out = path.strip()
    if not out.startswith("/"):
        out = "/" + out
    for form in _PLACEHOLDER_FORMS:
        out = form.sub("{id}", out)
    out = re.sub(r"/{2,}", "/", out)
    if len(out) > 1:
        out = out.rstrip("/")
    return out or "/"


def join_prefix(prefix: str, path: str) -> str:
    """Combine a router prefix with a route path.

    A FastAPI ``APIRouter(prefix="/api/v1")`` means every path under it is
    declared relative. Ignoring the prefix would record ``/accounts`` where the
    service serves ``/api/v1/accounts``, and the two would never correlate.
    """
    if not prefix:
        return path
    return normalise_declared_path(prefix.rstrip("/") + "/" + path.lstrip("/"))
