"""The declared response contract, and the property that makes it safe.

`api/app/contracts.py` exists so the console's types can be generated rather
than asserted. It is attached with `responses={200: {"model": ...}}` and never
with `response_model=`, and that distinction is the whole safety argument:
`response_model` filters a response down to its declared fields, so a model
missing one key silently deletes that key from a live payload and the first sign
of it is a console surface going blank.
"""

from __future__ import annotations

import os  # noqa: F401  — DATABASE_URL is set by the root conftest

os.environ.setdefault("AUTH_DISABLED", "true")
os.environ.setdefault("REDIS_URL", "")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from sentry_core.db import create_all  # noqa: E402

ADMIN = {"Authorization": "Bearer dev-admin"}


def test_every_operation_declares_a_response_schema():
    """47 of 53 operations declared `{"type": "object"}` with no properties,
    because every handler returns a bare dict. A generator over that emits
    `Record<string, unknown>` for everything — strictly worse than the
    hand-written types it was meant to replace."""
    spec = app.openapi()

    untyped = []
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            schema = (((op.get("responses") or {}).get("200") or {})
                      .get("content", {}).get("application/json", {}).get("schema")) or {}
            named = schema.get("$ref") or schema.get("allOf") or schema.get("properties")
            if not named:
                untyped.append(f"{method.upper()} {path}")

    assert not untyped, (
        f"{len(untyped)} operations declare no response shape, so the generated "
        f"console types for them are `unknown`: {untyped[:5]}")


def test_no_route_uses_response_model():
    """`response_model` filters. Every route must use the documenting form.

    This is not style. A model that omits a field the handler returns makes that
    field vanish from the response, and nothing raises — the console just stops
    showing it.
    """
    offenders = [
        f"{m} {r.path}"
        for r in app.routes
        for m in getattr(r, "methods", [])
        if getattr(r, "response_model", None) is not None
        and str(r.path).startswith("/api/")
    ]
    assert not offenders, (
        f"these routes filter their response through a model: {offenders}")


def test_an_undeclared_field_still_reaches_the_client():
    """The property the whole approach rests on, asserted against the real app.

    `/api/v1/system` declares a model; its handler returns keys the model may not
    list. Every one of them must survive.
    """
    create_all()
    with TestClient(app) as client:
        body = client.get("/api/v1/system", headers=ADMIN).json()

    spec = app.openapi()
    ref = (spec["paths"]["/api/v1/system"]["get"]["responses"]["200"]
           ["content"]["application/json"]["schema"])
    name = (ref.get("$ref") or "").rsplit("/", 1)[-1]
    declared = set(spec["components"]["schemas"][name].get("properties") or {})

    assert declared, "the system route declares no properties"
    assert set(body) >= declared, (
        f"the response is missing declared keys {declared - set(body)} — the "
        f"contract is describing something the handler does not return")
