"""OpenAPI collector — the request schema a service publishes for itself.

This is not a discovery source and deliberately does not behave like one. The
four sources — kernel, gateway, repository, legacy contract — answer *does this
endpoint exist*, and SHADOW is a query over their disagreement. A published
OpenAPI document answers a different question: *what does a caller have to send*.
Adding it as a fifth source would put a new term into the shadow definition for
a document that says nothing about whether traffic exists.

It exists because the API Judge could not replay a REST write. Stage 01 discards
payloads in kernel, so a captured `POST` yields a method and a path and no body.
The Judge replayed that — an empty POST — and a service that answers a body-less
write with a 400 makes every control under test look like it broke the endpoint.
SOAP never had this problem: a WSDL declares its operations and the Judge builds
an envelope from one. This is the same contract for REST.

An unreachable document is not an empty one. A service that cannot be polled
leaves the endpoint's schema `None`, and the Judge then replays bodyless and
counts it — which is what it did for every REST endpoint before this collector
existed, and is still the honest answer when no contract is published.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

import httpx

#: A brace-templated OpenAPI parameter. SENTRY normalises every parameter to
#: `{id}` regardless of the name the contract gave it, so `{card_id}` and
#: `{cardId}` and `{id}` all collapse to one template and meet the identity the
#: kernel built from a live path.
_PARAM = re.compile(r"\{[^}]+\}")


class OpenAPIUnavailable(RuntimeError):
    pass


@dataclass
class Operation:
    method: str
    #: Normalised the same way stage 03 normalises a captured path.
    path_template: str
    host: str
    request_schema: dict | None = None


@dataclass
class OpenAPIScan:
    operations: list[Operation] = field(default_factory=list)
    healthy: bool = True
    unreadable: list[str] = field(default_factory=list)

    @property
    def with_schema(self) -> int:
        return sum(1 for o in self.operations if o.request_schema)


def document_urls() -> list[str]:
    """Where to look, from configuration rather than from a scan.

    Probing every discovered host for `/openapi.json` would have SENTRY issuing
    unsolicited requests across the estate it is measuring, and those requests
    are themselves traffic the sensor would capture.
    """
    raw = os.getenv("OPENAPI_DOCUMENT_URLS", "")
    return [u.strip() for u in raw.split(",") if u.strip()]


def normalise_path(path: str) -> str:
    """`/api/v1/cards/{card_id}/limits` -> `/api/v1/cards/{id}/limits`."""
    p = _PARAM.sub("{id}", path.strip())
    segs = [s for s in p.split("/") if s]
    return "/" + "/".join(s if s == "{id}" else s.lower() for s in segs) if segs else "/"


def _host_of(url: str) -> str:
    return httpx.URL(url).host


def parse(doc: dict, host: str) -> list[Operation]:
    out: list[Operation] = []
    for raw_path, methods in (doc.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        tmpl = normalise_path(raw_path)
        for method, op in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            schema = None
            body = (op or {}).get("requestBody") or {}
            content = (body.get("content") or {}).get("application/json") or {}
            if isinstance(content.get("schema"), dict):
                schema = content["schema"]
            out.append(Operation(method=method.upper(), path_template=tmpl,
                                 host=host, request_schema=schema))
    return out


def fetch(url: str, *, timeout: float = 10.0) -> list[Operation]:
    with httpx.Client(timeout=timeout, verify=False) as c:  # noqa: S501
        # verify=False: the estate speaks TLS with self-signed certificates,
        # which is one of the postures SENTRY exists to report. Refusing to read
        # a contract because of it would make the finding hide the evidence.
        r = c.get(url)
        if r.status_code >= 400:
            raise OpenAPIUnavailable(f"{url} returned {r.status_code}")
        doc = r.json()
    if not isinstance(doc, dict) or "paths" not in doc:
        raise OpenAPIUnavailable(f"{url} is not an OpenAPI document")
    return parse(doc, _host_of(url))


def collect(urls: list[str] | None = None) -> OpenAPIScan:
    """Read every configured contract. Never raises on one that cannot be read."""
    urls = document_urls() if urls is None else urls
    scan = OpenAPIScan()
    if not urls:
        scan.healthy = False
        return scan

    for url in urls:
        try:
            scan.operations.extend(fetch(url))
        except (OpenAPIUnavailable, httpx.HTTPError, ValueError) as exc:
            scan.unreadable.append(f"{url}: {exc}")

    # Healthy means at least one document was read. All of them failing is a
    # collector outage, and the Judge must not read that as "no service in this
    # estate publishes a contract".
    scan.healthy = bool(scan.operations)
    return scan
