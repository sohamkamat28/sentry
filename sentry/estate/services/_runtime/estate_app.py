"""The estate's minimal web framework.

Decorator-declared routes over Python's ssl module, which is OpenSSL — so the
agent's uprobes on SSL_write_ex/SSL_read_ex attach to these services exactly as
they would to any production workload linked against libssl.

Routes are declared with decorators rather than a lookup table because that is
what the repository collector parses. A dict of paths would be readable by a
grep and by nothing that understands code; ``@app.get("/api/v1/accounts/<id>")``
is a decorator call with a string literal argument, which is the shape the
collector's Python AST pass actually looks for and the shape Flask, FastAPI and
every framework an institution really runs produce.
"""

from __future__ import annotations

import http.client
import json
import os
import random
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

SERVICE = os.getenv("SERVICE_NAME", "unnamed")
PORT = int(os.getenv("PORT", "8443"))

rng = random.Random(20260726)

# Self-signed certs across the estate, and verification off between services on
# purpose: this is the workload under analysis, and one of the postures SENTRY is
# meant to find is exactly this one.
_client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_client_ctx.check_hostname = False
_client_ctx.verify_mode = ssl.CERT_NONE


class Router:
    """Decorator-declared routes.

    ``<param>`` in a path is a single-segment placeholder, the same convention
    Flask uses. A request matches on the literal segments and passes the
    placeholder values positionally.
    """

    def __init__(self) -> None:
        self.routes: list[tuple[str, list[str], object]] = []
        #: (method, path) -> JSON Schema of the request body, for the routes that
        #: take one. Published at /openapi.json.
        self.schemas: dict[tuple[str, str], dict] = {}
        self.paths: dict[tuple[str, str], str] = {}

    def _register(self, method: str, path: str, body_schema: dict | None = None):
        def decorate(fn):
            segs = [s for s in path.split("/") if s]
            self.routes.append((method, segs, fn))
            self.paths[(method, path)] = path
            if body_schema is not None:
                self.schemas[(method, path)] = body_schema
            return fn
        return decorate

    def get(self, path: str):
        return self._register("GET", path)

    def post(self, path: str, body_schema: dict | None = None):
        """A route that accepts a request body, and the schema of that body.

        The schema is declared here because it has to come from somewhere real.
        The Judge replays captured request shapes to measure whether a control
        breaks a caller, and stage 01 discards payloads in kernel — so for a
        `POST` it had a method and a path and no body, replayed nothing, and
        counted the result as `replay_bodyless`. A service that answers a
        body-less POST with a 400 makes every control look like it broke the
        endpoint.

        SOAP already worked, because a WSDL declares its operations and the
        Judge builds an envelope from it. This is the same contract for REST,
        published the same way a real service publishes one.
        """
        return self._register("POST", path, body_schema)

    def soap(self, path: str):
        """A SOAP endpoint: one path, many operations.

        The operation is in the SOAPAction header, not the URL, so the handler
        receives it. That is why the kernel probe appends it to the path as
        ``<path>#<Operation>`` — a SOAP service with forty operations behind one
        URL is forty endpoints, and a registry that recorded one would be
        describing the transport rather than the surface.
        """
        return self._register("SOAP", path)

    def match(self, method: str, path: str):
        want = [s for s in path.split("/") if s]
        for route_method, pattern, fn in self.routes:
            if route_method != method or len(pattern) != len(want):
                continue
            params, ok = [], True
            for expected, actual in zip(pattern, want):
                if expected.startswith("<") and expected.endswith(">"):
                    params.append(actual)
                elif expected != actual:
                    ok = False
                    break
            if ok:
                return fn, params
        return None, []

    def openapi(self) -> dict:
        """The service's own contract, in the shape a collector expects.

        `<param>` becomes `{param}`: OpenAPI templates its path parameters in
        braces, and so does SENTRY's own normalised form, so the document and
        the sensor's endpoint identity meet on the same string — the same
        property that makes the WSDL correlate.
        """
        paths: dict[str, dict] = {}
        for (method, raw) in sorted(self.paths):
            segs = []
            for s in raw.split("/"):
                if s.startswith("<") and s.endswith(">"):
                    segs.append("{" + s[1:-1] + "}")
                elif s:
                    segs.append(s)
            tmpl = "/" + "/".join(segs) if segs else "/"

            op: dict = {"operationId": f"{method.lower()}_{tmpl}",
                        "responses": {"200": {"description": "ok"}}}
            schema = self.schemas.get((method, raw))
            if schema is not None:
                op["requestBody"] = {
                    "required": True,
                    "content": {"application/json": {"schema": schema}},
                }
            paths.setdefault(tmpl, {})[method.lower()] = op

        return {
            "openapi": "3.0.3",
            "info": {"title": SERVICE, "version": "1.0.0"},
            "paths": paths,
        }

    def serve(self) -> None:
        router = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _dispatch(self) -> None:
                path = self.path.split("?", 1)[0]

                # Served by the router itself rather than declared as a route:
                # it describes the routes, and describing itself would put the
                # contract endpoint into the estate's own surface.
                if path == "/openapi.json" and self.command == "GET":
                    body = json.dumps(router.openapi()).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                # A SOAP route is matched on POST and handed its operation.
                if self.command == "POST":
                    fn, params = router.match("SOAP", path)
                    if fn is not None:
                        action = (self.headers.get("SOAPAction") or "").strip('"')
                        payload = fn(action).encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "text/xml; charset=utf-8")
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)
                        return

                fn, params = router.match(self.command, path)
                if fn is None:
                    self.send_error(404)
                    return
                out = fn(*params)
                if isinstance(out, str):
                    body, ctype = out.encode(), "text/xml; charset=utf-8"
                else:
                    body, ctype = json.dumps(out).encode(), "application/json"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                self._dispatch()

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    self.rfile.read(length)
                self._dispatch()

            def log_message(self, fmt: str, *args) -> None:
                sys.stderr.write(f"{SERVICE} {fmt % args}\n")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")

        srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        print(f"{SERVICE} listening on :{PORT} — {len(self.routes)} routes, "
              f"TLS, OpenSSL {ssl.OPENSSL_VERSION}", flush=True)
        srv.serve_forever()


app = Router()


def call_upstream(url: str) -> dict:
    """One real HTTPS request to another estate service.

    A service that fans out to others is what gives the call graph depth: both
    the caller's SSL_write and the callee's SSL_read are observed, so stage 03
    gets a real edge rather than an assumed one.
    """
    parts = urlsplit(url)
    conn = http.client.HTTPSConnection(
        parts.hostname, parts.port or 443, context=_client_ctx, timeout=5)
    try:
        conn.request("GET", parts.path or "/", headers={"Host": parts.netloc})
        resp = conn.getresponse()
        return {"url": url, "status": resp.status, "bytes": len(resp.read())}
    except OSError as exc:
        # Reported, not hidden. A composite endpoint whose dependency is down is
        # a fact the sensor should see in the response it serves.
        return {"url": url, "error": type(exc).__name__}
    finally:
        conn.close()


# ── response bodies ─────────────────────────────────────────────────────────
# Deliberately carrying Indian financial identifiers so the in-kernel data-class
# detection has something to find. The values are fabricated — this is the
# estate under analysis, not a real bank — but they are the correct *shape*,
# which is what the detector keys on.
def account_body(account_id: str = "") -> dict:
    return {
        "accountNumber": f"{rng.randint(10**11, 10**12 - 1)}",
        "accountHolder": "Test Holder",
        "balance": f"{rng.randint(1000, 900000)}.{rng.randint(0, 99):02d}",
        "currency": "INR",
        "ifsc": f"HDFC0{rng.randint(100000, 999999)}",
        "branch": "Mumbai Fort",
        "asOf": "2026-07-28T00:00:00Z",
    }


def kyc_body(customer_id: str = "") -> dict:
    # A 12-digit Aadhaar and a PAN in the canonical five-letters/four-digits/
    # letter form. The kernel tags the class and discards the value in the same
    # operation.
    return {
        "customerId": customer_id,
        "aadhaar": f"{rng.randint(10**11, 10**12 - 1)}",
        "pan": "ABCDE1234F",
        "dob": "1985-03-14",
        "status": "VERIFIED",
    }


def payment_body(reference: str = "") -> dict:
    return {
        "reference": reference or "UPI0000",
        "debitAccount": f"{rng.randint(10**11, 10**12 - 1)}",
        "ifsc": f"HDFC0{rng.randint(100000, 999999)}",
        "amount": f"{rng.randint(100, 90000)}.00",
        "status": "SETTLED",
    }


def health() -> dict:
    return {"ok": True, "service": SERVICE}
