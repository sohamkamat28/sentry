"""Request bodies for the Judge, synthesised from declared contracts.

Stage 01 discards payloads in kernel — the classifier reads them, records the
data classes it found, and never stores a byte. So a replayed POST has nothing
to send, and until now every one of them went out bodyless and the run reported
``coverage: partial``.

That is not a small gap. A patch measured only against requests the upstream
rejects for having no body is a patch measured against 400s: the control half
and the variant half both fail, they agree perfectly, and the Judge passes a
control it never exercised. It is the same defect as the router-not-ready case,
reached from a different direction.

Bodies here come from a **declared contract**, never from a captured payload:

* SOAP, from the WSDL the legacy collector already fetches. The operation name
  is in the endpoint's own identity — ``<path>#<Operation>`` — so the envelope
  and the SOAPAction header are both recoverable from the endpoint id alone.
* JSON, from an OpenAPI request schema where one is declared.

Every value is synthetic and drawn from the same reserved ranges the honeypot
uses. Nothing in this module can emit a real customer value, because nothing in
it can read one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

#: Reserved, non-resolvable. The same prefix the honeypot's generator uses, for
#: the same reason: a value that escapes into a log or a leak must be traceable
#: to this system rather than to a customer.
SYNTHETIC_ACCOUNT_PREFIX = "9999"

SOAP_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    "<soap:Body>{body}</soap:Body>"
    "</soap:Envelope>"
)


@dataclass
class Body:
    content: str
    content_type: str
    headers: dict[str, str]
    #: Which contract this came from, recorded on the judge run so a reviewer
    #: can tell a synthesised body from an observed one.
    source: str


def soap_operation(path_template: str) -> str | None:
    """The operation name out of a SOAP endpoint identity.

    ``/finacle/CustomerService#GetCustomerKyc`` -> ``GetCustomerKyc``. The
    identity is built this way by both the kernel probe and the legacy
    collector, so it is the one place the operation is reliably recoverable.
    """
    if "#" not in path_template:
        return None
    operation = path_template.rsplit("#", 1)[1].strip()
    return operation or None


def soap_body(path_template: str, namespace: str = "") -> Body | None:
    """A well-formed SOAP request for an operation.

    The element is the operation name, which is the convention every WSDL in
    this estate follows. Parameters are omitted: a service that requires one
    answers with a SOAP fault, and a fault is a *real* response that both halves
    of the shadow pair receive identically — which is a valid measurement of the
    control, unlike a 400 for a malformed request.
    """
    operation = soap_operation(path_template)
    if operation is None:
        return None

    ns = f' xmlns="{namespace}"' if namespace else ""
    inner = f"<{operation}{ns}/>"
    return Body(
        content=SOAP_ENVELOPE.format(body=inner),
        content_type="text/xml; charset=utf-8",
        # Quoted, as the SOAP 1.1 binding requires. An unquoted SOAPAction is
        # rejected by some stacks and silently ignored by others, which would
        # route every replayed operation to the service's default.
        headers={"SOAPAction": f'"{operation}"'},
        source="wsdl",
    )


#: Example values by declared type. Deliberately dull and obviously synthetic.
_EXAMPLES: dict[str, object] = {
    "string": "SENTRY-SYNTHETIC",
    "integer": 0,
    "number": 0,
    "boolean": False,
}


def _example(schema: dict, depth: int = 0) -> object:
    """One value satisfying a JSON schema, shallowly.

    Bounded on depth: a self-referential schema is legal and would otherwise
    recurse until the stack gives out.
    """
    if depth > 6 or not isinstance(schema, dict):
        return None

    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if enum := schema.get("enum"):
        return enum[0]

    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        required = set(schema.get("required") or [])
        props = schema.get("properties") or {}
        # Required fields only. Sending every optional field exercises paths the
        # observed traffic never used, and the Judge is measuring a control
        # against real usage.
        return {
            name: _example(sub, depth + 1)
            for name, sub in props.items()
            if not required or name in required
        }
    if kind == "array":
        return [_example(schema.get("items") or {}, depth + 1)]

    fmt = str(schema.get("format") or "")
    name_hint = str(schema.get("title") or "").lower()
    if "account" in name_hint:
        return SYNTHETIC_ACCOUNT_PREFIX + "00000000"
    if fmt == "date":
        return "2026-01-01"
    if fmt == "date-time":
        return "2026-01-01T00:00:00Z"

    return _EXAMPLES.get(str(kind), "SENTRY-SYNTHETIC")


def json_body(schema: dict | None) -> Body | None:
    """A JSON request body satisfying a declared schema."""
    if not schema:
        return None
    value = _example(schema)
    if value is None:
        return None
    return Body(
        content=json.dumps(value),
        content_type="application/json",
        headers={},
        source="openapi",
    )


def for_endpoint(method: str, path_template: str,
                 schema: dict | None = None,
                 namespace: str = "") -> Body | None:
    """The body to replay for one endpoint, or None when none is needed.

    GET and DELETE carry no body and are not counted as missing one — the
    ``bodyless`` flag exists to mark a request that *should* have had a body and
    did not, and applying it to a GET would make every run look incomplete.
    """
    if method.upper() not in ("POST", "PUT", "PATCH"):
        return None
    if "#" in path_template:
        return soap_body(path_template, namespace)
    return json_body(schema)
