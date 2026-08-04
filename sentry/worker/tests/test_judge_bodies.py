"""Request bodies for the Judge.

The gap these close is not cosmetic. A patch measured only against requests the
upstream rejects for having no body is measured against 400s: the control half
and the variant half both fail, they agree perfectly, and the Judge passes a
control it never exercised — the same defect as the router-not-ready case,
reached from a different direction.
"""

from __future__ import annotations

from sentry_worker.judge import bodies, replay


# ─────────────────────────────────────────────────────────────────────────────
# SOAP
# ─────────────────────────────────────────────────────────────────────────────
def test_the_operation_comes_out_of_the_endpoint_identity():
    """`<path>#<Operation>` is built the same way by the kernel probe and the
    legacy collector, so it is the one place the operation is recoverable."""
    assert bodies.soap_operation("/finacle/CustomerService#GetCustomerKyc") == \
        "GetCustomerKyc"


def test_a_rest_path_carries_no_operation():
    assert bodies.soap_operation("/api/v1/accounts/{id}") is None


def test_a_soap_body_is_well_formed_and_names_the_operation():
    body = bodies.soap_body("/finacle/CustomerService#GetNostroPosition")

    assert body is not None
    assert body.content.startswith('<?xml version="1.0"')
    assert "<soap:Envelope" in body.content
    assert "<GetNostroPosition/>" in body.content
    assert body.source == "wsdl"


def test_the_soapaction_header_is_quoted():
    """SOAP 1.1 requires it. Unquoted, some stacks reject the request and others
    ignore the header — which routes every replayed operation to the service's
    default and measures the wrong thing."""
    body = bodies.soap_body("/finacle/CustomerService#PostLedgerEntry")
    assert body.headers["SOAPAction"] == '"PostLedgerEntry"'


def test_the_content_type_is_xml():
    body = bodies.soap_body("/x#Op")
    assert body.content_type.startswith("text/xml")


# ─────────────────────────────────────────────────────────────────────────────
# JSON from a declared schema
# ─────────────────────────────────────────────────────────────────────────────
def test_a_json_body_satisfies_a_declared_schema():
    schema = {
        "type": "object",
        "required": ["reference", "amount"],
        "properties": {
            "reference": {"type": "string"},
            "amount": {"type": "number"},
            "memo": {"type": "string"},
        },
    }
    body = bodies.json_body(schema)

    assert body is not None
    import json
    payload = json.loads(body.content)
    # Required only. Sending every optional field exercises paths the observed
    # traffic never used.
    assert set(payload) == {"reference", "amount"}
    assert body.source == "openapi"


def test_a_declared_example_wins_over_a_generated_value():
    body = bodies.json_body({"type": "string", "example": "RTGS-0001"})
    assert body.content == '"RTGS-0001"'


def test_a_self_referential_schema_terminates():
    """Legal, and it would otherwise recurse until the stack gives out."""
    schema: dict = {"type": "object", "required": ["next"], "properties": {}}
    schema["properties"]["next"] = schema
    assert bodies.json_body(schema) is not None


def test_no_schema_yields_no_body():
    assert bodies.json_body(None) is None
    assert bodies.json_body({}) is None


# ─────────────────────────────────────────────────────────────────────────────
# Which requests need one
# ─────────────────────────────────────────────────────────────────────────────
def test_a_get_needs_no_body():
    """The bodyless flag marks a request that *should* have carried one. Applying
    it to a GET would make every run report incomplete coverage forever."""
    assert bodies.for_endpoint("GET", "/api/v1/accounts/{id}") is None


def test_a_post_to_a_soap_operation_gets_an_envelope():
    body = bodies.for_endpoint("POST", "/finacle/CustomerService#GetCustomerKyc")
    assert body is not None and body.source == "wsdl"


def test_a_post_with_no_contract_gets_nothing_and_is_counted():
    """Not concealed. A run that quietly dropped these would report coverage it
    does not have."""
    assert bodies.for_endpoint("POST", "/api/v1/transfers") is None


# ─────────────────────────────────────────────────────────────────────────────
# Through the replay builder
# ─────────────────────────────────────────────────────────────────────────────
def _rows(method: str, path: str, n: int = 3) -> list[dict]:
    return [{"method": method, "path_raw": f"{path}/{i}", "auth_scheme": None}
            for i in range(n)]


def test_soap_shapes_are_replayed_with_a_body():
    reqs = replay.requests_from_observations(
        _rows("POST", "/finacle/CustomerService"), limit=10,
        path_template="/finacle/CustomerService#GetCustomerKyc")

    assert reqs
    for r in reqs:
        assert r.body is not None
        assert r.synthesised is True
        assert r.bodyless is False
        assert r.body_headers["SOAPAction"] == '"GetCustomerKyc"'
        assert r.body_source == "wsdl"


def test_a_get_is_neither_bodyless_nor_synthesised():
    reqs = replay.requests_from_observations(
        _rows("GET", "/api/v1/accounts"), limit=10,
        path_template="/api/v1/accounts/{id}")

    assert all(not r.bodyless and not r.synthesised for r in reqs)


def test_a_post_with_no_contract_is_still_replayed_and_marked():
    reqs = replay.requests_from_observations(
        _rows("POST", "/api/v1/transfers"), limit=10,
        path_template="/api/v1/transfers")

    assert reqs
    assert all(r.bodyless and not r.synthesised for r in reqs)


def test_shapes_are_still_deduplicated():
    rows = [{"method": "POST", "path_raw": "/finacle/CustomerService",
             "auth_scheme": None}] * 8
    reqs = replay.requests_from_observations(
        rows, limit=10, path_template="/finacle/CustomerService#GetCustomerKyc")

    assert len(reqs) == 1


# ── OpenAPI-driven REST bodies ──────────────────────────────────────────────
def test_a_rest_post_with_a_published_schema_replays_with_a_body():
    """The gap that made every REST control look like it broke its endpoint.

    Stage 01 discards payloads in kernel, so a captured POST yields a method and
    a path and nothing else. Replayed as an empty POST against a service that
    validates its input, the baseline call fails — and the Judge then attributes
    that failure to the control under test. SOAP never had the problem because a
    WSDL declares its operations; this is the same contract for REST.
    """
    from sentry_worker.judge.replay import requests_from_observations

    schema = {
        "type": "object",
        "required": ["cardId", "amount", "merchantId"],
        "properties": {
            "cardId": {"type": "string"},
            "amount": {"type": "string"},
            "merchantId": {"type": "string"},
        },
    }
    rows = [{"method": "POST", "path_raw": "/api/v1/cards/authorise",
             "auth_scheme": None}]

    reqs = requests_from_observations(rows, 5,
                                      path_template="/api/v1/cards/authorise",
                                      schema=schema)

    assert reqs, "no replay shape was built"
    r = reqs[0]
    assert r.body, "a POST with a published schema still replayed bodyless"
    assert "cardId" in r.body
    assert r.body_headers.get("Content-Type", "").startswith("application/json")


def test_a_rest_post_without_a_schema_still_replays_bodyless():
    """No contract is not an empty contract.

    A service that publishes nothing leaves `request_schema` NULL, and the
    honest answer is a bodyless replay that is counted as one — not a body
    invented from the field names of some other endpoint.
    """
    from sentry_worker.judge.replay import requests_from_observations

    rows = [{"method": "POST", "path_raw": "/api/v1/unknown", "auth_scheme": None}]
    reqs = requests_from_observations(rows, 5, path_template="/api/v1/unknown",
                                      schema=None)

    assert reqs
    assert not reqs[0].body
