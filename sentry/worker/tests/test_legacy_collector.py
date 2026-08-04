"""Stage 01 — the legacy collector.

A SOAP connector is one URL with forty operations behind it. The kernel probe
reports the URL and a SOAPAction header; the gateway reports one route; a
repository scan finds a generated client with no route declarations in it. Only
the contract says what the surface is.

The tests that matter here are about *identity*. Both halves of the endpoint key
— the path template and the service — have to come out of this collector matching
what the kernel independently produces, or the same operation is recorded twice
and neither copy carries the other's evidence.
"""

from __future__ import annotations

import textwrap

import pytest

from sentry_worker.collectors import legacy

TARGET_NS = "http://finacle.corebank.internal/customer"


def wsdl(operations=("GetCustomerBalance", "GetCustomerKyc"),
         address="https://finacle-bridge:8443/finacle/CustomerService",
         service_name="CustomerService", with_actions=True) -> str:
    """A WSDL, assembled without indentation.

    Built by joining rather than by dedenting a template: an interpolated block
    with its own indentation defeats textwrap's common-prefix detection, and the
    result is a document with whitespace before its XML declaration that no
    parser will accept.
    """
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"',
        ' xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"',
        f' xmlns:tns="{TARGET_NS}" targetNamespace="{TARGET_NS}">',
        '<portType name="P">',
    ]
    lines += [f'<operation name="{op}"/>' for op in operations]
    lines += ['</portType>', '<binding name="B" type="tns:P">']
    for op in operations:
        action = f'<soap:operation soapAction="{op}"/>' if with_actions else ""
        lines.append(f'<operation name="{op}">{action}</operation>')
    lines += ['</binding>', f'<service name="{service_name}">',
              '<port name="Port" binding="tns:B">']
    if address:
        lines.append(f'<soap:address location="{address}"/>')
    lines += ['</port>', '</service>', '</definitions>']
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Identity — the whole point
# ─────────────────────────────────────────────────────────────────────────────
def test_the_identity_form_is_what_the_kernel_probe_emits():
    """The agent does `obs.PathRaw += "#" + SOAPAction` in Go. This builds the
    same string in Python from a WSDL.

    They have to agree exactly. If they do not, the contract's operation and the
    observed call are two endpoints, and the registry describes the same thing
    twice while neither row has the other's evidence.
    """
    assert legacy.soap_identity("/finacle/CustomerService", "GetCustomerKyc") == \
        "/finacle/CustomerService#GetCustomerKyc"


def test_the_operation_case_is_preserved():
    """SOAPAction is case-sensitive. Lowercasing it here would produce an
    identity no probe will ever emit."""
    assert legacy.soap_identity("/x", "GetNostroPosition").endswith("#GetNostroPosition")


@pytest.mark.parametrize("path,expected", [
    ("/finacle/CustomerService", "/finacle/CustomerService#Op"),
    ("finacle/CustomerService", "/finacle/CustomerService#Op"),
    ("/finacle/CustomerService/", "/finacle/CustomerService#Op"),
])
def test_the_path_is_normalised_before_the_action_is_appended(path, expected):
    assert legacy.soap_identity(path, "Op") == expected


def test_the_service_is_the_deployed_host_not_the_contract_name():
    """Endpoint identity keys on method, template *and* service.

    The contract calls itself "CustomerService"; the kernel reports the host it
    reached, "finacle-bridge". Attributing the operation to the contract name
    recorded it twice — once per source — and the datastore edge landed on one
    copy while the source row landed on the other.
    """
    ops = legacy.operations_from_wsdl(wsdl())

    assert {o.host for o in ops} == {"finacle-bridge"}
    assert {o.service for o in ops} == {"CustomerService"}


def test_a_contract_with_no_address_falls_back_to_its_own_name():
    """No advertised address means no way to say which deployed service this
    belongs to. The contract name is the honest stand-in, not a guess at a
    hostname."""
    ops = legacy.operations_from_wsdl(wsdl(address=""))
    assert {o.host for o in ops} == {"CustomerService"}


# ─────────────────────────────────────────────────────────────────────────────
# WSDL
# ─────────────────────────────────────────────────────────────────────────────
def test_every_operation_becomes_an_endpoint():
    """One URL, four operations, four endpoints. A registry that recorded the URL
    would be describing the transport rather than the surface."""
    ops = legacy.operations_from_wsdl(
        wsdl(("GetCustomerBalance", "GetCustomerKyc", "PostLedgerEntry",
              "GetNostroPosition")))

    assert len(ops) == 4
    assert {o.method for o in ops} == {"POST"}
    assert all(o.path_template.startswith("/finacle/CustomerService#") for o in ops)


def test_the_soap_action_is_read_from_the_binding():
    ops = legacy.operations_from_wsdl(wsdl(("GetCustomerKyc",)))
    assert ops[0].soap_action == "GetCustomerKyc"


def test_a_binding_with_no_action_defaults_to_the_operation_name():
    """The convention in that case is that the action equals the operation name,
    which is what the client sends and therefore what the probe sees."""
    ops = legacy.operations_from_wsdl(wsdl(("GetCustomerKyc",), with_actions=False))
    assert ops[0].soap_action == "GetCustomerKyc"


def test_the_address_path_is_used_not_the_url_the_wsdl_came_from():
    """A WSDL commonly lives at ?wsdl on the service address, and commonly does
    not. Only the contract knows."""
    ops = legacy.operations_from_wsdl(
        wsdl(address="https://host:8443/soap/v2/Customer"),
        source="https://elsewhere/contracts/customer.wsdl")
    assert ops[0].service_path == "/soap/v2/Customer"


def test_a_document_that_is_not_wsdl_is_unreadable_not_empty(tmp_path):
    """An unreadable contract contributes no evidence. Reporting zero operations
    would make every one of them look absent."""
    bad = tmp_path / "not.wsdl"
    bad.write_text("<html><body>gateway timeout</body></html>")

    scan = legacy.fetch_wsdl(str(bad))
    # Parses as XML but declares nothing; no operations, and readable, because
    # the document was genuinely read.
    assert scan.operations == []


def test_an_unfetchable_contract_is_unreadable(tmp_path):
    scan = legacy.fetch_wsdl(str(tmp_path / "absent.wsdl"))

    assert scan.readable is False
    assert scan.error


def test_malformed_xml_is_unreadable(tmp_path):
    bad = tmp_path / "broken.wsdl"
    bad.write_text("<definitions><unclosed>")

    scan = legacy.fetch_wsdl(str(bad))
    assert scan.readable is False
    assert "not parseable as WSDL" in scan.error


# ─────────────────────────────────────────────────────────────────────────────
# Registry export
# ─────────────────────────────────────────────────────────────────────────────
REGISTRY = textwrap.dedent('''\
    # Finacle interface inventory export
    INTERFACE_NAME,SERVICE_PATH,OPERATION_NAME,BACKING_STORE
    CustomerService,https://finacle-bridge:8443/finacle/CustomerService,GetCustomerKyc,FINACLE.KYC_MASTER
    CustomerService,https://finacle-bridge:8443/finacle/CustomerService,PostLedgerEntry,FINACLE.GL_LEDGER
''')


def test_a_registry_export_carries_the_backing_datastore():
    """The column no other collector can know. A WSDL does not carry it, a
    gateway route does not, and a generated SOAP client holds no reference to a
    table — so this is where a blast radius learns that retiring an operation
    touches the general ledger."""
    ops, unusable = legacy.operations_from_registry(REGISTRY)

    assert unusable == 0
    stores = {o.operation: o.datastore for o in ops}
    assert stores == {"GetCustomerKyc": "FINACLE.KYC_MASTER",
                      "PostLedgerEntry": "FINACLE.GL_LEDGER"}


def test_a_comment_preamble_does_not_become_the_header():
    """A real export carries one. Feeding it unstripped to DictReader makes the
    first comment line the header and every column unrecognisable."""
    ops, _ = legacy.operations_from_registry(REGISTRY)
    assert len(ops) == 2


def test_column_names_are_matched_loosely():
    """No two core banking exports agree on a header."""
    ops, _ = legacy.operations_from_registry(textwrap.dedent('''\
        interface name,End Point,Txn Code,Table
        Nostro,https://h:8443/finacle/Nostro,ReconcileNostro,FINACLE.NOSTRO_POS
    '''))
    assert len(ops) == 1
    assert ops[0].datastore == "FINACLE.NOSTRO_POS"


def test_a_row_with_no_operation_is_counted_not_guessed_at():
    ops, unusable = legacy.operations_from_registry(textwrap.dedent('''\
        SERVICE_PATH,OPERATION_NAME
        https://h:8443/finacle/Customer,GetOne
        https://h:8443/finacle/Customer,
        ,GetTwo
    '''))
    assert len(ops) == 1
    assert unusable == 2


def test_an_export_missing_a_required_column_is_wholly_unusable():
    """Without a path and an operation there is no identity to build. Reporting
    it as an empty inventory would make the whole SOAP estate look absent."""
    ops, unusable = legacy.operations_from_registry(textwrap.dedent('''\
        INTERFACE_NAME,BACKING_STORE
        CustomerService,FINACLE.KYC_MASTER
    '''))
    assert ops == []
    assert unusable == 1


# ─────────────────────────────────────────────────────────────────────────────
# Merge
# ─────────────────────────────────────────────────────────────────────────────
def test_a_contract_and_an_export_describing_one_operation_merge(tmp_path):
    """One operation, two documents, one endpoint — and it keeps the datastore
    only the export knows."""
    contract = tmp_path / "c.wsdl"
    contract.write_text(wsdl(("GetCustomerKyc",)))
    export = tmp_path / "r.csv"
    export.write_text(REGISTRY)

    snapshot = legacy.collect([str(contract)], [str(export)])
    by_path = {o.path_template: o for o in snapshot.operations}

    kyc = by_path["/finacle/CustomerService#GetCustomerKyc"]
    assert kyc.origin == "wsdl"                       # the contract wins identity
    assert kyc.datastore == "FINACLE.KYC_MASTER"      # the export contributes this
    # An operation only the export knows is still reported.
    assert "/finacle/CustomerService#PostLedgerEntry" in by_path


def test_a_snapshot_is_unhealthy_when_any_source_is_unreadable(tmp_path):
    contract = tmp_path / "c.wsdl"
    contract.write_text(wsdl(("GetCustomerKyc",)))

    snapshot = legacy.collect([str(contract), str(tmp_path / "missing.wsdl")], [])

    assert snapshot.healthy is False
    assert len(snapshot.unreadable) == 1
    assert snapshot.operations  # what it did read is still reported


def test_nothing_configured_is_unhealthy():
    """Reading nothing is not the same as finding nothing. Treated as such, a
    SOAP estate would silently go unrepresented."""
    snapshot = legacy.collect([], [])
    assert snapshot.configured is False
    assert snapshot.healthy is False
