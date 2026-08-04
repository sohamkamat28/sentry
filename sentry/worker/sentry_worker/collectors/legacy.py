"""Legacy collector — the interface inventory a core banking platform publishes.

The fourth of stage 01's four sources, and the one that covers the part of a bank
the other three cannot see. A SOAP connector is a single URL with forty
operations behind it: the kernel probe reports the URL and the SOAPAction header,
the gateway reports one route, and a repository scan finds a generated client
with no route declarations in it at all. Only the WSDL says what the surface
actually is.

**Identity is the whole design here.** A WSDL operation becomes
``POST <service-path>#<Operation>``, which is exactly the form the kernel probe
emits when it appends a SOAPAction to the path. The two sources therefore
correlate on identity — the same string, produced independently — rather than by
a heuristic that matches an operation name against a URL and hopes.

Two inputs, because a bank has both:

* **WSDL** at ``LEGACY_WSDL_URLS``. The contract a client fetches.
* **A registry export** at ``LEGACY_REGISTRY_PATH``. How a core banking platform
  publishes its own inventory — Finacle-format CSV — which carries the backing
  datastore per interface, and that is where the datastore edges at stage 03
  come from.

Divergence from the design, stated rather than hidden: the design specifies
``zeep``. ``zeep`` is a SOAP *client*, and reading the operations out of a
contract needs an XML parser rather than one — the standard library's
ElementTree is exact for this and adds no dependency. Calling a SOAP service is
something this collector never does, so the rest of zeep would be unused.
"""

from __future__ import annotations

import csv
import io
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from sentry_core.config import settings

VERSION = "legacy-1.0.0"

WSDL_NS = "http://schemas.xmlsoap.org/wsdl/"
SOAP_NS = "http://schemas.xmlsoap.org/wsdl/soap/"
SOAP12_NS = "http://schemas.xmlsoap.org/wsdl/soap12/"


@dataclass
class LegacyOperation:
    """One operation, as the contract declares it."""

    #: The deployed host, from the contract's own endpoint address.
    #:
    #: Not the WSDL's ``<service name>``. Endpoint identity keys on method, path
    #: template *and* service, so both sources have to agree on all three. The
    #: contract calls itself "CustomerService" and the kernel reports the host it
    #: reached, "finacle-bridge" — attributing the operation to the contract name
    #: recorded the same operation twice, once per source, and neither copy
    #: carried the other's evidence.
    host: str
    service: str
    service_path: str
    operation: str
    #: ``<service-path>#<Operation>`` — the form the kernel probe emits.
    path_template: str
    method: str = "POST"
    soap_action: str | None = None
    #: Where the operation's data lives, when the registry says.
    datastore: str | None = None
    source_ref: str | None = None
    origin: str = "wsdl"


@dataclass
class LegacyScan:
    source: str
    operations: list[LegacyOperation] = field(default_factory=list)
    #: False when the document could not be fetched or parsed. An unreadable
    #: contract contributes no evidence, and saying so is what stops its
    #: operations being reported as absent.
    readable: bool = True
    error: str | None = None


def soap_identity(service_path: str, operation: str) -> str:
    """The one place the SOAP identity form is written.

    The kernel probe builds this in Go, from a path and a SOAPAction header. This
    builds it in Python, from a WSDL. They have to agree exactly or the two
    sightings of one operation become two endpoints — so the rule lives in one
    function on this side and one line on that one, and a test pins the pair.
    """
    path = service_path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1:
        path = path.rstrip("/")
    return f"{path}#{operation}"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _service_address(root: ET.Element) -> tuple[str, str]:
    """The host and path the contract advertises, from ``soap:address``.

    Read from the contract rather than assumed from the URL the WSDL was fetched
    from: a WSDL commonly lives at ``?wsdl`` on the service address, and commonly
    does not. The host is what the kernel reports having reached, so taking it
    from here is what makes the two sightings one endpoint.
    """
    for tag in (f"{{{SOAP_NS}}}address", f"{{{SOAP12_NS}}}address"):
        for node in root.iter(tag):
            location = node.get("location")
            if location:
                parts = urlsplit(location)
                return (parts.hostname or ""), (parts.path or "/")
    return "", "/"


def operations_from_wsdl(document: str, source: str = "") -> list[LegacyOperation]:
    """Every operation a WSDL declares.

    Operations are read from ``portType``, and the ``soapAction`` from the
    binding where one is given. A binding that names no action is not an error:
    the convention in that case is that the action equals the operation name,
    which is what the client will send and therefore what the probe will see.
    """
    root = ET.fromstring(document)

    service_name = ""
    for node in root.iter(f"{{{WSDL_NS}}}service"):
        service_name = node.get("name", "")
        break
    if not service_name:
        service_name = Path(urlsplit(source).path or "legacy").stem or "legacy"

    host, path = _service_address(root)
    if not host:
        # No advertised address means no way to say which deployed service this
        # contract belongs to. The contract name is the honest fallback and is
        # recorded as such rather than presented as a host.
        host = service_name

    actions: dict[str, str] = {}
    for binding in root.iter(f"{{{WSDL_NS}}}binding"):
        for op in binding.iter(f"{{{WSDL_NS}}}operation"):
            name = op.get("name")
            if not name:
                continue
            for child in op:
                if _local(child.tag) == "operation" and child.get("soapAction"):
                    actions[name] = child.get("soapAction", "")

    seen: set[str] = set()
    out: list[LegacyOperation] = []
    for port_type in root.iter(f"{{{WSDL_NS}}}portType"):
        for op in port_type.iter(f"{{{WSDL_NS}}}operation"):
            name = op.get("name")
            if not name or name in seen:
                continue
            seen.add(name)
            out.append(LegacyOperation(
                host=host,
                service=service_name,
                service_path=path,
                operation=name,
                path_template=soap_identity(path, name),
                soap_action=actions.get(name, name),
                source_ref=source or None,
                origin="wsdl",
            ))
    return out


def fetch_wsdl(url: str, *, timeout: float = 10.0) -> LegacyScan:
    """Read a contract, from a URL or a file path.

    TLS verification is off for the same reason it is off between estate
    services: a self-signed core banking connector is one of the postures this
    system exists to find, and refusing to read its contract would mean not
    finding it.
    """
    scan = LegacyScan(source=url)
    try:
        if url.startswith(("http://", "https://")):
            document = httpx.get(url, timeout=timeout, verify=False).text
        else:
            document = Path(url).expanduser().read_text()
    except (httpx.HTTPError, OSError) as exc:
        scan.readable = False
        scan.error = f"{type(exc).__name__}: {exc}"[:300]
        return scan

    try:
        scan.operations = operations_from_wsdl(document, source=url)
    except ET.ParseError as exc:
        scan.readable = False
        scan.error = f"not parseable as WSDL: {exc}"[:300]
    return scan


# ─────────────────────────────────────────────────────────────────────────────
# Registry export
# ─────────────────────────────────────────────────────────────────────────────
#: Column aliases, because no two core banking exports agree on a header.
#:
#: Matched case- and separator-insensitively. A required column that is absent
#: makes the row unusable, and the row is counted rather than guessed at.
_COLUMNS = {
    "service": ("service", "servicename", "interface", "interfacename", "module"),
    "path": ("path", "endpoint", "url", "servicepath", "uri"),
    "operation": ("operation", "operationname", "method", "function", "txncode"),
    "datastore": ("datastore", "table", "database", "backingstore", "schema"),
    "host": ("host", "hostname", "endpointhost", "server"),
}


def _normalise_header(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _column_map(fieldnames: list[str]) -> dict[str, str]:
    normalised = {_normalise_header(f): f for f in fieldnames or []}
    out: dict[str, str] = {}
    for key, aliases in _COLUMNS.items():
        for alias in aliases:
            if alias in normalised:
                out[key] = normalised[alias]
                break
    return out


def operations_from_registry(content: str, source: str = "") -> tuple[list[LegacyOperation], int]:
    """Operations from a Finacle-format registry export.

    Returns the operations and how many rows were unusable. A row missing its
    service path or its operation cannot be turned into an identity that
    correlates with anything, so it is counted and dropped rather than recorded
    against a guess.
    """
    # A real export carries a preamble. Feeding it to DictReader unstripped
    # makes the first comment line the header and every column unrecognisable.
    body = "\n".join(line for line in content.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))
    reader = csv.DictReader(io.StringIO(body))
    columns = _column_map(list(reader.fieldnames or []))
    out: list[LegacyOperation] = []
    unusable = 0

    if "path" not in columns or "operation" not in columns:
        # Without both there is no identity to build. The whole file is unusable
        # and that is reported, not silently treated as an empty inventory.
        return [], sum(1 for _ in reader)

    for row in reader:
        raw_path = (row.get(columns["path"]) or "").strip()
        operation = (row.get(columns["operation"]) or "").strip()
        if not raw_path or not operation:
            unusable += 1
            continue
        service = (row.get(columns.get("service", "")) or "").strip() or "legacy"
        datastore = (row.get(columns.get("datastore", "")) or "").strip() or None

        # An export that gives a full URL names the deployed host; one that gives
        # a bare path does not, and the interface name is the honest stand-in.
        parts = urlsplit(raw_path)
        path = parts.path or raw_path
        host = parts.hostname or (row.get(columns.get("host", "")) or "").strip() or service

        out.append(LegacyOperation(
            host=host,
            service=service,
            service_path=path,
            operation=operation,
            path_template=soap_identity(path, operation),
            datastore=datastore,
            source_ref=source or None,
            origin="registry",
        ))
    return out, unusable


def read_registry(path: str) -> LegacyScan:
    scan = LegacyScan(source=path)
    try:
        content = Path(path).expanduser().read_text()
    except OSError as exc:
        scan.readable = False
        scan.error = f"{type(exc).__name__}: {exc}"[:300]
        return scan
    scan.operations, unusable = operations_from_registry(content, source=path)
    if unusable:
        scan.error = f"{unusable} row(s) unusable: no service path or no operation"
    return scan


# ─────────────────────────────────────────────────────────────────────────────
# Snapshot
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class LegacySnapshot:
    scans: list[LegacyScan] = field(default_factory=list)

    @property
    def configured(self) -> bool:
        return bool(self.scans)

    @property
    def healthy(self) -> bool:
        return self.configured and all(s.readable for s in self.scans)

    @property
    def operations(self) -> list[LegacyOperation]:
        merged: dict[str, LegacyOperation] = {}
        for scan in self.scans:
            for op in scan.operations:
                existing = merged.get(op.path_template)
                if existing is None:
                    merged[op.path_template] = op
                    continue
                # The same operation in a contract and in a registry export is
                # one operation. The WSDL wins on identity because it is what a
                # client actually binds to; the registry contributes the
                # datastore, which the WSDL never carries.
                if existing.origin == "wsdl" and op.datastore and not existing.datastore:
                    existing.datastore = op.datastore
                elif existing.origin == "registry" and op.origin == "wsdl":
                    op.datastore = op.datastore or existing.datastore
                    merged[op.path_template] = op
        return list(merged.values())

    @property
    def unreadable(self) -> list[dict]:
        return [{"source": s.source, "error": s.error}
                for s in self.scans if not s.readable]


def wsdl_urls() -> list[str]:
    return [u.strip() for u in (settings.legacy_wsdl_urls or "").split(",") if u.strip()]


def registry_paths() -> list[str]:
    return [p.strip() for p in (settings.legacy_registry_path or "").split(",") if p.strip()]


def collect(urls: list[str] | None = None,
            registries: list[str] | None = None) -> LegacySnapshot:
    """Read every configured contract and registry export.

    Never raises. An unreadable source is a valid answer that stage 04 knows how
    to handle, and an exception would abort a pipeline run over one unreachable
    connector.
    """
    scans = [fetch_wsdl(u) for u in (urls if urls is not None else wsdl_urls())]
    scans += [read_registry(p) for p in
              (registries if registries is not None else registry_paths())]
    return LegacySnapshot(scans=scans)
