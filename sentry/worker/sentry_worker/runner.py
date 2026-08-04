"""Pipeline execution against the observation store.

The engines are pure functions over facts. This module is what reads those facts
out of the database, calls the engines in dependency order, and writes the
results back. Nothing here computes a verdict; it moves data.

Stage order is taken from ``pipeline.STAGE_DEPS`` rather than written out here,
so the ordering constraint lives in exactly one place.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from dataclasses import dataclass

import networkx as nx
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from sentry_core import audit, clock
from sentry_core.config import settings
from sentry_core.enums import (
    Auth,
    Confidence,
    ControlState,
    Criticality,
    Governance,
    Lifecycle,
    Phase,
    Source,
    Tier,
)
from sentry_core.models import (
    Anomaly,
    Blast,
    CallEdge,
    Cdri,
    Certificate,
    DatastoreEdge,
    ChangeRequest,
    Classification,
    Decommission,
    Endpoint,
    EndpointDaily,
    EndpointSource,
    Control,
    Finding,
    Fingerprint,
    Forecast,
    GateEvent,
    JudgeRun,
    Observation,
    Ownership,
    PipelineRun,
    PolicySetting,
    PolicyWeights,
    Probe,
    ResurrectionAlert,
    Service,
    StageRun,
)

from . import pipeline
from .actuators import control_plane, kong, siem, worm
from .collectors import code, codeowners, directory, gateway, legacy, openapi
from .judge import replay
from .engines import baseline, behaviour, blast, cdri, classification, correlation
from .engines import findings as findings_engine
from .engines import forecast as forecast_engine
from .engines import decommission
from .engines import fingerprint
from .engines import operations
from .engines import zerotrust
from .engines import remediation


@dataclass
class StageOutcome:
    stage: int
    records: int
    duration_ms: int
    detail: dict


def _weights(db: Session) -> tuple[int, dict]:
    row = db.execute(
        select(PolicyWeights).order_by(PolicyWeights.version.desc()).limit(1)
    ).scalar_one_or_none()
    if row is None:
        row = PolicyWeights(weights=dict(cdri.DEFAULT_WEIGHTS), note="runner default",
                            created_by="system:runner")
        db.add(row)
        db.flush()
    return row.version, dict(row.weights)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 01 — Gateway collector
# ─────────────────────────────────────────────────────────────────────────────
def stage_01_gateway(db: Session, vday: int) -> StageOutcome:
    """Emit what the gateway declares as sightings, for stage 03 to correlate.

    A declaration goes through the same path as a kernel capture rather than
    being written straight onto the endpoint. Two things fall out of that.
    Deduplication stays a property of the identity function — the same endpoint
    seen by two sources produces two ``endpoint_source`` rows against one
    ``endpoint``, with no merge pass that could run twice and differ. And a
    route the gateway declares that nothing ever calls still becomes an
    endpoint, which is the correct answer: registered and never invoked is a
    finding, not an absence.

    These rows are declarations, not invocations. Stage 02 counts only what the
    sensor observed, so a registry entry never inflates a call figure.

    An unreachable gateway writes nothing and says so. Stage 04 reads the same
    health signal and withholds SHADOW rather than deriving it from a failed
    poll — absence from a registry nobody could read is not evidence of
    anything.
    """
    snapshot = gateway.collect()
    if not snapshot.healthy:
        return StageOutcome(1, 0, 0, {"collector": "gateway", "healthy": False,
                                      "error": snapshot.error})

    now = datetime.now(timezone.utc)
    emitted = 0
    deprecated_marked = 0

    for route in snapshot.routes:
        # The service row carries declared metadata, and it is written here
        # rather than inferred at correlation. Criticality drives the latency
        # budget at stage 10 and the throttle exemption at stage 11: guessed
        # from a path string it is wrong in both directions, and
        # /api/v1/payment-history is a reporting endpoint while /api/v1/xfr may
        # be settlement.
        svc_id = correlation.service_id(route.service_name)
        svc = db.get(Service, svc_id)
        if svc is None:
            svc = Service(id=svc_id, name=route.service_name,
                          criticality=Criticality.INTERNAL,
                          first_vday=vday, last_vday=vday)
            db.add(svc)
        svc.last_vday = max(svc.last_vday, vday)

        declared = gateway.criticality_from_tags(route.tags)
        if declared:
            try:
                svc.criticality = Criticality(declared)
            except ValueError:
                pass
        if team := gateway.team_from_tags(route.tags):
            svc.team = team

        # A declared deprecation, applied to the endpoints this route fronts.
        #
        # Set only when the tag is present, never cleared here: removing the tag
        # is not the same statement as never having made it, and an endpoint
        # already enrolled in a sunset should not fall out of it because
        # somebody tidied a gateway label.
        if gateway.deprecated_from_tags(route.tags):
            for template in route.path_templates:
                for method in route.methods:
                    ep_id = correlation.endpoint_id(
                        method.upper(), correlation.normalise_path(template), svc_id)
                    declared_ep = db.get(Endpoint, ep_id)
                    if declared_ep is not None and not declared_ep.deprecated:
                        declared_ep.deprecated = True
                        deprecated_marked += 1

        for template in route.path_templates:
            for method in route.methods:
                db.add(Observation(
                    vday=vday, wall_ts=now, source=Source.GATEWAY,
                    method=method.upper(), path_raw=template,
                    host=route.service_name, port=route.port,
                    auth_present=bool(route.plugins) and any(
                        p in ("key-auth", "oauth2", "jwt", "basic-auth")
                        for p in route.plugins),
                    data_classes=[],
                ))
                emitted += 1

    db.flush()
    return StageOutcome(1, emitted, 0, {
        "collector": "gateway", "healthy": True,
        "gateway_routes": len(snapshot.routes),
        "gateway_services": snapshot.service_count,
        "sightings_emitted": emitted,
        # Endpoints a team has formally announced as retiring. The other way
        # into the sunset workflow, alongside being measured as a zombie.
        "deprecated_marked": deprecated_marked,
    })


def _service_for_repo(path: str, repo_name: str) -> str:
    """Which service a repository belongs to.

    Directory name by default, overridable per path. The service name is what
    the endpoint identity function keys on, so getting it wrong records a
    declared route against a service that does not serve it — and the endpoint
    the repository actually describes still reads as code-absent.
    """
    for pair in (settings.code_repo_services or "").split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            if key.strip() in (path, path.rstrip("/")):
                return value.strip()
    return repo_name


def stage_01_code(db: Session, vday: int) -> StageOutcome:
    """Emit what the institution's repositories declare, for stage 03 to correlate.

    Same path as the sensor and the gateway: sightings, not endpoint rows. The
    identity function deduplicates, so one endpoint seen in code and in traffic
    is two ``endpoint_source`` rows against one ``endpoint`` — and the endpoints
    that end up with no CODE source are the ones nobody can account for.

    A route declared here that nothing ever calls still becomes an endpoint, and
    that is the correct answer: it is unreleased rather than dead, and stage 04
    tells the two apart by ``last_call_vday IS NULL``.

    An unreadable repository makes the snapshot unhealthy and stage 04 withholds
    SHADOW, exactly as it does for an unreachable gateway. Absence from a
    repository nobody could read is not evidence of absence.
    """
    paths = code.repo_paths()
    if not paths:
        return StageOutcome(1, 0, 0, {
            "collector": "code", "healthy": False,
            "reason": "CODE_REPO_PATHS is empty, so no repository was scanned",
            "consequence": "every endpoint reads as absent from code; DOCUMENTED "
                           "is unreachable and stage 04 withholds SHADOW"})

    snapshot = code.collect(paths)
    now = datetime.now(timezone.utc)
    emitted = 0
    blamed = 0
    per_repo: list[dict] = []

    for path, scan in zip(paths, snapshot.scans):
        service = _service_for_repo(path, scan.repo)
        per_repo.append({"repo": scan.repo, "service": service,
                         "readable": scan.readable,
                         "files": scan.files_scanned,
                         "routes": len(scan.routes),
                         "parse_errors": scan.parse_errors})
        if not scan.readable:
            continue

        svc_id = correlation.service_id(service)
        svc = db.get(Service, svc_id)
        if svc is None:
            svc = Service(id=svc_id, name=service, criticality=Criticality.INTERNAL,
                          first_vday=vday, last_vday=vday)
            db.add(svc)
        svc.last_vday = max(svc.last_vday, vday)

        for route in scan.routes:
            # /healthz is a liveness probe, not API surface. Recording it would
            # put one row per service in the register that no operator will ever
            # act on.
            if route.path in ("/healthz", "/readyz", "/livez", "/metrics"):
                continue
            db.add(Observation(
                vday=vday, wall_ts=now, source=Source.CODE,
                method=route.method, path_raw=route.path,
                host=service, port=None,
                auth_present=route.has_auth_middleware,
                data_classes=[],
            ))
            emitted += 1

            # Where the route is declared, and who last touched that line.
            #
            # Attached to the CODE source of the endpoint the route describes,
            # which is rung 2 of the ownership ladder at stage 03. The endpoint
            # id is computed the same way correlation computes it, so the two
            # agree by construction rather than by a lookup that could miss.
            #
            # An endpoint this collector is the first to see has no source row
            # yet — the observation above creates it on this pass, and the blame
            # attaches on the next. A collector that emits and a correlator that
            # resolves are one cycle apart by design.
            ep_id = correlation.endpoint_id(route.method, route.path, svc_id)
            src = db.get(EndpointSource, (ep_id, Source.CODE))
            if src is None:
                continue
            detail = dict(src.detail or {})
            detail.update({"repo": scan.repo, "path": route.file, "line": route.line,
                           "handler": route.handler, "framework": route.framework})
            if route.last_author_email:
                detail["last_author"] = route.last_author
                detail["last_author_email"] = route.last_author_email
                detail["last_commit"] = route.last_commit_iso
            else:
                # Stated rather than left blank: a checkout that is not a git
                # repository has no blame to give, and rung 2 misses for that
                # reason rather than because nobody has ever edited the file.
                detail["blame"] = "unavailable: not a git repository"
            src.detail = detail
            blamed += int(bool(route.last_author_email))

    db.flush()
    return StageOutcome(1, emitted, 0, {
        "collector": "code",
        "healthy": snapshot.healthy,
        "repos": per_repo,
        "unreadable": snapshot.unreadable,
        "sightings_emitted": emitted,
        # Rung 2 of the ownership ladder. Zero here with routes found means the
        # repositories are not git checkouts, so the rung misses for want of a
        # blame rather than for want of an author.
        "routes_with_blame": blamed,
        # Which repositories were scanned is the entire meaning of "absent from
        # code", so the coverage claim travels with the result.
        "scanned": paths,
    })


def stage_01_legacy(db: Session, vday: int) -> StageOutcome:
    """Emit what the core banking platform declares, for stage 03 to correlate.

    The identity a WSDL yields — ``POST <path>#<Operation>`` — is character for
    character what the kernel probe emits when it appends a SOAPAction to the
    path. The two sources meet on the same string, produced independently, which
    is the difference between correlating and guessing.

    The registry export carries the backing datastore per operation, and nothing
    else in this system can know it: a WSDL does not say, a gateway route does
    not, and a generated SOAP client holds no reference to a table. It is written
    to ``datastore_edge`` so a blast radius can report that retiring an operation
    touches the general ledger.
    """
    urls, registries = legacy.wsdl_urls(), legacy.registry_paths()
    if not urls and not registries:
        return StageOutcome(1, 0, 0, {
            "collector": "legacy", "healthy": False,
            "reason": "LEGACY_WSDL_URLS and LEGACY_REGISTRY_PATH are both empty",
            "consequence": "a SOAP estate goes unrepresented; its operations are "
                           "visible only as whatever traffic the sensor happens "
                           "to catch"})

    snapshot = legacy.collect(urls, registries)
    now = datetime.now(timezone.utc)
    emitted = datastores = 0

    for op in snapshot.operations:
        # Attributed to the deployed host, not to the contract's own name. The
        # endpoint identity keys on the service, and the kernel reports the host
        # it reached — disagreeing here records the same operation twice, once
        # per source, with neither copy carrying the other's evidence.
        svc_id = correlation.service_id(op.host)
        svc = db.get(Service, svc_id)
        if svc is None:
            svc = Service(id=svc_id, name=op.host, criticality=Criticality.INTERNAL,
                          first_vday=vday, last_vday=vday)
            db.add(svc)
        svc.last_vday = max(svc.last_vday, vday)

        db.add(Observation(
            vday=vday, wall_ts=now, source=Source.LEGACY,
            method=op.method, path_raw=op.path_template,
            # The deployed host, matching the datastore edge below and matching
            # what the kernel reports. Carrying the contract name here while the
            # edge used the host put the source row on one endpoint and the
            # datastore on another — the same operation, recorded twice, with
            # neither copy holding the other's evidence.
            host=op.host, port=None,
            auth_present=False, data_classes=[],
        ))
        emitted += 1

        if not op.datastore:
            continue
        # Attached to the endpoint the operation describes, computed the same way
        # correlation computes it. An operation this collector is the first to
        # see has no endpoint row yet; the observation above creates it and the
        # edge attaches on the next pass.
        ep_id = correlation.endpoint_id(
            op.method, correlation.normalise_path(op.path_template), svc_id)
        if db.get(Endpoint, ep_id) is None:
            continue
        if db.get(DatastoreEdge, (ep_id, op.datastore)) is None:
            db.add(DatastoreEdge(endpoint_id=ep_id, datastore=op.datastore,
                                 source=Source.LEGACY, first_vday=vday))
            datastores += 1

    db.flush()
    return StageOutcome(1, emitted, 0, {
        "collector": "legacy",
        "healthy": snapshot.healthy,
        "operations": emitted,
        "datastore_edges": datastores,
        "unreadable": snapshot.unreadable,
        "wsdl": urls,
        "registries": registries,
    })


def stage_01_collectors(db: Session, vday: int) -> StageOutcome:
    """Every collector SENTRY owns, in one stage.

    The kernel sensor is not here: it runs continuously as an agent and writes
    through ingest. What belongs to a pipeline pass is polling the registries the
    sensor cannot see — the gateway's, and the institution's repositories.

    Each reports its own health, and the failure of one does not stop the other.
    Stage 04 reads both: SHADOW requires that the gateway *and* the code were
    both readable, because absence from a source nobody could reach is not
    evidence of absence from anywhere.
    """
    gw = stage_01_gateway(db, vday)
    src = stage_01_code(db, vday)
    leg = stage_01_legacy(db, vday)
    api = stage_01_openapi(db, vday)

    return StageOutcome(1, gw.records + src.records + leg.records, 0, {
        "gateway": gw.detail,
        "code": src.detail,
        "legacy": leg.detail,
        "openapi": api.detail,
        "collectors_healthy": {
            "gateway": bool(gw.detail.get("healthy")),
            "code": bool(src.detail.get("healthy")),
            "legacy": bool(leg.detail.get("healthy")),
        },
    })


def stage_01_openapi(db: Session, vday: int) -> StageOutcome:
    """Attach each endpoint's published request schema.

    Emits no observations and is deliberately absent from
    ``collectors_healthy``. The other three collectors answer *does this endpoint
    exist*, and stage 04 withholds a SHADOW verdict when one of them is
    unhealthy — because an unreadable gateway would otherwise brand the whole
    estate undocumented. This one answers *what does a caller have to send*, and
    a service that publishes no contract is not evidence of anything at all.

    Attaches to endpoints that already exist rather than creating them, for the
    same reason: a contract is not a sighting.
    """
    scan = openapi.collect()
    if not scan.operations:
        return StageOutcome(1, 0, 0, {
            "collector": "openapi", "healthy": scan.healthy,
            "documents": openapi.document_urls(),
            "unreadable": scan.unreadable,
            "consequence": "REST endpoints keep request_schema NULL; the Judge "
                           "replays them without a body and counts it"})

    attached = 0
    for op in scan.operations:
        if op.request_schema is None:
            continue
        ep_id = correlation.endpoint_id(
            op.method, correlation.normalise_path(op.path_template),
            correlation.service_id(op.host))
        ep = db.get(Endpoint, ep_id)
        if ep is None:
            continue
        if ep.request_schema != op.request_schema:
            ep.request_schema = op.request_schema
            attached += 1

    db.flush()
    return StageOutcome(1, 0, 0, {
        "collector": "openapi",
        "healthy": scan.healthy,
        "operations": len(scan.operations),
        "with_schema": scan.with_schema,
        "attached": attached,
        "unreadable": scan.unreadable,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Stage 03 — Correlation
# ─────────────────────────────────────────────────────────────────────────────
def stage_03_correlation(db: Session, vday: int) -> StageOutcome:
    """Turn raw sightings into a registry.

    Runs first because every later stage needs endpoint identity. Observations
    arrive with ``endpoint_id`` null; this is what fills it in.
    """
    rows = db.execute(
        select(Observation).where(Observation.endpoint_id.is_(None))
    ).scalars().all()

    services: dict[str, Service] = {}
    endpoints: dict[str, Endpoint] = {}
    sources: dict[tuple[str, Source], EndpointSource] = {}
    edges: dict[tuple[str, str], dict] = {}
    #: caller service id -> the name the sensor resolved, for callers that never
    #: appear as a Host and so have no other source of a name.
    caller_names: dict[str, str] = {}
    resolved = 0

    for o in rows:
        # The host header is the service the request was addressed to. Without
        # it there is nothing to attribute the call to, so the row waits for a
        # later cycle rather than being attached to a guess.
        host = (o.host or "").split(":")[0]
        if not host or not o.method:
            continue

        # SENTRY's own scaffolding is not part of the estate.
        #
        # The Judge builds a shadow pair of Kong services to measure a patch,
        # and the sensor sees that traffic like any other. Left in, the platform
        # discovers its own measurement apparatus, registers it as two new
        # endpoints, scores them, and reports an estate two endpoints larger
        # than it is — which then decays into zombies once the Judge run ends.
        if o.path_raw.startswith(replay.JUDGE_ROOT) or host.startswith(kong.JUDGE_PREFIX):
            continue

        svc_id = correlation.service_id(host)
        svc = services.get(svc_id) or db.get(Service, svc_id)
        if svc is None:
            svc = Service(id=svc_id, name=host, team=None,
                          criticality=_criticality_for(host),
                          first_vday=o.vday, last_vday=o.vday)
            db.add(svc)
        svc.last_vday = max(svc.last_vday, o.vday)
        services[svc_id] = svc

        template = correlation.normalise_path(o.path_raw)
        ep_id = correlation.endpoint_id(o.method, template, svc_id)

        ep = endpoints.get(ep_id) or db.get(Endpoint, ep_id)
        if ep is None:
            ep = Endpoint(id=ep_id, method=o.method.upper(), path_template=template,
                          service_id=svc_id, host=host, port=o.port,
                          first_vday=o.vday, auth=Auth.NONE)
            db.add(ep)
        # The earliest sighting, not the first row this loop happened to reach.
        #
        # Rows are not ordered by vday, and a gateway sighting emitted today for
        # an endpoint the sensor has watched for a month would set first_vday to
        # today. Every window is measured from it: observed_vdays collapses, the
        # endpoint drops below the baseline, and stage 04 withholds a verdict on
        # an endpoint with a month of history.
        ep.first_vday = min(ep.first_vday, o.vday)
        # Backfill the port from any sighting that carries one.
        #
        # Only the egress half of an exchange names the port it dialled; the
        # ingress half is the callee reading its own socket and has none. An
        # endpoint seen exclusively from the server side therefore has a null
        # port, and everything downstream that needs an origin — the Judge's
        # shadow pair most of all — fell back to 443 and proxied to a port the
        # estate does not serve. Both halves agreed perfectly, on two failures.
        if ep.port is None and o.port:
            ep.port = o.port
        endpoints[ep_id] = ep

        # Observed posture. Recorded from what the sensor saw, never assumed.
        if o.tls_version:
            ep.tls_version = o.tls_version
        if o.auth_present and o.auth_scheme:
            ep.auth = _auth_for(o.auth_scheme)
        if o.data_classes:
            ep.data_classes = sorted(set(ep.data_classes or []) | set(o.data_classes))

        key = (ep_id, o.source)
        src = sources.get(key) or db.get(EndpointSource, key)
        if src is None:
            src = EndpointSource(endpoint_id=ep_id, source=o.source,
                                 first_vday=o.vday, last_vday=o.vday, detail={})
            db.add(src)
        src.last_vday = max(src.last_vday, o.vday)
        sources[key] = src

        if o.peer_service:
            caller = correlation.service_id(o.peer_service)
            caller_names[caller] = o.peer_service
            e = edges.setdefault((caller, ep_id),
                                 {"first": o.vday, "last": o.vday, "calls": 0})
            e["calls"] += 1
            e["last"] = max(e["last"], o.vday)

        o.endpoint_id = ep_id
        resolved += 1

    db.flush()

    for (caller, ep_id), e in edges.items():
        # A caller that serves nothing is still a caller.
        #
        # Only services that appeared as a Host header got a service row, so a
        # workload that exclusively makes calls — a batch driver, a mobile
        # backend, anything at the edge of the estate — produced no node and its
        # edges were dropped. Endpoints it was the sole consumer of then reported
        # zero dependants, which is the one wrong answer that matters here: it is
        # the input to a recommendation to retire them.
        svc = db.get(Service, caller)
        if svc is None:
            svc = services.get(caller)
        if svc is None:
            name = caller_names.get(caller, caller)
            svc = Service(id=caller, name=name, criticality=Criticality.INTERNAL,
                          first_vday=e["first"], last_vday=e["last"])
            db.add(svc)
            services[caller] = svc
            db.flush()
        row = db.get(CallEdge, (caller, ep_id))
        if row is None:
            db.add(CallEdge(caller_service_id=caller, endpoint_id=ep_id,
                            first_vday=e["first"], last_vday=e["last"], calls=e["calls"]))
        else:
            row.calls += e["calls"]
            row.last_vday = max(row.last_vday, e["last"])

    # Ownership. All four rungs, in order, each recording what it returned.
    #
    # The directory is loaded once for the whole pass rather than per endpoint:
    # it answers the same question thousands of times and changes on the
    # timescale of a working day.
    hr = directory.load(settings.hr_directory_source)
    codeowner_rules = _codeowner_rules()

    for ep_id in endpoints:
        if db.get(Ownership, ep_id) is not None:
            continue

        code_src = db.get(EndpointSource, (ep_id, Source.CODE))
        detail = (code_src.detail or {}) if code_src else {}

        # Rung 1: the declared owner. The only source here that somebody wrote
        # down on purpose, which is why a match carries confidence 1.00.
        declared = None
        repo, rel_path = detail.get("repo"), detail.get("path")
        if repo and rel_path and (rules := codeowner_rules.get(repo)):
            found = codeowners.owners_for(rules, rel_path)
            if found.email or found.team:
                declared = {"email": found.email, "team": found.team,
                            "source": f"CODEOWNERS:{found.line} {found.pattern}"}

        # Rung 2: whoever last edited the line that declares this route.
        #
        # A far better lead than an empty ownership field, and evidence rather
        # than a guess — which is why the ladder records it below a declared
        # CODEOWNERS entry rather than beside one.
        blame = None
        if detail.get("last_author_email"):
            blame = {"email": detail["last_author_email"],
                     "name": detail.get("last_author"),
                     "source": f"git blame {detail.get('path')}:{detail.get('line')}"}

        # Rung 3: whatever the gateway tag happened to be set to. Weakest of the
        # three because nothing validates it and nobody is accountable for it.
        gw = None
        gw_src = db.get(EndpointSource, (ep_id, Source.GATEWAY))
        if gw_src and (gw_src.detail or {}).get("team"):
            gw = {"email": (gw_src.detail or {}).get("owner"),
                  "team": gw_src.detail["team"], "source": "kong tag"}

        o = correlation.resolve_ownership(
            declared, blame, gw, hr.lookup,
            department_head=settings.default_department_head or None)
        db.add(Ownership(endpoint_id=ep_id, owner_email=o.owner_email,
                         owner_team=o.owner_team, resolved_by=o.resolved_by,
                         confidence=o.confidence, reachable=o.reachable,
                         escalation=o.escalation, ladder=o.ladder))

    db.flush()
    return StageOutcome(3, len(endpoints), 0,
                        {"observations_resolved": resolved,
                         "services": len(services), "endpoints": len(endpoints),
                         "call_edges": len(edges)})


def _codeowner_rules() -> dict[str, list]:
    """CODEOWNERS rules per configured repository, loaded once per pass.

    Keyed on the repository path the code collector recorded, so a rule set is
    only ever applied to paths from the repository that declared it. Merging
    them into one table would let one team's catch-all claim another team's
    service.
    """
    out: dict[str, list] = {}
    for path in [p.strip() for p in settings.code_repo_paths.split(",") if p.strip()]:
        rules = codeowners.load(path)
        if rules:
            # Keyed on the repository *name*, which is what the code collector
            # records on the source row. Keying on the configured path instead
            # meant every lookup missed and rung 1 never fired, while rung 2
            # kept working — so ownership resolved, at a lower confidence, from
            # a weaker source, with nothing anywhere reporting a problem.
            out[os.path.basename(path.rstrip("/"))] = rules
    return out


def _criticality_for(host: str) -> Criticality:
    """Criticality from declared service metadata.

    In a full deployment this comes from Kong tags or repository metadata. It is
    never inferred from the path string: an endpoint called /api/v1/payment-history
    is a reporting endpoint, and one called /api/v1/xfr may be settlement.
    """
    known = {
        "payments-upi": Criticality.PAYMENT,
        "payments-rtgs": Criticality.SETTLEMENT,
        "cards-auth": Criticality.PAYMENT,
        "recon-quarterly": Criticality.REGULATORY,
    }
    return known.get(host, Criticality.CUSTOMER)


def _auth_for(scheme: str) -> Auth:
    return {"bearer": Auth.BEARER, "basic": Auth.BASIC}.get(scheme.lower(), Auth.NONE)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 02 — Baseline
# ─────────────────────────────────────────────────────────────────────────────
def _invocations(day_rows: list[Observation]) -> list[Observation]:
    """Reduce one endpoint-day to one row per call that actually happened.

    Two corrections live here, and both change every volume figure the product
    derives.

    **Only the sensor witnesses a call, and not every sighting is a call.** A gateway route, a repository handler
    and a WSDL binding are declarations that the endpoint *exists*; none of them
    is evidence that anyone invoked it. Counting a registry entry as a call
    would make a registered-but-never-invoked endpoint — one of the findings
    this system exists to produce — look like an endpoint with traffic.

    **A witnessed call is witnessed twice.** Between two instrumented workloads
    the caller's ``SSL_write`` and the callee's ``SSL_read`` are both genuine
    sightings of one exchange. Both are kept in ``observation``: the egress copy
    is the only one that can name the caller, and the ingress copy is the only
    one present when the client sits outside the estate. Counting both doubles
    the total.

    The larger half wins rather than a fixed preference for one direction. Ring
    buffer loss and the in-kernel discarders act on each side independently, so
    whichever half saw more is the better lower bound on how many exchanges
    happened, and the rule needs no special case for an endpoint instrumented
    on one side only.
    """
    # Traffic the platform generated is not usage.
    #
    # The API Judge replays real request shapes through the gateway to the real
    # upstream, so the sensor captures them exactly as it captures a caller.
    # Counted, they reset the silence clock on the endpoint stage 10 is judging
    # — and stage 10 judges precisely the endpoints under scrutiny, so a zombie
    # stays alive for as long as the system keeps examining it.
    ebpf = [o for o in day_rows if o.source == Source.EBPF and not o.synthetic]

    ingress = [o for o in ebpf if o.direction == "INGRESS"]
    egress = [o for o in ebpf if o.direction == "EGRESS"]
    # Captured before the sensor labelled direction, or by a probe that cannot
    # tell. Not attributable to either half, so kept rather than discarded.
    unlabelled = [o for o in ebpf if o.direction not in ("INGRESS", "EGRESS")]

    chosen = ingress if len(ingress) >= len(egress) else egress
    return chosen + unlabelled


def _captured_vdays(db: Session) -> set[int]:
    """Every vday in which the platform received an observation from any source.

    The virtual clock advances on wall time whether or not a sensor is running,
    so a vday with no rows at all across the whole estate is one where nothing
    was watching. Silence in such a vday is a fact about the platform, not about
    an endpoint, and the distinction decides whether a monitoring outage reads
    as a retirement queue.
    """
    return set(db.execute(select(Observation.vday).distinct()).scalars())


def stage_02_baseline(db: Session, vday: int) -> StageOutcome:
    eps = db.execute(select(Endpoint)).scalars().all()
    captured = _captured_vdays(db)
    written = 0

    for ep in eps:
        obs = db.execute(
            select(Observation).where(Observation.endpoint_id == ep.id)
        ).scalars().all()
        if not obs:
            continue

        by_vday: dict[int, list[Observation]] = defaultdict(list)
        for o in obs:
            by_vday[o.vday].append(o)

        rolled = {}
        for v, day_rows in by_vday.items():
            # Callers are read from every sighting; metrics from one half only.
            peers = {o.peer_service for o in day_rows if o.peer_service}
            items = [{
                "latency_us": o.latency_us, "resp_bytes": o.resp_bytes,
                "status": o.status, "peer_service": o.peer_service,
                "auth_present": o.auth_present, "wall_ts": o.wall_ts,
            } for o in _invocations(day_rows)]
            rolled[v] = baseline.rollup(ep.id, v, items, peers=peers)

        # Zero days are materialised so the forecast fits a contiguous series;
        # a gap and an explicit zero produce different slopes.
        series = baseline.materialise_zero_days(rolled, ep.id, ep.first_vday, vday,
                                                captured_vdays=captured)

        for row in series:
            existing = db.get(EndpointDaily, (ep.id, row.vday))
            if existing is None:
                db.add(EndpointDaily(
                    endpoint_id=row.endpoint_id, vday=row.vday, calls=row.calls,
                    distinct_peers=row.distinct_peers, err_calls=row.err_calls,
                    p50_latency_us=row.p50_latency_us, p95_latency_us=row.p95_latency_us,
                    mean_resp_bytes=row.mean_resp_bytes, auth_missing=row.auth_missing,
                    hour_histogram=row.hour_histogram))
            else:
                existing.calls = row.calls
                existing.distinct_peers = row.distinct_peers
                existing.err_calls = row.err_calls
                existing.hour_histogram = row.hour_histogram
            written += 1

        ep.last_call_vday = baseline.last_call_vday(series)
        ep.total_calls = sum(r.calls for r in series)

    db.flush()
    return StageOutcome(2, written, 0, {
        "endpoints": len(eps),
        "captured_vdays": len(captured),
        # The gap between these two is time nobody was watching. A large gap
        # means every silence figure below is measured over less history than
        # the clock suggests, which is the honest reading of it.
        "clock_vdays": vday + 1,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Stage 04 — Classification
# ─────────────────────────────────────────────────────────────────────────────
def stage_04_classification(db: Session, vday: int) -> StageOutcome:
    eps = db.execute(select(Endpoint).where(Endpoint.retired.is_(False))).scalars().all()

    # Silence is counted in vdays where something was watching.
    #
    # ZOMBIE is a claim that an endpoint stopped being called, and the only
    # evidence for it is the absence of observations. Absence of observations
    # while the sensor is down is not that evidence. Counting raw clock vdays
    # here means a weekend of agent downtime ages the whole estate past the
    # ninety-vday threshold and presents it as a retirement queue.
    captured = sorted(_captured_vdays(db))

    # SHADOW needs both negative sources to be trustworthy.
    #
    # The verdict is "traffic present, gateway absent, code absent", and each
    # absence is only evidence if the source was actually read. A gateway that
    # was down or a repository set that was empty would otherwise turn the whole
    # estate shadow — the highest-urgency cell in the matrix — on the strength of
    # two things nobody looked at.
    gateway_seen = db.execute(
        select(func.count()).select_from(EndpointSource)
        .where(EndpointSource.source == Source.GATEWAY)
    ).scalar_one()
    code_seen = db.execute(
        select(func.count()).select_from(EndpointSource)
        .where(EndpointSource.source == Source.CODE)
    ).scalar_one()
    shadow_reliable = gateway_seen > 0 and code_seen > 0

    written = withheld = 0
    for ep in eps:
        srcs = {s.source for s in db.execute(
            select(EndpointSource).where(EndpointSource.endpoint_id == ep.id)).scalars()}
        own = db.get(Ownership, ep.id)

        facts = classification.Facts(
            silent_vdays=(
                None if ep.last_call_vday is None
                else sum(1 for v in captured if v > ep.last_call_vday)
            ),
            in_gateway=Source.GATEWAY in srcs,
            has_reachable_owner=bool(own and own.reachable),
            deprecated=ep.deprecated,
            in_code=Source.CODE in srcs,
            owner_confidence=own.confidence if own else 0.0,
            shadow_reliable=shadow_reliable,
        )
        # Observed history is also counted in watched vdays, for the same
        # reason: the confidence ramp must not mature on time the sensor spent
        # switched off.
        observed = sum(1 for v in captured if v >= ep.first_vday)
        verdict = classification.classify(facts, observed)

        if verdict is None:
            # Below the baseline the system is not entitled to an opinion, and an
            # absent row says that unambiguously.
            withheld += 1
            continue

        row = db.get(Classification, ep.id)
        if row is None:
            db.add(Classification(
                endpoint_id=ep.id, lifecycle=verdict.lifecycle,
                governance=verdict.governance, confidence=verdict.confidence,
                severity_bump=verdict.severity_bump, trace=verdict.trace,
                vday=vday, engine_version=classification.VERSION))
        else:
            # pre_zombie is deliberately not touched: stage 07 owns it, and a
            # re-classification must not clear a forecast result.
            row.lifecycle = verdict.lifecycle
            row.governance = verdict.governance
            row.confidence = verdict.confidence
            row.severity_bump = verdict.severity_bump
            row.trace = verdict.trace
            row.vday = vday
            row.engine_version = classification.VERSION
        written += 1

    db.flush()
    return StageOutcome(4, written, 0,
                        {"withheld_below_baseline": withheld,
                         "shadow_reliable": shadow_reliable})


# ─────────────────────────────────────────────────────────────────────────────
# Stage 05 — Behaviour
# ─────────────────────────────────────────────────────────────────────────────
def stage_05_behaviour(db: Session, vday: int) -> StageOutcome:
    eps = db.execute(select(Endpoint).where(Endpoint.retired.is_(False))).scalars().all()
    series: list[behaviour.Series] = []

    for ep in eps:
        rows = db.execute(
            select(EndpointDaily).where(EndpointDaily.endpoint_id == ep.id)
            .order_by(EndpointDaily.vday)).scalars().all()
        if not rows:
            continue
        hist = [0] * 24
        for r in rows:
            for i, v in enumerate(r.hour_histogram or []):
                hist[i] += v
        series.append(behaviour.Series(
            endpoint_id=ep.id,
            calls=[r.calls for r in rows],
            resp_bytes=[r.mean_resp_bytes or 0 for r in rows],
            err_calls=[r.err_calls for r in rows],
            auth_missing=[r.auth_missing for r in rows],
            hour_histogram=hist,
            peer_counts=[r.distinct_peers for r in rows],
            auth=ep.auth.value,
        ))

    report = behaviour.run(series)
    for r in report.results:
        row = db.get(Anomaly, r.endpoint_id)
        if row is None:
            db.add(Anomaly(endpoint_id=r.endpoint_id, flag=r.flag, score=r.score,
                           isolation_depth=r.isolation_depth, patterns=r.patterns,
                           features=r.features, vday=vday,
                           engine_version=behaviour.VERSION))
        else:
            row.flag, row.score = r.flag, r.score
            row.isolation_depth, row.patterns = r.isolation_depth, r.patterns
            row.features, row.vday = r.features, vday

    db.flush()
    return StageOutcome(5, len(report.results), 0,
                        {"fitted": report.fitted, "fitted_on": report.fitted_on,
                         "excluded_insufficient_history":
                             report.excluded_insufficient_history})


# ─────────────────────────────────────────────────────────────────────────────
# Stage 06 — CDRI
# ─────────────────────────────────────────────────────────────────────────────
def stage_06_cdri(db: Session, vday: int) -> StageOutcome:
    version, weights = _weights(db)
    eps = db.execute(select(Endpoint).where(Endpoint.retired.is_(False))).scalars().all()
    written = 0

    for ep in eps:
        cls = db.get(Classification, ep.id)
        if cls is None:
            continue  # no score without a lifecycle verdict
        anom = db.get(Anomaly, ep.id)

        result = cdri.score(cdri.Inputs(
            auth=ep.auth, lifecycle=cls.lifecycle, data_classes=ep.data_classes,
            tls_version=ep.tls_version, rate_limited=ep.rate_limited,
            anomaly_flag=anom.flag if anom else None,
        ), weights)

        ttb, factors = cdri.time_to_breach(
            result.score, ep.auth, ep.data_classes, cls.governance,
            anom.patterns if anom else None, ep.internet_reachable)

        row = db.get(Cdri, ep.id)
        if row is None:
            db.add(Cdri(endpoint_id=ep.id, score=result.score, tier=result.tier,
                        parts=result.parts, weights_version=version,
                        time_to_breach_d=ttb, ttb_factors=factors, vday=vday,
                        engine_version=cdri.VERSION))
        else:
            row.score, row.tier, row.parts = result.score, result.tier, result.parts
            row.weights_version, row.time_to_breach_d = version, ttb
            row.ttb_factors, row.vday = factors, vday
        written += 1

    db.flush()
    return StageOutcome(6, written, 0, {"weights_version": version})


# ─────────────────────────────────────────────────────────────────────────────
# Stage 07 — Forecast
# ─────────────────────────────────────────────────────────────────────────────
def stage_07_forecast(db: Session, vday: int) -> StageOutcome:
    eps = db.execute(select(Endpoint).where(Endpoint.retired.is_(False))).scalars().all()
    written = flagged = 0

    for ep in eps:
        cls = db.get(Classification, ep.id)
        if cls is None or cls.lifecycle.value == "ZOMBIE":
            continue  # forecasting the death of something already dead helps nobody

        rows = db.execute(
            select(EndpointDaily).where(EndpointDaily.endpoint_id == ep.id)
            .order_by(EndpointDaily.vday)).scalars().all()
        if len(rows) < 2:
            continue

        series = [float(r.calls) for r in rows]
        own = db.get(Ownership, ep.id)
        silence = 0 if ep.last_call_vday is None else vday - ep.last_call_vday

        res = forecast_engine.run_one(
            series, silence, None,
            bool(own and own.reachable), own.confidence if own else 0.0)

        row = db.get(Forecast, ep.id)
        payload = dict(days_to_zombie=res.days_to_zombie, slope=res.projection.slope,
                       level=res.projection.level, signals=res.signals,
                       observed=series, adjusted=res.projection.adjusted,
                       projection=res.projection.points,
                       deseasonalised=res.projection.deseasonalised, vday=vday,
                       engine_version=forecast_engine.VERSION)
        if row is None:
            db.add(Forecast(endpoint_id=ep.id, **payload))
        else:
            for k, v in payload.items():
                setattr(row, k, v)

        # The one legal back-edge in the DAG: stage 07 writes onto the stage 04
        # record, because the projection is not available when lifecycle is set.
        cls.pre_zombie = res.pre_zombie
        written += 1
        flagged += int(res.pre_zombie)

    db.flush()
    return StageOutcome(7, written, 0, {"pre_zombie_flagged": flagged})


# ─────────────────────────────────────────────────────────────────────────────
# Stage 09 — Blast radius
# ─────────────────────────────────────────────────────────────────────────────
def stage_09_blast(db: Session, vday: int) -> StageOutcome:
    services = [{"id": s.id, "name": s.name, "criticality": s.criticality.value}
                for s in db.execute(select(Service)).scalars()]
    endpoints = [{"id": e.id, "service_id": e.service_id, "method": e.method,
                  "path_template": e.path_template}
                 for e in db.execute(select(Endpoint)).scalars()]
    window_floor = vday - settings.window_vdays
    edges = [{"caller_service_id": c.caller_service_id, "endpoint_id": c.endpoint_id,
              "calls": c.calls}
             for c in db.execute(select(CallEdge)).scalars()
             if c.last_vday >= window_floor]

    g = blast.build_graph(services, endpoints, edges, [])
    written = 0

    for ep in endpoints:
        r = blast.radius(g, ep["id"])
        row = db.get(Blast, ep["id"])
        payload = dict(tier=r.tier, direct_callers=r.direct_callers,
                       hop2_callers=r.hop2_callers, affected=r.affected,
                       datastores=r.datastores, touches_critical=r.touches_critical,
                       in_graph=r.in_graph, hop_limit=r.hop_limit, vday=vday,
                       engine_version=blast.VERSION)
        if row is None:
            db.add(Blast(endpoint_id=ep["id"], **payload))
        else:
            for k, v in payload.items():
                setattr(row, k, v)
        written += 1

    db.flush()
    return StageOutcome(9, written, 0, {"graph_nodes": g.number_of_nodes(),
                                        "graph_edges": g.number_of_edges()})


# ─────────────────────────────────────────────────────────────────────────────
# Stage 08 — Findings
# ─────────────────────────────────────────────────────────────────────────────
def stage_08_findings(db: Session, vday: int) -> StageOutcome:
    generator = findings_engine.TemplateGenerator()
    tiers = {"CRITICAL", "HIGH"}
    written = 0

    for ep in db.execute(select(Endpoint).where(Endpoint.retired.is_(False))).scalars():
        d = db.get(Cdri, ep.id)
        cls = db.get(Classification, ep.id)
        if d is None or cls is None or d.tier.value not in tiers:
            continue

        b = db.get(Blast, ep.id)
        anom = db.get(Anomaly, ep.id)
        own = db.get(Ownership, ep.id)
        fc = db.get(Forecast, ep.id)
        svc = db.get(Service, ep.service_id)

        ctx = findings_engine.Context(
            endpoint_id=ep.id, method=ep.method, path=ep.path_template,
            service=svc.name if svc else "",
            silent_vdays=None if ep.last_call_vday is None else vday - ep.last_call_vday,
            lifecycle=cls.lifecycle.value, governance=cls.governance.value,
            auth=ep.auth.value, tls_version=ep.tls_version,
            rate_limited=ep.rate_limited, data_classes=ep.data_classes,
            internet_reachable=ep.internet_reachable,
            cdri_score=d.score, cdri_tier=d.tier.value, cdri_parts=d.parts,
            blast_tier=b.tier.value if b else None,
            blast_affected=b.affected if b else [],
            time_to_breach_d=d.time_to_breach_d, ttb_factors=d.ttb_factors,
            anomaly_patterns=anom.patterns if anom else [],
            owner_email=own.owner_email if own else None,
            owner_reachable=bool(own and own.reachable),
            escalation=own.escalation if own else None,
            pre_zombie=cls.pre_zombie,
            days_to_zombie=fc.days_to_zombie if fc else None,
        )

        result = findings_engine.build(ctx, generator)
        fid = findings_engine.finding_id(ep.id, vday)
        if db.get(Finding, fid) is None:
            db.add(Finding(id=fid, endpoint_id=ep.id,
                           narrative={"summary": result.narrative.summary,
                                      "technical": result.narrative.technical,
                                      "action": result.narrative.action},
                           generator=result.generator, model=result.model,
                           regulations=result.regulations,
                           time_to_breach_d=d.time_to_breach_d, vday=vday,
                           engine_version=findings_engine.VERSION))
            written += 1

    db.flush()
    return StageOutcome(8, written, 0, {})


# ─────────────────────────────────────────────────────────────────────────────
# Stage 10 — Remediation
# ─────────────────────────────────────────────────────────────────────────────
def _upstream_url(ep: Endpoint) -> str:
    """Where the Judge's shadow pair should proxy to.

    The endpoint's own origin, taken from what the sensor observed rather than
    from the gateway's declaration. A patch measured against a different
    upstream than the one it will front is not a measurement of that patch.
    """
    host = (ep.host or "").split(":")[0]
    port = ep.port or 443
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}"


def _peak_calls(db: Session, endpoint_id: str, vday: int) -> int:
    window = max(0, vday - settings.baseline_vdays)
    rows = db.execute(
        select(EndpointDaily.calls)
        .where(EndpointDaily.endpoint_id == endpoint_id, EndpointDaily.vday >= window)
    ).scalars().all()
    return max(rows) if rows else 0


def stage_10_remediation(db: Session, vday: int) -> StageOutcome:
    """Generate a control, prove it is safe, apply it at the gateway.

    Three phases, and the boundaries between them are the point.

    Generation reads the CDRI parts and proposes gateway configuration for the
    indicators that fired. The Judge measures each proposal against the
    endpoint's own traffic through a shadow pair on the live gateway. Only a
    control that passed every dimension is applied, and it is applied by POSTing
    the stored config verbatim — ``APPLIED`` is set only when Kong returns a
    plugin id, never on a hopeful 2xx.

    A control whose Judge run could not happen stays ``PROPOSED``. That is
    distinct from ``REJECTED``: one means the patch was measured and failed, the
    other means it was never measured, and collapsing them would let an
    infrastructure outage read as a safety finding.
    """
    if not kong.healthy():
        return StageOutcome(10, 0, 0, {"gateway": "unreachable",
                                       "remedy": "check KONG_ADMIN_URL"})

    # A worker killed mid-judge leaves a shadow pair behind, and one killed
    # between a plugin POST and its commit leaves an applied plugin no control
    # row records. Both are reconciled before anything new is written, so the
    # gateway starts this run holding exactly what the database says it holds.
    purged = kong.purge_judge_objects()
    drift = control_plane.reconcile(db)

    # Which route fronts each endpoint, read from the gateway now rather than
    # from what stage 01 recorded earlier in the run.
    #
    # A control attaches to a route, not a service: a service usually fronts
    # several endpoints and only one of them was judged, and Kong permits one
    # instance of a plugin name per service anyway. The lookup is live because a
    # route can be renamed or removed between the collector pass and this one,
    # and attaching a plugin to a stale name either 404s or patches the wrong
    # route.
    snapshot = gateway.collect()
    if not snapshot.healthy:
        return StageOutcome(10, 0, 0, {"gateway": "registry unreadable",
                                       "error": snapshot.error})

    routes_by_key: dict[tuple[str, str, str], str] = {}
    for route in snapshot.routes:
        for template in route.path_templates:
            for method in route.methods:
                routes_by_key[(route.service_name, method.upper(), template)] = \
                    route.route_name

    # The other direction of the same reconciliation, and it needs the snapshot,
    # so it runs here rather than inside `reconcile`. `reconcile` asks whether
    # the gateway holds what the database claims; this asks whether a row still
    # claiming to need an operator is describing something already enforced.
    # Rows that are not stay FAILED — the point is to shrink the queue to the
    # ones that are real, not to empty it.
    reconciled = control_plane.reconcile_failed(db, snapshot)

    eligible = db.execute(
        select(Endpoint, Cdri, Classification)
        .join(Cdri, Cdri.endpoint_id == Endpoint.id)
        .join(Classification, Classification.endpoint_id == Endpoint.id)
        .where(Endpoint.retired.is_(False), Cdri.tier.in_(settings.remediation_tiers))
        .order_by(Cdri.score.desc())
    ).all()

    proposed = judged = applied = rejected = unmeasured = 0
    ungatewayed = 0
    details: list[dict] = []

    for ep, cdri_row, _cls in eligible:
        # A shadow endpoint has no route on the gateway, so there is nothing to
        # attach a plugin to. That is the whole point of it being shadow: the
        # traffic does not pass through the control plane, so the control plane
        # cannot control it. Proposing gateway configuration here and watching
        # the POST 404 would report an infrastructure fault; the truth is that
        # this endpoint has to be onboarded or retired before any virtual patch
        # is possible.
        route_name = routes_by_key.get(
            (ep.service.name, ep.method.upper(), ep.path_template))
        if not route_name:
            ungatewayed += 1
            details.append({
                "endpoint": f"{ep.method} {ep.path_template}",
                "verdict": "NO_GATEWAY_ROUTE",
                "reason": "no gateway route fronts this endpoint, so no gateway "
                          "control can reach it; onboard it or retire it at stage 11",
            })
            continue

        facts = remediation.EndpointFacts(
            endpoint_id=ep.id,
            method=ep.method,
            path_template=ep.path_template,
            service_name=ep.service.name,
            criticality=ep.service.criticality,
            auth=ep.auth,
            tls_version=ep.tls_version,
            data_classes=list(ep.data_classes or []),
            peak_calls_per_vday=_peak_calls(db, ep.id, vday),
            rate_limited=any(
                c.kind == "rate-limit" and c.state is ControlState.APPLIED
                for c in db.execute(
                    select(Control).where(Control.endpoint_id == ep.id)).scalars()
            ),
        )
        plan = remediation.plan_for(facts, remediation.fired_indicators(cdri_row.parts))

        obs = db.execute(
            select(Observation)
            .where(Observation.endpoint_id == ep.id, Observation.source == Source.EBPF)
            .order_by(Observation.vday.desc())
            .limit(settings.judge_max_requests)
        ).scalars().all()
        shapes = replay.requests_from_observations(
            [{"method": o.method, "path_raw": o.path_raw, "auth_scheme": o.auth_scheme}
             for o in obs],
            settings.judge_replay_shapes,
            # The template, not the raw path: the SOAP operation lives in the
            # endpoint identity and never appears in the URL a client dialled.
            path_template=ep.path_template,
            # The published contract, where the service publishes one. Without
            # it a POST replays empty, and a service that answers a body-less
            # write with a 400 makes every control look like it broke the
            # endpoint.
            schema=ep.request_schema,
        )

        for prop in plan.proposals:
            # Idempotent: a control already applied or already rejected on this
            # config is not re-judged. Re-running the pipeline must not spray
            # duplicate plugins into a gateway.
            #
            # Broader than the guard in `control_plane.apply`, which skips only
            # an APPLIED control stating the *same* config. Deliberately not
            # narrowed to match: this is the path with the Judge in it, and a
            # changed proposal here means a shadow pair, a replay and a fresh
            # control row on every pass. `apply` can afford the finer test
            # because a config that differs costs one refused Kong call.
            existing = db.execute(
                select(Control).where(
                    Control.endpoint_id == ep.id,
                    Control.kind == prop.kind,
                    Control.state.in_([ControlState.APPLIED, ControlState.REJECTED]),
                )
            ).scalars().first()
            if existing is not None:
                continue

            control = Control(
                endpoint_id=ep.id, kind=prop.kind,
                plugin_config=prop.plugin_config,
                state=ControlState.PROPOSED,
                generator=prop.generator, origin_stage=10,
                actor="system:stage-10",
            )
            db.add(control)
            # Committed before the gateway is touched, not after. The POST and
            # the commit cannot be one transaction, so the ordering decides which
            # way an interruption fails: this way leaves a control row with no
            # plugin, which the next run simply re-judges. The other way leaves a
            # plugin with no control row — unattributable policy in a production
            # gateway.
            db.commit()
            proposed += 1

            try:
                result = replay.run(
                    endpoint_id=ep.id,
                    upstream_url=_upstream_url(ep),
                    plugin_config=prop.plugin_config,
                    requests=shapes,
                    criticality=ep.service.criticality.value,
                )
            except replay.JudgeUnavailable as exc:
                # Measured nothing, so claims nothing.
                control.error = f"judge did not run: {exc}"
                unmeasured += 1
                details.append({"endpoint": ep.path_template, "control": prop.kind,
                                "verdict": "UNMEASURED", "reason": str(exc)})
                continue

            run_row = JudgeRun(
                endpoint_id=ep.id,
                requests=result.scores.requests,
                replay_exact=result.replay_exact,
                replay_synthesised=result.replay_synthesised,
                replay_bodyless=result.replay_bodyless,
                schema_score=result.scores.schema,
                latency_score=result.scores.latency,
                error_score=result.scores.error,
                exposure_score=result.scores.exposure,
                verdict=result.verdict,
                reason=",".join(result.scores.failing) or None,
                latency_delta_us=result.scores.latency_delta_us,
                budget_us=result.scores.budget_us,
                diff_summary=result.diff_summary,
            )
            db.add(run_row)
            db.flush()
            control.judge_run_id = run_row.id
            judged += 1

            record = {
                "endpoint": f"{ep.method} {ep.path_template}",
                "control": prop.kind,
                "verdict": result.verdict,
                "scores": {"schema": result.scores.schema,
                           "latency": result.scores.latency,
                           "error": result.scores.error,
                           "exposure": result.scores.exposure},
                "requests": result.scores.requests,
            }

            if result.verdict != "PASS":
                control.state = ControlState.REJECTED
                control.error = "judge rejected: " + ", ".join(result.scores.failing)
                rejected += 1
                record["failing"] = result.scores.failing
                details.append(record)
                continue

            # Apply. The stored config is POSTed verbatim — there is no
            # transformation between what was judged and what reaches Kong.
            try:
                ref = kong.create_route_plugin(route_name, prop.plugin_config,
                                               control_id=control.id)
            except (kong.KongUnavailable, kong.KongRejected) as exc:
                control.state = ControlState.FAILED
                control.error = str(exc)[:500]
                record["verdict"] = "FAILED"
                record["error"] = str(exc)[:200]
                details.append(record)
                continue

            control.kong_plugin_id = ref.id
            control.state = ControlState.APPLIED
            control.applied_at = datetime.now(timezone.utc)
            applied += 1
            record["kong_plugin_id"] = ref.id
            details.append(record)

            # The change request carries the permanent fix through the normal
            # CAB cycle. The exposure is already closed by the control above;
            # this is the governance record, not the remediation.
            db.add(ChangeRequest(
                endpoint_id=ep.id, control_id=control.id,
                state="DRAFT",
                stub=not settings.servicenow_url,
                payload={
                    "short_description":
                        f"Permanent fix for {ep.method} {ep.path_template}",
                    "description": prop.rationale,
                    "assignment_group": settings.servicenow_group,
                    "category": "Security",
                    "u_virtual_patch_applied": ref.id,
                    "u_cdri_score": round(cdri_row.score, 3),
                },
            ))

    db.flush()
    return StageOutcome(10, applied, 0, {
        "judge_objects_purged": purged,
        "orphan_plugins_removed": drift["orphans_removed"],
        "controls_drifted": drift["controls_drifted"],
        "controls_superseded": len(reconciled["superseded"]),
        "controls_still_failed": reconciled["still_failed"],
        "supersession_declined": reconciled["unresolved"],
        "endpoints_considered": len(eligible),
        "no_gateway_route": ungatewayed,
        "proposed": proposed, "judged": judged,
        "applied": applied, "rejected": rejected, "unmeasured": unmeasured,
        "results": details,
    })



# ─────────────────────────────────────────────────────────────────────────────
# Stage 11 — Decommission
# ─────────────────────────────────────────────────────────────────────────────
#: Which gateway route fronts an endpoint. Lives with the writer — the
#: reconciler needs the same answer, and a second copy is how the first one
#: diverged the moment one of them learned about SOAP.
_route_for = control_plane.route_for


def _record_hidden_callers(db: Session, dec: Decommission, ep: Endpoint,
                           since_vday: int) -> int:
    """Any call during quarantine is, by definition, an undiscovered dependency.

    This is the forcing function of the whole workflow. A quarterly batch job or
    a third-party integration no registry knew about surfaces here, while the
    endpoint is still fully working — which is why finding one is a success and
    the console labels it that way rather than as a failure.
    """
    rows = db.execute(
        select(Observation)
        .where(Observation.endpoint_id == ep.id,
               Observation.vday >= since_vday,
               Observation.source == Source.EBPF,
               Observation.synthetic.is_(False))
    ).scalars().all()

    # One row per exchange, preferring the half that names the caller.
    #
    # A call between two instrumented workloads is captured twice, and only the
    # egress copy knows who made it. Counting both listed the same three calls
    # as two dependants — "traffic" and "unresolved:unknown" — which reads as
    # two teams to contact when there is one. Where no egress copy exists the
    # ingress one is kept: a caller from outside the estate is unidentifiable
    # and is exactly the dependency this quarantine exists to surface, so
    # dropping it would defeat the purpose.
    egress = [o for o in rows if o.direction == "EGRESS"]
    counted = egress if egress else rows

    known = {c["service"]: c for c in (dec.hidden_callers or [])}
    for o in counted:
        name = o.peer_service or f"unresolved:{o.peer_ip or 'unknown'}"
        entry = known.get(name)
        if entry is None:
            known[name] = {"service": name, "ip": o.peer_ip,
                           "first_vday": o.vday, "calls": 1}
        else:
            entry["calls"] += 1
            entry["first_vday"] = min(entry["first_vday"], o.vday)

    dec.hidden_callers = sorted(known.values(), key=lambda c: -c["calls"])
    return len(dec.hidden_callers)


def _replacement_for(db: Session, ep: Endpoint) -> str | None:
    """The upstream a canary migrates onto.

    Found by convention — the same service name with a version suffix, serving
    the same path — and verified to exist in the registry before it is used.
    Shifting production traffic onto a host nobody has confirmed is serving is
    the one mistake a canary must not make, so an absent replacement stops the
    migration rather than starting one into nothing.
    """
    if not ep.host or not ep.port:
        return None
    for suffix in ("-v2", "-v3", "-next"):
        candidate = f"{ep.host}{suffix}"
        exists = db.execute(
            select(func.count()).select_from(Endpoint)
            .join(Service, Service.id == Endpoint.service_id)
            .where(Service.name == candidate,
                   Endpoint.path_template == ep.path_template,
                   Endpoint.method == ep.method)
        ).scalar_one()
        if exists:
            return f"{candidate}:{ep.port}"
    return None


def _shift_canary(db: Session, dec: Decommission, ep: Endpoint,
                  route_name: str | None, actor: str) -> dict:
    """Move the weights at the gateway to match the recorded split.

    Until this existed the canary path set ``canary_split`` and changed nothing:
    the number moved 0.10 → 0.01 → 0.00 across three phases while every request
    kept reaching the endpoint being retired. The migration was bookkeeping.
    """
    # The replacement first. Whether one exists is a fact about the estate and
    # is knowable without a gateway, and it is the actionable answer — "no
    # gateway configured" tells an operator about their deployment, "nothing to
    # migrate onto" tells them why this endpoint has been sitting in canary.
    replacement = _replacement_for(db, ep)
    if replacement is None:
        # Stated rather than silently skipped. An endpoint parked in canary with
        # nowhere to go is the state the estate was in, and it looked like
        # progress.
        return {"canary_error": "no replacement upstream is registered; "
                                "the migration cannot start"}

    if not route_name:
        return {"canary_error": "no gateway route for this endpoint"}
    if not settings.kong_admin_url:
        return {"canary_error": "no gateway configured"}

    current = f"{ep.host}:{ep.port}"
    split = dec.canary_split if dec.canary_split is not None else 1.0
    try:
        upstream = kong.ensure_canary_upstream(ep.id, current, replacement, route_name)
        kong.set_upstream_weights(
            upstream, kong.canary_weights(upstream, current, replacement, split))
        # Read back, because the point of a canary is that somebody can verify
        # where traffic is going.
        observed = {t["target"]: t["weight"] for t in kong.upstream_targets(upstream)}
    except Exception as exc:  # noqa: BLE001
        return {"canary_error": f"{type(exc).__name__}: {exc}"[:200]}

    audit.record(db, actor=actor, action="decommission.canary.shifted", target=ep.id,
                 detail={"split": split, "upstream": upstream,
                         "replacement": replacement, "weights": observed})
    return {"canary_upstream": upstream, "canary_replacement": replacement,
            "canary_weights": observed}


def _enter_phase(db: Session, dec: Decommission, ep: Endpoint, phase: Phase,
                 path: decommission.Path, route_name: str | None,
                 vday: int, actor: str) -> dict:
    """Apply the gateway change this phase requires, then record the transition.

    Gateway state is never written here directly — every throttle, header and
    termination goes through the shared actuator so it exists as a control row
    with a plugin id to revert by.
    """
    result: dict = {"phase": phase.value, "entered_vday": vday}

    if phase is Phase.A:
        if path.canary or decommission.criticality_is_exempt(ep.service.criticality):
            # Deliberately degrading a payment path to encourage migration is
            # itself the incident it is meant to prevent.
            dec.canary = True
            dec.canary_split = decommission.next_canary_split(None)
            result["action"] = "canary"
            result["canary_split"] = dec.canary_split
            result.update(_shift_canary(db, dec, ep, route_name, actor))
        else:
            peak = _peak_calls(db, ep.id, vday)
            limit = decommission.throttle_limit(peak)
            result["action"] = "throttle"
            result["limit_per_minute"] = limit
            if route_name:
                try:
                    control_plane.apply(
                        db, endpoint_id=ep.id, route_name=route_name,
                        kind="sunset-throttle",
                        plugin_config=kong.rate_limit(limit),
                        origin_stage=11, actor=actor)
                except control_plane.ApplyFailed as exc:
                    result["error"] = str(exc)[:200]

    elif phase is Phase.B:
        vc = clock.ensure_vclock(db)
        when = decommission.sunset_at(dec.entered_vday or vday, path, phase,
                                      vc.epoch_wall, vc.scale_seconds)
        result["action"] = "sunset-header"
        result["sunset"] = decommission.rfc8594(when)
        if route_name:
            try:
                control_plane.apply(
                    db, endpoint_id=ep.id, route_name=route_name,
                    kind="sunset-header",
                    plugin_config=kong.sunset_headers(
                        decommission.rfc8594(when),
                        f"{settings.console_base_url}/sunset/{ep.id}"),
                    origin_stage=11, actor=actor)
            except control_plane.ApplyFailed as exc:
                result["error"] = str(exc)[:200]

    elif phase is Phase.C:
        # The endpoint stays fully operational. Nothing is applied at the
        # gateway: quarantine is a watch, and breaking the endpoint would
        # prevent the very calls it is trying to observe.
        result["action"] = "quarantine"
        result["gateway_change"] = None

    # A canary advances one step per phase, and the step is what makes it a
    # migration rather than a countdown. Applied after the phase's own action so
    # a failed weight shift does not leave the phase half-entered.
    if dec.canary and phase in (Phase.B, Phase.C):
        nxt = decommission.next_canary_split(dec.canary_split)
        if nxt is not None:
            dec.canary_split = nxt
            result["canary_split"] = nxt
            result.update(_shift_canary(db, dec, ep, route_name, actor))

    dec.phase = phase
    dec.phase_vday = vday
    if dec.entered_vday is None:
        dec.entered_vday = vday

    audit.record(db, actor=actor, action="decommission.phase", target=ep.id,
                 detail=result)
    return result


def _complete_phase_d(db: Session, dec: Decommission, ep: Endpoint,
                      route_name: str | None, vday: int, actor: str) -> dict:
    """Archive, then 410, then certificate. The order is enforced.

    Phase D cannot complete without a WORM object and a retention date. Retiring
    an endpoint whose history was not archived destroys the evidence the archive
    exists to preserve, and there is no way to recover it afterwards — so an
    unreachable object store blocks the phase rather than degrading it.
    """
    cls = db.get(Classification, ep.id)
    blast_row = db.get(Blast, ep.id)
    cdri_row = db.get(Cdri, ep.id)

    # The fingerprint comes first, before anything changes how the endpoint
    # behaves. Once the 410 lands the endpoint stops behaving like itself, and a
    # signature captured after that describes a retired endpoint rather than the
    # one being retired — so it would match every other retirement and none of
    # the redeployments it exists to catch.
    #
    # A failure here blocks the phase. Retiring without a fingerprint silently
    # removes resurrection detection for that endpoint: the endpoint is gone, the
    # capability is gone with it, and nothing anywhere reports that it happened.
    try:
        fp = _capture_fingerprint(db, ep, vday)
    except Exception as exc:  # noqa: BLE001
        return {"phase": "D", "blocked": True,
                "reason": f"fingerprint capture failed: {type(exc).__name__}: {exc}"[:300],
                "remedy": "the endpoint keeps serving; retiring it without a "
                          "fingerprint would remove resurrection detection silently"}

    observations = db.execute(
        select(Observation).where(Observation.endpoint_id == ep.id)
    ).scalars().all()
    daily = db.execute(
        select(EndpointDaily).where(EndpointDaily.endpoint_id == ep.id)
    ).scalars().all()

    payload = {
        "endpoint": {"id": ep.id, "method": ep.method, "path": ep.path_template,
                     "service": ep.service.name, "host": ep.host, "port": ep.port,
                     "first_vday": ep.first_vday, "last_call_vday": ep.last_call_vday,
                     "total_calls": ep.total_calls,
                     "data_classes": list(ep.data_classes or [])},
        "classification": None if cls is None else {
            "lifecycle": cls.lifecycle.value, "governance": cls.governance.value,
            "confidence": cls.confidence.value, "vday": cls.vday},
        "blast": None if blast_row is None else {
            "tier": blast_row.tier.value, "direct_callers": blast_row.direct_callers,
            "hop2_callers": blast_row.hop2_callers, "affected": blast_row.affected,
            "in_graph": blast_row.in_graph},
        "cdri": None if cdri_row is None else {
            "score": cdri_row.score, "tier": cdri_row.tier.value, "parts": cdri_row.parts},
        "hidden_callers": dec.hidden_callers,
        # The full observation history. Labels only — the values were discarded
        # in kernel and have no representation anywhere on this path.
        "observations": [
            {"vday": o.vday, "wall_ts": o.wall_ts, "method": o.method,
             "path_raw": o.path_raw, "status": o.status, "direction": o.direction,
             "peer_service": o.peer_service, "data_classes": o.data_classes}
            for o in observations],
        "endpoint_daily": [
            {"vday": d.vday, "calls": d.calls, "err_calls": d.err_calls,
             "distinct_peers": d.distinct_peers, "p95_latency_us": d.p95_latency_us}
            for d in daily],
        "archived_vday": vday,
    }

    try:
        object_uri, retain_until = worm.archive(
            f"decommission/{ep.id}/{vday}.json.gz", payload)
    except Exception as exc:  # noqa: BLE001 — any archive failure blocks the phase
        return {"phase": "D", "blocked": True,
                "reason": f"WORM archive unavailable: {type(exc).__name__}: {exc}"[:300],
                "remedy": "the endpoint keeps serving; retirement cannot proceed "
                          "without an archived history"}

    dec.worm_object = object_uri
    dec.worm_retain_until = retain_until

    # 410, not 404. This URL existed and was intentionally removed, which is
    # information a client is entitled to.
    gateway_result = None
    if route_name:
        try:
            control_plane.apply(
                db, endpoint_id=ep.id, route_name=route_name,
                kind="request-termination",
                plugin_config=kong.gone_410(f"{ep.method} {ep.path_template} was retired"),
                origin_stage=11, actor=actor)
            gateway_result = "410"
        except control_plane.ApplyFailed as exc:
            gateway_result = f"failed: {exc}"[:200]

    # The honeypot, last and conditionally.
    #
    # Three things must all be true, and each is checked rather than assumed:
    # the institution has signed off in the policy record, an upstream is
    # configured, and the gateway accepts the route. Any of them false leaves the
    # 410 in place — which is a complete retirement, just without intelligence
    # collection. The certificate then says so, because the previous version of
    # this code asserted honeypot_activated: true on the strength of a boolean
    # nobody acted on.
    signed, signoff_ref = _signoff(db)
    honeypot: dict | None = None
    honeypot_reason: str | None = None
    if not signed:
        honeypot_reason = ("no legal sign-off recorded in "
                           "policy_setting.honeypot_legal_signoff")
    elif not settings.honeypot_upstream:
        honeypot_reason = "no honeypot upstream configured"
    elif gateway_result != "410":
        # Without the 410 having been applied, the route still reaches the real
        # upstream and the sunset sequence did not complete. Activating a
        # honeypot from that state would mean the endpoint went straight from
        # live to fabricating data.
        honeypot_reason = f"410 not in place ({gateway_result}); honeypot withheld"
    else:
        try:
            # The 410 comes off first. It is attached to the very route being
            # repointed and answers before the upstream is consulted, so leaving
            # it on leaves the honeypot live, correctly configured, and dark.
            for control in control_plane.active_for(db, ep.id, kind="request-termination"):
                control_plane.revert(db, control, actor=actor,
                                     reason="superseded by honeypot activation")
            honeypot = kong.honeypot_route(
                ep.id, ep.path_template, ep.method, settings.honeypot_upstream,
                route_name=route_name)
            gateway_result = "honeypot"
        except Exception as exc:  # noqa: BLE001
            honeypot_reason = f"{type(exc).__name__}: {exc}"[:200]

    # Silence in watched vdays, the same measure classification used to call this
    # a zombie. The raw clock difference would put a larger number on the
    # certificate than the evidence supports — 1,031 where 95 vdays were
    # actually observed — and the certificate is the document that outlives the
    # endpoint and is read when somebody asks why it was removed.
    captured = _captured_vdays(db)
    evidence = decommission.Evidence(
        silent_vdays=(
            None if ep.last_call_vday is None
            else sum(1 for v in captured if v > ep.last_call_vday)
        ),
        confidence=cls.confidence.value if cls else "UNKNOWN",
        blast={} if blast_row is None else {
            "tier": blast_row.tier.value,
            "direct_callers": blast_row.direct_callers,
            "in_graph": blast_row.in_graph},
        hidden_callers_found=len(dec.hidden_callers or []),
        phases=[{"phase": dec.phase.value, "entered_vday": dec.entered_vday}],
        cdri_at_retirement=None if cdri_row is None else round(cdri_row.score, 4),
        worm_object=object_uri,
        worm_retain_until=retain_until.isoformat(),
        # What was actually done, not what was intended. A certificate is the
        # document that outlives the endpoint and is read when somebody asks
        # why it was removed; an unconditional `true` here made it the one
        # place in the system asserting something no code had checked.
        honeypot_activated=honeypot is not None,
        honeypot_legal_signoff=signoff_ref if signed else None,
    )
    body = decommission.certificate_body(ep, ep.service.name, vday, evidence)
    content_hash = hashlib.blake2b(
        audit.canonical_json(body).encode(), digest_size=32).digest()

    cert_id = "cert_" + hashlib.blake2s(
        f"{ep.id}:{vday}".encode(), digest_size=8).hexdigest()
    db.add(Certificate(id=cert_id, endpoint_id=ep.id, body=body,
                       content_hash=content_hash, worm_object=object_uri,
                       approved_by=actor))

    dec.phase = Phase.RETIRED
    dec.phase_vday = vday
    dec.certificate_id = cert_id
    ep.retired = True
    # Set only when a route actually exists. The honeypot service reads this
    # column to decide what it will answer for, so a true here with no route is
    # a service advertising a capability it does not have.
    ep.honeypot_active = honeypot is not None

    # The hash goes to the ledger, so the certificate is tamper-evident
    # independently of the row that holds it.
    audit.record(db, actor=actor, action="endpoint.retired", target=ep.id,
                 detail={"certificate_id": cert_id,
                         "content_hash": content_hash.hex(),
                         "worm_object": object_uri,
                         "worm_retain_until": retain_until.isoformat(),
                         "hidden_callers": len(dec.hidden_callers or []),
                         "gateway": gateway_result,
                         "honeypot": honeypot,
                         "honeypot_withheld": honeypot_reason})

    return {"phase": "D", "retired": True, "certificate_id": cert_id,
            "worm_object": object_uri,
            "worm_retain_until": retain_until.isoformat(),
            "gateway": gateway_result,
            "honeypot": honeypot,
            "honeypot_withheld": honeypot_reason,
            "fingerprint": {"shingles": len(fp.shingles or []),
                            "observations": (fp.features or {}).get("observations", 0),
                            "has_schema": (fp.features or {}).get("has_schema", False)},
            "hidden_callers": len(dec.hidden_callers or [])}


def stage_11_decommission(db: Session, vday: int) -> StageOutcome:
    """Enrol what is eligible, advance what is due, retire what an operator released.

    Nothing advances into Phase D on a timer. Archival and a 410 are
    irreversible in effect, so the final transition needs a human to have looked
    at the hidden callers the quarantine surfaced. This runner performs that
    transition only for decommissions an approver has already released, which
    the API's advance route records.
    """
    actor = "system:stage-11"
    snapshot = gateway.collect()

    enrolled = advanced = retired = held = blocked = 0
    refused: dict[str, int] = defaultdict(int)
    details: list[dict] = []

    candidates = db.execute(
        select(Endpoint).where(Endpoint.retired.is_(False))
    ).scalars().all()

    for ep in candidates:
        cls = db.get(Classification, ep.id)
        blast_row = db.get(Blast, ep.id)
        dec = db.get(Decommission, ep.id)

        if dec is None:
            try:
                decommission.eligible(ep, cls, blast_row)
            except decommission.NotEligible as exc:
                refused[exc.code] += 1
                continue

            path = decommission.select_path(blast_row)
            dec = Decommission(endpoint_id=ep.id, phase=Phase.NONE,
                               express=path.express, canary=path.canary,
                               entered_vday=vday, phase_vday=vday,
                               hidden_callers=[])
            db.add(dec)
            db.flush()
            enrolled += 1
            audit.record(db, actor=actor, action="decommission.enrolled", target=ep.id,
                         detail={"path": path.name, "express": path.express,
                                 "canary": path.canary,
                                 "blast_tier": blast_row.tier.value,
                                 "confidence": cls.confidence.value})
            details.append({"endpoint": f"{ep.method} {ep.path_template}",
                            "action": "enrolled", "path": path.name})

        if dec.hold:
            held += 1
            continue
        if dec.phase in (Phase.RETIRED, Phase.REVERTED):
            continue

        path = decommission.Path(express=dec.express, canary=dec.canary)
        route_name = _route_for(snapshot, ep) if snapshot.healthy else None

        # Quarantine watches for callers on every pass, not only on transition.
        if dec.phase is Phase.C:
            found = _record_hidden_callers(db, dec, ep, dec.phase_vday or vday)
            if found:
                details.append({"endpoint": f"{ep.method} {ep.path_template}",
                                "action": "hidden-caller",
                                "callers": [c["service"] for c in dec.hidden_callers]})

        upcoming = decommission.next_phase(dec.phase, path)
        if upcoming is None:
            continue
        if not decommission.due(vday, dec.phase_vday, dec.phase) and dec.phase is not Phase.NONE:
            continue
        if not decommission.may_auto_advance(upcoming) and not dec.released_for_phase_d:
            details.append({"endpoint": f"{ep.method} {ep.path_template}",
                            "action": "awaiting-release",
                            "reason": "phase D is irreversible in effect and needs "
                                      "an approver to release it"})
            continue

        if upcoming is Phase.D:
            outcome = _complete_phase_d(db, dec, ep, route_name, vday, actor)
            if outcome.get("blocked"):
                blocked += 1
            else:
                retired += 1
            outcome["endpoint"] = f"{ep.method} {ep.path_template}"
            details.append(outcome)
        else:
            outcome = _enter_phase(db, dec, ep, upcoming, path, route_name, vday, actor)
            outcome["endpoint"] = f"{ep.method} {ep.path_template}"
            advanced += 1
            details.append(outcome)

    db.flush()
    return StageOutcome(11, enrolled + advanced + retired, 0, {
        "gateway_healthy": snapshot.healthy,
        "enrolled": enrolled, "advanced": advanced, "retired": retired,
        "on_hold": held, "blocked": blocked,
        "not_eligible": dict(refused),
        "results": details,
    })



# ─────────────────────────────────────────────────────────────────────────────
# Stage 12 — Honeypot and resurrection detection
# ─────────────────────────────────────────────────────────────────────────────
def _signoff(db: Session) -> tuple[bool, str]:
    """The one-time legal authorisation for honeypot activation.

    Read from ``policy_setting``, not from configuration. An environment
    variable is set by whoever deploys; this record is set by whoever is
    accountable, and the distinction is the entire point of the guardrail. The
    default seeded at bootstrap is ``signed: false``, so the honeypot is off
    until somebody signs it on.
    """
    row = db.get(PolicySetting, "honeypot_legal_signoff")
    if row is None:
        return False, ""
    value = row.value or {}
    reference = value.get("reference") or ""
    return bool(value.get("signed")) and bool(reference), reference


def _band(value: float | None, edges: tuple[float, ...], names: tuple[str, ...]) -> str:
    """Bucket a magnitude.

    Fingerprints compare a redeployed endpoint against its retired original, and
    the redeployment never serves byte-identical volumes. Banding is what makes
    "the same behaviour at slightly different scale" match; exact values would
    make every comparison fail on noise.
    """
    if value is None:
        return "unknown"
    for edge, name in zip(edges, names):
        if value <= edge:
            return name
    return names[-1]


_SIZE_EDGES = (256.0, 1024.0, 8192.0, 65536.0)
_SIZE_NAMES = ("tiny", "small", "medium", "large", "huge")


def _behaviour_profile(db: Session, ep: Endpoint) -> dict:
    """What the endpoint does, assembled from what was actually observed.

    Only real captures count. ``Source.EBPF`` excludes the collector rows that
    represent a gateway route or a WSDL operation — those describe a declared
    surface, not behaviour — and ``synthetic == False`` excludes the Judge's own
    replayed traffic. A fingerprint built from SENTRY's probing would describe
    SENTRY, and would then match every other endpoint SENTRY had probed.
    """
    rows = db.execute(
        select(Observation).where(
            Observation.endpoint_id == ep.id,
            Observation.source == Source.EBPF,
            Observation.synthetic.is_(False),
        )
    ).scalars().all()

    hour_shape = [0] * 24
    req_sizes: list[int] = []
    resp_sizes: list[int] = []
    auth_missing = 0
    for o in rows:
        hour_shape[o.wall_ts.hour] += 1
        if o.req_bytes:
            req_sizes.append(o.req_bytes)
        if o.resp_bytes:
            resp_sizes.append(o.resp_bytes)
        if not o.auth_present:
            auth_missing += 1

    callers = [
        name for (name,) in db.execute(
            select(Service.name)
            .join(CallEdge, CallEdge.caller_service_id == Service.id)
            .where(CallEdge.endpoint_id == ep.id)
            .distinct()
        )
    ]

    # Response field names, observed.
    #
    # These used to be unavailable: the kernel matched bodies against data-class
    # patterns and discarded them, so the only schema was whatever a contract
    # source happened to declare — and for the endpoints stage 12 exists to catch
    # there is no contract, because a resurrection is by definition undocumented.
    # The classifier now carries the key names out with the class mask, and this
    # is the union of what was actually seen.
    #
    # Union across observations, not intersection: a response that omits an
    # optional field is still the same surface, and intersecting would erode the
    # signature towards whatever every single response happened to share.
    observed_fields: set[str] = set()
    for o in rows:
        observed_fields.update(o.response_fields or [])

    # A declared contract still contributes where one exists. It describes the
    # same surface from the other side, and an endpoint whose WSDL names a field
    # the sensor has not yet seen is not a different endpoint.
    for src in db.execute(
        select(EndpointSource).where(EndpointSource.endpoint_id == ep.id)
    ).scalars():
        fields = (src.detail or {}).get("response_fields")
        if fields:
            observed_fields.update(fields)

    response_fields = sorted(observed_fields)

    missing_ratio = (auth_missing / len(rows)) if rows else None
    median = lambda xs: sorted(xs)[len(xs) // 2] if xs else None  # noqa: E731

    return {
        "method": ep.method,
        "response_fields": response_fields,
        "data_classes": sorted(ep.data_classes or []),
        "callers": sorted(callers),
        "hour_shape": hour_shape,
        "auth": ep.auth.value if ep.auth else "none",
        "auth_missing_band": _band(missing_ratio, (0.0, 0.02, 0.20),
                                   ("none", "rare", "frequent", "mostly")),
        "req_size_band": _band(median(req_sizes), _SIZE_EDGES, _SIZE_NAMES),
        "resp_size_band": _band(median(resp_sizes), _SIZE_EDGES, _SIZE_NAMES),
        # Provenance for the audit route. A fingerprint built from four
        # observations is a weak one, and the operator reading a 0.91 similarity
        # is entitled to know that.
        "observations": len(rows),
        "has_schema": bool(response_fields),
    }


def _capture_fingerprint(db: Session, ep: Endpoint, vday: int) -> Fingerprint:
    """Record the behavioural signature. Must run before behaviour changes.

    Called from Phase D ahead of the 410, because the moment the termination
    plugin lands the endpoint stops behaving like itself: calls fail, sizes
    collapse, callers drop away. A fingerprint taken afterwards describes a
    retired endpoint, and would match every other retired endpoint rather than
    the redeployment it exists to catch.
    """
    profile = _behaviour_profile(db, ep)
    if not profile["observations"]:
        # A signature built from no observations is not a weak signature, it is
        # a description of the default profile — and it matches every other
        # endpoint that also has nothing to say. Two of those scored 0.9167
        # against unrelated live endpoints.
        #
        # This is reachable in normal operation: retention prunes observations
        # on a window measured in vdays, and at a compressed clock scale that
        # window can elapse before a lifecycle completes. Refusing here turns a
        # silently useless fingerprint into a blocked Phase D with a reason.
        raise ValueError(
            f"no captured observations remain for {ep.method} {ep.path_template}; "
            f"a fingerprint built from none would match every other endpoint "
            f"with no history")

    shingles = fingerprint.behavioural_shingles(profile)
    minhash = fingerprint.build_minhash(shingles)

    row = db.get(Fingerprint, ep.id)
    if row is None:
        row = Fingerprint(endpoint_id=ep.id)
        db.add(row)
    row.minhash = fingerprint.serialise(minhash)
    row.features = profile
    row.shingles = shingles
    row.captured_vday = vday
    row.origin_path = ep.path_template
    row.origin_method = ep.method
    db.flush()
    return row


def _load_index(db: Session) -> tuple[fingerprint.ResurrectionIndex, int]:
    """Rebuild the LSH index from Postgres.

    Rebuilt every scan rather than cached in Redis and trusted. The design
    permits a Redis-backed index for sub-linear lookup at estate scale; at this
    estate's size the rebuild costs milliseconds, and rebuilding is exactly what
    the "survives a Redis flush" requirement asks for. What must never happen is
    an empty index being reported as "no matches" — so the count of loaded
    fingerprints is returned and the caller states it.
    """
    index = fingerprint.ResurrectionIndex()
    loaded = 0
    for row in db.execute(select(Fingerprint)).scalars():
        index.insert(row.endpoint_id, list(row.shingles or []), row.origin_path)
        loaded += 1
    return index, loaded


def stage_12_threat(db: Session, vday: int) -> StageOutcome:
    """Scan the live estate against the fingerprints of everything retired.

    An endpoint that was retired and has come back under a new path is the thing
    being detected, and the path is the attacker's variable — so the comparison
    is on behaviour only and the alert names the original path, which is what
    makes the rename visible to the operator.
    """
    actor = "system:stage-12"
    index, loaded = _load_index(db)

    live = db.execute(
        select(Endpoint).where(Endpoint.retired.is_(False))
    ).scalars().all()

    alerts: list[dict] = []
    scanned = 0
    if loaded:
        for ep in live:
            profile = _behaviour_profile(db, ep)
            # An endpoint with no captured traffic has no behaviour to compare.
            # Scoring it would compare two mostly-empty shingle sets, which are
            # highly similar to each other for reasons that are not evidence of
            # anything.
            if not profile["observations"]:
                continue
            scanned += 1
            shingles = fingerprint.behavioural_shingles(profile)
            for hit in index.query(shingles):
                if not hit["alert"] or hit["endpoint_id"] == ep.id:
                    continue
                origin = db.get(Fingerprint, hit["endpoint_id"])
                existing = db.execute(
                    select(ResurrectionAlert).where(
                        ResurrectionAlert.new_endpoint_id == ep.id,
                        ResurrectionAlert.origin_endpoint_id == hit["endpoint_id"],
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    continue
                db.add(ResurrectionAlert(
                    new_endpoint_id=ep.id,
                    origin_endpoint_id=hit["endpoint_id"],
                    origin_path=hit["origin_path"],
                    similarity=hit["similarity"],
                    threshold=index.threshold,
                    lsh_hit=hit["lsh_hit"],
                    vday=vday,
                ))
                audit.record(db, actor=actor, action="resurrection.alerted",
                             target=ep.id,
                             detail={"origin_endpoint_id": hit["endpoint_id"],
                                     "origin_path": hit["origin_path"],
                                     "similarity": hit["similarity"],
                                     "threshold": index.threshold,
                                     "lsh_hit": hit["lsh_hit"]})
                alerts.append({
                    "new_endpoint": f"{ep.method} {ep.path_template}",
                    "origin_path": hit["origin_path"],
                    "similarity": hit["similarity"],
                    "lsh_hit": hit["lsh_hit"]})

    signed, reference = _signoff(db)
    active = db.execute(
        select(func.count()).select_from(Endpoint)
        .where(Endpoint.honeypot_active.is_(True))
    ).scalar_one()
    probes = db.execute(
        select(func.count()).select_from(Probe).where(Probe.vday == vday)
    ).scalar_one()
    sources = db.execute(
        select(func.count(func.distinct(Probe.source_ip)))
    ).scalar_one()

    detail = {
        "fingerprints": loaded,
        "endpoints_scanned": scanned,
        "alerts": alerts,
        "honeypots_active": active,
        "probes_vday": probes,
        "unique_sources": sources,
        "threshold": index.threshold,
        "signoff": reference if signed else None,
    }
    if not loaded:
        # Distinguished from "nothing matched". Nothing has been retired yet, so
        # there is no signature to match against, and reporting zero alerts
        # without saying so would present an unarmed detector as a clean scan.
        detail["withheld"] = ("no fingerprints captured; nothing has completed "
                              "Phase D, so there is no signature to match against")
    return StageOutcome(12, len(alerts), 0, detail)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 13 — Zero-Trust posture
# ─────────────────────────────────────────────────────────────────────────────
#: Remedy key -> the config generator that produces it.
#:
#: Every one of these already exists for stage 10. Stage 13 chooses which gaps
#: to close and in what order; it does not invent gateway configuration, and it
#: has no actuator of its own.
_ZT_GENERATORS = {
    "rate-limit": lambda ep, peak: kong.rate_limit(remediation.rate_limit_for(peak)),
    "tls-min": lambda ep, peak: kong.tls_min(settings.zt_tls_floor),
    "response-mask": lambda ep, peak: kong.response_mask(
        remediation.mask_fields_for(list(ep.data_classes or []))),
    "oauth2": lambda ep, peak: kong.oauth2(),
    "mtls": lambda ep, peak: kong.mtls(),
    "dpop": lambda ep, peak: kong.dpop(),
}

#: Remedy key -> the control kind recorded on the row. Distinct from the plugin
#: name: two remedies can produce a pre-function, and an operator reverting one
#: needs to know which.
_ZT_KINDS = {
    "rate-limit": "rate-limit", "tls-min": "tls-min", "response-mask": "response-mask",
    "oauth2": "oauth2", "mtls": "mtls-auth", "dpop": "dpop",
}


def _applied_kinds(db: Session) -> dict[str, set[str]]:
    """What is on the gateway, by endpoint.

    APPLIED only. A PROPOSED control is a plan, and reporting an endpoint as
    protected by a plan is the fiction this system exists not to produce.
    """
    out: dict[str, set[str]] = defaultdict(set)
    for c in db.execute(
        select(Control).where(Control.state == ControlState.APPLIED)
    ).scalars():
        out[c.endpoint_id].add(c.kind)
    return out


def assess_endpoint(db: Session, ep: Endpoint,
                    applied: dict[str, set[str]] | None = None) -> zerotrust.Posture:
    kinds = (applied if applied is not None else _applied_kinds(db)).get(ep.id, set())
    cdri_row = db.get(Cdri, ep.id)
    return zerotrust.assess(ep, ep.service.criticality, kinds,
                            priority=cdri_row.score if cdri_row else 0.0)


def harden_endpoint(db: Session, ep: Endpoint, vday: int, *, actor: str,
                    dry_run: bool = False) -> dict:
    """Close an endpoint's control gaps through the stage 10 pipeline.

    Generate, judge, apply — the same three phases, the same actuator, the same
    audit events. A control applied from here has been differentially tested
    exactly like one applied from the remediation queue, because it went through
    the same code.

    Each control is judged on its own and a rejection skips only that control.
    Stopping partway is why the order matters: the gaps that cannot break a
    caller are closed first, so a run that gets three of five in leaves the
    endpoint better off than it started.
    """
    before = assess_endpoint(db, ep)
    gaps = zerotrust.plan(before)

    if dry_run:
        return {"endpoint_id": ep.id, "posture": before.as_dict(),
                "would_apply": [{"control": g.key, "remedy": g.remedy,
                                 "requires_migration": g.requires_migration}
                                for g in gaps]}

    snapshot = gateway.collect()
    route_name = _route_for(snapshot, ep) if snapshot.healthy else None
    if route_name is None:
        return {"endpoint_id": ep.id, "posture": before.as_dict(), "controls": [],
                "blocked": "no gateway route fronts this endpoint, so no gateway "
                           "control can reach it"}

    peak = _peak_calls(db, ep.id, vday)
    obs = db.execute(
        select(Observation)
        .where(Observation.endpoint_id == ep.id,
               Observation.source == Source.EBPF,
               Observation.synthetic.is_(False))
        .order_by(Observation.vday.desc())
        .limit(settings.judge_max_requests)
    ).scalars().all()
    shapes = replay.requests_from_observations(
        [{"method": o.method, "path_raw": o.path_raw, "auth_scheme": o.auth_scheme}
         for o in obs],
        settings.judge_replay_shapes,
        path_template=ep.path_template,
        schema=ep.request_schema)

    results: list[dict] = []
    for gap in gaps:
        generator = _ZT_GENERATORS.get(gap.remedy)
        kind = _ZT_KINDS.get(gap.remedy, gap.remedy)
        if generator is None:
            results.append({"control": gap.key, "remedy": gap.remedy,
                            "state": "NO_GENERATOR"})
            continue

        config = generator(ep, peak)
        if not config.get("config", {}) and gap.remedy == "response-mask":
            results.append({"control": gap.key, "remedy": gap.remedy,
                            "state": "SKIPPED",
                            "reason": "no field-name mapping for the detected classes"})
            continue

        existing = db.execute(
            select(Control).where(
                Control.endpoint_id == ep.id, Control.kind == kind,
                Control.state.in_([ControlState.APPLIED, ControlState.REJECTED]))
        ).scalars().first()
        if existing is not None:
            results.append({"control": gap.key, "remedy": gap.remedy,
                            "state": existing.state.value,
                            "reason": "already decided at stage 10"})
            continue

        try:
            judged = replay.run(
                endpoint_id=ep.id, upstream_url=_upstream_url(ep),
                plugin_config=config, requests=shapes,
                criticality=ep.service.criticality.value)
        except replay.JudgeUnavailable as exc:
            # Measured nothing, so claims nothing — and nothing is applied.
            results.append({"control": gap.key, "remedy": gap.remedy,
                            "state": "UNMEASURED", "reason": str(exc)[:200]})
            continue

        run_row = JudgeRun(
            endpoint_id=ep.id, requests=judged.scores.requests,
            replay_exact=judged.replay_exact,
            replay_synthesised=judged.replay_synthesised,
            replay_bodyless=judged.replay_bodyless,
            schema_score=judged.scores.schema, latency_score=judged.scores.latency,
            error_score=judged.scores.error, exposure_score=judged.scores.exposure,
            verdict=judged.verdict, reason=",".join(judged.scores.failing) or None,
            latency_delta_us=judged.scores.latency_delta_us,
            budget_us=judged.scores.budget_us, diff_summary=judged.diff_summary)
        db.add(run_row)
        db.flush()

        if judged.verdict != "PASS":
            rejected = Control(
                endpoint_id=ep.id, kind=kind, plugin_config=config,
                state=ControlState.REJECTED, judge_run_id=run_row.id,
                origin_stage=13, actor=actor,
                error="judge rejected: " + ", ".join(judged.scores.failing))
            db.add(rejected)
            db.commit()
            results.append({"control": gap.key, "remedy": gap.remedy,
                            "state": "REJECTED", "failing": judged.scores.failing,
                            "requests": judged.scores.requests})
            continue

        try:
            control = control_plane.apply(
                db, endpoint_id=ep.id, route_name=route_name, kind=kind,
                plugin_config=config, origin_stage=13, actor=actor,
                judge_run_id=run_row.id)
        except control_plane.ApplyFailed as exc:
            results.append({"control": gap.key, "remedy": gap.remedy,
                            "state": "FAILED", "reason": str(exc)[:200]})
            continue

        results.append({"control": gap.key, "remedy": gap.remedy, "state": "APPLIED",
                        "kong_plugin_id": control.kong_plugin_id,
                        "requests": judged.scores.requests})

    db.flush()
    after = assess_endpoint(db, ep)
    return {"endpoint_id": ep.id,
            **zerotrust.summarise(results, before, after)}


def stage_13_zerotrust(db: Session, vday: int) -> StageOutcome:
    """Assess every live endpoint against the five controls.

    Assessment only. Hardening is an approver's decision made per endpoint
    through the API, because four of the five remedies can break a caller and
    the fifth is only free because it is additive. A pipeline pass that hardened
    the estate on a schedule would apply authentication to every unprovisioned
    consumer in it.
    """
    applied = _applied_kinds(db)
    eps = db.execute(select(Endpoint).where(Endpoint.retired.is_(False))).scalars().all()

    distribution = {i: 0 for i in range(6)}
    gaps = {k: 0 for k in ("auth", "tls", "binding", "ratelimit", "response")}
    postures: list[dict] = []

    for ep in eps:
        posture = assess_endpoint(db, ep, applied)
        distribution[posture.satisfied] += 1
        for control in posture.gaps:
            gaps[control.key] += 1
        postures.append(posture.as_dict())

    postures.sort(key=lambda p: (-p["priority"], p["satisfied"]))
    return StageOutcome(13, len(eps), 0, {
        "distribution": distribution,
        "gaps": gaps,
        # Retired endpoints have no posture to improve, and counting them would
        # make the estate look worse every time it got better.
        "assessed": len(eps),
        "worst": postures[:3],
    })



# ─────────────────────────────────────────────────────────────────────────────
# Stage 14 — Continuous operations
# ─────────────────────────────────────────────────────────────────────────────
def _siem_events(db: Session, vday: int) -> list[siem.Event]:
    """What this cycle is worth telling the security team about.

    Deliberately not everything. A feed that reports every endpoint every cycle
    is one an analyst filters out on day three, and a filtered feed is the same
    as no feed. These are the states that changed or that carry an active risk.
    """
    events: list[siem.Event] = []

    rows = db.execute(
        select(Endpoint, Classification, Cdri, Service)
        .join(Classification, Classification.endpoint_id == Endpoint.id)
        .join(Service, Service.id == Endpoint.service_id)
        .outerjoin(Cdri, Cdri.endpoint_id == Endpoint.id)
        .where(Endpoint.retired.is_(False))
    ).all()

    for ep, cls, score, svc in rows:
        frameworks = []
        finding = db.get(Finding, ep.id)
        if finding is not None:
            frameworks = [c.get("framework", "") for c in (finding.citations or [])]

        common = dict(endpoint_id=ep.id, method=ep.method, path=ep.path_template,
                      service=svc.name,
                      cdri=None if score is None else score.score,
                      frameworks=[f for f in frameworks if f],
                      time_to_breach_d=None if score is None else score.time_to_breach_d)

        if cls.lifecycle is Lifecycle.ZOMBIE and score is not None \
                and score.tier in (Tier.CRITICAL, Tier.HIGH):
            events.append(siem.Event(
                name="ZOMBIE_CRITICAL",
                message=f"Zombie endpoint scoring {score.tier.value}", **common))

        if cls.governance is Governance.SHADOW:
            events.append(siem.Event(
                name="SHADOW_DETECTED",
                message="Endpoint serving traffic with no gateway route and no "
                        "code reference", **common))

    # A caller reaching a quarantined endpoint is an undiscovered dependency and
    # the most actionable thing this system produces in a cycle.
    for dec in db.execute(
        select(Decommission).where(Decommission.phase == Phase.C)
    ).scalars():
        for caller in dec.hidden_callers or []:
            ep = db.get(Endpoint, dec.endpoint_id)
            events.append(siem.Event(
                name="QUARANTINE_HIT",
                message=f"Quarantined endpoint called by {caller.get('service')}",
                endpoint_id=dec.endpoint_id,
                method=ep.method if ep else None,
                path=ep.path_template if ep else None,
                src=caller.get("ip"),
                extra={"calls": caller.get("calls", 0)}))

    return events


def _leaderboard_rows(db: Session) -> list[dict]:
    rows = db.execute(
        select(Endpoint, Service, Classification, Cdri, Ownership)
        .join(Service, Service.id == Endpoint.service_id)
        .outerjoin(Classification, Classification.endpoint_id == Endpoint.id)
        .outerjoin(Cdri, Cdri.endpoint_id == Endpoint.id)
        .outerjoin(Ownership, Ownership.endpoint_id == Endpoint.id)
        .where(Endpoint.retired.is_(False))
    ).all()

    return [{
        "team": svc.team,
        "lifecycle": cls.lifecycle.value if cls else None,
        "governance": cls.governance.value if cls else None,
        "pre_zombie": bool(cls.pre_zombie) if cls else False,
        "cdri_score": score.score if score else 0.0,
        "cdri_tier": score.tier.value if score else None,
        # Resolved by the ladder, or merely declared on the service. The
        # leaderboard discounts the first kind and not the second.
        "owner_resolved": bool(own and own.resolved_by
                               and own.resolved_by != "unresolved"),
        "ownership_confidence": own.confidence if own else None,
    } for _ep, svc, cls, score, own in rows]


def stage_14_operations(db: Session, vday: int) -> StageOutcome:
    """Emit to the SIEM and refresh the leaderboard.

    Everything here reads. The one thing it writes is to somebody else's
    system, and if that system is unreachable the events are spooled rather than
    dropped — a cycle that could not reach the SIEM still ran, and the alerts it
    raised are still owed.
    """
    emitter = siem.default_emitter()

    events = _siem_events(db, vday)
    delivered = sum(1 for e in events if emitter.emit(e))

    board = operations.leaderboard(_leaderboard_rows(db))

    return StageOutcome(14, len(events), 0, {
        "siem": {"events": len(events), "delivered": delivered,
                 **emitter.stats()},
        "leaderboard": board,
        "by_event": {name: sum(1 for e in events if e.name == name)
                     for name in {e.name for e in events}},
    })


#: Shingle prefixes a route declaration can supply. Everything else in a
#: behavioural fingerprint — rhythm, callers, sizes, auth-miss ratio — is
#: observed at runtime and is simply not knowable from a diff.
DECLARABLE_PREFIXES = ("method:", "field:", "class:")


def _project(shingles: list[str]) -> set[str]:
    return {s for s in shingles if s.startswith(DECLARABLE_PREFIXES)}


def _declarable_shingles(decl, raw: dict) -> set[str]:
    """What the pull request itself asserts about the surface.

    Response fields and data classes come from the extractor where it can see
    them. Where it cannot, the comparison rests on method alone and will not
    reach the threshold — which is the honest outcome: a route declaration that
    reveals nothing about what it returns cannot be shown to be a resurrection.
    """
    out = {f"method:{decl.method.upper()}"}
    for field in raw.get("response_fields") or []:
        out.add(f"field:{field}")
    for dc in raw.get("data_classes") or []:
        out.add(f"class:{dc}")
    return out


def run_gate(db: Session, *, repo: str, pr_number: int, commit_sha: str,
             routes: list[dict], fail_on: str | None = None) -> dict:
    """The CI pre-merge gate.

    Every other stage finds zombies after they exist. This one refuses the next
    generation at the pull request, while the person who wrote it still
    remembers why.

    The resurrection check is matched against real retired endpoints in this
    database, not against a list the caller supplied — a gate that trusts CI to
    tell it what has been retired can be talked out of its own finding.
    """
    declarations = [
        operations.RouteDeclaration(
            method=r.get("method", "GET"), path=r.get("path", "/"),
            file=r.get("file"), line=r.get("line"), owner=r.get("owner"),
            has_auth_middleware=bool(r.get("has_auth_middleware")),
            in_catalogue=bool(r.get("in_catalogue")),
            tls_floor=r.get("tls_floor"))
        for r in routes
    ]

    retired = db.execute(
        select(Endpoint).where(Endpoint.retired.is_(True))
    ).scalars().all()

    matches: dict[str, list[dict]] = {}
    for decl, raw in zip(declarations, routes):
        key = f"{decl.method.upper()} {decl.path}"
        declared = _declarable_shingles(decl, raw)
        for old in retired:
            stored = db.get(Fingerprint, old.id)
            if stored is None:
                # Nothing to compare against. Recorded as an abstention rather
                # than scored zero: a retired endpoint whose fingerprint was
                # never captured cannot be matched, and reporting 0.0 would
                # present "we cannot tell" as "definitely not a resurrection".
                matches.setdefault(key, []).append(
                    {"path": old.path_template, "endpoint_id": old.id,
                     "score": None, "reason": "no fingerprint captured"})
                continue

            # Projected onto the features a *declaration* can supply.
            #
            # A pull request has no behaviour: no traffic, no callers, no
            # rhythm, no observed payload sizes. Comparing a diff against a full
            # behavioural fingerprint compares a handful of shingles against
            # thirty and scores near zero for every route, which is why this
            # check passed a redeployment that stage 12 later matched at 1.00.
            # Both sides are reduced to what is knowable at authorship — method,
            # response fields, and the data classes those fields imply — and
            # compared on that.
            projected = _project(list(stored.shingles or []))
            union = declared | projected
            score = (len(declared & projected) / len(union)) if union else 0.0
            matches.setdefault(key, []).append(
                {"path": old.path_template, "endpoint_id": old.id,
                 "score": round(score, 4),
                 "compared_on": sorted(projected)})

    result = operations.run_gate(declarations, matches)
    event = GateEvent(repo=repo, pr_number=pr_number, commit_sha=commit_sha,
                      checks=[c.as_dict() for c in result.checks],
                      passed=result.passed(fail_on))
    db.add(event)
    db.commit()

    return result.as_dict(fail_on)


STAGES = {
    # Kernel capture is the agent's job and runs continuously; what belongs to
    # a pipeline pass is polling the registries the sensor cannot see.
    1: stage_01_collectors,
    2: stage_02_baseline,
    3: stage_03_correlation,
    4: stage_04_classification,
    5: stage_05_behaviour,
    6: stage_06_cdri,
    7: stage_07_forecast,
    8: stage_08_findings,
    9: stage_09_blast,
    10: stage_10_remediation,
    11: stage_11_decommission,
    12: stage_12_threat,
    13: stage_13_zerotrust,
    14: stage_14_operations,
}


def run_all(db: Session, run_id: int | None = None) -> list[StageOutcome]:
    """Execute every stage in dependency order.

    Order comes from the DAG, so stage 05 provably precedes 06 and the CDRI
    formula never reads an input that has not been produced.
    """
    vday = clock.current_vday(db)
    completed: set[int] = set()
    failed: set[int] = set()
    outcomes: list[StageOutcome] = []

    for stage in pipeline.topological_order():
        fn = STAGES.get(stage)
        if fn is None:
            continue

        # A stage whose input never got produced is skipped, not run on stale
        # data. Running stage 06 after stage 05 failed would score every
        # endpoint against last cycle's anomaly term and report the result as
        # this cycle's.
        blocked = pipeline.STAGE_DEPS.get(stage, frozenset()) & failed
        if blocked:
            failed.add(stage)
            outcome = StageOutcome(stage, 0, 0, {
                "skipped": True,
                "reason": f"depends on stage(s) {sorted(blocked)}, which failed"})
            outcomes.append(outcome)
            if run_id is not None:
                db.add(StageRun(run_id=run_id, stage=stage, vday=vday, records=0,
                                duration_ms=0, ok=False,
                                error=outcome.detail["reason"], detail=outcome.detail))
                db.commit()
            continue

        pipeline.check_dependencies(stage, completed)

        started = time.perf_counter()
        try:
            outcome = fn(db, vday)
        except Exception as exc:  # noqa: BLE001
            # One stage failing is not the cycle failing.
            #
            # Aborting here loses every stage after it, including the ones with
            # no dependency on the broken one — so a transient fault in the
            # forecast would take out the SIEM feed and the audit trail with it.
            # The cycle completes and reports partial.
            db.rollback()
            failed.add(stage)
            duration = int((time.perf_counter() - started) * 1000)
            detail = {"error": f"{type(exc).__name__}: {exc}"[:500]}
            outcomes.append(StageOutcome(stage, 0, duration, detail))
            if run_id is not None:
                db.add(StageRun(run_id=run_id, stage=stage, vday=vday, records=0,
                                duration_ms=duration, ok=False,
                                error=detail["error"], detail=detail))
                db.commit()
            continue

        outcome.duration_ms = int((time.perf_counter() - started) * 1000)
        db.commit()

        completed.add(stage)
        outcomes.append(outcome)

        if run_id is not None:
            db.add(StageRun(run_id=run_id, stage=stage, vday=vday,
                            records=outcome.records, duration_ms=outcome.duration_ms,
                            ok=True, detail=outcome.detail))
            db.commit()

    return outcomes


def scan_cycle(db: Session, *, trigger: str = "scheduled",
               actor: str | None = None) -> tuple[int, list[StageOutcome]]:
    """One recorded pass over the whole pipeline.

    The run row exists before the first stage and is closed after the last, so a
    process killed mid-cycle leaves a run with no ``finished_at`` — which is how
    an operator tells a cycle that crashed from one that is still going.
    """
    run = PipelineRun(trigger=trigger, actor=actor)
    db.add(run)
    db.commit()

    outcomes = run_all(db, run_id=run.id)

    run.finished_at = datetime.now(timezone.utc)
    run.ok = all(not o.detail.get("error") and not o.detail.get("skipped")
                 for o in outcomes)
    db.commit()
    return run.id, outcomes


def main() -> int:
    """One pipeline pass, for an operator or a cron entry.

    Reports every stage's record count and detail on stdout. A stage that
    produced nothing says so with its reason — withheld below baseline, gateway
    unreachable, model unfitted — because a silent zero and a deliberate
    abstention look identical otherwise, and only one of them is a problem.
    """
    import json
    import sys

    from sentry_core.clock import ensure_vclock
    from sentry_core.db import SessionLocal

    with SessionLocal() as db:
        # The clock is the analysis time base and every observation needs one.
        # Creating it here means a pass against a fresh database bootstraps
        # itself rather than failing on a missing row.
        ensure_vclock(db)
        db.commit()

        vday = clock.current_vday(db)
        print(f"vday {vday}")
        for outcome in run_all(db):
            print(f"stage {outcome.stage:02d}  records={outcome.records:<6} "
                  f"{outcome.duration_ms:>5}ms  {json.dumps(outcome.detail)}",
                  file=sys.stdout, flush=True)
        db.commit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
