"""Stage 10 phase 2 — the API Judge.

A patch is never applied without being measured against real traffic first.

**The shadow pair.** Two services are created in the running gateway, both
pointing at the endpoint's real upstream. One carries the proposed plugin; one
does not. Requests reconstructed from ``observation`` are replayed through both
and the responses compared. The pair is namespaced under a path no estate
caller uses and torn down when the run ends, so the measurement happens on the
gateway that will host the patch without the patch ever touching a live route.

**What is replayed, and what is not.** Method, path and header shape come from
the observation rows. **Request bodies are not replayed, because they were never
captured** — stage 01 discards payloads in kernel and there is no body to
replay. Where a declared schema exists a body is synthesised from it; where
neither exists, body-bearing methods go without one and are counted. Every run
reports its coverage rather than implying completeness.

That is a real tension and it was resolved deliberately: capturing payloads
would make replay perfect and would put customer financial data in the system.
The privacy property is worth more than replay fidelity.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field

from . import bodies, oidc

import httpx

from sentry_core.config import settings

from ..actuators import kong
from ..engines import judge_scoring

VERSION = "judge-1.0.0"


class JudgeUnavailable(RuntimeError):
    """The Judge could not run. Distinct from a patch that failed: a control is
    never marked PASS or REJECT on a run that did not happen."""


@dataclass
class ReplayRequest:
    method: str
    path: str
    auth_scheme: str | None = None
    #: True when a body-bearing method was replayed without one.
    bodyless: bool = False
    #: True when the body was built from a declared schema rather than observed.
    synthesised: bool = False
    #: The synthesised payload, and whatever headers the contract requires with
    #: it — SOAPAction for a SOAP operation, Content-Type for either.
    body: str | None = None
    body_headers: dict[str, str] = field(default_factory=dict)
    #: Which contract the body came from. Recorded on the run, so a reviewer can
    #: see that a passing verdict rested on a declared shape rather than an
    #: observed one.
    body_source: str | None = None


@dataclass
class Exchange:
    status: int
    latency_us: int
    body: bytes
    error: str | None = None


@dataclass
class JudgeResult:
    scores: judge_scoring.Scores
    diff_summary: dict
    replay_exact: int
    replay_synthesised: int
    replay_bodyless: int

    @property
    def verdict(self) -> str:
        return self.scores.verdict


#: Path prefix for the shadow pair. Namespaced so no estate caller can reach it
#: even in the window where it exists.
JUDGE_ROOT = "/__sentry_judge"

#: Marks every request the platform generates itself.
#:
#: The sensor records it and the pipeline excludes those rows from usage. The
#: header travels to the upstream because the estate's own services are what the
#: sensor is watching — namespacing the gateway path is not enough, since the
#: path is stripped before the upstream ever sees it.
SYNTHETIC_HEADER = "X-Sentry-Synthetic"
SYNTHETIC_VALUE = "judge"


def requests_from_observations(rows: list[dict], limit: int,
                               *, path_template: str = "",
                               schema: dict | None = None) -> list[ReplayRequest]:
    """Reconstruct request shapes from what the sensor recorded.

    Deduplicated on (method, path): replaying the same shape four hundred times
    measures the gateway's cache, not the patch. Distinct shapes are what
    exercise it.

    Bodies are synthesised from the endpoint's declared contract, never from a
    captured payload — the kernel discards those. A body-bearing method with no
    contract to synthesise from is still replayed and still counted as
    ``bodyless``, because a run that quietly dropped those would report coverage
    it does not have.
    """
    seen: set[tuple[str, str]] = set()
    out: list[ReplayRequest] = []
    for r in rows:
        method = (r.get("method") or "GET").upper()
        path = r.get("path_raw") or "/"
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)

        # The template carries the SOAP operation; the raw path does not, because
        # the identity is built as `<path>#<Operation>` on the endpoint rather
        # than on the URL the client dialled.
        body = bodies.for_endpoint(method, path_template or path, schema)
        needs_body = method in ("POST", "PUT", "PATCH")

        out.append(ReplayRequest(
            method=method,
            path=path,
            auth_scheme=r.get("auth_scheme"),
            bodyless=needs_body and body is None,
            synthesised=body is not None,
            body=body.content if body else None,
            body_headers=dict(body.headers, **{"Content-Type": body.content_type})
            if body else {},
            body_source=body.source if body else None,
        ))
        if len(out) >= limit:
            break
    return out


@dataclass
class _Pair:
    control_service: str
    variant_service: str
    control_prefix: str
    variant_prefix: str
    plugin: kong.PluginRef | None = None
    created: list[str] = field(default_factory=list)


def _build_pair(endpoint_id: str, upstream_url: str, plugin_config: dict) -> _Pair:
    token = uuid.uuid4().hex[:12]
    short = endpoint_id.replace("ep_", "")[:16]

    pair = _Pair(
        control_service=f"{kong.JUDGE_PREFIX}c-{short}-{token}",
        variant_service=f"{kong.JUDGE_PREFIX}v-{short}-{token}",
        control_prefix=f"{JUDGE_ROOT}/c/{token}",
        variant_prefix=f"{JUDGE_ROOT}/v/{token}",
    )

    tags = [kong.JUDGE_TAG, f"sentry:endpoint:{endpoint_id}"]
    for service, prefix in ((pair.control_service, pair.control_prefix),
                            (pair.variant_service, pair.variant_prefix)):
        kong.create_service(service, upstream_url, tags=tags)
        pair.created.append(service)
        # strip_path so the namespacing prefix is removed before the request
        # reaches the upstream: the origin must see the path it would normally
        # see, or the comparison measures a 404 against a 404.
        kong.create_route(service, f"{service}-route", paths=[prefix],
                          tags=tags, strip_path=True)

    pair.plugin = kong.create_route_plugin(f"{pair.variant_service}-route", plugin_config)
    return pair


def _teardown(pair: _Pair) -> None:
    for service in pair.created:
        kong.delete_service(service)


#: How long to wait for the gateway's router to pick up the new pair.
ROUTER_READY_TIMEOUT_S = 20.0
ROUTER_POLL_INTERVAL_S = 0.5


def _await_pair(base: str, pair: _Pair, probe: ReplayRequest) -> None:
    """Block until the gateway actually routes both halves of the pair.

    Kong rebuilds its router asynchronously after an Admin API write, so a
    request issued immediately after creating a route is answered with
    ``no Route matched`` — on both halves, identically. Compared against each
    other those two 404s agree perfectly: identical structure, identical error
    rate, identical absence of data classes. Every dimension scores 100 and the
    patch passes, having never been exercised.

    A patch that passes because nothing was measured is worse than one that
    fails, so this waits for the router rather than trusting the write.
    """
    deadline = time.monotonic() + ROUTER_READY_TIMEOUT_S
    with httpx.Client(timeout=10.0, verify=False) as client:  # noqa: S501
        while time.monotonic() < deadline:
            control = _send(client, base, pair.control_prefix, probe)
            variant = _send(client, base, pair.variant_prefix, probe)
            if control.status not in (0, 404) and variant.status != 0:
                return
            time.sleep(ROUTER_POLL_INTERVAL_S)

    raise JudgeUnavailable(
        f"the gateway did not route the shadow pair within "
        f"{ROUTER_READY_TIMEOUT_S:.0f}s; nothing was measured")


#: Plugins that reject a request lacking a credential, and the header a holder
#: of that credential presents.
CREDENTIALLED_PLUGINS = {"key-auth": "apikey"}

#: The consumer the Judge replays as. Named, tagged and reused rather than
#: created per run: a run killed between provisioning and teardown would
#: otherwise leave an anonymous credential in the gateway with nothing to
#: associate it with.
JUDGE_CONSUMER = "sentry-judge"


#: Tag prefixes marking a control whose verdict depends on the connection
#: rather than on the request. Matched on the tag the generator emits, not on
#: the plugin name: several controls compile to a pre-function and only some of
#: them read connection state.
TRANSPORT_TAG_PREFIXES = ("sentry:tls-min:",)


def _reads_transport(plugin_config: dict) -> bool:
    tags = (plugin_config or {}).get("tags") or []
    return any(t.startswith(p) for t in tags for p in TRANSPORT_TAG_PREFIXES)


def _base_for(plugin_config: dict) -> str | None:
    """Which listener to replay against.

    A tls-min control inspects ``ssl_protocol``, which is empty on a plain HTTP
    listener — so replaying it over http:// made the pre-function reject every
    request, and the Judge reported that the patch broke the endpoint. That
    verdict was sound and the measurement was worthless: it described what the
    control does to an unencrypted connection, which is not the connection any
    caller uses.

    Falls back to the plain listener when no TLS listener is configured, because
    a measurement over the wrong transport is still better than no measurement —
    but the caller can tell from the recorded proxy base which one happened.
    """
    if _reads_transport(plugin_config) and settings.kong_proxy_tls_url:
        return settings.kong_proxy_tls_url
    return settings.kong_proxy_url


def _declared_removals(plugin_config: dict) -> list[str]:
    """Fields the control under test says it will remove.

    Read from the plugin configuration rather than from the remedy name, so the
    Judge is comparing against what will actually be applied to the gateway
    rather than against what the engine intended to apply.
    """
    config = (plugin_config or {}).get("config") or {}
    remove = config.get("remove") or {}
    return list(remove.get("json") or [])


def _credential_for(plugin_config: dict) -> dict[str, str]:
    """Headers the Judge must present for the control under test.

    Without this the Judge replays an anonymous request against an auth plugin,
    observes a 401, and reports that the patch broke the endpoint. That is a
    true statement about anonymous callers and a useless one about the control:
    it is what an auth plugin is *for*, so every auth control was rejected on
    the evidence that it worked.

    The measurement that matters is whether a caller who *has* a credential
    still receives the same response — schema, status and latency — because
    that is what separates "this control breaks the contract" from "this control
    requires callers to migrate", and stage 13 already reports the second as
    ``requires_migration`` rather than as a failure.
    """
    name = (plugin_config or {}).get("name", "")

    # A `jwt` control is validated against a real authorisation server, so the
    # credential is a token obtained from that server rather than a value this
    # process chose. Kong is given the issuer's public key so it can verify the
    # signature; the Judge is given a token so it can be a caller who holds one.
    #
    # A failure here is not fatal and is deliberately not substituted for. No
    # token means the replay goes out anonymous, the plugin rejects it, and the
    # control is rejected for a reason that is once again about the harness —
    # which is the honest outcome when the issuer is not answering.
    if name == "jwt":
        try:
            token = oidc.fetch_token()
            kong.ensure_consumer(JUDGE_CONSUMER, tags=[kong.JUDGE_TAG])
            kong.ensure_jwt_credential(
                JUDGE_CONSUMER, oidc.issuer_of(token), oidc.signing_key_pem())
        except oidc.NoToken:
            return {}
        except (kong.KongUnavailable, kong.KongRejected) as exc:
            raise JudgeUnavailable(
                f"could not provision the judge's jwt credential: {exc}") from exc
        return {"Authorization": f"Bearer {token}"}

    header = CREDENTIALLED_PLUGINS.get(name)
    if not header:
        return {}

    key = hashlib.blake2s(JUDGE_CONSUMER.encode(), digest_size=16).hexdigest()
    try:
        kong.ensure_consumer(JUDGE_CONSUMER, tags=[kong.JUDGE_TAG])
        kong.ensure_key_auth(JUDGE_CONSUMER, key)
    except (kong.KongUnavailable, kong.KongRejected) as exc:
        raise JudgeUnavailable(
            f"could not provision the judge consumer for {name}: {exc}") from exc
    return {header: key}


def _send(client: httpx.Client, base: str, prefix: str, req: ReplayRequest,
          extra_headers: dict[str, str] | None = None) -> Exchange:
    url = f"{base.rstrip('/')}{prefix}{req.path}"
    headers = {SYNTHETIC_HEADER: SYNTHETIC_VALUE}
    headers.update(req.body_headers)
    headers.update(extra_headers or {})
    started = time.perf_counter()
    try:
        resp = client.request(req.method, url, headers=headers,
                              content=req.body.encode() if req.body else None)
    except httpx.HTTPError as exc:
        return Exchange(status=0, latency_us=0, body=b"", error=type(exc).__name__)
    elapsed = int((time.perf_counter() - started) * 1_000_000)
    return Exchange(status=resp.status_code, latency_us=elapsed, body=resp.content)


def _json_keys(body: bytes) -> set[str]:
    """Top-level and one-level-nested keys of a JSON response.

    Structure, not values. The Judge decides whether a consumer's contract
    survived the patch, and a consumer's contract is the shape.
    """
    import json

    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return set()

    keys: set[str] = set()

    def walk(node, prefix=""):
        if isinstance(node, dict):
            for k, v in node.items():
                keys.add(f"{prefix}{k}")
                if isinstance(v, (dict, list)) and prefix.count(".") < 1:
                    walk(v, f"{prefix}{k}.")
        elif isinstance(node, list) and node:
            walk(node[0], prefix)

    walk(doc)
    return keys


def _classes_in(body: bytes) -> set[str]:
    """Re-scan a response for data classes.

    The kernel's detector runs on the estate's traffic; this runs on the
    variant's responses, which the kernel never sees because the Judge's pair is
    not part of the estate. Same shapes, so a patch that claims to mask a field
    is checked against the bytes rather than against its own configuration.
    """
    import re

    text = body.decode("utf-8", errors="ignore")
    found = set()
    if re.search(r"\b[A-Z]{5}\d{4}[A-Z]\b", text):
        found.add("PAN")
    if re.search(r"\b\d{12}\b", text):
        found.add("AADHAAR")
    if re.search(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", text):
        found.add("IFSC")
    if re.search(r"\b\d{9,18}\b", text):
        found.add("ACCOUNT_NO")
    return found


def _percentile(values: list[int], q: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(q * (len(s) - 1)))))
    return s[k]


def run(
    endpoint_id: str,
    upstream_url: str,
    plugin_config: dict,
    requests: list[ReplayRequest],
    criticality: str,
    proxy_base: str | None = None,
) -> JudgeResult:
    """Measure a proposed control against the endpoint's real traffic shapes.

    Raises ``JudgeUnavailable`` when the gateway could not host the pair. A
    control whose Judge run did not happen stays PROPOSED — never PASS, and
    never REJECT either, because a failed measurement is not a failed patch.
    """
    base = proxy_base or _base_for(plugin_config)
    if not base:
        raise JudgeUnavailable("KONG_PROXY_URL is not configured")
    if not requests:
        # Scores treat zero requests as a REJECT, but reaching that through an
        # empty replay would report "the patch failed" when the truth is "there
        # was nothing to test it with".
        raise JudgeUnavailable("no observed traffic to replay for this endpoint")

    try:
        pair = _build_pair(endpoint_id, upstream_url, plugin_config)
    except (kong.KongUnavailable, kong.KongRejected) as exc:
        raise JudgeUnavailable(f"could not build the shadow pair: {exc}") from exc

    try:
        # The router first, the credential second. A pair the gateway never
        # routes is the more fundamental failure and the one worth reporting;
        # provisioning a consumer for it would be work done for a measurement
        # that cannot happen. _await_pair itself needs no credential — it only
        # checks that both halves answer at all, and a 401 from the variant is
        # an answer.
        _await_pair(base, pair, requests[0])
        credential = _credential_for(plugin_config)

        control_lat: list[int] = []
        variant_lat: list[int] = []
        control_err = variant_err = 0
        removed: set[str] = set()
        added: set[str] = set()
        control_classes: set[str] = set()
        variant_classes: set[str] = set()
        compared = 0

        # verify=False, deliberately and narrowly.
        #
        # This connects to the gateway's own TLS listener, which in a reference
        # deployment presents a self-signed certificate. The Judge is measuring
        # what a control does to a connection, not validating the gateway's
        # identity — and it is talking to an address it configured itself, not
        # one supplied by a caller. Refusing the handshake here would mean TLS
        # controls could only ever be judged over plaintext, which is the defect
        # this replaces.
        with httpx.Client(timeout=15.0, follow_redirects=False,
                          verify=False) as client:  # noqa: S501
            for req in requests:
                # The credential goes to both halves. Sending it only to the
                # variant would make the two requests differ in more than the
                # control under test, and the comparison would be measuring the
                # header as much as the plugin. The control half has no auth
                # plugin attached, so an unrecognised header is ignored there.
                c_ex = _send(client, base, pair.control_prefix, req, credential)
                v_ex = _send(client, base, pair.variant_prefix, req, credential)

                # A transport failure on either side is not a measurement. It is
                # excluded from the sample rather than scored as an error the
                # patch caused.
                if c_ex.error or v_ex.error:
                    continue

                compared += 1
                control_lat.append(c_ex.latency_us)
                variant_lat.append(v_ex.latency_us)
                control_err += 1 if c_ex.status >= 400 else 0
                variant_err += 1 if v_ex.status >= 400 else 0

                c_keys, v_keys = _json_keys(c_ex.body), _json_keys(v_ex.body)
                removed |= c_keys - v_keys
                added |= v_keys - c_keys

                control_classes |= _classes_in(c_ex.body)
                variant_classes |= _classes_in(v_ex.body)

        if compared == 0:
            raise JudgeUnavailable("every replayed request failed in transport; "
                                   "nothing was measured")

        # The control half must be serving the endpoint.
        #
        # If it is not, the two halves are being compared while neither works,
        # and agreement between two broken responses reads as a perfect score on
        # every dimension. This is the guard for that whole class of failure, of
        # which the asynchronous router rebuild above was one instance: a
        # misrouted pair, a dead upstream and an unreachable estate all land
        # here rather than being reported as a safe patch.
        if control_err == compared:
            raise JudgeUnavailable(
                f"the control half failed every one of {compared} requests; "
                "the patch was never exercised, so no verdict is available")

        budget = judge_scoring.budget_for(criticality)
        delta = _percentile(variant_lat, 0.95) - _percentile(control_lat, 0.95)

        scores = judge_scoring.Scores(
            schema=judge_scoring.schema_score(
                sorted(removed), sorted(added),
                intended_removals=_declared_removals(plugin_config)),
            latency=judge_scoring.latency_score(delta, budget),
            error=judge_scoring.error_score(control_err / compared, variant_err / compared),
            exposure=judge_scoring.exposure_score(control_classes, variant_classes),
            latency_delta_us=delta,
            budget_us=budget,
            requests=compared,
        )

        return JudgeResult(
            scores=scores,
            diff_summary={
                "removed_fields": sorted(removed),
                "added_fields": sorted(added),
                "control_error_rate": round(control_err / compared, 4),
                "variant_error_rate": round(variant_err / compared, 4),
                "control_p95_us": _percentile(control_lat, 0.95),
                "variant_p95_us": _percentile(variant_lat, 0.95),
                "classes_control": sorted(control_classes),
                "classes_variant": sorted(variant_classes),
                "coverage": "partial" if any(r.bodyless for r in requests) else "full",
            },
            replay_exact=sum(1 for r in requests if not r.bodyless and not r.synthesised),
            replay_synthesised=sum(1 for r in requests if r.synthesised),
            replay_bodyless=sum(1 for r in requests if r.bodyless),
        )
    finally:
        # Always. A shadow pair left in a production gateway is a service an
        # operator did not create and cannot explain.
        _teardown(pair)
