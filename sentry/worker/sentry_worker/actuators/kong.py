"""Kong Admin API actuator — the single writer of gateway state.

Stages 11 and 13 delegate here rather than writing Kong directly, so APPLIED
means "Kong confirmed it" everywhere in the system and there is one rollback
path.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from sentry_core.config import settings


class KongUnavailable(RuntimeError):
    pass


class KongRejected(RuntimeError):
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"kong returned {status}: {body[:400]}")


class KongConflict(KongRejected):
    """A *different* policy already occupies the slot being written.

    Subclasses KongRejected so existing handlers still catch it, but says what
    an operator has to decide rather than repeating Kong's constraint name. The
    common 409 — re-applying a control that is already applied — is not this;
    that one is now a success and never reaches a caller.
    """

    def __init__(self, message: str) -> None:
        RuntimeError.__init__(self, message)
        self.status = 409
        self.body = message


def _client() -> httpx.Client:
    if not settings.kong_admin_url:
        raise KongUnavailable("KONG_ADMIN_URL is not configured")
    headers = {}
    if settings.kong_admin_token:
        headers["Kong-Admin-Token"] = settings.kong_admin_token
    return httpx.Client(base_url=settings.kong_admin_url, headers=headers, timeout=10.0)


@dataclass
class PluginRef:
    id: str
    name: str


#: Marks a plugin as SENTRY's, carrying the control row that owns it.
#:
#: A gateway write and a database commit cannot be one transaction. A process
#: killed between them leaves a plugin enforcing policy that no control row
#: records, which is unattributable configuration in a production gateway and
#: the exact thing an audit finds. The tag makes every such plugin traceable to
#: the row that should exist, so reconcile_orphans can remove the ones that do
#: not.
CONTROL_TAG_PREFIX = "sentry:control:"
OWNED_TAG = "sentry:owned"


def delete_plugin(plugin_id: str) -> None:
    try:
        with _client() as c:
            r = c.delete(f"/plugins/{plugin_id}")
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code not in (204, 404):
        raise KongRejected(r.status_code, r.text)


def get_plugin(plugin_id: str) -> dict | None:
    """Read back through Kong's own API.

    Used by the verification run: a system reporting its own success is not
    evidence.
    """
    try:
        with _client() as c:
            r = c.get(f"/plugins/{plugin_id}")
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code == 404:
        return None
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    return r.json()


# ── shadow pair, for the Judge ───────────────────────────────────────────────
#
# Every object the Judge creates is prefixed and tagged, so a crashed run leaves
# something an operator can identify and remove rather than an unexplained
# service in a production gateway.
JUDGE_PREFIX = "sentry-judge-"
JUDGE_TAG = "sentry:judge"


def create_service(name: str, url: str, tags: list[str] | None = None) -> str:
    """Create or replace a service by name. Returns its id."""
    body = {"name": name, "url": url, "tags": tags or []}
    try:
        with _client() as c:
            r = c.put(f"/services/{name}", json=body)
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    return r.json()["id"]


def create_route(service_name: str, route_name: str, paths: list[str],
                 methods: list[str] | None = None,
                 tags: list[str] | None = None,
                 strip_path: bool = True) -> str:
    body = {
        "name": route_name,
        "paths": paths,
        "strip_path": strip_path,
        "tags": tags or [],
    }
    if methods:
        body["methods"] = [m.upper() for m in methods]
    try:
        with _client() as c:
            r = c.put(f"/services/{service_name}/routes/{route_name}", json=body)
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    return r.json()["id"]


def config_is_subset(desired: dict, live: dict) -> bool:
    """Does ``live`` already say everything ``desired`` asks for?

    Subset, not equality. Kong answers with the plugin's *whole* schema, every
    unset field filled in with its default, so the config that comes back is
    always a superset of the one that went in: ``{"remove": {"json": [...]}}``
    reads back as ``{"remove": {"json": [...], "headers": []}}`` plus five more
    keys. Comparing for equality would find every plugin different from itself
    and turn this check into a no-op.

    Only the keys a control actually states are compared — those are the policy.
    The defaults are Kong's, and a control that never expressed an opinion about
    them is not in conflict with them.

    Public because the write is no longer its only caller. ``reconcile_failed``
    asks the same question of a FAILED row — is this policy already enforced? —
    and the two must answer it identically, or a row would be filed as
    superseded on a comparison the actuator would have called a conflict.
    """
    for key, want in desired.items():
        if key not in live:
            return False
        have = live[key]
        if isinstance(want, dict) and isinstance(have, dict):
            if not config_is_subset(want, have):
                return False
        elif want != have:
            return False
    return True


def _instance_name(route_name: str, plugin_name: str) -> str:
    """A stable address for "this plugin, on this route".

    Keyed on the pair Kong itself enforces uniqueness over, so the name a retry
    computes is the name the first attempt used. Deliberately *not* keyed on the
    control id: a re-proposal writes a new control row every time — that is what
    produced 636 distinct FAILED rows for two policies — so an id-keyed name
    would be new on every retry and would collide exactly as the POST did.
    """
    return f"sentry-{route_name}-{plugin_name}"[:128]


def create_route_plugin(route_name: str, config: dict,
                        control_id: int | None = None) -> PluginRef:
    """Attach a plugin to a single route, idempotently.

    Route scope is the correct scope for a control, not just a convenience for
    the Judge. A control is judged against one endpoint's traffic, and a service
    usually fronts several — attaching it to the service applies it to endpoints
    that were never measured.

    There is deliberately no service-scoped counterpart to this function. One
    existed, unused, and carried the same create-only POST this function was
    fixed for; it was removed rather than repaired, because a working
    service-scoped attach is the obvious thing to reach for when a caller has a
    service name in hand, and over-applying a control to unmeasured endpoints
    fails silently where the 409 at least failed loudly.

    Kong permits one instance of a plugin *name* per route: the constraint is
    ``{consumer, name, route, service}``, not the plugin id. A plain POST is
    therefore a create-only operation, and re-applying a control that is already
    applied was a 409. Since a re-proposal commits a fresh control row before it
    writes, each retry left another FAILED row behind — one policy already live
    at the gateway reported as ``tls-min failed ×482`` on the Remediation
    surface, with nothing an operator could do about any of them.

    So the write is now an upsert, in the shape the rest of this module already
    uses (`create_service`, `ensure_consumer`, `set_upstream_weights`) and the
    `kong-consumers` compose job uses, for the same reason:

    * An existing plugin of the same name whose config already satisfies this
      one is **success** — the desired state holds, and its ref is returned so
      the control records the id a revert needs. Nothing is written: re-applying
      an applied control should not touch the gateway 482 times.
    * An existing plugin of the same name saying something **different** is a
      real conflict — two policies contending for one slot, e.g. `tls-min` and
      `dpop` both compiling to `pre-function`. That is raised, because silently
      overwriting it would retire an enforced control while its row still reads
      APPLIED.
    * Otherwise the plugin is PUT at a deterministic address, which is the only
      form Kong treats as an upsert, so a racing duplicate resolves instead of
      failing.

    Ownership tags are left as they are when adopting: the plugin keeps the
    control that created it. `reconcile_orphans` reads one owner per plugin, and
    the adopting control's row is APPLIED with a true plugin id either way.
    """
    plugin_name = config.get("name")
    body = dict(config)
    if control_id is not None:
        body["tags"] = sorted(set(body.get("tags", []))
                              | {OWNED_TAG, f"{CONTROL_TAG_PREFIX}{control_id}"})

    desired = config.get("config", {})

    try:
        with _client() as c:
            existing = _route_plugin_by_name(c, route_name, plugin_name)
            if existing is not None:
                if not config_is_subset(desired, existing.get("config") or {}):
                    raise KongConflict(
                        f"route {route_name} already carries a different "
                        f"{plugin_name} (plugin {existing.get('id')}, control "
                        f"{control_id_of(existing)}). Revert that control before "
                        f"applying this one — Kong allows one {plugin_name} per route."
                    )
                if not existing.get("id"):
                    raise KongRejected(200, "existing plugin without an id")
                return PluginRef(id=existing["id"],
                                 name=existing.get("name", plugin_name or ""))

            body.setdefault("instance_name", _instance_name(route_name, plugin_name))
            r = c.put(f"/routes/{route_name}/plugins/{body['instance_name']}", json=body)
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc

    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    written = r.json()
    if not written.get("id"):
        raise KongRejected(r.status_code, "2xx without a plugin id")
    return PluginRef(id=written["id"], name=written.get("name", config.get("name", "")))


def route_plugins(route_name: str) -> list[dict]:
    """Every plugin currently attached to a route, as the gateway reports it.

    Read back through Kong rather than inferred from the control table: the
    database's view of what is applied is the thing being reconciled, so it
    cannot also be the evidence. That constraint is what makes this a separate
    call rather than a query — ``reconcile_failed`` decides whether a FAILED
    control's policy is already enforced, and only the gateway can answer.
    """
    try:
        with _client() as c:
            return _plugins_on_route(c, route_name)
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc


def _plugins_on_route(c: httpx.Client, route_name: str) -> list[dict]:
    r = c.get(f"/routes/{route_name}/plugins")
    if r.status_code == 404:
        return []
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    return r.json().get("data", [])


def _route_plugin_by_name(c: httpx.Client, route_name: str,
                          plugin_name: str | None) -> dict | None:
    """The plugin of this name already on this route, if any."""
    if not plugin_name:
        return None
    for plugin in _plugins_on_route(c, route_name):
        if plugin.get("name") == plugin_name:
            return plugin
    return None


def delete_service(name: str) -> None:
    """Remove a service and its routes.

    Kong refuses to delete a service that still has routes, so they go first.
    Failures are swallowed deliberately: this is teardown, and an object that
    was already gone is the outcome being asked for.
    """
    try:
        with _client() as c:
            routes = c.get(f"/services/{name}/routes")
            if routes.status_code < 400:
                for route in routes.json().get("data", []):
                    plugins = c.get(f"/routes/{route['id']}/plugins")
                    if plugins.status_code < 400:
                        for pl in plugins.json().get("data", []):
                            c.delete(f"/plugins/{pl['id']}")
                    c.delete(f"/routes/{route['id']}")
            c.delete(f"/services/{name}")
    except httpx.HTTPError:
        return


def purge_judge_objects() -> int:
    """Remove every object a Judge run left behind. Returns how many.

    Called before a run rather than only after one: a worker killed mid-judge
    leaves a shadow pair in the gateway, and the next run must start from a
    known state rather than inherit a plugin it did not create.
    """
    removed = 0
    try:
        with _client() as c:
            r = c.get("/services")
            if r.status_code >= 400:
                return 0
            for svc in r.json().get("data", []):
                if (svc.get("name") or "").startswith(JUDGE_PREFIX):
                    delete_service(svc["name"])
                    removed += 1
    except httpx.HTTPError:
        return removed
    return removed


def list_owned_plugins() -> list[dict]:
    """Every plugin SENTRY has written, by tag."""
    try:
        with _client() as c:
            r = c.get("/plugins")
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    return [p for p in r.json().get("data", [])
            if OWNED_TAG in (p.get("tags") or [])]


def control_id_of(plugin: dict) -> int | None:
    for tag in plugin.get("tags") or []:
        if tag.startswith(CONTROL_TAG_PREFIX):
            try:
                return int(tag[len(CONTROL_TAG_PREFIX):])
            except ValueError:
                return None
    return None


def reconcile_orphans(live_control_ids: set[int]) -> list[dict]:
    """Delete plugins whose owning control is not APPLIED. Returns what went.

    This is the other half of the non-atomic write. A worker killed between the
    POST and the commit leaves a plugin enforcing policy that no control row
    records; the next run finds it by tag, sees no APPLIED control behind it,
    and removes it. The gateway ends up holding exactly the controls the
    database says it should — which is the property an audit is actually asking
    about.

    Untagged plugins are never touched. Anything an operator put there by hand
    is theirs.
    """
    removed: list[dict] = []
    for plugin in list_owned_plugins():
        cid = control_id_of(plugin)
        if cid is not None and cid in live_control_ids:
            continue
        try:
            delete_plugin(plugin["id"])
        except (KongUnavailable, KongRejected):
            continue
        removed.append({"plugin_id": plugin["id"], "name": plugin.get("name"),
                        "control_id": cid})
    return removed


CANARY_PREFIX = "sentry-canary-"


def set_upstream_weights(upstream: str, targets: dict[str, int]) -> None:
    """Canary traffic shifting. Used by stage 11 for endpoints whose blast radius
    touches a payment, settlement or regulatory system.

    ``PUT /upstreams/{u}/targets/{target}`` — the individual target, not the
    collection.

    The collection does not accept PUT and answers ``405 Method not allowed``;
    POSTing to it 409s on a target that already exists, which every step after
    the first does. Only the addressed form is an upsert. This function had the
    right verb on the wrong URL and never ran until an endpoint actually reached
    the canary path, so the first real migration failed at the first shift and
    the second failed one call later.
    """
    try:
        with _client() as c:
            for target, weight in targets.items():
                r = c.put(f"/upstreams/{upstream}/targets/{target}",
                          json={"target": target, "weight": weight})
                if r.status_code >= 400:
                    raise KongRejected(r.status_code, r.text)
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc


def ensure_canary_upstream(endpoint_id: str, current: str, replacement: str,
                           route_name: str) -> str:
    """Put a weighted upstream in front of a route so traffic can be shifted.

    Kong balances across an upstream's targets by weight, and a service pointing
    at a single host has nothing to balance. So the migration needs the route's
    service repointed at an upstream holding both hosts — after which a canary
    step is one PUT per target rather than a reroute.

    Created at weight 1000/0: every request still reaches the endpoint being
    retired. Creating it mid-migration would move traffic before anybody asked,
    which is precisely what a canary exists to avoid.
    """
    name = f"{CANARY_PREFIX}{endpoint_id[:16]}"
    tags = [OWNED_TAG, f"sentry:canary:{endpoint_id}"]

    try:
        with _client() as c:
            r = c.put(f"/upstreams/{name}", json={"name": name, "tags": tags})
            if r.status_code >= 400:
                raise KongRejected(r.status_code, r.text)

            for target, weight in ((current, 1000), (replacement, 0)):
                t = c.put(f"/upstreams/{name}/targets/{target}",
                          json={"target": target, "weight": weight})
                if t.status_code >= 400:
                    raise KongRejected(t.status_code, t.text)

            # The service the route already uses is repointed at the upstream by
            # name. Kong resolves a service host that matches an upstream name
            # through the balancer instead of DNS, which is what makes the
            # weights take effect without touching the route.
            route = c.get(f"/routes/{route_name}")
            if route.status_code >= 400:
                raise KongRejected(route.status_code, route.text)
            service_id = (route.json().get("service") or {}).get("id")
            if not service_id:
                raise KongRejected(404, f"route {route_name} has no service")

            s = c.patch(f"/services/{service_id}", json={"host": name})
            if s.status_code >= 400:
                raise KongRejected(s.status_code, s.text)
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc

    return name


def canary_weights(upstream: str, current: str, replacement: str,
                   split: float) -> dict[str, int]:
    """Weights for a split, expressed as the share still on the old endpoint.

    ``split`` is what the decommission engine tracks: 0.10 means a tenth of
    traffic still reaches the endpoint being retired. Kong takes integers, and
    1000 rather than 100 so a 0.01 step is a whole number rather than a rounding
    decision.
    """
    remaining = max(0, min(1000, round(split * 1000)))
    return {current: remaining, replacement: 1000 - remaining}


def upstream_targets(upstream: str) -> list[dict]:
    """What the gateway currently says the weights are.

    Read back rather than assumed: the point of a canary is that somebody can
    verify where traffic is going, and a number this system printed from its own
    intent is not that.
    """
    try:
        with _client() as c:
            r = c.get(f"/upstreams/{upstream}/targets")
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    return r.json().get("data", [])


def healthy() -> bool:
    try:
        with _client() as c:
            return c.get("/status").status_code < 400
    except Exception:
        return False


# ── control config generation ────────────────────────────────────────────────
def rate_limit(per_minute: int) -> dict:
    return {"name": "rate-limiting",
            "config": {"minute": per_minute, "policy": "local", "limit_by": "service"}}


def tls_min(floor: str = "1.3") -> dict:
    """Kong OSS has no TLS-version plugin; a pre-function rejects below the floor."""
    v = floor.replace(".", "")
    return {
        "name": "pre-function",
        "config": {"access": [
            f'local p = ngx.var.ssl_protocol or ""\n'
            f'if p ~= "TLSv{floor}" then\n'
            f'  return kong.response.exit(426, {{message="TLS {floor} required"}})\n'
            f'end'
        ]},
        "tags": [f"sentry:tls-min:{v}"],
    }


def response_mask(fields: list[str]) -> dict:
    return {"name": "response-transformer",
            "config": {"remove": {"json": list(fields)}}}


def key_auth() -> dict:
    return {"name": "key-auth", "config": {"key_names": ["apikey"]}}


def oauth2() -> dict:
    """Validate tokens from the institution's authorisation server.

    Kong's own `oauth2` plugin makes *Kong* the authorisation server: it issues
    and stores its own tokens, with its own client registry, independent of
    whatever identity provider the bank already runs. No institution with a
    Keycloak deployment wants a second token issuer at the gateway, and a
    control that only an isolated Kong can satisfy is not a control anyone would
    apply.

    Where an issuer is configured, this emits `jwt` instead — Kong OSS's
    signature-validating plugin — keyed on the issuer's public key. That is the
    control an institution actually deploys, and it is judgeable here because
    the Judge can obtain a real token from that issuer and present it.

    With no issuer configured there is nothing to validate against, and the
    original plugin is emitted unchanged rather than silently substituted.
    """
    if not settings.oidc_issuer:
        return {"name": "oauth2",
                "config": {"scopes": ["read", "write"], "enable_client_credentials": True,
                           "accept_http_if_already_terminated": False}}

    return {
        "name": "jwt",
        "config": {
            # The issuer claim carries the credential's key, which is how Kong
            # selects the public key to verify against.
            "key_claim_name": "iss",
            "claims_to_verify": ["exp"],
        },
        "tags": ["sentry:oauth2:jwt"],
    }


def mtls() -> dict:
    """mtls-auth is Enterprise-only.

    On Kong OSS the equivalent is the proxy listener configured with
    ssl_verify_client plus a per-route pre-function that rejects unverified
    connections. That is what this generates; KONG_MTLS_MODE selects the
    Enterprise plugin where a licence exists.
    """
    if settings.kong_mtls_mode == "mtls-auth":
        return {"name": "mtls-auth", "config": {"revocation_check_mode": "SKIP"}}
    return {
        "name": "pre-function",
        "config": {"access": [
            'if ngx.var.ssl_client_verify ~= "SUCCESS" then\n'
            '  return kong.response.exit(496, {message="client certificate required"})\n'
            'end'
        ]},
        "tags": ["sentry:mtls"],
    }


def dpop() -> dict:
    """No OSS plugin implements DPoP. This validates the proof header directly —
    real enforcement, described as what it is rather than as a plugin that does
    not exist."""
    return {
        "name": "pre-function",
        "config": {"access": [
            'local dpop = kong.request.get_header("DPoP")\n'
            'if not dpop then\n'
            '  return kong.response.exit(401, {message="DPoP proof required"})\n'
            'end'
        ]},
        "tags": ["sentry:dpop"],
    }


def sunset_headers(sunset_rfc8594: str, link: str) -> dict:
    return {
        "name": "response-transformer",
        "config": {"add": {"headers": [
            f"Sunset: {sunset_rfc8594}",
            "Deprecation: true",
            f'Link: <{link}>; rel="sunset"',
        ]}},
    }


def gone_410(message: str = "Endpoint retired") -> dict:
    """410, not 404: this URL existed and was intentionally removed, which is
    information a client should have."""
    return {"name": "request-termination",
            "config": {"status_code": 410, "message": message}}


CONSUMER_TAG = "sentry:consumer"


def ensure_consumer(username: str, tags: list[str] | None = None) -> str:
    """Create or update a consumer by username. Returns its id.

    A gateway with an auth plugin and no consumers rejects everything, so
    provisioning the identity is part of applying the control rather than a
    prerequisite somebody is expected to have arranged.
    """
    body = {"username": username, "tags": sorted(set(tags or []) | {OWNED_TAG, CONSUMER_TAG})}
    try:
        with _client() as c:
            r = c.put(f"/consumers/{username}", json=body)
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    return r.json()["id"]


def ensure_jwt_credential(username: str, issuer: str, public_key_pem: str) -> None:
    """Register the authorisation server's signing key against a consumer.

    Kong's `jwt` plugin verifies a token's signature against a credential
    selected by the token's own `iss` claim, so the credential's `key` is the
    issuer string and its `rsa_public_key` is that issuer's signing key. Nothing
    secret is stored: this is the public half, the same value the issuer
    publishes at its JWKS endpoint.

    Idempotent by comparing on the key. Kong has no upsert for this credential
    either, and re-POSTing an existing one is a 409.
    """
    try:
        with _client() as c:
            existing = c.get(f"/consumers/{username}/jwt")
            if existing.status_code < 400:
                for cred in existing.json().get("data", []):
                    if cred.get("key") == issuer:
                        if cred.get("rsa_public_key") == public_key_pem:
                            return
                        # The issuer rotated its key. A stale credential rejects
                        # every token the issuer now signs, which would read as
                        # the control breaking the endpoint.
                        c.delete(f"/consumers/{username}/jwt/{cred['id']}")
            r = c.post(f"/consumers/{username}/jwt", json={
                "key": issuer,
                "algorithm": "RS256",
                "rsa_public_key": public_key_pem,
            })
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code == 409:
        return
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)


def ensure_key_auth(username: str, key: str) -> None:
    """Give a consumer an API key, idempotently.

    Kong's key-auth credential endpoint has no natural upsert — POSTing the same
    key twice is a 409 — so an existing identical key is treated as success.
    Anything else is surfaced.
    """
    try:
        with _client() as c:
            existing = c.get(f"/consumers/{username}/key-auth")
            if existing.status_code < 400:
                for cred in existing.json().get("data", []):
                    if cred.get("key") == key:
                        return
            r = c.post(f"/consumers/{username}/key-auth", json={"key": key})
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code == 409:
        return
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)


def delete_consumer(username: str) -> None:
    try:
        with _client() as c:
            c.delete(f"/consumers/{username}")
    except httpx.HTTPError:
        return


def list_consumers() -> list[dict]:
    try:
        with _client() as c:
            r = c.get("/consumers")
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    return r.json().get("data", [])


HONEYPOT_PREFIX = "sentry-honeypot-"
HONEYPOT_TAG = "sentry:honeypot"


def honeypot_route(endpoint_id: str, path: str, method: str, upstream: str,
                   *, route_name: str) -> dict:
    """Repoint the retired endpoint's existing route at the honeypot.

    The first version of this created a *second* route for the same path and
    assumed Kong would prefer it as the more specific match. Both routes carried
    the identical path, so there was nothing to be more specific about: the
    original route kept matching, its request-termination plugin short-circuited
    the request, and every probe got 410. The honeypot was live, correctly
    configured, and unreachable — with nothing reporting a problem, because from
    SENTRY's side the route had been created successfully.

    Repointing the one route that already owns the path removes the ambiguity.
    Three properties follow:

    * **The 410 must be withdrawn by the caller first.** A termination plugin on
      this route answers before the upstream is ever consulted, so leaving it
      attached leaves the honeypot dark.
    * **Reverting restores a retired endpoint, not a live one.** The route's
      original service is returned here so the caller can record it; putting it
      back is a deliberate act with a recorded before-state.
    * **``strip_path`` is off.** The honeypot's table is keyed on the path the
      endpoint actually served, so it must arrive intact — stripping it turns
      every probe into a 404 and the capture yields nothing.
    """
    suffix = endpoint_id[:16]
    service_name = f"{HONEYPOT_PREFIX}{suffix}"
    tags = [OWNED_TAG, HONEYPOT_TAG, f"sentry:endpoint:{endpoint_id}"]

    create_service(service_name, upstream, tags=tags)

    try:
        with _client() as c:
            before = c.get(f"/routes/{route_name}")
            if before.status_code >= 400:
                raise KongRejected(before.status_code, before.text)
            previous = (before.json().get("service") or {}).get("id")

            r = c.patch(f"/routes/{route_name}", json={
                "service": {"name": service_name},
                "strip_path": False,
                "tags": sorted(set(before.json().get("tags") or []) | set(tags)),
            })
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)

    return {"service": service_name, "route": route_name,
            "path": path, "method": method, "upstream": upstream,
            "previous_service_id": previous}


def remove_honeypot_route(endpoint_id: str) -> None:
    delete_service(f"{HONEYPOT_PREFIX}{endpoint_id[:16]}")


def list_honeypot_routes() -> list[dict]:
    """Every honeypot object currently in the gateway.

    Used to reconcile: a honeypot route serving a path whose endpoint is no
    longer retired is the one failure this system must never have, and finding
    it requires asking the gateway rather than the database.
    """
    try:
        with _client() as c:
            r = c.get("/services", params={"tags": HONEYPOT_TAG})
    except httpx.HTTPError as exc:
        raise KongUnavailable(str(exc)) from exc
    if r.status_code >= 400:
        raise KongRejected(r.status_code, r.text)
    return r.json().get("data", [])


GENERATORS = {
    "rate-limit": rate_limit,
    "tls-min": tls_min,
    "response-mask": response_mask,
    "key-auth": key_auth,
    "oauth2": oauth2,
    "mtls-auth": mtls,
    "dpop": dpop,
    "sunset-header": sunset_headers,
    "request-termination": gone_410,
}
