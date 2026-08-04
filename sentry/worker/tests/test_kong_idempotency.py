"""Applying a control that is already applied must be a success.

Regression for 636 FAILED control rows carrying a Kong 409 — ``tls-min failed
×482`` and ``response-mask failed ×153`` on one endpoint, for two policies that
were live at the gateway the whole time. The actuator POSTed, Kong refused the
duplicate, and because a re-proposal commits a fresh control row before it
writes, every retry left another unactionable row on the Remediation surface.

Kong's constraint is ``{consumer, name, route, service}`` — one plugin of a
given *name* per route, independent of the plugin id. That is the thing these
tests hold the actuator to.

Kong is faked rather than mocked loosely: the fake enforces that constraint, and
answers reads the way a real gateway does, with every unset field filled in from
the plugin schema. Both are load-bearing — a fake that skipped either would pass
against the code that produced these 636 rows. The default-filled shapes below
are copied from a live Kong 3.8.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

from sentry_worker.actuators import kong


ROUTE = "finacle-customerservice"

# What Kong stores for an unset field, per plugin. A control states a few keys;
# the gateway answers with the whole schema.
SCHEMA_DEFAULTS = {
    "pre-function": {"rewrite": [], "access": [], "header_filter": [],
                     "body_filter": [], "certificate": [], "log": []},
    "response-transformer": {
        "replace": {"json": [], "json_types": [], "headers": []},
        "remove": {"json": [], "headers": []},
        "append": {"json": [], "json_types": [], "headers": []},
        "add": {"json": [], "json_types": [], "headers": []},
        "rename": {"json": [], "headers": []},
    },
}


def _fill_defaults(name: str, config: dict) -> dict:
    """Merge a stated config over the plugin's schema defaults, as Kong does."""
    stored = json.loads(json.dumps(SCHEMA_DEFAULTS.get(name, {})))
    for key, value in config.items():
        if isinstance(value, dict) and isinstance(stored.get(key), dict):
            stored[key].update(value)
        else:
            stored[key] = value
    return stored


class FakeKong:
    """Enough of the Admin API to hold the actuator to Kong's real constraint."""

    def __init__(self) -> None:
        self.plugins: dict[str, list[dict]] = {}
        self.requests: list[tuple[str, str]] = []

    def _handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        parts = [p for p in request.url.path.split("/") if p]

        if parts[:1] == ["routes"] and parts[2:3] == ["plugins"]:
            route = parts[1]
            on_route = self.plugins.setdefault(route, [])

            if request.method == "GET":
                return httpx.Response(200, json={"data": on_route, "next": None})

            body = json.loads(request.content)
            name = body.get("name")

            if request.method == "PUT":
                instance = parts[3]
                for existing in on_route:
                    if existing.get("instance_name") == instance:
                        existing["config"] = _fill_defaults(name, body.get("config", {}))
                        existing["tags"] = body.get("tags", [])
                        return httpx.Response(200, json=existing)
                    # The real constraint: one plugin of a name per route, and
                    # the plugin id is not part of it.
                    if existing.get("name") == name:
                        return httpx.Response(409, json={
                            "name": "unique constraint violation",
                            "message": f"UNIQUE violation detected on "
                                       f"'{{name=\"{name}\",route={route}}}'"})
                created = {"id": str(uuid.uuid4()), "name": name,
                           "instance_name": instance,
                           "config": _fill_defaults(name, body.get("config", {})),
                           "tags": body.get("tags", [])}
                on_route.append(created)
                return httpx.Response(201, json=created)

            if request.method == "POST":
                for existing in on_route:
                    if existing.get("name") == name:
                        return httpx.Response(409, json={
                            "name": "unique constraint violation",
                            "message": f"UNIQUE violation detected on "
                                       f"'{{name=\"{name}\",route={route}}}'"})
                created = {"id": str(uuid.uuid4()), "name": name,
                           "config": _fill_defaults(name, body.get("config", {})),
                           "tags": body.get("tags", [])}
                on_route.append(created)
                return httpx.Response(201, json=created)

        return httpx.Response(404, json={"message": "not found"})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._handler),
                            base_url="http://kong:8001")


@pytest.fixture
def gateway(monkeypatch) -> FakeKong:
    fake = FakeKong()
    monkeypatch.setattr(kong, "_client", fake.client)
    return fake


# ─────────────────────────────────────────────────────────────────────────────
# The regression
# ─────────────────────────────────────────────────────────────────────────────
def test_reapplying_an_applied_control_succeeds(gateway):
    """The 636 rows. Same policy, a new control row each time — because the
    proposer commits before it writes — must not turn into a FAILED row."""
    config = kong.tls_min("1.3")

    first = kong.create_route_plugin(ROUTE, config, control_id=1160)
    again = kong.create_route_plugin(ROUTE, config, control_id=1168)

    assert again.id == first.id, "a re-apply must resolve to the plugin already there"
    assert len(gateway.plugins[ROUTE]) == 1, "the route grew a duplicate plugin"


def test_reapply_is_stable_over_many_retries(gateway):
    """482 retries is the observed number; none of them may fail or accumulate."""
    config = kong.tls_min("1.3")
    first = kong.create_route_plugin(ROUTE, config, control_id=1160)

    ids = {kong.create_route_plugin(ROUTE, config, control_id=cid).id
           for cid in range(1168, 1188)}

    assert ids == {first.id}
    assert len(gateway.plugins[ROUTE]) == 1


def test_reapply_does_not_write_to_the_gateway(gateway):
    """Idempotent means no-op, not "writes the same thing again". A control
    already applied should cost one read and nothing else."""
    config = kong.response_mask(["aadhaar", "pan"])
    kong.create_route_plugin(ROUTE, config, control_id=1161)

    before = list(gateway.requests)
    gateway.requests.clear()
    kong.create_route_plugin(ROUTE, config, control_id=1167)

    assert [m for m, _ in gateway.requests] == ["GET"], (
        f"re-apply wrote to Kong: {gateway.requests} (first apply was {before})")


def test_kong_filled_defaults_do_not_read_as_a_different_policy(gateway):
    """The trap. Kong answers with the whole schema, so the config that comes
    back is never equal to the one that went in — ``{"remove": {"json": [...]}}``
    reads back with ``headers: []`` and five more keys. Comparing for equality
    would find every plugin different from itself and re-break this."""
    config = kong.response_mask(["aadhaar", "aadhaarNumber", "pan"])
    first = kong.create_route_plugin(ROUTE, config, control_id=1161)

    live = gateway.plugins[ROUTE][0]["config"]
    assert live != config["config"], "fake gateway is not filling defaults"
    assert kong.create_route_plugin(ROUTE, config, control_id=1167).id == first.id


# ─────────────────────────────────────────────────────────────────────────────
# What must still fail
# ─────────────────────────────────────────────────────────────────────────────
def test_a_different_policy_in_the_same_slot_is_refused(gateway):
    """`tls-min` and `dpop` both compile to `pre-function`, and Kong allows one
    per route. Overwriting silently would retire an enforced control while its
    row still read APPLIED, so this stays an error — a described one."""
    kong.create_route_plugin(ROUTE, kong.tls_min("1.3"), control_id=1160)

    with pytest.raises(kong.KongConflict) as exc:
        kong.create_route_plugin(ROUTE, kong.dpop(), control_id=1200)

    assert "pre-function" in str(exc.value)
    assert "1160" in str(exc.value), "the conflicting control should be named"


def test_a_refused_conflict_leaves_the_live_policy_untouched(gateway):
    kong.create_route_plugin(ROUTE, kong.tls_min("1.3"), control_id=1160)

    with pytest.raises(kong.KongConflict):
        kong.create_route_plugin(ROUTE, kong.dpop(), control_id=1200)

    assert len(gateway.plugins[ROUTE]) == 1
    assert "TLSv1.3" in gateway.plugins[ROUTE][0]["config"]["access"][0]


def test_a_tightened_policy_is_not_mistaken_for_the_applied_one(gateway):
    """Widening the masked-field set is a different policy, not a retry."""
    kong.create_route_plugin(ROUTE, kong.response_mask(["aadhaar"]), control_id=1161)

    with pytest.raises(kong.KongConflict):
        kong.create_route_plugin(ROUTE, kong.response_mask(["aadhaar", "ifsc"]),
                                 control_id=1300)


def test_conflict_is_caught_by_existing_handlers(gateway):
    """`control_plane.apply` and the stage-11 runner both catch
    ``(KongUnavailable, KongRejected)``. A new exception type outside that pair
    would escape as an unhandled error mid-apply."""
    kong.create_route_plugin(ROUTE, kong.tls_min("1.3"), control_id=1160)

    with pytest.raises((kong.KongUnavailable, kong.KongRejected)):
        kong.create_route_plugin(ROUTE, kong.dpop(), control_id=1200)


# ─────────────────────────────────────────────────────────────────────────────
# The write itself
# ─────────────────────────────────────────────────────────────────────────────
def test_first_apply_uses_the_addressed_upsert(gateway):
    """Only ``PUT /routes/{r}/plugins/{id}`` is an upsert; POSTing the collection
    is create-only and 409s on the second writer. Same correction as
    ``set_upstream_weights``."""
    kong.create_route_plugin(ROUTE, kong.tls_min("1.3"), control_id=1160)

    assert "POST" not in [m for m, _ in gateway.requests]
    assert "PUT" in [m for m, _ in gateway.requests]


def test_the_instance_name_is_not_keyed_on_the_control_id(gateway):
    """The reason an id-keyed name would not have fixed anything: a re-proposal
    writes a new control row every time, so the address would be new on every
    retry and collide exactly as the POST did."""
    assert (kong._instance_name(ROUTE, "pre-function")
            == kong._instance_name(ROUTE, "pre-function"))

    kong.create_route_plugin(ROUTE, kong.tls_min("1.3"), control_id=1160)
    kong.create_route_plugin(ROUTE, kong.tls_min("1.3"), control_id=99999)

    assert len(gateway.plugins[ROUTE]) == 1


def test_ownership_tags_are_written_on_create(gateway):
    """reconcile_orphans finds SENTRY's plugins by tag; an untagged one is
    unattributable configuration in a production gateway."""
    kong.create_route_plugin(ROUTE, kong.tls_min("1.3"), control_id=1160)

    tags = gateway.plugins[ROUTE][0]["tags"]
    assert kong.OWNED_TAG in tags
    assert f"{kong.CONTROL_TAG_PREFIX}1160" in tags
    assert kong.control_id_of(gateway.plugins[ROUTE][0]) == 1160


def test_adopting_leaves_the_original_owner_in_place(gateway):
    """The adopting control's row is APPLIED with a true plugin id either way,
    and ``control_id_of`` reads one owner per plugin — so the tag stays with the
    control that created it rather than moving to whichever row re-proposed
    last, which would leave reconcile chasing a moving owner."""
    kong.create_route_plugin(ROUTE, kong.tls_min("1.3"), control_id=1160)
    kong.create_route_plugin(ROUTE, kong.tls_min("1.3"), control_id=1168)

    assert kong.control_id_of(gateway.plugins[ROUTE][0]) == 1160


def test_there_is_no_service_scoped_attach(gateway):
    """The scope is part of the fix, not just the verb.

    A service-scoped ``create_plugin`` sat in this module carrying the same
    create-only POST, unused. Repairing it would have left a working
    service-scoped attach as the obvious call for a caller holding a service
    name — and a service usually fronts several endpoints, so the control would
    reach endpoints the Judge never measured. That fails silently, where the 409
    at least failed loudly. It was deleted; this keeps it deleted.
    """
    assert not hasattr(kong, "create_plugin"), (
        "a service-scoped plugin attach is back — see create_route_plugin's "
        "docstring for why route scope is the only scope a control is applied at")


# ─────────────────────────────────────────────────────────────────────────────
# The comparison itself
# ─────────────────────────────────────────────────────────────────────────────
def test_config_subset_ignores_defaults_the_control_never_stated():
    live = {"access": ["x"], "rewrite": [], "log": []}
    assert kong.config_is_subset({"access": ["x"]}, live)


def test_config_subset_is_recursive():
    live = {"remove": {"json": ["pan"], "headers": []}}
    assert kong.config_is_subset({"remove": {"json": ["pan"]}}, live)
    assert not kong.config_is_subset({"remove": {"json": ["pan", "uid"]}}, live)


def test_config_subset_rejects_a_missing_key():
    assert not kong.config_is_subset({"minute": 300}, {"policy": "local"})
