"""What happens to a control row that never needed to exist.

Making `create_route_plugin` idempotent stopped the 636 FAILED rows being
*created*. It did nothing about the ones already there, and on its own it turns
the old failure into a quieter one: a re-proposal that used to 409 now succeeds,
so repeated proposals accumulate APPLIED rows all naming one `kong_plugin_id`.
A hundred controls that revert as one is a worse account of the gateway than a
hundred failures was.

Three things are held here, and the second is the one with teeth:

* a FAILED row whose policy the gateway is already enforcing becomes SUPERSEDED;
* a FAILED row whose policy the gateway is *not* enforcing stays FAILED, even
  when it sits beside 482 that are — 152 of the original 636 ask for `ifsc` to
  be masked and the live plugin masks `pan` and not `ifsc`, so a sweep by count
  would have closed an open PII exposure;
* one plugin is one piece of enforcement, so reverting it reverts every row that
  claims it rather than leaving the others APPLIED over nothing.

The endpoint ids and control ids are the real ones from the incident.
"""

from __future__ import annotations

import os  # noqa: F401  — DATABASE_URL is set by the root conftest
from dataclasses import dataclass, field

import pytest

from sentry_core.db import SessionLocal, create_all  # noqa: E402
from sentry_core.enums import ControlState, Criticality  # noqa: E402
from sentry_core.models import Control, Endpoint, Service  # noqa: E402
from sentry_worker.actuators import control_plane, kong  # noqa: E402

ROUTE = "finacle-customerservice"
SERVICE = "finacle"

# The two endpoints that collapse onto one gateway route: a SOAP operation and
# the URL that contains it. This is why the 409s happened at all.
EP_URL = "ep_7bf33b50216c3d57"          # POST /finacle/customerservice
EP_OPERATION = "ep_d3a639ab3a9b1676"    # POST /finacle/customerservice#GetCustomerKyc

MASK_PAN = ["aadhaar", "aadhaarNumber", "uid", "accountNumber", "accountNo",
            "pan", "panNumber"]
MASK_PAN_AND_IFSC = ["aadhaar", "aadhaarNumber", "uid", "accountNumber",
                     "accountNo", "ifsc", "ifscCode", "pan", "panNumber"]


# ── the gateway snapshot, as the collector reports it ────────────────────────
@dataclass
class _Route:
    route_name: str
    service_name: str
    path_templates: list[str]
    methods: list[str]


@dataclass
class _Snapshot:
    routes: list[_Route] = field(default_factory=list)
    healthy: bool = True


def _snapshot() -> _Snapshot:
    return _Snapshot(routes=[_Route(ROUTE, SERVICE, ["/finacle/customerservice"],
                                    ["POST"])])


@pytest.fixture
def db():
    create_all()
    with SessionLocal() as s:
        for table in (Control, Endpoint, Service):
            s.query(table).delete()
        s.commit()

        svc = Service(id="svc_a3c153292bf5", name=SERVICE,
                      criticality=Criticality.CUSTOMER,
                      first_vday=0, last_vday=0)
        s.add(svc)
        s.add(Endpoint(id=EP_URL, service_id=svc.id, method="POST",
                       path_template="/finacle/customerservice",
                       first_vday=0, last_call_vday=0))
        s.add(Endpoint(id=EP_OPERATION, service_id=svc.id, method="POST",
                       path_template="/finacle/customerservice#GetCustomerKyc",
                       first_vday=0, last_call_vday=0))
        s.commit()
        yield s
        s.rollback()


def _control(db, **kw) -> Control:
    fields = {"endpoint_id": EP_URL, "kind": "tls-min",
              "plugin_config": kong.tls_min("1.3"),
              "state": ControlState.FAILED, "generator": "template",
              "origin_stage": 10, "actor": "system:stage-10"}
    fields.update(kw)
    control = Control(**fields)
    db.add(control)
    db.commit()
    return control


def _live(name: str, config: dict, *, control_id: int, plugin_id: str) -> dict:
    """A plugin as Kong reports it — schema defaults filled in, ownership tagged."""
    return {"id": plugin_id, "name": name, "config": config,
            "tags": [kong.OWNED_TAG, f"{kong.CONTROL_TAG_PREFIX}{control_id}"]}


@pytest.fixture
def gateway(monkeypatch):
    """The plugins on the route, as the reconciler will read them back."""
    plugins: dict[str, list[dict]] = {ROUTE: []}

    def route_plugins(route_name: str) -> list[dict]:
        if plugins.get(route_name) is None:
            raise kong.KongUnavailable("connection refused")
        return plugins.get(route_name, [])

    monkeypatch.setattr(kong, "route_plugins", route_plugins)
    return plugins


# ─────────────────────────────────────────────────────────────────────────────
# The 483 that were already enforced
# ─────────────────────────────────────────────────────────────────────────────
def test_a_failed_row_whose_policy_is_live_becomes_superseded(db, gateway):
    """Control 1160 put the `pre-function` on the route. The 482 `tls-min` rows
    that 409'd against it describe exactly that policy."""
    owner = _control(db, id=1160, endpoint_id=EP_OPERATION, kind="tls-min",
                     state=ControlState.APPLIED, kong_plugin_id="b4055c2c")
    failed = _control(db, id=1168)
    gateway[ROUTE] = [_live("pre-function",
                            {"access": kong.tls_min("1.3")["config"]["access"],
                             "rewrite": [], "log": []},
                            control_id=owner.id, plugin_id="b4055c2c")]

    result = control_plane.reconcile_failed(db, _snapshot())

    assert failed.state is ControlState.SUPERSEDED
    assert failed.superseded_by == 1160
    assert [s["control_id"] for s in result["superseded"]] == [1168]


def test_supersession_crosses_endpoints_because_the_route_is_shared(db, gateway):
    """The enforcing control belongs to a *different* endpoint.

    A SOAP operation and its containing URL are two endpoints and one route, and
    Kong permits one plugin of a name per route. Matching on `(endpoint_id,
    kind)` would find nothing here and leave all 482 rows FAILED — the whole
    reason the match is made against the gateway instead.
    """
    owner = _control(db, id=1160, endpoint_id=EP_OPERATION, kind="tls-min",
                     state=ControlState.APPLIED, kong_plugin_id="b4055c2c")
    failed = _control(db, id=1168, endpoint_id=EP_URL)
    gateway[ROUTE] = [_live("pre-function",
                            {"access": kong.tls_min("1.3")["config"]["access"]},
                            control_id=owner.id, plugin_id="b4055c2c")]

    control_plane.reconcile_failed(db, _snapshot())

    assert failed.endpoint_id != owner.endpoint_id
    assert failed.state is ControlState.SUPERSEDED
    assert str(owner.id) in (failed.error or ""), (
        "an operator has to be able to reach the row that is enforcing")


def test_kong_filled_defaults_do_not_block_supersession(db, gateway):
    """Same trap as the writer's: Kong answers with the whole schema, so the
    live config is never equal to the stored one. Equality here would supersede
    nothing."""
    owner = _control(db, id=1161, endpoint_id=EP_OPERATION, kind="response-mask",
                     plugin_config=kong.response_mask(MASK_PAN),
                     state=ControlState.APPLIED, kong_plugin_id="5f4b72ad")
    failed = _control(db, id=1167, kind="response-mask",
                      plugin_config=kong.response_mask(MASK_PAN))
    gateway[ROUTE] = [_live("response-transformer",
                            {"remove": {"json": MASK_PAN, "headers": []},
                             "add": {"json": [], "headers": []},
                             "rename": {"json": [], "headers": []}},
                            control_id=owner.id, plugin_id="5f4b72ad")]

    control_plane.reconcile_failed(db, _snapshot())

    assert failed.state is ControlState.SUPERSEDED


# ─────────────────────────────────────────────────────────────────────────────
# The 154 that were not — the half that must survive
# ─────────────────────────────────────────────────────────────────────────────
def test_a_wider_policy_is_not_superseded_by_a_narrower_live_one(db, gateway):
    """152 of the 636. The live mask covers `pan`; these rows ask for `ifsc` too.

    They sit on the same route, under the same kind, next to 482 rows that are
    genuinely satisfied. Clearing the queue by count marks an unmasked IFSC
    field as remediated — the exposure this system exists to find, closed on the
    strength of the row next to it.
    """
    owner = _control(db, id=1161, endpoint_id=EP_OPERATION, kind="response-mask",
                     plugin_config=kong.response_mask(MASK_PAN),
                     state=ControlState.APPLIED, kong_plugin_id="5f4b72ad")
    failed = _control(db, id=1171, kind="response-mask",
                      plugin_config=kong.response_mask(MASK_PAN_AND_IFSC))
    gateway[ROUTE] = [_live("response-transformer",
                            {"remove": {"json": MASK_PAN, "headers": []}},
                            control_id=owner.id, plugin_id="5f4b72ad")]

    result = control_plane.reconcile_failed(db, _snapshot())

    assert failed.state is ControlState.FAILED
    assert result["superseded"] == []
    assert result["still_failed"] == 1


def test_a_different_plugin_in_the_slot_does_not_supersede(db, gateway):
    """The two `sunset-header` rows. `sunset-header` and `response-mask` both
    compile to `response-transformer`, and the slot is taken by the mask — so no
    Sunset header is being served and the row is a live problem, not history."""
    owner = _control(db, id=1147, endpoint_id=EP_OPERATION, kind="response-mask",
                     plugin_config=kong.response_mask(MASK_PAN),
                     state=ControlState.APPLIED, kong_plugin_id="7792c1d1")
    failed = _control(db, id=1165, kind="sunset-header", origin_stage=11,
                      plugin_config=kong.sunset_headers(
                          "Fri, 31 Jul 2026 14:51:12 GMT", "http://c/sunset"))
    gateway[ROUTE] = [_live("response-transformer",
                            {"remove": {"json": MASK_PAN, "headers": []},
                             "add": {"json": [], "headers": []}},
                            control_id=owner.id, plugin_id="7792c1d1")]

    control_plane.reconcile_failed(db, _snapshot())

    assert failed.state is ControlState.FAILED


def test_an_untagged_plugin_does_not_supersede(db, gateway):
    """Enforcement an operator put there by hand is theirs, and this system has
    no row to point an auditor at. The control keeps asking."""
    failed = _control(db, id=1168)
    gateway[ROUTE] = [{"id": "b4055c2c", "name": "pre-function",
                       "config": {"access": kong.tls_min("1.3")["config"]["access"]},
                       "tags": []}]

    control_plane.reconcile_failed(db, _snapshot())

    assert failed.state is ControlState.FAILED


def test_an_owner_that_is_not_applied_does_not_supersede(db, gateway):
    """A row mid-drift is not evidence. `reconcile` settles that direction; this
    one must not read it as proof the policy is held."""
    owner = _control(db, id=1160, endpoint_id=EP_OPERATION, kind="tls-min",
                     state=ControlState.REVERTED, kong_plugin_id="b4055c2c")
    failed = _control(db, id=1168)
    gateway[ROUTE] = [_live("pre-function",
                            {"access": kong.tls_min("1.3")["config"]["access"]},
                            control_id=owner.id, plugin_id="b4055c2c")]

    control_plane.reconcile_failed(db, _snapshot())

    assert failed.state is ControlState.FAILED


def test_an_unreadable_gateway_supersedes_nothing(db, gateway):
    """Unreadable is not unenforced, and it is certainly not enforced. A gateway
    outage must not resolve a single row in either direction."""
    _control(db, id=1160, endpoint_id=EP_OPERATION, kind="tls-min",
             state=ControlState.APPLIED, kong_plugin_id="b4055c2c")
    failed = _control(db, id=1168)
    gateway[ROUTE] = None

    result = control_plane.reconcile_failed(db, _snapshot())

    assert failed.state is ControlState.FAILED
    assert result["still_failed"] == 1


def test_an_endpoint_with_no_route_supersedes_nothing(db, gateway):
    """No route fronts it, so nothing can be enforcing its policy."""
    failed = _control(db, id=1168)

    result = control_plane.reconcile_failed(db, _Snapshot(routes=[]))

    assert failed.state is ControlState.FAILED
    assert result["still_failed"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Not proposing what is already applied
# ─────────────────────────────────────────────────────────────────────────────
def test_reapplying_an_applied_control_writes_no_second_row(db, monkeypatch):
    """The duplicate the idempotent actuator would otherwise produce.

    Every re-proposal now succeeds at the gateway, so without this each pass
    leaves another APPLIED row pointing at the one plugin.
    """
    existing = _control(db, id=1155, kind="tls-min", state=ControlState.APPLIED,
                        kong_plugin_id="2c00c476")
    monkeypatch.setattr(kong, "create_route_plugin",
                        lambda *a, **k: pytest.fail("the gateway was touched"))

    got = control_plane.apply(
        db, endpoint_id=EP_URL, route_name=ROUTE, kind="tls-min",
        plugin_config=kong.tls_min("1.3"), origin_stage=10, actor="system:stage-13")

    assert got.id == existing.id
    assert db.query(Control).count() == 1, "a duplicate control row was committed"


def test_a_changed_policy_is_still_proposed(db, monkeypatch):
    """Skipping on `(endpoint_id, kind)` alone would file a tightened mask as
    already-satisfied and never enforce the difference. It goes to Kong, which
    refuses it as a conflict — loudly, which is the point."""
    _control(db, id=1145, kind="response-mask", state=ControlState.APPLIED,
             kong_plugin_id="4034797d",
             plugin_config=kong.response_mask(MASK_PAN))
    monkeypatch.setattr(kong, "create_route_plugin",
                        lambda *a, **k: kong.PluginRef(id="new", name="rt"))

    got = control_plane.apply(
        db, endpoint_id=EP_URL, route_name=ROUTE, kind="response-mask",
        plugin_config=kong.response_mask(MASK_PAN_AND_IFSC),
        origin_stage=10, actor="system:stage-10")

    assert got.id != 1145
    assert db.query(Control).count() == 2


def test_an_applied_row_without_a_plugin_id_is_not_proof(db, monkeypatch):
    """That row is the drift `reconcile` exists to catch. Treating it as
    enforcement would let one broken row suppress every attempt to fix it."""
    _control(db, id=1155, kind="tls-min", state=ControlState.APPLIED,
             kong_plugin_id=None)
    monkeypatch.setattr(kong, "create_route_plugin",
                        lambda *a, **k: kong.PluginRef(id="fresh", name="pre-function"))

    got = control_plane.apply(
        db, endpoint_id=EP_URL, route_name=ROUTE, kind="tls-min",
        plugin_config=kong.tls_min("1.3"), origin_stage=10, actor="system:stage-10")

    assert got.id != 1155
    assert got.kong_plugin_id == "fresh"


def test_a_reverted_control_can_be_applied_again(db, monkeypatch):
    """The guard is about APPLIED rows only. A control that was reverted has no
    enforcement behind it, and re-applying it must still reach the gateway."""
    _control(db, id=1155, kind="tls-min", state=ControlState.REVERTED,
             kong_plugin_id="2c00c476")
    monkeypatch.setattr(kong, "create_route_plugin",
                        lambda *a, **k: kong.PluginRef(id="fresh", name="pre-function"))

    got = control_plane.apply(
        db, endpoint_id=EP_URL, route_name=ROUTE, kind="tls-min",
        plugin_config=kong.tls_min("1.3"), origin_stage=10, actor="system:stage-10")

    assert got.state is ControlState.APPLIED
    assert got.id != 1155


# ─────────────────────────────────────────────────────────────────────────────
# One plugin, one revert
# ─────────────────────────────────────────────────────────────────────────────
def test_reverting_a_shared_plugin_reverts_every_row_that_claims_it(db, monkeypatch):
    """The hazard the duplicates create.

    Two endpoints differing only by a SOAP operation fragment share a route, the
    actuator adopts the plugin already in the slot for the second, and both rows
    are legitimately APPLIED against one plugin. Deleting it while leaving the
    sibling APPLIED is the console reporting enforcement that does not exist —
    the drift direction `reconcile` calls the more dangerous one.
    """
    first = _control(db, id=1160, endpoint_id=EP_OPERATION, kind="tls-min",
                     state=ControlState.APPLIED, kong_plugin_id="b4055c2c")
    second = _control(db, id=2900, endpoint_id=EP_URL, kind="tls-min",
                      state=ControlState.APPLIED, kong_plugin_id="b4055c2c")
    deleted: list[str] = []
    monkeypatch.setattr(kong, "delete_plugin", lambda pid: deleted.append(pid))

    control_plane.revert(db, first, actor="approver", reason="test")

    assert deleted == ["b4055c2c"], "the plugin is one thing and goes once"
    assert first.state is ControlState.REVERTED
    assert second.state is ControlState.REVERTED, (
        "a row left APPLIED over a deleted plugin is enforcement the console "
        "reports and the gateway does not have")
    assert str(first.id) in (second.error or "")


def test_reverting_does_not_touch_a_different_plugin(db, monkeypatch):
    """The sibling sweep is keyed on the plugin id, not the endpoint or kind."""
    target = _control(db, id=1160, kind="tls-min", state=ControlState.APPLIED,
                      kong_plugin_id="b4055c2c")
    other = _control(db, id=1161, kind="response-mask", state=ControlState.APPLIED,
                     kong_plugin_id="5f4b72ad")
    monkeypatch.setattr(kong, "delete_plugin", lambda pid: None)

    control_plane.revert(db, target, actor="approver", reason="test")

    assert other.state is ControlState.APPLIED


def test_a_failed_delete_reverts_nothing(db, monkeypatch):
    """If the plugin is still there, every row that claims it is still true."""
    first = _control(db, id=1160, kind="tls-min", state=ControlState.APPLIED,
                     kong_plugin_id="b4055c2c")
    second = _control(db, id=2900, endpoint_id=EP_OPERATION, kind="tls-min",
                      state=ControlState.APPLIED, kong_plugin_id="b4055c2c")

    def refuse(pid):
        raise kong.KongUnavailable("connection refused")

    monkeypatch.setattr(kong, "delete_plugin", refuse)

    with pytest.raises(kong.KongUnavailable):
        control_plane.revert(db, first, actor="approver", reason="test")

    assert first.state is ControlState.APPLIED
    assert second.state is ControlState.APPLIED
