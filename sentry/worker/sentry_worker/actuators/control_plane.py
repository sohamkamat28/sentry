"""The single writer of gateway state.

Every throttle, sunset header, canary weight and 410 termination in this system
goes through ``apply`` — stage 10's virtual patches and stage 11's phase
transitions alike. One writer means one audit trail, one place where ``APPLIED``
can become true, and one rollback path.

A phase transition that wrote to Kong directly would be a gateway change with no
``control`` row to revert it by, which is the state the reconciler exists to
prevent and would have no way to distinguish from an operator's own work.

Two reconcilers, because a control row and a gateway plugin can disagree in both
directions. ``reconcile`` asks whether the gateway holds what the database
claims. ``reconcile_failed`` asks the reverse of the rows that claim nothing: a
FAILED control is a request to an operator, and 636 of them asked for work that
was already done. Neither trusts this table for evidence — both read Kong.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from sentry_core import audit
from sentry_core.enums import ControlState
from sentry_core.models import Control, Endpoint

from . import kong


class ApplyFailed(RuntimeError):
    """The gateway refused or was unreachable. The control row records why."""

    def __init__(self, control: Control, reason: str) -> None:
        self.control = control
        super().__init__(reason)


def route_for(snapshot, ep) -> str | None:
    """Which gateway route fronts an endpoint.

    A SOAP operation's identity is ``<path>#<Operation>`` and no gateway route
    path carries a fragment — the operation travels in the SOAPAction header. So
    the fragment is stripped before matching, and the consequence is stated
    rather than hidden: a control applied to this route affects every operation
    on that URL, not only the one that was judged, because Kong routes on the
    path and cannot see the header.

    That consequence is not theoretical. ``POST /finacle/customerservice`` and
    ``POST /finacle/customerservice#GetCustomerKyc`` are two endpoints that
    collapse onto one route, and Kong permits one instance of a plugin name per
    route — so the second endpoint's ``tls-min`` collided with the first's 482
    times. Reading this function is how the reconciler knows those two rows are
    talking about the same plugin.

    This is the single implementation. It lives beside the writer rather than in
    the runner because the reconciler needs it too, and a second copy is how the
    first one diverged the moment one of them learned about SOAP.
    """
    wanted = ep.path_template.split("#", 1)[0].casefold()
    full = ep.path_template.casefold()

    for route in snapshot.routes:
        if route.service_name != ep.service.name:
            continue
        for template in route.path_templates:
            for method in route.methods:
                if method.upper() != ep.method.upper():
                    continue
                # Case-folded: the collector normalises templates to lower case
                # and a declared route keeps whatever case its author wrote.
                if template.casefold() in (full, wanted):
                    return route.route_name
    return None


def _same_policy(a: dict, b: dict) -> bool:
    """Do two stored ``plugin_config`` values state the same policy?

    Both sides are configs as a control stores them — what the proposer wrote,
    not what Kong echoes back — so this is equality, not the subset test the
    gateway comparison needs. Canonicalised because a JSON round-trip through
    the database does not promise key order.

    Deliberately strict. A false negative costs one redundant proposal, which
    the gateway then resolves. A false positive skips a control that says
    something the applied one does not — a wider set of masked fields, a lower
    throttle — and silently leaves the difference unenforced.
    """
    return audit.canonical_json(a or {}) == audit.canonical_json(b or {})


def _applied_equivalent(db: Session, endpoint_id: str, kind: str,
                        plugin_config: dict) -> Control | None:
    """An APPLIED control on this endpoint already stating this exact policy.

    Requires a ``kong_plugin_id``: a row claiming APPLIED without one is the
    drift ``reconcile`` exists to catch, and treating it as proof of enforcement
    would let one broken row suppress every future attempt to fix it.
    """
    for existing in db.execute(
        select(Control).where(
            Control.endpoint_id == endpoint_id,
            Control.kind == kind,
            Control.state == ControlState.APPLIED,
        ).order_by(Control.id)
    ).scalars():
        if existing.kong_plugin_id and _same_policy(existing.plugin_config, plugin_config):
            return existing
    return None


def apply(
    db: Session,
    *,
    endpoint_id: str,
    route_name: str,
    kind: str,
    plugin_config: dict,
    origin_stage: int,
    actor: str,
    judge_run_id: int | None = None,
    generator: str = "template",
) -> Control:
    """Create the control row, then put the plugin on the route.

    The row is committed before the gateway is touched. The two cannot be one
    transaction, so the ordering decides which way an interruption fails: this
    way leaves a control row with no plugin, which the next reconcile re-applies
    or discards. The other way leaves a plugin enforcing policy that no row
    records — unattributable configuration in a production gateway.

    ``APPLIED`` is set only when Kong returns a plugin id. There is no path
    here that marks a control applied on a hopeful 2xx, because the id is what
    the rollback needs.

    A proposal that is already applied returns the existing row and writes
    nothing — no control row, no gateway call. Without this, an idempotent
    actuator turns the old failure into a quieter one: every re-proposal now
    succeeds, so a hundred passes leave a hundred APPLIED rows all naming one
    ``kong_plugin_id``. That reads on the Remediation surface as a hundred
    controls and reverts as one, which is a worse lie than the 409 was.

    Equivalence is judged on the stored config, so a control that says something
    *different* about the same slot is still proposed and still reaches Kong —
    where it is refused as a conflict, by design. Skipping it here would file a
    tightened policy as already-satisfied and never enforce it.
    """
    duplicate = _applied_equivalent(db, endpoint_id, kind, plugin_config)
    if duplicate is not None:
        return duplicate

    control = Control(
        endpoint_id=endpoint_id,
        kind=kind,
        plugin_config=plugin_config,
        state=ControlState.PROPOSED,
        generator=generator,
        judge_run_id=judge_run_id,
        origin_stage=origin_stage,
        actor=actor,
    )
    db.add(control)
    db.commit()

    try:
        ref = kong.create_route_plugin(route_name, plugin_config, control_id=control.id)
    except (kong.KongUnavailable, kong.KongRejected) as exc:
        control.state = ControlState.FAILED
        control.error = str(exc)[:500]
        db.commit()
        raise ApplyFailed(control, str(exc)) from exc

    control.kong_plugin_id = ref.id
    control.state = ControlState.APPLIED
    control.applied_at = datetime.now(timezone.utc)

    audit.record(
        db, actor=actor, action="control.applied", target=endpoint_id,
        detail={"control_id": control.id, "kind": kind, "origin_stage": origin_stage,
                "kong_plugin_id": ref.id, "route": route_name},
    )
    db.commit()
    return control


def revert(db: Session, control: Control, *, actor: str, reason: str) -> None:
    """Remove the plugin and mark every control that claimed it reverted.

    A control with no plugin id was never applied, so there is nothing at the
    gateway to remove — the row is still marked, because an operator asking why
    a control is gone needs the reason either way.

    More than one APPLIED row can name the same ``kong_plugin_id``, and this is
    not only a historical accident. Two endpoints that differ solely by a SOAP
    operation fragment resolve to one gateway route, the idempotent actuator
    adopts the plugin already in the slot for the second of them, and both rows
    are legitimately APPLIED against the one plugin that enforces both.

    There is exactly one plugin, so there is exactly one thing to delete and one
    outcome to record. Reverting the row in hand and leaving its siblings APPLIED
    would leave the console reporting enforcement that no longer exists — the
    precise failure ``reconcile`` calls the more dangerous direction of drift,
    manufactured here deliberately instead of found. The siblings go with it, and
    the audit entry for each names the control the operator actually acted on.
    """
    siblings: list[Control] = []
    if control.kong_plugin_id:
        siblings = [
            c for c in db.execute(
                select(Control).where(
                    Control.kong_plugin_id == control.kong_plugin_id,
                    Control.state == ControlState.APPLIED,
                    Control.id != control.id,
                )
            ).scalars()
        ]
        try:
            kong.delete_plugin(control.kong_plugin_id)
        except (kong.KongUnavailable, kong.KongRejected) as exc:
            control.error = f"revert failed: {str(exc)[:400]}"
            db.commit()
            raise

    now = datetime.now(timezone.utc)
    for other in siblings:
        other.state = ControlState.REVERTED
        other.reverted_at = now
        other.error = (
            f"reverted with control {control.id}: both were applied to plugin "
            f"{control.kong_plugin_id}, and removing it removes this one too"
        )[:500]
        audit.record(
            db, actor=actor, action="control.reverted", target=other.endpoint_id,
            detail={"control_id": other.id, "kind": other.kind,
                    "reason": reason, "reverted_with": control.id,
                    "kong_plugin_id": control.kong_plugin_id},
        )

    control.state = ControlState.REVERTED
    control.reverted_at = now
    audit.record(
        db, actor=actor, action="control.reverted", target=control.endpoint_id,
        detail={"control_id": control.id, "kind": control.kind, "reason": reason,
                **({"also_reverted": [c.id for c in siblings]} if siblings else {})},
    )
    db.commit()


def reconcile(db: Session, *, actor: str = "system:reconcile") -> dict:
    """Make the gateway and the database agree, and report what disagreed.

    Two directions, and both are failures of the same kind — a claim about
    enforcement that enforcement does not support.

    A plugin with no APPLIED control behind it is unattributable policy, left by
    a process that died between the POST and the commit. It is removed.

    A control marked APPLIED whose plugin is no longer at the gateway is the
    more dangerous one: the console shows the finding as remediated and nothing
    is enforcing. A declarative re-import, a `db_reset`, or an operator deleting
    a plugin by hand all produce it. The row is moved back to PROPOSED so the
    next pass re-applies it, and the drift is recorded rather than quietly
    corrected — an operator needs to know their gateway lost a control, not just
    that it has one again.
    """
    applied = {
        c.id: c for c in db.execute(
            select(Control).where(Control.state == ControlState.APPLIED)
        ).scalars()
    }

    removed = kong.reconcile_orphans(set(applied))

    live_plugin_ids = {p["id"] for p in kong.list_owned_plugins()}
    drifted: list[dict] = []
    for control in applied.values():
        if control.kong_plugin_id and control.kong_plugin_id in live_plugin_ids:
            continue
        drifted.append({"control_id": control.id, "endpoint_id": control.endpoint_id,
                        "kind": control.kind, "plugin_id": control.kong_plugin_id})
        control.state = ControlState.PROPOSED
        control.error = "gateway drift: the plugin is no longer present"
        control.kong_plugin_id = None
        audit.record(db, actor=actor, action="control.drift", target=control.endpoint_id,
                     detail={"control_id": control.id, "kind": control.kind})

    if drifted:
        db.commit()
    return {"orphans_removed": removed, "controls_drifted": drifted}


def reconcile_failed(db: Session, snapshot, *,
                     actor: str = "system:reconcile") -> dict:
    """Close out FAILED controls whose policy the gateway is already enforcing.

    ``reconcile`` answers "does the gateway hold what the database claims". This
    answers the question the other way round, for the rows that claim nothing: a
    FAILED control is a request to an operator, and 636 of them asked for work
    that was mostly already done.

    A row is superseded when, and only when, all of this holds:

    * a route fronts its endpoint;
    * that route carries a live plugin of the same name whose config satisfies
      this row's — the same subset test the writer uses, so a row is never filed
      as satisfied on a comparison the actuator would have called a conflict;
    * the plugin is owned, by tag, by a control that is APPLIED and names it.

    Everything else stays FAILED, and that is the load-bearing half. Of the 636,
    482 ``tls-min`` rows and one ``response-mask`` state exactly what control
    1160 and 1161 put on ``finacle-customerservice``. The other 152 ask for
    ``ifsc`` and ``ifscCode`` to be masked and the live plugin masks neither, and
    two ``sunset-header`` rows want a ``response-transformer`` on a route whose
    one permitted instance is already a response mask. Those 154 are real: a
    sweep that cleared them by count would have closed an open PII exposure on
    the strength of a row next to it.

    Evidence comes from Kong, never from this table. The database's account of
    what is enforced is the thing being checked.
    """
    failed = list(db.execute(
        select(Control).where(Control.state == ControlState.FAILED)
        .order_by(Control.id)
    ).scalars())
    if not failed:
        return {"superseded": [], "still_failed": 0, "unresolved": []}

    endpoints = {
        ep.id: ep for ep in db.execute(
            select(Endpoint)
            .options(selectinload(Endpoint.service))
            .where(Endpoint.id.in_({c.endpoint_id for c in failed}))
        ).scalars()
    }
    applied = {
        c.id: c for c in db.execute(
            select(Control).where(Control.state == ControlState.APPLIED)
        ).scalars()
    }

    plugins_by_route: dict[str, list[dict] | None] = {}
    superseded: list[dict] = []
    unresolved: dict[str, int] = {}

    for control in failed:
        ep = endpoints.get(control.endpoint_id)
        route = route_for(snapshot, ep) if ep is not None else None
        if route is None:
            unresolved["no gateway route fronts this endpoint"] = \
                unresolved.get("no gateway route fronts this endpoint", 0) + 1
            continue

        if route not in plugins_by_route:
            try:
                plugins_by_route[route] = kong.route_plugins(route)
            except (kong.KongUnavailable, kong.KongRejected):
                # Unreadable is not the same as unenforced. The row keeps its
                # FAILED state and the next pass asks again.
                plugins_by_route[route] = None
        live = plugins_by_route[route]
        if live is None:
            unresolved["gateway unreadable"] = unresolved.get("gateway unreadable", 0) + 1
            continue

        owner = _enforcing_control(control, live, applied)
        if owner is None:
            unresolved["policy is not enforced at the gateway"] = \
                unresolved.get("policy is not enforced at the gateway", 0) + 1
            continue

        control.state = ControlState.SUPERSEDED
        control.superseded_by = owner.id
        control.error = (
            f"superseded: this policy is enforced on route {route} by control "
            f"{owner.id} (plugin {owner.kong_plugin_id}), which was applied to "
            f"endpoint {owner.endpoint_id}"
        )[:500]
        audit.record(
            db, actor=actor, action="control.superseded", target=control.endpoint_id,
            detail={"control_id": control.id, "kind": control.kind,
                    "superseded_by": owner.id, "route": route,
                    "kong_plugin_id": owner.kong_plugin_id},
        )
        superseded.append({"control_id": control.id, "endpoint_id": control.endpoint_id,
                           "kind": control.kind, "superseded_by": owner.id,
                           "route": route})

    if superseded:
        db.commit()

    return {
        "superseded": superseded,
        "still_failed": len(failed) - len(superseded),
        "unresolved": [{"reason": r, "controls": n} for r, n in sorted(unresolved.items())],
    }


def _enforcing_control(control: Control, live: list[dict],
                       applied: dict[int, Control]) -> Control | None:
    """The APPLIED control whose live plugin already satisfies ``control``."""
    want_name = (control.plugin_config or {}).get("name")
    want_config = (control.plugin_config or {}).get("config", {})
    if not want_name:
        return None

    for plugin in live:
        if plugin.get("name") != want_name:
            continue
        if not kong.config_is_subset(want_config, plugin.get("config") or {}):
            continue
        owner = applied.get(kong.control_id_of(plugin) or -1)
        # An owner that does not name this plugin is a row mid-drift; let
        # `reconcile` settle it rather than reading it as evidence.
        if owner is not None and owner.kong_plugin_id == plugin.get("id"):
            return owner
    return None


def active_for(db: Session, endpoint_id: str, kind: str | None = None) -> list[Control]:
    stmt = select(Control).where(
        Control.endpoint_id == endpoint_id,
        Control.state == ControlState.APPLIED,
    )
    if kind is not None:
        stmt = stmt.where(Control.kind == kind)
    return list(db.execute(stmt).scalars())
