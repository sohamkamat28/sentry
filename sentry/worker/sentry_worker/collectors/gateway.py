"""Gateway collector — what the institution says it publishes.

The kernel sensor reports what the estate *does*. This reports what the gateway
*knows about*. Neither is the truth on its own, and the whole shadow argument
is the difference between them: an endpoint serving live traffic that no gateway
has a route for is either undocumented or deliberately bypassing the front door,
and in a bank both are findings.

That difference is only meaningful when this collector actually ran. A failed
poll and an empty registry are indistinguishable from the outside, and treating
one as the other would let a Kong outage brand every endpoint in the estate as
shadow. Every function here therefore reports its own health, and stage 04
withholds the SHADOW verdict when this collector is unhealthy rather than
inferring one from silence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from sentry_core.config import settings


class GatewayUnavailable(RuntimeError):
    pass


@dataclass
class GatewayRoute:
    """One route as the gateway has it declared."""

    service_name: str
    route_name: str
    #: Path templates in SENTRY's normalised form, ready to correlate.
    path_templates: list[str]
    methods: list[str] = field(default_factory=list)
    host: str | None = None
    port: int | None = None
    tags: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)


@dataclass
class GatewaySnapshot:
    routes: list[GatewayRoute]
    healthy: bool
    #: Populated only when healthy is False. Carried into the stage-04 trace so
    #: a withheld SHADOW verdict states why it was withheld.
    error: str | None = None

    @property
    def service_count(self) -> int:
        return len({r.service_name for r in self.routes})


def _client() -> httpx.Client:
    if not settings.kong_admin_url:
        raise GatewayUnavailable("KONG_ADMIN_URL is not configured")
    headers = {}
    if settings.kong_admin_token:
        headers["Kong-Admin-Token"] = settings.kong_admin_token
    return httpx.Client(base_url=settings.kong_admin_url, headers=headers, timeout=10.0)


def _paged(c: httpx.Client, path: str) -> list[dict]:
    """Walk Kong's cursor pagination to the end.

    Reading only the first page would silently truncate the registry, and a
    truncated registry marks the endpoints it omitted as shadow.
    """
    out: list[dict] = []
    url: str | None = path
    seen = 0
    while url:
        r = c.get(url)
        if r.status_code >= 400:
            raise GatewayUnavailable(f"{path} returned {r.status_code}: {r.text[:200]}")
        body = r.json()
        out.extend(body.get("data", []))
        url = body.get("next")
        seen += 1
        if seen > 100:  # a cursor that never terminates is a bug, not a big estate
            raise GatewayUnavailable(f"{path} paginated past 100 pages")
    return out


#: Kong path values beginning with ~ are regexes.
_REGEX_PREFIX = "~"


def normalise_gateway_path(path: str) -> str:
    """Turn a Kong path into the same template shape stage 03 produces.

    Kong expresses a parameter as a regex (``~/api/v1/accounts/\\d+$``) or as a
    prefix (``/api/v1/payments/upi``); SENTRY expresses it as ``{id}``. Without
    this the same endpoint carries a different key on each side and the two
    sources never correlate — every gateway-registered endpoint would then be
    reported as shadow, which is the failure mode with the worst consequences,
    because it is the one that generates work.
    """
    p = path.strip()
    if p.startswith(_REGEX_PREFIX):
        p = p[1:]
    p = p.rstrip("$").lstrip("^")

    segs = []
    for seg in p.split("/"):
        if seg == "":
            continue
        # Anything with regex metacharacters or a named capture is a parameter.
        if re.search(r"[\\\[\](){}+*?|]", seg) or seg.startswith(":"):
            segs.append("{id}")
        else:
            segs.append(seg.lower())

    return "/" + "/".join(segs) if segs else "/"


def collect() -> GatewaySnapshot:
    """Read every service, route and plugin the gateway has declared.

    Never raises on an unreachable gateway: an unhealthy snapshot is a valid
    answer that downstream stages know how to handle, and an exception here
    would abort a pipeline run over a dependency that only affects one of the
    five governance questions.
    """
    try:
        with _client() as c:
            services = {s["id"]: s for s in _paged(c, "/services")}
            routes = _paged(c, "/routes")
            plugins = _paged(c, "/plugins")
    except (GatewayUnavailable, httpx.HTTPError) as exc:
        return GatewaySnapshot(routes=[], healthy=False, error=str(exc))

    by_service: dict[str, list[str]] = {}
    for pl in plugins:
        svc = (pl.get("service") or {}).get("id")
        if svc:
            by_service.setdefault(svc, []).append(pl.get("name", "?"))

    out: list[GatewayRoute] = []
    for r in routes:
        svc_id = (r.get("service") or {}).get("id")
        svc = services.get(svc_id, {})
        name = svc.get("name") or svc_id or "unknown"

        templates = [normalise_gateway_path(p) for p in (r.get("paths") or [])]
        if not templates:
            # A route matched on host or header alone has no path to correlate
            # on. Recorded as the service root rather than dropped, so the
            # service is not mistaken for an unregistered one.
            templates = ["/"]

        out.append(GatewayRoute(
            service_name=name,
            route_name=r.get("name") or r.get("id", ""),
            path_templates=templates,
            methods=[m.upper() for m in (r.get("methods") or [])] or ["GET"],
            host=svc.get("host"),
            port=svc.get("port"),
            tags=list(svc.get("tags") or []),
            plugins=by_service.get(svc_id, []),
        ))

    return GatewaySnapshot(routes=out, healthy=True)


def criticality_from_tags(tags: list[str]) -> str | None:
    """Read declared criticality off the service.

    Tagged metadata, never inferred from the path string. An endpoint called
    ``/api/v1/payment-history`` is a reporting endpoint and one called
    ``/api/v1/xfr`` may be settlement; guessing from the name gets both wrong in
    the direction that matters.
    """
    for t in tags:
        if t.startswith("criticality:"):
            return t.split(":", 1)[1].upper()
    return None


def team_from_tags(tags: list[str]) -> str | None:
    for t in tags:
        if t.startswith("team:"):
            return t.split(":", 1)[1]
    return None


def deprecated_from_tags(tags: list[str]) -> bool:
    """Whether the owning team has formally announced this endpoint's retirement.

    A *declared* fact, not an inferred one, and the distinction is the whole
    point: an endpoint may be busy and deprecated at the same time, and the
    lifecycle axis — which is measured from traffic — cannot express that. It is
    the other way an endpoint becomes eligible for decommissioning, alongside
    being measured as a zombie.

    Nothing wrote this column. `Endpoint.deprecated` declared stage 03 as its
    writer and stage 03 only ever copied it, so a team had no way to announce a
    retirement at all and the only route into the sunset workflow was going
    silent for ninety days.
    """
    return any(t.strip().lower() in ("deprecated", "lifecycle:deprecated")
               for t in tags)
