"""Identity and role enforcement.

Four roles. The analyst/approver boundary is the technical expression of the
governance requirement: the person who proposes a production change is not
automatically the person who authorises it. An analyst can prepare a fully
evidenced control and cannot apply it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from sentry_core.config import settings

from .errors import PermissionError_, Unauthenticated

_bearer = HTTPBearer(auto_error=False)

ROLE_ORDER = {"viewer": 0, "analyst": 1, "approver": 2, "admin": 3}


@dataclass
class Claims:
    sub: str
    roles: list[str] = field(default_factory=list)
    email: str | None = None

    def has(self, *required: str) -> bool:
        if "admin" in self.roles:
            return True
        return bool(set(required) & set(self.roles))

    @property
    def actor(self) -> str:
        return self.email or self.sub


class _JWKSCache:
    def __init__(self) -> None:
        self._keys: dict | None = None
        self._fetched_at = 0.0

    def get(self) -> dict:
        now = time.time()
        if self._keys is None or now - self._fetched_at > settings.oidc_jwks_cache_s:
            url = settings.oidc_jwks_url or (
                f"{settings.oidc_issuer.rstrip('/')}/protocol/openid-connect/certs")
            with httpx.Client(timeout=5.0) as c:
                self._keys = c.get(url).json()
            self._fetched_at = now
        return self._keys


_jwks = _JWKSCache()

#: Dev-mode identities. Reachable only when AUTH_DISABLED is set, which the
#: config layer refuses in prod.
DEV_TOKENS = {
    "dev-viewer": Claims("dev-viewer", ["viewer"], "viewer@dev.local"),
    "dev-analyst": Claims("dev-analyst", ["viewer", "analyst"], "analyst@dev.local"),
    "dev-approver": Claims("dev-approver", ["viewer", "analyst", "approver"],
                           "approver@dev.local"),
    "dev-admin": Claims("dev-admin", ["viewer", "analyst", "approver", "admin"],
                        "admin@dev.local"),
    "ci-gate": Claims("ci-gate", ["ci-gate"], "ci@dev.local"),
}


def _decode(token: str) -> Claims:
    from jose import jwt

    key = _jwks.get()
    payload = jwt.decode(
        token,
        key,
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer,
        options={"leeway": 60},
    )
    realm = payload.get("realm_access", {}).get("roles", [])
    return Claims(sub=payload["sub"], roles=list(realm), email=payload.get("email"))


async def verify_token(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Claims:
    if creds is None or not creds.credentials:
        raise Unauthenticated("TOKEN_REQUIRED", "bearer token required")

    token = creds.credentials

    if settings.auth_disabled:
        claims = DEV_TOKENS.get(token)
        if claims is None:
            raise Unauthenticated("UNKNOWN_DEV_TOKEN",
                                  f"dev tokens: {', '.join(sorted(DEV_TOKENS))}")
        request.state.claims = claims
        return claims

    if not settings.oidc_issuer:
        raise Unauthenticated("OIDC_NOT_CONFIGURED", "OIDC_ISSUER is not set")

    try:
        claims = _decode(token)
    except Exception as exc:
        raise Unauthenticated("TOKEN_INVALID", str(exc)) from exc

    request.state.claims = claims
    return claims


def require(*roles: str):
    """Route dependency. Disabling rather than hiding is the console's job; here
    the check is absolute."""

    async def _dep(claims: Claims = Depends(verify_token)) -> Claims:
        if not claims.has(*roles):
            raise PermissionError_(
                "ROLE_REQUIRED",
                f"requires one of: {', '.join(roles)}",
                {"required": list(roles), "held": claims.roles},
            )
        return claims

    return _dep


viewer = require("viewer", "analyst", "approver", "admin")
analyst = require("analyst", "approver", "admin")
approver = require("approver", "admin")
admin = require("admin")
ci_gate = require("ci-gate")
