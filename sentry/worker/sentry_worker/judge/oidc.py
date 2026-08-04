"""Tokens from the institution's authorisation server, for the Judge to present.

The `oauth2` control was rejected on every run, and the reason was the harness
rather than the control: the Judge replayed anonymously against a plugin whose
entire purpose is to reject anonymous callers, observed a 401, and reported that
the patch broke the endpoint. That is a true statement about callers without a
token and a useless one about the control — the same defect that made `key-auth`
unjudgeable until a consumer and a credential existed.

`key-auth` was fixable by provisioning a key. This needs a real issuer: a token
signed by something Kong can verify against, obtained the way a service actually
obtains one. Keycloak is deployed here as the platform's own identity provider,
so the issuer exists and this asks it for a client-credentials token.

Nothing is faked. If Keycloak is unreachable, or the client is not registered, no
token is returned and the Judge replays without one — which puts the control back
where it was, rejected for a stated reason, rather than passing on a token this
module invented.
"""

from __future__ import annotations

import base64
import json
import threading
import time

import httpx

from sentry_core.config import settings


class NoToken(RuntimeError):
    """No token could be obtained. The caller replays anonymously and says so."""


#: Cached until shortly before expiry. A token fetch per replayed request would
#: put the authorisation server on the hot path of a measurement that is trying
#: to observe latency, and the token's own round trip would land in the number.
_lock = threading.Lock()
_cached: tuple[str, float] | None = None


def _token_url() -> str:
    return f"{(settings.oidc_issuer or '').rstrip('/')}/protocol/openid-connect/token"


def _internal(url: str) -> str:
    """Reach the issuer on the network rather than at its published identity.

    An issuer is an identity, not an address. Keycloak's `iss` here is
    `http://localhost:8081/...` because that is what a browser sees, and nothing
    inside the compose network can resolve it — the same split that made the API
    reject its own tokens as "invalid issuer" until the JWKS URL was configured
    separately. The JWKS URL already carries the reachable host, so the token
    endpoint is derived from it.
    """
    jwks = settings.oidc_jwks_url
    if not jwks:
        return url
    base = jwks.split("/protocol/", 1)[0]
    return f"{base}/protocol/openid-connect/token"


def fetch_token(*, timeout: float = 10.0) -> str:
    """A client-credentials access token, cached until it nears expiry."""
    global _cached

    if not settings.oidc_issuer:
        raise NoToken("OIDC_ISSUER is not configured; there is no issuer to ask")
    client_id = settings.judge_oidc_client_id
    secret = settings.judge_oidc_client_secret
    if not client_id or not secret:
        raise NoToken("JUDGE_OIDC_CLIENT_ID/SECRET are not configured")

    with _lock:
        if _cached and _cached[1] > time.time() + 30:
            return _cached[0]

        try:
            r = httpx.post(
                _internal(_token_url()),
                data={"grant_type": "client_credentials",
                      "client_id": client_id,
                      "client_secret": secret},
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            raise NoToken(f"authorisation server unreachable: {exc}") from exc

        if r.status_code >= 400:
            raise NoToken(f"token request returned {r.status_code}: {r.text[:200]}")

        body = r.json()
        token = body.get("access_token")
        if not token:
            raise NoToken("token response carried no access_token")

        ttl = float(body.get("expires_in") or 60)
        _cached = (token, time.time() + ttl)
        return token


def issuer_of(token: str) -> str:
    """The `iss` claim the token actually carries.

    Read from the token rather than from configuration, because Kong's `jwt`
    plugin selects the verifying credential by matching this claim against the
    credential's key — so a credential registered under any other string is
    never consulted and every token is rejected as unknown.

    They differ here for a real reason. `OIDC_ISSUER` is
    `http://localhost:8081/...`, the address a browser uses; Keycloak stamps
    `iss` with the host the token was requested through, which from inside the
    network is `http://keycloak:8081/...`. That is the same identity-versus-
    address split that made the API reject its own tokens as "invalid issuer"
    until the JWKS URL was configured separately from the issuer.

    The claim is read without verifying the signature, which is safe for this
    use: the value only selects which public key Kong will verify against, and
    a token naming a key it cannot be verified by is rejected by Kong.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError) as exc:
        raise NoToken(f"token is not a readable JWT: {exc}") from exc
    iss = claims.get("iss")
    if not iss:
        raise NoToken("token carries no iss claim, so Kong cannot select a key")
    return str(iss)


def _b64u_int(v: str) -> int:
    raw = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
    return int.from_bytes(raw, "big")


def _pem_from_jwk(jwk: dict) -> str:
    """A SubjectPublicKeyInfo PEM built from the JWK's own modulus and exponent.

    Built from `n`/`e` rather than from `x5c`. An x5c entry is a DER X.509
    *certificate* — the key wrapped in an identity, a validity window and a
    signature — and re-wrapping those bytes in `BEGIN PUBLIC KEY` headers
    produces a file whose armour claims one structure and whose contents are
    another. Kong parses it, finds a certificate where a SubjectPublicKeyInfo
    should be, and answers `rsa_public_key: invalid key`.

    `n` and `e` are the key itself, and every JWKS publishes them for an RSA
    signing key, so this also works for an issuer that omits x5c entirely.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    try:
        key = rsa.RSAPublicNumbers(
            e=_b64u_int(jwk["e"]), n=_b64u_int(jwk["n"])).public_key()
    except (KeyError, ValueError) as exc:
        raise NoToken(f"JWKS entry is not a usable RSA key: {exc}") from exc

    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def signing_key_pem(*, timeout: float = 10.0) -> str:
    """The issuer's RS256 signing key, in the PEM form Kong's jwt plugin wants.

    Read from the issuer's own JWKS rather than configured, so a key rotation is
    picked up on the next judge run instead of silently rejecting every token
    until somebody notices.
    """
    if not settings.oidc_jwks_url:
        raise NoToken("OIDC_JWKS_URL is not configured")
    try:
        r = httpx.get(settings.oidc_jwks_url, timeout=timeout)
        r.raise_for_status()
        keys = r.json().get("keys") or []
    except (httpx.HTTPError, ValueError) as exc:
        raise NoToken(f"JWKS unreadable: {exc}") from exc

    for k in keys:
        if k.get("kty") == "RSA" and k.get("alg") == "RS256" \
                and k.get("use") in (None, "sig"):
            return _pem_from_jwk(k)
    raise NoToken("no RS256 signing key in the issuer's JWKS")
