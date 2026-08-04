"""The Judge's own credential at the authorisation server.

`oauth2` was rejected on every run before this, and the reason was the harness:
the Judge replayed anonymously against a plugin whose entire purpose is to reject
anonymous callers, saw a 401, and reported that the control broke the endpoint.
That is the same defect that made `key-auth` unjudgeable until a consumer and a
key existed — a control rejected on the evidence that it works.
"""

from __future__ import annotations

import base64
import json

import pytest

from sentry_worker.judge import oidc


def _jwt(claims: dict) -> str:
    def seg(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.signature"


def test_the_credential_is_keyed_on_the_token_s_own_issuer():
    """Kong selects the verifying key by matching the token's `iss` against the
    credential's key, so a credential registered under the *configured* issuer is
    never consulted.

    These genuinely differ here: OIDC_ISSUER is the browser-facing
    `localhost:8081`, and Keycloak stamps `iss` with the host the token was
    requested through, which from inside the network is `keycloak:8081`. The same
    identity-versus-address split made the API reject its own tokens as "invalid
    issuer" until the JWKS URL was configured separately.
    """
    token = _jwt({"iss": "http://keycloak:8081/realms/sentry", "exp": 1})
    assert oidc.issuer_of(token) == "http://keycloak:8081/realms/sentry"


def test_a_token_without_an_issuer_is_refused():
    with pytest.raises(oidc.NoToken):
        oidc.issuer_of(_jwt({"exp": 1}))


def test_a_malformed_token_is_refused_rather_than_guessed_at():
    with pytest.raises(oidc.NoToken):
        oidc.issuer_of("not-a-jwt")


def test_the_signing_key_is_built_from_the_modulus_not_the_certificate():
    """`x5c` is a DER X.509 certificate — the key wrapped in an identity, a
    validity window and a signature. Re-armouring those bytes as `BEGIN PUBLIC
    KEY` produces a file whose header claims one structure and whose body is
    another, and Kong answers `rsa_public_key: invalid key`.

    `n` and `e` are the key itself.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()

    def b64u(i: int) -> str:
        raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    pem = oidc._pem_from_jwk({"n": b64u(numbers.n), "e": b64u(numbers.e)})

    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    # Round-trips: what Kong parses is the key the issuer actually signs with.
    loaded = serialization.load_pem_public_key(pem.encode())
    assert loaded.public_numbers() == numbers


def test_no_issuer_configured_means_no_token_rather_than_a_fabricated_one(monkeypatch):
    """A missing issuer puts the control back where it was — rejected for a
    stated reason — instead of passing on something this process invented."""
    from sentry_core.config import settings

    monkeypatch.setattr(settings, "oidc_issuer", None)
    with pytest.raises(oidc.NoToken):
        oidc.fetch_token()
