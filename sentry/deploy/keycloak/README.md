# Keycloak realm

`sentry-realm.json` is imported by `--import-realm` at container start.

**It carries no comments.** Keycloak's realm importer deserialises with
`FAIL_ON_UNKNOWN_PROPERTIES` enabled, so a `_comment` key anywhere in the
document aborts the whole import — the server exits non-zero and the realm does
not exist. That is why the reasoning lives here instead.

## Roles

Four in a ladder, plus one machine identity outside it.

| Role | Grants | Composite of |
|---|---|---|
| `viewer` | Read every analytical surface | — |
| `analyst` | Propose controls, enrol decommissions, run scans | `viewer` |
| `approver` | Apply and revert gateway controls, release Phase D | `analyst` |
| `admin` | Policy, weights, the virtual clock, retention | `approver` |
| `ci-gate` | `POST /gate/check` only | — deliberately not in the ladder |

The boundary that matters is **analyst → approver**. An analyst can prepare a
fully evidenced gateway control and cannot apply it; applying it is a production
change and needs a second person. That is a governance requirement expressed
technically rather than a convention, and it is why there is one account per
rung rather than one account holding everything — a permission boundary nobody
can fail is not demonstrable.

`ci-gate` is outside the ladder on purpose. A build has no user, and giving CI a
human's token would attribute every gate verdict to whoever last logged in.

## Clients

| Client | Type | Why |
|---|---|---|
| `sentry-console` | public, PKCE required | A single-page app cannot hold a secret — shipping one in a bundle publishes it — so the code exchange binds to a per-attempt verifier instead |
| `sentry-api` | bearer-only | Validates tokens, never initiates a login. It exists as a client purely to be a nameable audience |
| `sentry-ci` | confidential, client credentials | Machine identity for the build gate |

### The audience mapper is load-bearing

`api/app/security.py` decodes with `audience=OIDC_AUDIENCE` (`sentry-api`).
Keycloak's default access token carries `aud: account`, so without the
`oidc-audience-mapper` on each client **every request fails with
`TOKEN_INVALID`** — with a valid token, a correct issuer and a running realm.
The strictness is right: a token minted for another service must not be accepted
here. The audience therefore has to be put in deliberately.

### The email mapper is load-bearing too

The audit ledger records `claims.actor`, which is email or `sub`. Without the
mapper every entry in a tamper-evident ledger is attributed to a UUID — which is
technically an identity and practically useless when somebody asks who applied a
control.

### Service-account roles

`ci-gate` is granted on the implicit `service-account-sentry-ci` user, not on
the client. A client-credentials token carries that user's roles, so a role
attached anywhere else never reaches `realm_access.roles` and the gate route
answers 403 to a correctly configured CI.

## Development credentials

The four passwords equal their usernames, and `sentry-ci`'s secret is
`dev-ci-secret-change-me`. These are for a local realm import.

`AUTH_DISABLED` defaults to true in compose, so this path is used only when an
operator deliberately turns real authentication on:

```bash
AUTH_DISABLED=false docker compose up -d api
```

`config.py` refuses to start in prod when `AUTH_DISABLED` is true, when
`OIDC_ISSUER` is unset, or when any secret is a placeholder — which is the check
that stops these values travelling.

## Obtaining a token

`directAccessGrantsEnabled` is on for `sentry-console` in this realm so a
verification script can get a real token without driving a browser:

```bash
curl -s -d grant_type=password -d client_id=sentry-console \
     -d username=analyst -d password=analyst \
     http://localhost:8081/realms/sentry/protocol/openid-connect/token
```
