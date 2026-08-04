"""core-accounts — customer account and balance retrieval.

Team: core-banking.
"""

from estate_app import account_body, app, health


@app.get("/api/v1/accounts/<account_id>")
def get_account(account_id: str) -> dict:
    return account_body(account_id)


@app.get("/api/v1/accounts/balance/<account_id>")
def get_balance(account_id: str) -> dict:
    return account_body(account_id)


# Superseded by /api/v1/accounts/balance in 2024 and never removed. Still
# routed, still serving, and nothing calls it any more.
@app.get("/api/v1/legacy-balance")
def get_legacy_balance() -> dict:
    return account_body()


# The resurrection.
#
# Same handler, same response, same callers, same rhythm — a new path. This is
# what a team does when an endpoint is retired and something still needed it:
# they stand it back up somewhere else, and the registry has no way to know it
# is the same surface because every identifier it keys on has changed.
#
# Stage 12 catches it because the fingerprint excludes path tokens by
# construction. Nothing here is marked, tagged or registered as a resurrection;
# it is an ordinary new route, and the match is a measurement.
@app.get("/api/v2/balance-v2")
def get_balance_v2() -> dict:
    return account_body()


@app.get("/healthz")
def healthz() -> dict:
    return health()
