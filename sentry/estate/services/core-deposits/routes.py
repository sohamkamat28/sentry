"""core-deposits — term deposits, and the estate's east-west caller.

Team: core-banking.

Every other service in the estate is a leaf. This one calls `core-accounts` on
two of its routes, which is what gives the call graph depth: stage 09 measures
blast radius by walking real edges, and an estate of leaves makes every radius
ZERO by construction. The edges here are observed on both sides — this service's
`SSL_write` and `core-accounts`'s `SSL_read` — so they are measurements rather
than declarations.
"""

import os

from estate_app import account_body, app, call_upstream, health

ACCOUNTS = os.getenv("UPSTREAM_ACCOUNTS", "https://core-accounts:8443")


@app.get("/api/v1/deposits/<deposit_id>")
def get_deposit(deposit_id: str) -> dict:
    return {
        "depositId": deposit_id,
        "accountNumber": account_body()["accountNumber"],
        "principal": "250000.00",
        "rate": "7.10",
        "tenureMonths": 24,
        "status": "ACTIVE",
    }


@app.get("/api/v1/deposits/<deposit_id>/interest")
def get_interest(deposit_id: str) -> dict:
    # Reads the funding account before it can answer, so the edge exists because
    # the work requires it rather than because the estate needed an edge.
    upstream = call_upstream(f"{ACCOUNTS}/api/v1/accounts/{deposit_id}")
    return {
        "depositId": deposit_id,
        "accruedInterest": "4218.55",
        "nextPayoutDate": "2026-09-01",
        "fundingAccount": upstream,
    }


@app.get("/api/v1/deposits/<deposit_id>/maturity")
def get_maturity(deposit_id: str) -> dict:
    upstream = call_upstream(f"{ACCOUNTS}/api/v1/accounts/balance/{deposit_id}")
    return {
        "depositId": deposit_id,
        "maturityDate": "2027-08-01",
        "maturityAmount": "287400.00",
        "creditAccount": upstream,
    }


@app.get("/api/v1/deposits/summary")
def get_summary() -> dict:
    return {
        "openDeposits": 41207,
        "totalPrincipal": "9841200000.00",
        "currency": "INR",
        "asOf": "2026-07-28T00:00:00Z",
    }


@app.post("/api/v1/deposits", body_schema={
    "type": "object",
    "required": ["accountNumber", "principal", "tenureMonths"],
    "properties": {
        "accountNumber": {"type": "string"},
        "principal": {"type": "string"},
        "tenureMonths": {"type": "integer"},
    },
})
def create_deposit() -> dict:
    return {
        "depositId": "TD00918822",
        "accountNumber": account_body()["accountNumber"],
        "principal": "100000.00",
        "status": "CREATED",
    }


@app.get("/healthz")
def healthz() -> dict:
    return health()
