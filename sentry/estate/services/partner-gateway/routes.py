"""partner-gateway — the estate's internet-facing surface.

Team: partnerships.

Every other service in this estate is reachable only from inside the network, so
`internet_reachable` has been false for every endpoint SENTRY has ever scored and
the CDRI term that weights it has never contributed anything. This one is
declared externally reachable in the gateway registry, which is what puts a real
non-zero value into that term.

It fans out to `payments-upi` and `core-accounts`: an external caller reaching
two internal services is the shape that makes blast radius interesting, because
the two-hop cap starts mattering here rather than terminating immediately.
"""

import os

from estate_app import app, call_upstream, health

ACCOUNTS = os.getenv("UPSTREAM_ACCOUNTS", "https://core-accounts:8443")
UPI = os.getenv("UPSTREAM_UPI", "https://payments-upi:8443")


@app.get("/api/v1/partner/status")
def get_status() -> dict:
    return {
        "partner": "AGGREGATOR-01",
        "state": "LIVE",
        "since": "2024-04-01",
        "tier": "GOLD",
    }


@app.get("/api/v1/partner/<partner_id>/limits")
def get_limits(partner_id: str) -> dict:
    return {
        "partnerId": partner_id,
        "dailyValueLimit": "50000000.00",
        "dailyCountLimit": 200000,
        "currency": "INR",
    }


@app.get("/api/v1/partner/rates")
def get_rates() -> dict:
    return {
        "USDINR": "83.42",
        "EURINR": "90.18",
        "GBPINR": "105.77",
        "asOf": "2026-07-28T09:00:00Z",
    }


@app.post("/api/v1/partner/settlement", body_schema={
    "type": "object",
    "required": ["partnerId", "batchId"],
    "properties": {
        "partnerId": {"type": "string"},
        "batchId": {"type": "string"},
        "valueDate": {"type": "string"},
    },
})
def post_settlement() -> dict:
    account = call_upstream(f"{ACCOUNTS}/api/v1/accounts/balance/40001")
    payment = call_upstream(f"{UPI}/api/v1/payments/upi/PARTNER01")
    return {
        "settlementId": "PSET-20260728-001",
        "count": 18402,
        "value": "412900000.00",
        "status": "ACCEPTED",
        "legs": [account, payment],
    }


@app.get("/healthz")
def healthz() -> dict:
    return health()
