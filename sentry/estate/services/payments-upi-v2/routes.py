"""payments-upi-v2 — the replacement the canary path migrates onto.

Team: payments.

Same contract as payments-upi: same path, same response shape, same upstream
dependencies. That is what makes it a valid migration target rather than a
different endpoint — a canary shifts a proportion of live traffic onto this and
compares error rates, so any difference it measures has to be attributable to
the migration and not to the two services doing different things.

The estate had no replacement upstream at all, which is why the canary path
could be selected, tested in unit tests, and never once run: an endpoint whose
blast radius touches a payment system was routed to canary and then waited
forever for somewhere to go.
"""

from estate_app import app, call_upstream, health, payment_body

UPSTREAMS = [
    "https://core-accounts:8443/api/v1/accounts/balance/8814",
    "https://shadow-fx-rate:8443/internal/fx/rate",
]


@app.get("/api/v1/payments/upi/<reference>")
def get_payment(reference: str) -> dict:
    body = payment_body(reference)
    body["dependencies"] = [call_upstream(u) for u in UPSTREAMS]
    return body


@app.get("/healthz")
def healthz() -> dict:
    return health()
