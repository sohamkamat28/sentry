"""payments-upi — UPI payment initiation.

Team: payments. Calls core-accounts for the debit balance and shadow-fx-rate for
conversion.
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
