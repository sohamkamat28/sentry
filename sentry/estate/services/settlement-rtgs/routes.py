"""settlement-rtgs — RTGS settlement instruction status.

Team: payments. Settlement class: throttle-exempt.
"""

from estate_app import app, call_upstream, health, payment_body

UPSTREAMS = [
    "https://core-accounts:8443/api/v1/accounts/8814",
    "https://shadow-fx-rate:8443/internal/fx/rate",
]


@app.get("/api/v1/settlement/rtgs/<reference>")
def get_settlement(reference: str) -> dict:
    body = payment_body(reference)
    body["dependencies"] = [call_upstream(u) for u in UPSTREAMS]
    return body


@app.get("/healthz")
def healthz() -> dict:
    return health()
