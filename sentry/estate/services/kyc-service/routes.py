"""kyc-service — customer identity verification status.

Team: compliance. Responses carry Aadhaar and PAN.
"""

from estate_app import app, health, kyc_body


@app.get("/api/v1/kyc/<customer_id>")
def get_kyc(customer_id: str) -> dict:
    return kyc_body(customer_id)


@app.get("/healthz")
def healthz() -> dict:
    return health()
