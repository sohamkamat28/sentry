"""shadow-fx-rate — FX conversion rates.

Stood up during a migration, called service-to-service, and never registered
anywhere: absent from the gateway, and its repository absent from the set the
code collector is pointed at. That second absence is deliberate and is the whole
point of this service — an endpoint SENTRY can only find by watching traffic.

CODE_REPO_PATHS does not include this directory. Nothing stops an operator
adding it, and doing so is what onboarding this service would mean.
"""

from estate_app import app, health


@app.get("/internal/fx/rate")
def get_rate() -> dict:
    return {"pair": "USDINR", "rate": "83.42"}


@app.get("/healthz")
def healthz() -> dict:
    return health()
