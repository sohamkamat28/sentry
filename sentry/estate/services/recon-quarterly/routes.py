"""recon-quarterly — statutory reconciliation, fired on quarter boundaries.

Team: compliance. REGULATORY criticality.

The endpoint that must never be classified a zombie. It is silent for eighty-nine
consecutive vdays and then issues a burst, which is exactly the shape a 30-day
lifecycle window reads as dead. Nothing marks it exempt: the confidence ramp and
the 90-day window are what keep it ACTIVE, and if they stop doing so this service
is how that regression becomes visible.
"""

from estate_app import app, health


@app.post("/api/v1/recon/statutory", body_schema={
    "type": "object",
    "required": ["period"],
    "properties": {
        "period": {"type": "string"},
        "submitTo": {"type": "string"},
    },
})
def run_statutory() -> dict:
    return {
        "runId": "RECON-2026-Q3",
        "period": "2026-Q3",
        "ledgerEntries": 1841902,
        "breaks": 3,
        "status": "COMPLETED",
        "submittedTo": "RBI",
    }


@app.get("/api/v1/recon/status")
def get_status() -> dict:
    return {
        "lastRun": "2026-07-01T02:00:00Z",
        "nextRun": "2026-10-01T02:00:00Z",
        "cadence": "QUARTERLY",
        "state": "IDLE",
    }


@app.get("/api/v1/recon/<run_id>/report")
def get_report(run_id: str) -> dict:
    return {
        "runId": run_id,
        "breaks": [
            {"ledger": "NOSTRO.USD", "amount": "1200.00", "age": 2},
            {"ledger": "NOSTRO.EUR", "amount": "840.00", "age": 1},
        ],
        "signedOffBy": "compliance",
    }


@app.get("/healthz")
def healthz() -> dict:
    return health()
