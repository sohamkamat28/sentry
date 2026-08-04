"""nostro-sync — correspondent-bank position sync.

No team tag, no CODEOWNERS entry, and no repository in the scanned set. That is
deliberate: it is rung 4 of the ownership ladder, the case where every source
fails and the record must say *unresolved* rather than guess.

The estate's second zombie. Traffic decays from vday 40 and stops at 55, and it
serves account numbers and IFSC codes with no authentication — so as it dies it
climbs rather than falls on CDRI, which is the point. A dead endpoint that still
answers with customer data is worse than a live one, and the score has to say so.
"""

from estate_app import account_body, app, health


@app.get("/api/v1/nostro")
def list_nostro() -> dict:
    return {
        "accounts": [
            {"correspondent": "CITIUS33", "currency": "USD",
             "accountNumber": account_body()["accountNumber"], "balance": "8412900.00"},
            {"correspondent": "DEUTDEFF", "currency": "EUR",
             "accountNumber": account_body()["accountNumber"], "balance": "2210400.00"},
        ],
        "asOf": "2026-07-28T00:00:00Z",
    }


@app.get("/api/v1/nostro/<correspondent>/positions")
def get_positions(correspondent: str) -> dict:
    return {
        "correspondent": correspondent,
        "accountNumber": account_body()["accountNumber"],
        "ifsc": account_body()["ifsc"],
        "opening": "8412900.00",
        "closing": "8388200.00",
        "currency": "USD",
    }


@app.post("/api/v1/nostro/sync", body_schema={
    "type": "object",
    "required": ["correspondent"],
    "properties": {
        "correspondent": {"type": "string"},
        "valueDate": {"type": "string"},
    },
})
def sync() -> dict:
    return {"synced": 2, "failed": 0, "at": "2026-07-28T02:00:00Z"}


@app.get("/healthz")
def healthz() -> dict:
    return health()
