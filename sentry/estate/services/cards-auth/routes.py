"""cards-auth — card authorisation and card servicing.

Team: cards. PAYMENT criticality.

The only service in the estate that returns card numbers and CVVs. `DC_CARD` and
`DC_CVV` are both defined in the BPF classifier and nothing has ever served a
body that could set either, so those two detection paths have run against no
traffic at all. This is what exercises them.
"""

import random

from estate_app import app, health

rng = random.Random(20260802)


def _card() -> str:
    """Sixteen digits in one unbroken run.

    The classifier keys `DC_CARD` on a digit run of thirteen or more, so the
    grouping matters: `4111 1111 1111 1111` is four runs of four and sets
    nothing. Real payment payloads carry the unformatted PAN, and so does this.
    """
    return f"4{rng.randint(10**14, 10**15 - 1)}"


@app.post("/api/v1/cards/authorise", body_schema={
    "type": "object",
    "required": ["cardId", "amount", "merchantId"],
    "properties": {
        "cardId": {"type": "string"},
        "amount": {"type": "string"},
        "merchantId": {"type": "string"},
        "currency": {"type": "string"},
    },
})
def authorise() -> dict:
    return {
        "cardNumber": _card(),
        "cvv": f"{rng.randint(100, 999)}",
        "expiry": "09/29",
        "amount": f"{rng.randint(100, 60000)}.00",
        "merchant": "RELIANCE RETAIL MUMBAI",
        "decision": "APPROVED",
        "authCode": f"{rng.randint(100000, 999999)}",
    }


@app.get("/api/v1/cards/<card_id>")
def get_card(card_id: str) -> dict:
    return {
        "cardId": card_id,
        "cardNumber": _card(),
        "cardHolder": "Test Holder",
        "expiry": "09/29",
        "network": "VISA",
        "status": "ACTIVE",
    }


@app.get("/api/v1/cards/<card_id>/limits")
def get_limits(card_id: str) -> dict:
    return {
        "cardId": card_id,
        "dailyLimit": "200000.00",
        "perTransactionLimit": "50000.00",
        "contactlessLimit": "5000.00",
        "currency": "INR",
    }


@app.get("/api/v1/cards/<card_id>/transactions")
def get_transactions(card_id: str) -> dict:
    return {
        "cardId": card_id,
        "cardNumber": _card(),
        "transactions": [
            {"at": "2026-07-27T11:04:00Z", "amount": "1249.00", "merchant": "SWIGGY"},
            {"at": "2026-07-27T19:41:00Z", "amount": "8600.00", "merchant": "CROMA"},
        ],
    }


@app.post("/api/v1/cards/<card_id>/block", body_schema={
    "type": "object",
    "required": ["reason"],
    "properties": {"reason": {"type": "string"}},
})
def block_card(card_id: str) -> dict:
    return {"cardId": card_id, "status": "BLOCKED", "blockedAt": "2026-07-28T00:00:00Z"}


@app.get("/healthz")
def healthz() -> dict:
    return health()
