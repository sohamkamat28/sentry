"""Domain enumerations.

Lifecycle and governance are two independent axes rather than one list. An
endpoint can be alive but ownerless, or dead but properly owned, and a single
enum cannot express both without leaving combinations that match nothing.
"""

from __future__ import annotations

import enum


class Criticality(str, enum.Enum):
    PAYMENT = "PAYMENT"
    SETTLEMENT = "SETTLEMENT"
    REGULATORY = "REGULATORY"
    CUSTOMER = "CUSTOMER"
    INTERNAL = "INTERNAL"

    @property
    def is_critical_path(self) -> bool:
        """Endpoints on these paths are exempt from sunset throttling."""
        return self in (Criticality.PAYMENT, Criticality.SETTLEMENT, Criticality.REGULATORY)


class Source(str, enum.Enum):
    EBPF = "ebpf"
    GATEWAY = "gateway"
    CODE = "code"
    LEGACY = "legacy"


class Lifecycle(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DORMANT = "DORMANT"  # days 31-89; matched no status in the source model
    DEPRECATED = "DEPRECATED"
    ZOMBIE = "ZOMBIE"


class Governance(str, enum.Enum):
    OWNED = "OWNED"
    ORPHANED = "ORPHANED"
    SHADOW = "SHADOW"


class Confidence(str, enum.Enum):
    NONE = "NONE"
    PROVISIONAL = "PROVISIONAL"
    CONFIRMED = "CONFIRMED"


class Tier(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class BlastTier(str, enum.Enum):
    ZERO = "ZERO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    CRITICAL = "CRITICAL"


class Auth(str, enum.Enum):
    NONE = "none"
    BASIC = "basic"
    APIKEY = "apikey"
    BEARER = "bearer"
    OAUTH2 = "oauth2"
    MTLS = "mtls"


class Phase(str, enum.Enum):
    NONE = "NONE"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    RETIRED = "RETIRED"
    REVERTED = "REVERTED"


class ControlState(str, enum.Enum):
    PROPOSED = "PROPOSED"
    JUDGED = "JUDGED"
    APPLIED = "APPLIED"
    # The Judge measured this control and it failed a dimension. Distinct from
    # FAILED, which means the gateway refused to accept a control the Judge had
    # already passed. One is a safety finding about the patch; the other is an
    # infrastructure fault, and an operator needs to tell them apart.
    REJECTED = "REJECTED"
    REVERTED = "REVERTED"
    FAILED = "FAILED"
    # This control was never applied and does not need to be: the policy it
    # states is already enforced at the gateway by another control, verified
    # against Kong rather than inferred from this table.
    #
    # Distinct from every neighbouring state, and the distinction is the whole
    # value of the row. FAILED says an operator has something to fix. REVERTED
    # says enforcement was removed. SUPERSEDED says the exposure is closed and
    # this particular row is not how it was closed — which is the only honest
    # description of 483 rows that each carried a Kong 409 for a policy that was
    # live the entire time.
    SUPERSEDED = "SUPERSEDED"


class DataClass(str, enum.Enum):
    PAN = "PAN"
    AADHAAR = "AADHAAR"
    IFSC = "IFSC"
    ACCOUNT_NO = "ACCOUNT_NO"
    CARD = "CARD"
    CVV = "CVV"
    DOB = "DOB"


#: Classes that trigger the highest data-exposure risk and the zero-trust
#: response-masking control.
SENSITIVE_CLASSES = frozenset(
    {DataClass.PAN, DataClass.AADHAAR, DataClass.CARD, DataClass.CVV}
)

ROLES = ("viewer", "analyst", "approver", "admin")
