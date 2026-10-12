"""Acceptance, funding, and settlement payloads (RS-003, RS-004 observations).

Structural models only. Signature checks and state rules belong to the
receiver (RS-001 section 8, RS-003 "Acceptance, funding, and settlement").
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import Field, model_validator

from rill_core.wire.canonical import canonicalize, parse_json_strict
from rill_core.wire.messages import ClientAcceptance, FundingBinding  # noqa: TC001
from rill_core.wire.types import ExactInteger, Hex32, Signature64, StrictModel

MIN_TRANSACTION_BYTES = 60
MAX_TRANSACTION_BYTES = 100_000
_HEX = re.compile(r"(?:[0-9a-f]{2})+")


class TermsAcceptPayload(StrictModel):
    """Client acceptance of one provider terms offer."""

    acceptance: ClientAcceptance
    client_acceptance_signature: Signature64


class FundingBindingPayload(StrictModel):
    """Signed funding binding plus the exact funding transaction bytes."""

    binding: FundingBinding
    funding_binding_signature: Signature64
    funding_transaction: str

    @model_validator(mode="after")
    def validate_transaction(self) -> FundingBindingPayload:
        """Require bounded lowercase hex transaction bytes."""
        size = len(self.funding_transaction) // 2
        if not (
            _HEX.fullmatch(self.funding_transaction)
            and MIN_TRANSACTION_BYTES <= size <= MAX_TRANSACTION_BYTES
        ):
            raise ValueError("funding_transaction must be bounded lowercase hex")
        return self


class AckPayload(StrictModel):
    """Delivery-state acknowledgment; never a financial result."""

    acknowledged_message_id: Hex32


class PaymentSettled(StrictModel):
    """The provider learned the preimage; the client verifies it."""

    kind: Literal["payment_settled"]
    payment_preimage: Hex32


class PaymentFailed(StrictModel):
    """The provider will not pay; the client waits for refund eligibility."""

    kind: Literal["payment_failed"]


class ClaimBroadcast(StrictModel):
    """The provider broadcast its claim transaction."""

    kind: Literal["claim_broadcast"]
    claim_txid: Hex32


class HoldAccepted(StrictModel):
    """LN to BTC: every accepted HTLC checked out; the funding_binding follows (RS-004)."""

    kind: Literal["hold_accepted"]


class HoldSettled(StrictModel):
    """LN to BTC: the provider settled the hold with the claim's preimage."""

    kind: Literal["hold_settled"]


class SwapAborted(StrictModel):
    """LN to BTC: nothing was funded; the hold is canceled or was never paid."""

    kind: Literal["swap_aborted"]
    reason: Annotated[str, Field(min_length=1, max_length=200)]


class RefundBroadcast(StrictModel):
    """LN to BTC: the provider broadcast its refund after the lock."""

    kind: Literal["refund_broadcast"]
    refund_txid: Hex32


class RefundConfirmed(StrictModel):
    """LN to BTC: the refund reached its signed depth; the hold is canceled."""

    kind: Literal["refund_confirmed"]
    refund_txid: Hex32


class EvmLockupObserved(StrictModel):
    """RS-010: a ``Lockup`` log matching the terms was found at this transaction and log index."""

    kind: Literal["evm_lockup_observed"]
    lock_tx_hash: Hex32
    log_index: ExactInteger
    block_number: ExactInteger


AnyObservation = (
    PaymentSettled
    | PaymentFailed
    | ClaimBroadcast
    | HoldAccepted
    | HoldSettled
    | SwapAborted
    | RefundBroadcast
    | RefundConfirmed
    | EvmLockupObserved
)
Observation = Annotated[AnyObservation, Field(discriminator="kind")]
_OBSERVATIONS: dict[str, type[AnyObservation]] = {
    "payment_settled": PaymentSettled,
    "payment_failed": PaymentFailed,
    "claim_broadcast": ClaimBroadcast,
    "hold_accepted": HoldAccepted,
    "hold_settled": HoldSettled,
    "swap_aborted": SwapAborted,
    "refund_broadcast": RefundBroadcast,
    "refund_confirmed": RefundConfirmed,
    "evm_lockup_observed": EvmLockupObserved,
}


def parse_observation(document: bytes) -> AnyObservation:
    """Strictly parse an observation payload, dispatching on ``kind``."""
    parsed = parse_json_strict(document)
    kind = parsed.get("kind") if isinstance(parsed, dict) else None
    model = _OBSERVATIONS.get(kind) if isinstance(kind, str) else None
    if model is None:
        raise ValueError("observation kind unsupported")
    return model.model_validate_json(canonicalize(parsed), strict=True)
