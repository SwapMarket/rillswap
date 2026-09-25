"""Pure answer policy for BTC to LN ``quote_request`` (RS-003 quotes).

Deterministic given its inputs, so the live store can call it inside the
transaction that records the answer. Indicative quotes grant no authority.
Firm requests are refused (``unsupported_request``): RS-003 forbids firm
offers until the provider keeps a complete payment-hash reservation history,
and no such store exists yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rill_core.wire.canonical import canonicalize
from rill_core.wire.quotes import (
    MAX_INDICATIVE_REQUESTS_PER_SESSION,
    FirmQuoteRequest,
    parse_quote_request,
)

if TYPE_CHECKING:
    from rill_core.wire.messages import Envelope

MILLIONTHS = 1_000_000


@dataclass(frozen=True, slots=True)
class QuoteSchedule:
    """Operator-chosen quote parameters beyond the public announcement terms."""

    funding_confirmations: int = 2
    settlement_confirmations: int = 3
    refund_resolution_confirmations: int = 6
    max_refund_delay_blocks: int = 288
    max_funding_fee_sat: int = 5_000
    max_claim_fee_sat: int = 5_000
    max_refund_fee_sat: int = 5_000
    minimum_invoice_remaining_seconds: int = 1_800
    lifetime: int = 60

    def __post_init__(self) -> None:
        """Refuse values the quote schema cannot carry."""
        counts = (
            self.funding_confirmations,
            self.settlement_confirmations,
            self.refund_resolution_confirmations,
            self.max_refund_delay_blocks,
            self.minimum_invoice_remaining_seconds,
            self.lifetime,
        )
        fees = (self.max_funding_fee_sat, self.max_claim_fee_sat, self.max_refund_fee_sat)
        if not (all(value > 0 for value in counts) and all(value >= 0 for value in fees)):
            raise ValueError("quote schedule unsupported")


@dataclass(frozen=True, slots=True)
class QuoteTerms:
    """Everything one answer depends on, fixed before the store transaction."""

    amount_bands: tuple[tuple[int, int], ...]
    base_fee_sat: int
    proportional_millionths: int
    schedule: QuoteSchedule
    tip_height: int | None
    now: int


def _error(code: str, message: str) -> tuple[str, dict[str, Any]]:
    return "error", {"code": code, "message": message}


def answer_quote(  # noqa: PLR0911 - one closed answer per rule
    request: Envelope, prior: tuple[Envelope, ...], terms: QuoteTerms
) -> tuple[str, dict[str, Any]]:
    """Return ``(message_type, payload)`` answering one admitted request."""
    try:
        parsed = parse_quote_request(canonicalize(request.payload))
    except ValueError:
        return _error("request_unacceptable", "malformed quote request")
    earlier = [item.payload.get("mode") for item in prior]
    if "firm" in earlier:
        return _error("unsupported_request", "no request may follow a firm request")
    if isinstance(parsed, FirmQuoteRequest):
        return _error("unsupported_request", "firm requests are not offered yet")
    if len(earlier) >= MAX_INDICATIVE_REQUESTS_PER_SESSION:
        return _error("unsupported_request", "indicative request limit reached")
    principal = int(parsed.lightning_principal_sat)
    if not any(low <= principal <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    if terms.tip_height is None or terms.tip_height <= 0:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    fee = terms.base_fee_sat + -(-principal * terms.proportional_millionths // MILLIONTHS)
    schedule = terms.schedule
    return "quote_offer", {
        "kind": "btc-to-ln",
        "indicative": True,
        "economics": {
            "kind": "btc-to-ln",
            "lightning_principal_sat": str(principal),
            "success_fee_sat": str(fee),
            "contract_amount_sat": str(principal + fee),
        },
        "funding_confirmations": schedule.funding_confirmations,
        "settlement_confirmations": schedule.settlement_confirmations,
        "refund_resolution_confirmations": schedule.refund_resolution_confirmations,
        "reference_height": terms.tip_height,
        "max_refund_delay_blocks": schedule.max_refund_delay_blocks,
        "max_funding_fee_sat": str(schedule.max_funding_fee_sat),
        "max_claim_fee_sat": str(schedule.max_claim_fee_sat),
        "max_refund_fee_sat": str(schedule.max_refund_fee_sat),
        "minimum_invoice_remaining_seconds": schedule.minimum_invoice_remaining_seconds,
        "expires_at": terms.now + schedule.lifetime,
        "extensions": {},
    }
