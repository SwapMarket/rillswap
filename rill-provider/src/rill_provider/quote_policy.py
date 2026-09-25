"""Answer policy for BTC to LN ``quote_request`` (RS-003 quotes).

Called by the live store inside the transaction that records the answer, so
every input (tip height, decoded invoice, clock) is fixed beforehand.
Indicative quotes grant no authority. A firm request, only as the first
request of a session, gets identity-signed ``ProviderTermsV1`` whose payment
hash the store reserves forever in the same transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from rill_core.domain.amounts import MAX_SATS
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import ContractTerms, InvoiceBinding, ProviderTerms
from rill_core.wire.quotes import (
    MAX_INDICATIVE_REQUESTS_PER_SESSION,
    FirmQuoteRequest,
    QuoteOffer,
    parse_quote_request,
)

from rill_provider.live_session_store import Answer

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.wire.messages import Envelope
    from rill_core.wire.types import NetworkIdentity

    from rill_provider.live_session_store import RequestContext

MILLIONTHS = 1_000_000
MAX_WIRE_INTEGER = 9_007_199_254_740_991  # RS-001 exact JSON integer
MAX_INVOICE_CLOCK_SKEW = 600

type InvoiceOutcome = InvoiceBinding | Literal["rejected", "unavailable"] | None


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
    outgoing_cltv_budget_blocks: int = 144
    learn_and_claim_blocks: int = 72
    client_response_blocks: int = 36
    claim_confirmation_blocks: int = 6
    terms_lifetime: int = 120

    def __post_init__(self) -> None:
        """Refuse values the wire cannot carry or timing that cannot fit."""
        counts = (
            self.funding_confirmations,
            self.settlement_confirmations,
            self.refund_resolution_confirmations,
            self.max_refund_delay_blocks,
            self.minimum_invoice_remaining_seconds,
            self.lifetime,
            self.outgoing_cltv_budget_blocks,
            self.learn_and_claim_blocks,
            self.client_response_blocks,
            self.claim_confirmation_blocks,
            self.terms_lifetime,
        )
        fees = (self.max_funding_fee_sat, self.max_claim_fee_sat, self.max_refund_fee_sat)
        if not (
            all(0 < value <= MAX_WIRE_INTEGER for value in counts)
            and all(0 <= value <= MAX_SATS for value in fees)
            and self.outgoing_cltv_budget_blocks + self.learn_and_claim_blocks
            < self.max_refund_delay_blocks
        ):
            raise ValueError("quote schedule unsupported")


@dataclass(frozen=True, slots=True)
class FirmSigner:
    """What a firm offer needs beyond the schedule; absent means no firm offers."""

    network: NetworkIdentity
    provider_identity_key: str
    provider_destination_script: str
    sign: Callable[[ProviderTerms], str]


@dataclass(frozen=True, slots=True)
class QuoteTerms:
    """Everything one answer depends on, fixed before the store transaction."""

    amount_bands: tuple[tuple[int, int], ...]
    base_fee_sat: int
    proportional_millionths: int
    schedule: QuoteSchedule
    tip_height: int | None
    now: int
    firm: FirmSigner | None = None
    invoice: InvoiceOutcome = None


def _error(code: str, message: str) -> Answer:
    return Answer("error", {"code": code, "message": message})


def success_fee(terms: QuoteTerms, principal: int) -> int:
    """Return the base fee plus the proportional fee, rounded up."""
    return terms.base_fee_sat + -(-principal * terms.proportional_millionths // MILLIONTHS)


def answer_quote(  # noqa: PLR0911 - one closed answer per rule
    request: Envelope, prior: tuple[Envelope, ...], context: RequestContext, terms: QuoteTerms
) -> Answer:
    """Answer one admitted request."""
    earlier = [item.payload.get("mode") for item in prior]
    if "firm" in earlier:  # RS-003: unconditional, whatever the payload
        return _error("unsupported_request", "no request may follow a firm request")
    try:
        parsed = parse_quote_request(canonicalize(request.payload))
    except ValueError:
        return _error("request_unacceptable", "malformed quote request")
    if isinstance(parsed, FirmQuoteRequest):
        if earlier:
            return _error("unsupported_request", "a firm request must open a fresh session")
        return _firm(parsed, context, terms)
    if len(earlier) >= MAX_INDICATIVE_REQUESTS_PER_SESSION:
        return _error("unsupported_request", "indicative request limit reached")
    principal = int(parsed.lightning_principal_sat)
    if not any(low <= principal <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    if terms.tip_height is None or terms.tip_height <= 0:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    fee = success_fee(terms, principal)
    schedule = terms.schedule
    offer: dict[str, Any] = {
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
    try:  # never sign a payload the wire model would refuse (e.g. overflow)
        parse_model_json(QuoteOffer, canonicalize(offer))
    except ValueError:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    return Answer("quote_offer", offer)


def _invoice_problem(binding: InvoiceBinding, principal: int, terms: QuoteTerms) -> str | None:
    schedule = terms.schedule
    if binding.amount_msat != str(principal * 1000):
        return "invoice amount differs from the principal"
    if binding.expires_at - terms.now < schedule.minimum_invoice_remaining_seconds:
        return "invoice expires too soon"
    if binding.created_at > terms.now + MAX_INVOICE_CLOCK_SKEW:
        return "invoice created in the future"
    if binding.min_final_cltv_delta >= schedule.outgoing_cltv_budget_blocks:
        return "invoice final CLTV exceeds the routing budget"
    return None


def _firm(  # noqa: PLR0911 - one closed answer per rule
    request: FirmQuoteRequest, context: RequestContext, terms: QuoteTerms
) -> Answer:
    firm, schedule, tip = terms.firm, terms.schedule, terms.tip_height
    if firm is None:
        return _error("unsupported_request", "firm requests are not offered")
    principal = int(request.lightning_principal_sat)
    if not any(low <= principal <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    binding = terms.invoice
    if tip is None or tip <= 0 or binding is None or binding == "unavailable":
        return _error("capacity_unavailable", "firm quotes temporarily unavailable")
    if binding == "rejected":
        return _error("invoice_unacceptable", "invoice could not be decoded")
    if context.is_payment_hash_reserved(binding.payment_hash):  # RS-003: no ownership oracle
        return _error("request_unacceptable", "request cannot be offered")
    problem = _invoice_problem(binding, principal, terms)
    if problem is not None:
        return _error("invoice_unacceptable", problem)
    fee = success_fee(terms, principal)
    limits = request.limits
    lock = min(tip + schedule.max_refund_delay_blocks - 1, limits.max_refund_lock_height)
    htlc_expiry = tip + schedule.outgoing_cltv_budget_blocks
    if (
        fee > int(limits.max_success_fee_sat)
        or schedule.max_funding_fee_sat > int(limits.max_funding_fee_sat)
        or schedule.max_claim_fee_sat > int(limits.max_claim_fee_sat)
        or schedule.max_refund_fee_sat > int(limits.max_refund_fee_sat)
        or htlc_expiry + schedule.learn_and_claim_blocks >= lock + 1
    ):
        return _error("limits_unsatisfiable", "client limits cannot be met")
    contract: dict[str, Any] = {
        "protocol": "rillswap",
        "contract_version": "1",
        "profile_id": "btc-to-ln/v1",
        "network_identity": firm.network.model_dump(mode="json"),
        "provider_identity_key": firm.provider_identity_key,
        "client_contract_compressed_key": request.client_contract_compressed_key,
        "provider_contract_compressed_key": context.provider_contract_key,
        "claimant": "provider",
        "refund_party": "client",
        "invoice_binding": binding.model_dump(mode="json"),
        "economics": {
            "kind": "btc-to-ln",
            "lightning_principal_sat": str(principal),
            "success_fee_sat": str(fee),
            "contract_amount_sat": str(principal + fee),
        },
        "refund_lock_height": lock,
        "funding_confirmations": schedule.funding_confirmations,
        "settlement_confirmations": schedule.settlement_confirmations,
        "refund_resolution_confirmations": schedule.refund_resolution_confirmations,
        "max_funding_fee_sat": str(schedule.max_funding_fee_sat),
        "max_claim_fee_sat": str(schedule.max_claim_fee_sat),
        "max_refund_fee_sat": str(schedule.max_refund_fee_sat),
        "client_destination_script": request.client_destination_script,
        "provider_destination_script": firm.provider_destination_script,
        "recovery_authorization_xonly_key": request.recovery_authorization_xonly_key,
        # Never outlive the invoice time the payment still needs.
        "terms_expiry": min(
            terms.now + schedule.terms_lifetime,
            binding.expires_at - schedule.minimum_invoice_remaining_seconds,
        ),
        "timing_policy": {
            "kind": "btc-to-ln",
            "max_outgoing_htlc_expiry_height": htlc_expiry,
            "learn_and_claim_blocks": schedule.learn_and_claim_blocks,
            "client_response_blocks": schedule.client_response_blocks,
            "claim_confirmation_blocks": schedule.claim_confirmation_blocks,
        },
        "required_features": [],
        "extensions": {},
    }
    try:
        contract_terms = parse_model_json(ContractTerms, canonicalize(contract))
    except ValueError:  # e.g. a client key colliding with a provider key
        return _error("request_unacceptable", "request cannot form valid terms")
    offer = ProviderTerms(
        contract_hash=contract_hash(contract_terms).hex(),
        contract_terms=contract_terms,
        handshake_hash=context.handshake_hash,
    )
    payload = {
        "terms": offer.model_dump(mode="json"),
        "provider_terms_signature": firm.sign(offer),
    }
    return Answer(
        "terms_offer", payload, payment_hash=binding.payment_hash, contract_hash=offer.contract_hash
    )
