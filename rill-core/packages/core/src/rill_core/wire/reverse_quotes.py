"""LN to BTC quote exchange payloads (RS-004 "Quotes and firm requests").

Mirror of ``rill_core.wire.quotes`` for the reverse direction: the client
names the payment hash of a preimage only it knows, the provider answers with
terms and a hold invoice for ``H``, and the client checks that the offer
honors its request before paying that invoice. Invoice decoding is the
caller's job; the decoded binding is passed in explicitly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import Field, model_validator

from rill_core.wire.canonical import JsonValue  # noqa: TC001 - pydantic resolves at runtime
from rill_core.wire.fee_policy import check_fee_breakdown, parse_fee_request
from rill_core.wire.hashes import FEE_POLICY_FEATURE
from rill_core.wire.messages import ContractTerms, InvoiceBinding, LnToBtcEconomics, LnToBtcTiming
from rill_core.wire.types import (
    CompressedKey,
    ExactInteger,
    Hex32,
    PositiveCount,
    ScriptHex,
    StrictModel,
    XOnlyKey,
    require_v1_destination_script,
    validate_decimal_sats,
    validate_extensions,
)

if TYPE_CHECKING:
    from rill_core.wire.quotes import TermsOfferPayload


class ReverseQuoteLimits(StrictModel):
    """Client-imposed bounds an LN to BTC firm offer must respect.

    The client is the claimant here: it needs enough claim fee reserve and
    enough blocks before the provider may refund, and it bounds how long its
    Lightning funds may stay held.
    """

    max_success_fee_sat: str
    min_claim_fee_reserve_sat: str
    max_claim_fee_sat: str
    min_refund_lock_height: int = Field(strict=True, gt=0, lt=500_000_000)
    max_incoming_htlc_expiry_height: int = Field(strict=True, gt=0, lt=500_000_000)

    @model_validator(mode="after")
    def validate_amounts(self) -> ReverseQuoteLimits:
        """Require canonical decimal satoshi strings."""
        for field in ("max_success_fee_sat", "min_claim_fee_reserve_sat", "max_claim_fee_sat"):
            validate_decimal_sats(getattr(self, field), field=field)
        return self


class ReverseIndicativeQuoteRequest(StrictModel):
    """Hash-free shopping request; exposes no swap."""

    kind: Literal["ln-to-btc"]
    mode: Literal["indicative"]
    nominal_payout_sat: str
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_request(self) -> ReverseIndicativeQuoteRequest:
        """Require a positive payout and valid extensions."""
        validate_decimal_sats(self.nominal_payout_sat, field="nominal_payout_sat", positive=True)
        validate_extensions(self.extensions)
        parse_fee_request(self.extensions)
        return self


class ReverseFirmQuoteRequest(StrictModel):
    """Request for signed LN to BTC terms; first request of a fresh session."""

    kind: Literal["ln-to-btc"]
    mode: Literal["firm"]
    nominal_payout_sat: str
    payment_hash: Hex32
    client_contract_compressed_key: CompressedKey
    recovery_authorization_xonly_key: XOnlyKey
    client_destination_script: ScriptHex
    limits: ReverseQuoteLimits
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_request(self) -> ReverseFirmQuoteRequest:
        """Require a positive payout and a v1 destination."""
        validate_decimal_sats(self.nominal_payout_sat, field="nominal_payout_sat", positive=True)
        require_v1_destination_script(
            self.client_destination_script, field="client_destination_script"
        )
        validate_extensions(self.extensions)
        parse_fee_request(self.extensions)
        return self


class ReverseQuoteOffer(StrictModel):
    """Indicative LN to BTC quote; grants no authority and commits nobody."""

    kind: Literal["ln-to-btc"]
    indicative: Literal[True]
    economics: LnToBtcEconomics
    funding_confirmations: PositiveCount
    settlement_confirmations: PositiveCount
    refund_resolution_confirmations: PositiveCount
    reference_height: int = Field(strict=True, gt=0, lt=500_000_000)
    refund_delay_blocks: PositiveCount
    incoming_htlc_expiry_delta_blocks: PositiveCount
    max_funding_fee_sat: str
    max_claim_fee_sat: str
    max_refund_fee_sat: str
    expires_at: ExactInteger
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_offer(self) -> ReverseQuoteOffer:
        """Require canonical fee caps, consistent windows, and valid extensions."""
        for field in ("max_funding_fee_sat", "max_claim_fee_sat", "max_refund_fee_sat"):
            validate_decimal_sats(getattr(self, field), field=field)
        if self.incoming_htlc_expiry_delta_blocks <= self.refund_delay_blocks:
            raise ValueError("incoming HTLC expiry must be after the refund delay")
        validate_extensions(self.extensions)
        return self


def check_reverse_terms_offer(
    request: ReverseFirmQuoteRequest,
    offer: TermsOfferPayload,
    *,
    handshake_hash: str,
    invoice_binding: InvoiceBinding,
    now: int | None = None,
) -> None:
    """Raise ValueError unless ``offer`` honors ``request`` (RS-004).

    ``invoice_binding`` is the caller's own decoding of ``offer.hold_invoice``.
    The client MUST run this before paying the hold invoice; the payment is
    what commits it. Signature verification is separate.
    """
    terms = offer.terms.contract_terms
    if not isinstance(terms, ContractTerms):
        raise ValueError("terms offer does not carry LN to BTC contract terms")  # noqa: TRY004
    economics = terms.economics
    timing = terms.timing_policy
    limits = request.limits
    checks = (
        (offer.terms.handshake_hash == handshake_hash, "handshake hash"),
        (terms.profile_id == "ln-to-btc/v1", "profile"),
        (terms.claimant == "client" and terms.refund_party == "provider", "roles"),
        (offer.hold_invoice is not None, "hold invoice"),
        (terms.invoice_binding == invoice_binding, "invoice binding"),
        (invoice_binding.payment_hash == request.payment_hash, "payment hash"),
        (
            terms.client_contract_compressed_key == request.client_contract_compressed_key,
            "client contract key",
        ),
        (
            terms.recovery_authorization_xonly_key == request.recovery_authorization_xonly_key,
            "recovery key",
        ),
        (terms.client_destination_script == request.client_destination_script, "destination"),
        (
            isinstance(economics, LnToBtcEconomics)
            and economics.nominal_payout_sat == request.nominal_payout_sat,
            "payout",
        ),
        (
            isinstance(economics, LnToBtcEconomics)
            and invoice_binding.amount_msat == str(int(economics.hold_invoice_sat) * 1000),
            "hold invoice amount",
        ),
        (terms.refund_lock_height >= limits.min_refund_lock_height, "refund lock height"),
        (
            isinstance(timing, LnToBtcTiming)
            and timing.min_incoming_htlc_expiry_height <= limits.max_incoming_htlc_expiry_height,
            "incoming HTLC expiry",
        ),
    )
    for ok, what in checks:
        if not ok:
            raise ValueError(f"terms offer does not honor request: {what}")
    assert isinstance(economics, LnToBtcEconomics)  # noqa: S101 - checked above
    check_fee_breakdown(
        terms.extensions,
        required=FEE_POLICY_FEATURE in terms.required_features,
        principal_sat=int(economics.nominal_payout_sat),
        success_fee_sat=int(economics.success_fee_sat),
        expires_at=terms.terms_expiry,
        request_extensions=request.extensions,
        now=now,
    )
    if int(economics.success_fee_sat) > int(limits.max_success_fee_sat):
        raise ValueError("terms offer does not honor request: success fee")
    if int(economics.claim_fee_reserve_sat) < int(limits.min_claim_fee_reserve_sat):
        raise ValueError("terms offer does not honor request: claim fee reserve")
    if int(economics.claim_fee_reserve_sat) > reverse_claim_fee_reserve_ceiling(
        limits.min_claim_fee_reserve_sat, terms.max_claim_fee_sat
    ):
        raise ValueError("terms offer does not honor request: inflated claim fee reserve")
    if int(terms.max_claim_fee_sat) > int(limits.max_claim_fee_sat):
        raise ValueError("terms offer does not honor request: claim fee")


def reverse_claim_fee_reserve_ceiling(min_reserve_sat: str, max_claim_fee_sat: str) -> int:
    """Largest claim fee reserve ``C`` a client accepts (RS-004).

    ``C`` raises the Lightning payment one for one. Above both the reserve the
    client asked for and the most fee a signed claim may spend, it buys the
    client nothing it wanted, so the provider may not add it.
    """
    return max(int(min_reserve_sat), int(max_claim_fee_sat))


def check_reverse_claim_window(
    terms: ContractTerms, *, tip_height: int, min_refund_delay_blocks: int
) -> None:
    """Raise ValueError unless the client still has its claim window at ``tip_height``.

    Run with a tip sampled after the terms arrived: blocks found during
    negotiation shorten the delay the request asked for. The signed margins
    (funding depth, client response, claim confirmation) must also fit before
    the refund lock, as the provider's own schedule promises; otherwise the
    client's claim deadline would fall before it can claim.
    """
    timing = terms.timing_policy
    if not isinstance(timing, LnToBtcTiming):
        raise ValueError("terms do not carry LN to BTC timing")  # noqa: TRY004
    remaining = terms.refund_lock_height - tip_height
    if remaining < min_refund_delay_blocks:
        raise ValueError("terms refund delay is shorter than requested at the current tip")
    margins = (
        terms.funding_confirmations
        + timing.client_response_blocks
        + timing.claim_confirmation_blocks
    )
    if margins > remaining:
        raise ValueError("terms claim margins leave no claim window before the refund lock")
