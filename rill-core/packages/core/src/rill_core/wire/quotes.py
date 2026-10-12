"""BTC to LN quote exchange payloads (RS-003 "Quotes and firm requests").

Structural models plus one contextual check: whether a provider's terms offer
honors the firm request it answers. Invoice decoding is the caller's job; the
decoded binding is passed in explicitly.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Literal, cast

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from rill_core.wire.canonical import JsonValue, canonicalize, parse_json_strict
from rill_core.wire.messages import BtcToLnEconomics, ContractTerms, InvoiceBinding, ProviderTerms
from rill_core.wire.types import (
    CompressedKey,
    ExactInteger,
    PositiveCount,
    ScriptHex,
    Signature64,
    StrictModel,
    XOnlyKey,
    require_v1_destination_script,
    validate_decimal_sats,
    validate_extensions,
)

MAX_INVOICE_CHARS = 2048
MAX_ERROR_MESSAGE_CHARS = 256
MAX_INDICATIVE_REQUESTS_PER_SESSION = 8
_INVOICE = re.compile(r"ln[a-z0-9]{1,2046}")
_PRINTABLE_ASCII = re.compile(r"[ -~]*")

ErrorCode = Literal[
    "amount_out_of_range",
    "capacity_unavailable",
    "invoice_unacceptable",
    "limits_unsatisfiable",
    "request_unacceptable",
    "unsupported_request",
]


class QuoteLimits(StrictModel):
    """Client-imposed ceilings a firm offer must respect."""

    max_success_fee_sat: str
    max_funding_fee_sat: str
    max_claim_fee_sat: str
    max_refund_fee_sat: str
    max_refund_lock_height: int = Field(strict=True, gt=0, lt=500_000_000)

    @model_validator(mode="after")
    def validate_amounts(self) -> QuoteLimits:
        """Require canonical decimal satoshi strings."""
        for field in (
            "max_success_fee_sat",
            "max_funding_fee_sat",
            "max_claim_fee_sat",
            "max_refund_fee_sat",
        ):
            validate_decimal_sats(getattr(self, field), field=field)
        return self


class IndicativeQuoteRequest(StrictModel):
    """Invoice-free shopping request; exposes no swap."""

    kind: Literal["btc-to-ln"]
    mode: Literal["indicative"]
    lightning_principal_sat: str
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_request(self) -> IndicativeQuoteRequest:
        """Require a positive principal and valid extensions."""
        validate_decimal_sats(
            self.lightning_principal_sat, field="lightning_principal_sat", positive=True
        )
        validate_extensions(self.extensions)
        return self


class FirmQuoteRequest(StrictModel):
    """Request for signed terms; only as the first request of a fresh session."""

    kind: Literal["btc-to-ln"]
    mode: Literal["firm"]
    lightning_principal_sat: str
    invoice: str
    client_contract_compressed_key: CompressedKey
    recovery_authorization_xonly_key: XOnlyKey
    client_destination_script: ScriptHex
    limits: QuoteLimits
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_request(self) -> FirmQuoteRequest:
        """Require a positive principal, bounded invoice, and v1 destination."""
        validate_decimal_sats(
            self.lightning_principal_sat, field="lightning_principal_sat", positive=True
        )
        if len(self.invoice) > MAX_INVOICE_CHARS or not _INVOICE.fullmatch(self.invoice):
            raise ValueError("invoice must be a lowercase BOLT11 string")
        require_v1_destination_script(
            self.client_destination_script, field="client_destination_script"
        )
        validate_extensions(self.extensions)
        return self


QuoteRequest = IndicativeQuoteRequest | FirmQuoteRequest
if TYPE_CHECKING:
    from rill_core.wire.evm_quotes import EvmQuoteRequest
    from rill_core.wire.reverse_quotes import (
        ReverseFirmQuoteRequest,
        ReverseIndicativeQuoteRequest,
    )

    AnyQuoteRequest = (
        QuoteRequest | ReverseIndicativeQuoteRequest | ReverseFirmQuoteRequest | EvmQuoteRequest
    )


def parse_quote_request(document: bytes) -> AnyQuoteRequest:
    """Strictly parse a ``QuoteRequestV1`` payload, dispatching on ``kind`` and ``mode``.

    Returns an RS-003 request for ``btc-to-ln``, an RS-004 request
    (``rill_core.wire.reverse_quotes``) for ``ln-to-btc``, and an RS-010 request
    (``rill_core.wire.evm_quotes``) for the ERC20 kinds.
    """
    from rill_core.wire import evm_quotes, reverse_quotes  # noqa: PLC0415 - they import this module

    parsed = parse_json_strict(document)
    kind = parsed.get("kind") if isinstance(parsed, dict) else None
    mode = parsed.get("mode") if isinstance(parsed, dict) else None
    models: dict[tuple[object, object], type[StrictModel]] = {
        ("btc-to-ln", "indicative"): IndicativeQuoteRequest,
        ("btc-to-ln", "firm"): FirmQuoteRequest,
        ("ln-to-btc", "indicative"): reverse_quotes.ReverseIndicativeQuoteRequest,
        ("ln-to-btc", "firm"): reverse_quotes.ReverseFirmQuoteRequest,
        ("erc20-to-ln", "indicative"): evm_quotes.Erc20IndicativeQuoteRequest,
        ("erc20-to-ln", "firm"): evm_quotes.Erc20FirmQuoteRequest,
        ("ln-to-erc20", "indicative"): evm_quotes.LnToErc20IndicativeQuoteRequest,
        ("ln-to-erc20", "firm"): evm_quotes.LnToErc20FirmQuoteRequest,
    }
    model = models.get((kind, mode))
    if model is None:
        raise ValueError("quote request kind or mode unsupported")
    return cast("AnyQuoteRequest", model.model_validate_json(canonicalize(parsed), strict=True))


class QuoteOffer(StrictModel):
    """Indicative provider quote; grants no authority and commits nobody."""

    kind: Literal["btc-to-ln"]
    indicative: Literal[True]
    economics: BtcToLnEconomics
    funding_confirmations: PositiveCount
    settlement_confirmations: PositiveCount
    refund_resolution_confirmations: PositiveCount
    reference_height: int = Field(strict=True, gt=0, lt=500_000_000)
    max_refund_delay_blocks: PositiveCount
    max_funding_fee_sat: str
    max_claim_fee_sat: str
    max_refund_fee_sat: str
    minimum_invoice_remaining_seconds: PositiveCount
    expires_at: ExactInteger
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_offer(self) -> QuoteOffer:
        """Require canonical fee caps and valid extensions."""
        for field in ("max_funding_fee_sat", "max_claim_fee_sat", "max_refund_fee_sat"):
            validate_decimal_sats(getattr(self, field), field=field)
        validate_extensions(self.extensions)
        return self


class TermsOfferPayload(StrictModel):
    """Firm answer: provider identity-signed ``ProviderTermsV1``.

    ``hold_invoice`` is present exactly for ``ln-to-btc/v1`` terms (RS-004):
    the BOLT11 hold invoice for ``H`` whose decoding must equal
    ``terms.contract_terms.invoice_binding``. BTC to LN offers carry exactly
    ``terms`` and ``provider_terms_signature`` (RS-003).
    """

    terms: ProviderTerms
    provider_terms_signature: Signature64
    hold_invoice: str | None = None

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        """Omit ``hold_invoice`` when absent so BTC to LN offers keep RS-003's shape."""
        document: dict[str, object] = handler(self)
        if document.get("hold_invoice") is None:
            document.pop("hold_invoice", None)
        return document

    @model_validator(mode="after")
    def validate_hold_invoice(self) -> TermsOfferPayload:
        """Require the hold invoice for LN to BTC and forbid it otherwise."""
        reverse = self.terms.contract_terms.profile_id in {"ln-to-btc/v1", "ln-to-erc20/v1"}
        if reverse and self.hold_invoice is None:
            raise ValueError("LN to BTC or LN to ERC20 terms offer requires a hold invoice")
        if not reverse and self.hold_invoice is not None:
            raise ValueError("BTC to LN or ERC20 to LN terms offer carries no hold invoice")
        if self.hold_invoice is not None and (
            len(self.hold_invoice) > MAX_INVOICE_CHARS or not _INVOICE.fullmatch(self.hold_invoice)
        ):
            raise ValueError("hold invoice must be a lowercase BOLT11 string")
        return self


class QuoteError(StrictModel):
    """Closed, oracle-free refusal of an authenticated, admitted request."""

    code: ErrorCode
    message: str = Field(max_length=MAX_ERROR_MESSAGE_CHARS)

    @model_validator(mode="after")
    def validate_message(self) -> QuoteError:
        """Require printable ASCII only."""
        if not _PRINTABLE_ASCII.fullmatch(self.message):
            raise ValueError("error message must be printable ASCII")
        return self


def check_terms_offer(
    request: FirmQuoteRequest,
    offer: TermsOfferPayload,
    *,
    handshake_hash: str,
    invoice_binding: InvoiceBinding,
) -> None:
    """Raise ValueError unless ``offer`` honors ``request`` (RS-003).

    ``invoice_binding`` is the caller's own decoding of ``request.invoice``.
    Signature verification is separate (``provider_terms_signature``).
    """
    terms = offer.terms.contract_terms
    if not isinstance(terms, ContractTerms):
        raise ValueError("terms offer does not carry BTC to LN contract terms")  # noqa: TRY004
    economics = terms.economics
    limits = request.limits
    checks = (
        (offer.terms.handshake_hash == handshake_hash, "handshake hash"),
        (terms.profile_id == "btc-to-ln/v1", "profile"),
        (terms.claimant == "provider" and terms.refund_party == "client", "roles"),
        (terms.invoice_binding == invoice_binding, "invoice binding"),
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
            isinstance(economics, BtcToLnEconomics)
            and economics.lightning_principal_sat == request.lightning_principal_sat,
            "principal",
        ),
        (
            invoice_binding.amount_msat == str(int(request.lightning_principal_sat) * 1000),
            "invoice amount",
        ),
        (terms.refund_lock_height <= limits.max_refund_lock_height, "refund lock height"),
    )
    for ok, what in checks:
        if not ok:
            raise ValueError(f"terms offer does not honor request: {what}")
    assert isinstance(economics, BtcToLnEconomics)  # noqa: S101 - checked above
    for offered, ceiling, what in (
        (economics.success_fee_sat, limits.max_success_fee_sat, "success fee"),
        (terms.max_funding_fee_sat, limits.max_funding_fee_sat, "funding fee"),
        (terms.max_claim_fee_sat, limits.max_claim_fee_sat, "claim fee"),
        (terms.max_refund_fee_sat, limits.max_refund_fee_sat, "refund fee"),
    ):
        if int(offered) > int(ceiling):
            raise ValueError(f"terms offer does not honor request: {what}")
