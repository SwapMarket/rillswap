"""Pure merchant receipt correspondence, NOT source inventory eligibility.

Observations are trusted internal inputs, not proof of their acquisition. The
caller must authenticate the pinned HTTPS server (no redirects/caches), decode
via the pinned LND, call observe_bound_settled_invoice successfully, and query
independent Core identity/tip evidence. Record entire acquisition intervals and
enforce monotonic elapsed-time limits in that runtime. No method acquires funds,
imports credits, or grants invocation authority. Refunds and previous spending
remain the separate journal's exclusive source-wallet authorization obligation.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Annotated, Literal, Self

from Cryptodome.Signature import eddsa
from pydantic import Field, HttpUrl, StringConstraints, field_validator, model_validator
from rill_core.domain.amounts import MAX_MILLISATS
from rill_core.wire.canonical import parse_model_json
from rill_core.wire.types import (
    CompressedKey,
    Hex32,
    NetworkIdentity,
    ScriptHex,
    Signature64,
    StrictModel,
)

from rill_cli.conversion_journal import SourceAuthority, SourceCredit

if TYPE_CHECKING:
    from rill_core.wire.messages import InvoiceBinding
    from rill_provider.lnd_hold_invoice import BoundHoldInvoiceObservation

type CheckoutId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,128}$")]
_MAX_SAFE_CLOCK = 9_007_199_254_740_991
type Clock = Annotated[int, Field(strict=True, ge=0, le=_MAX_SAFE_CLOCK)]
type Origin = Annotated[str, StringConstraints(min_length=1, max_length=255)]
type PositiveMsat = Annotated[str, StringConstraints(pattern=r"^[1-9][0-9]{0,18}$")]
type NonnegativeMsat = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]{0,18})$")]
_MAX_ACQUISITION_SECONDS = 10
_MAX_DOCUMENT_BYTES = 16384


def _origin(value: str) -> str:
    parsed = HttpUrl(value)
    if (
        not value.isascii()
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query is not None
        or parsed.fragment is not None
        or str(parsed).removesuffix("/") != value
    ):
        raise ValueError("exact canonical HTTPS merchant origin required")
    return value


def _amount(value: str) -> str:
    amount = int(value)
    if amount > MAX_MILLISATS or amount % 1000:
        raise ValueError("merchant receipt requires bounded whole satoshis")
    return value


class MerchantCreditError(ValueError):
    """No merchant source credit established, without projecting private inputs."""


class MerchantSourcePin(StrictModel):
    """Affirmative operator relationship between merchant signer and source node."""

    merchant_origin: Origin
    event_public_key: Hex32
    source_node: CompressedKey
    network: NetworkIdentity

    _validate_origin = field_validator("merchant_origin")(_origin)


class AcquisitionInterval(StrictModel):
    """Record the whole authenticated batch, not a fresh completion stamp alone."""

    started_at: Clock
    completed_at: Clock

    @model_validator(mode="after")
    def ordered(self) -> Self:
        """Reject reversed or excessively long acquisition intervals."""
        if not 0 <= self.completed_at - self.started_at <= _MAX_ACQUISITION_SECONDS:
            raise ValueError("merchant observation acquisition interval invalid")
        return self


class MerchantViewObservation(StrictModel):
    """Unsigned response, acquired by a trusted authenticated HTTPS transport."""

    origin: Origin
    intent_id: CheckoutId
    acquisition: AcquisitionInterval
    document: bytes

    _validate_origin = field_validator("origin")(_origin)


class SourceReceiptObservation(StrictModel):
    """Project only a successful bound SETTLED lookup, never arbitrary RPC state."""

    acquisition: AcquisitionInterval
    source_node: CompressedKey
    network: NetworkIdentity
    payment_hash: Hex32
    invoice_sha256: Hex32
    last_lnd_height: Annotated[int, Field(strict=True, ge=1)]
    last_lnd_block_hash: Hex32

    @classmethod
    def from_bound(
        cls, bound: BoundHoldInvoiceObservation, acquisition: AcquisitionInterval
    ) -> Self:
        """Exclude raw protobufs, HTLC metadata and secrets from trusted projection."""
        if bound.status.state != "SETTLED":
            raise MerchantCreditError("bound merchant settlement required")
        return cls(
            acquisition=acquisition,
            source_node=bound.node_pubkey,
            network=bound.network,
            payment_hash=bound.payment_hash,
            invoice_sha256=bound.bolt11_sha256,
            last_lnd_height=bound.last_lnd_height,
            last_lnd_block_hash=bound.last_lnd_block_hash,
        )


class CoreSourceObservation(StrictModel):
    """Independent authenticated Core reads, not atomic LND/Core attestation.

    The runtime must first call CoreTransactionReader.tip_height(), which checks
    configured chain/genesis/challenge. Namespace/profile remain operator pins.
    Then read genesis and the active hash at the exact reported LND height.
    """

    acquisition: AcquisitionInterval
    configured_network: NetworkIdentity
    genesis_hash: Hex32
    signet_challenge: ScriptHex | None
    tip_height: Annotated[int, Field(strict=True, ge=1)]
    source_height: Annotated[int, Field(strict=True, ge=1)]
    source_block_hash: Hex32


class _AcceptanceEvent(StrictModel):
    version: Literal["checkout-event/1"]
    id: CheckoutId
    merchant_origin: Origin = Field(alias="merchantOrigin")
    type: Literal["payment.accepted"]
    intent_id: CheckoutId = Field(alias="intentId")
    attempt_id: CheckoutId = Field(alias="attemptId")
    payment_hash: Hex32 = Field(alias="paymentHash")
    amount_msat: PositiveMsat = Field(alias="amountMsat")
    accepted_at: Clock = Field(alias="acceptedAt")

    _validate_origin = field_validator("merchant_origin")(_origin)
    _validate_amount = field_validator("amount_msat")(_amount)


class _SignedAcceptance(StrictModel):
    algorithm: Literal["Ed25519"]
    public_key: Hex32 = Field(alias="publicKey")
    event: _AcceptanceEvent
    signature: Signature64


class _Terms(StrictModel):
    version: Literal["checkout/0.1"]
    policy_version: Literal["native-lightning/1"] = Field(alias="policyVersion")
    merchant_origin: Origin = Field(alias="merchantOrigin")
    intent_id: CheckoutId = Field(alias="intentId")
    attempt_id: CheckoutId = Field(alias="attemptId")
    network: Literal["regtest", "signet", "mainnet"]
    amount_msat: PositiveMsat = Field(alias="amountMsat")
    payment_hash: Hex32 = Field(alias="paymentHash")
    receiver: CompressedKey
    expires_at: Annotated[int, Field(strict=True, ge=1, le=_MAX_SAFE_CLOCK)] = Field(
        alias="expiresAt"
    )
    buyer_extra_msat: NonnegativeMsat = Field(alias="buyerExtraMsat")

    _validate_origin = field_validator("merchant_origin")(_origin)
    _validate_amount = field_validator("amount_msat")(_amount)

    @field_validator("buyer_extra_msat")
    @classmethod
    def bounded_extra(cls, value: str) -> str:
        """Apply the existing checkout fee quantity bound."""
        if int(value) > MAX_MILLISATS:
            raise ValueError("merchant extra quantity exceeds bound")
        return value


class _Attempt(StrictModel):
    terms: _Terms
    invoice: Annotated[str, StringConstraints(min_length=1, max_length=8192)]


class _PaidView(StrictModel):
    version: Literal["checkout-view/1"]
    id: CheckoutId
    status: Literal["paid"]
    attempt: _Attempt


def _signature_bytes(event: _AcceptanceEvent) -> bytes:
    return json.dumps(
        [
            "rillswap-payment-event/1",
            event.version,
            event.id,
            event.merchant_origin,
            event.type,
            event.intent_id,
            event.attempt_id,
            event.payment_hash,
            event.amount_msat,
            event.accepted_at,
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf8")


def verify_merchant_credit(  # noqa: PLR0913, PLR0917 - one explicit sanitized correspondence boundary
    authority: SourceAuthority,
    pin: MerchantSourcePin,
    acceptance: bytes,
    view: MerchantViewObservation,
    invoice: InvoiceBinding,
    source: SourceReceiptObservation,
    core: CoreSourceObservation,
    *,
    now: int,
) -> SourceCredit:
    """Validate provenance ONLY, with mandatory destination source-authority pin.

    Trusted wrappers attest acquisition intent, not actual transport security.
    Runtime authentication and fresh source capacity cannot be inferred here.
    Historical acceptance or invoice expiry never triggers import or spending.
    """
    try:
        if (
            type(now) is not int
            or not 0 <= now <= _MAX_SAFE_CLOCK
            or authority.source_node != pin.source_node
            or authority.network != pin.network
            or len(acceptance) > _MAX_DOCUMENT_BYTES
            or len(view.document) > _MAX_DOCUMENT_BYTES
        ):
            raise ValueError  # noqa: TRY301 - sanitize private proof failures at boundary
        for interval in (view.acquisition, source.acquisition, core.acquisition):
            if (
                not 0 <= now - interval.started_at <= _MAX_ACQUISITION_SECONDS
                or interval.completed_at > now
            ):
                raise ValueError  # noqa: TRY301 - sanitize private proof failures at boundary
        envelope = parse_model_json(_SignedAcceptance, acceptance)
        paid = parse_model_json(_PaidView, view.document)
        event, terms = envelope.event, paid.attempt.terms
        if (
            envelope.public_key != pin.event_public_key
            or view.origin != pin.merchant_origin
            or event.merchant_origin != pin.merchant_origin
            or terms.merchant_origin != pin.merchant_origin
            or view.intent_id != paid.id
            or event.intent_id != paid.id
            or terms.intent_id != paid.id
            or event.attempt_id != terms.attempt_id
            or event.payment_hash != terms.payment_hash
            or event.amount_msat != terms.amount_msat
            or terms.receiver != pin.source_node
            or terms.network != pin.network.name
            or event.accepted_at > view.acquisition.completed_at
        ):
            raise ValueError  # noqa: TRY301 - sanitize private proof failures at boundary
        verifier = eddsa.new(
            eddsa.import_public_key(bytes.fromhex(pin.event_public_key)), "rfc8032"
        )
        verifier.verify(_signature_bytes(event), bytes.fromhex(envelope.signature))
        literal_invoice = paid.attempt.invoice
        if (
            not literal_invoice.isascii()
            or literal_invoice.lower() != literal_invoice
            or hashlib.sha256(literal_invoice.encode("ascii")).hexdigest() != invoice.bolt11_sha256
            or invoice.payment_hash != terms.payment_hash
            or invoice.amount_msat != terms.amount_msat
            or invoice.payee_compressed_pubkey != pin.source_node
            or invoice.expires_at < terms.expires_at
            or invoice.created_at > now
            or source.source_node != pin.source_node
            or source.network != pin.network
            or source.payment_hash != invoice.payment_hash
            or source.invoice_sha256 != invoice.bolt11_sha256
            or core.configured_network != pin.network
            or core.genesis_hash != pin.network.genesis_hash
            or core.signet_challenge != pin.network.signet_challenge
            or core.source_height != source.last_lnd_height
            or core.tip_height < core.source_height
            or core.source_block_hash != source.last_lnd_block_hash
        ):
            raise ValueError  # noqa: TRY301 - sanitize private proof failures at boundary
        return SourceCredit(
            payment_hash=invoice.payment_hash,
            invoice_sha256=invoice.bolt11_sha256,
            amount_msat=int(invoice.amount_msat),
        )
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise MerchantCreditError("merchant source proof refused") from None
