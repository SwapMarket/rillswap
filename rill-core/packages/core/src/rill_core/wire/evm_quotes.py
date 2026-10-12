"""ERC20 to LN and LN to ERC20 quote exchange payloads (RS-010).

Mirror of ``rill_core.wire.quotes`` and ``rill_core.wire.reverse_quotes`` for
the EVM HTLC profiles. The client names the asset by chain id and token
contract; the provider answers with the complete asset identity it is willing
to settle on, an integer rate, and the EVM reference block its timelock is
measured from.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import model_validator

from rill_core.wire.canonical import JsonValue  # noqa: TC001 - pydantic resolves at runtime
from rill_core.wire.messages import (  # noqa: TC001 - pydantic resolves at runtime
    Erc20ToLnEconomics,
    LnToErc20Economics,
)
from rill_core.wire.types import (
    DecimalTokenUnits,
    EvmAddress,
    EvmAssetIdentity,
    ExactInteger,
    Hex32,
    PositiveCount,
    PositiveTokenUnits,
    StrictModel,
    XOnlyKey,
    validate_decimal_sats,
    validate_extensions,
    validate_token_units,
)

MAX_INVOICE_CHARS = 2048
MAX_BLOCK_HEIGHT = 500_000_000
_INVOICE = re.compile(r"ln[a-z0-9]{1,2046}")


class EvmAssetRef(StrictModel):
    """Client-side asset selection; the provider answers with the full identity."""

    chain_id: PositiveCount
    token_contract: EvmAddress

    def matches(self, asset: EvmAssetIdentity) -> bool:
        """Whether a complete identity names this asset."""
        return asset.chain_id == self.chain_id and asset.token_contract == self.token_contract


class Erc20QuoteLimits(StrictModel):
    """ERC20 to LN client bounds; the client is the refund party."""

    max_success_fee_token_base: DecimalTokenUnits
    max_htlc_timelock_block: PositiveCount


class Erc20IndicativeQuoteRequest(StrictModel):
    """Invoice-free ERC20 to LN shopping request."""

    kind: Literal["erc20-to-ln"]
    mode: Literal["indicative"]
    lightning_principal_sat: str
    evm_asset: EvmAssetRef
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_request(self) -> Erc20IndicativeQuoteRequest:
        """Require a positive principal and valid extensions."""
        validate_decimal_sats(
            self.lightning_principal_sat, field="lightning_principal_sat", positive=True
        )
        validate_extensions(self.extensions)
        return self


class Erc20FirmQuoteRequest(StrictModel):
    """Request for signed ERC20 to LN terms."""

    kind: Literal["erc20-to-ln"]
    mode: Literal["firm"]
    lightning_principal_sat: str
    invoice: str
    evm_asset: EvmAssetRef
    client_evm_address: EvmAddress
    recovery_authorization_xonly_key: XOnlyKey
    limits: Erc20QuoteLimits
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_request(self) -> Erc20FirmQuoteRequest:
        """Require a positive principal and a bounded lowercase invoice."""
        validate_decimal_sats(
            self.lightning_principal_sat, field="lightning_principal_sat", positive=True
        )
        if len(self.invoice) > MAX_INVOICE_CHARS or not _INVOICE.fullmatch(self.invoice):
            raise ValueError("invoice must be a lowercase BOLT11 string")
        validate_extensions(self.extensions)
        return self


class Erc20QuoteOffer(StrictModel):
    """Indicative ERC20 to LN quote; grants no authority."""

    kind: Literal["erc20-to-ln"]
    indicative: Literal[True]
    economics: Erc20ToLnEconomics
    evm_asset: EvmAssetIdentity
    funding_confirmations: PositiveCount
    settlement_confirmations: PositiveCount
    evm_reference_block: ExactInteger
    max_timelock_delay_blocks: PositiveCount
    minimum_invoice_remaining_seconds: PositiveCount
    expires_at: ExactInteger
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_offer(self) -> Erc20QuoteOffer:
        """Require valid extensions."""
        validate_extensions(self.extensions)
        return self


class LnToErc20QuoteLimits(StrictModel):
    """LN to ERC20 client bounds; the client is the claimant."""

    max_success_fee_sat: str
    min_htlc_timelock_block: PositiveCount
    max_incoming_htlc_expiry_height: int

    @model_validator(mode="after")
    def validate_limits(self) -> LnToErc20QuoteLimits:
        """Require a canonical fee cap and a plausible Bitcoin height."""
        validate_decimal_sats(self.max_success_fee_sat, field="max_success_fee_sat")
        if not 0 < self.max_incoming_htlc_expiry_height < MAX_BLOCK_HEIGHT:
            raise ValueError("max_incoming_htlc_expiry_height must be a block height")
        return self


class LnToErc20IndicativeQuoteRequest(StrictModel):
    """Hash-free LN to ERC20 shopping request."""

    kind: Literal["ln-to-erc20"]
    mode: Literal["indicative"]
    payout_token_base: PositiveTokenUnits
    evm_asset: EvmAssetRef
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_request(self) -> LnToErc20IndicativeQuoteRequest:
        """Require a bounded payout and valid extensions."""
        validate_token_units(self.payout_token_base, field="payout_token_base", positive=True)
        validate_extensions(self.extensions)
        return self


class LnToErc20FirmQuoteRequest(StrictModel):
    """Request for signed LN to ERC20 terms and a hold invoice."""

    kind: Literal["ln-to-erc20"]
    mode: Literal["firm"]
    payout_token_base: PositiveTokenUnits
    payment_hash: Hex32
    evm_asset: EvmAssetRef
    client_evm_address: EvmAddress
    recovery_authorization_xonly_key: XOnlyKey
    limits: LnToErc20QuoteLimits
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_request(self) -> LnToErc20FirmQuoteRequest:
        """Require a bounded payout and valid extensions."""
        validate_token_units(self.payout_token_base, field="payout_token_base", positive=True)
        validate_extensions(self.extensions)
        return self


class LnToErc20QuoteOffer(StrictModel):
    """Indicative LN to ERC20 quote; grants no authority."""

    kind: Literal["ln-to-erc20"]
    indicative: Literal[True]
    economics: LnToErc20Economics
    evm_asset: EvmAssetIdentity
    funding_confirmations: PositiveCount
    settlement_confirmations: PositiveCount
    evm_reference_block: ExactInteger
    timelock_delay_blocks: PositiveCount
    incoming_htlc_expiry_delta_blocks: PositiveCount
    expires_at: ExactInteger
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_offer(self) -> LnToErc20QuoteOffer:
        """Require valid extensions."""
        validate_extensions(self.extensions)
        return self


EvmQuoteRequest = (
    Erc20IndicativeQuoteRequest
    | Erc20FirmQuoteRequest
    | LnToErc20IndicativeQuoteRequest
    | LnToErc20FirmQuoteRequest
)
