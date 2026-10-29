"""Answer policy for ERC20 quote requests (RS-010).

``answer_evm_quote`` mirrors ``quote_policy.answer_quote`` for the
``erc20-to-ln/v1`` and ``ln-to-erc20/v1`` profiles: the same session rules
(one firm request opening a fresh session, bounded indicative requests), the
same Lightning-side checks (invoice, bands, hold invoice), plus the token
conversion, the HTLC timelock, and the cross-chain timing inequality the
EVM leg needs. Everything EVM-specific an answer depends on is fixed in an
``EvmQuoteContext`` before the store transaction, like ``QuoteTerms``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.evm_quotes import (
    Erc20FirmQuoteRequest,
    Erc20IndicativeQuoteRequest,
    Erc20QuoteOffer,
    LnToErc20FirmQuoteRequest,
    LnToErc20IndicativeQuoteRequest,
    LnToErc20QuoteOffer,
)
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import EvmContractTerms, ProviderTerms, ceil_div
from rill_core.wire.quotes import MAX_INDICATIVE_REQUESTS_PER_SESSION, parse_quote_request

from rill_provider.dynamic_pricing import TokenPricing
from rill_provider.live_session_store import Answer
from rill_provider.quote_policy import (
    QuoteTerms,
    _error,
    _invoice_problem,
    granted_rebate,
    rebate_exhausted,
    service_fee,
    success_fee,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from rill_core.wire.evm_quotes import EvmAssetRef
    from rill_core.wire.messages import Envelope
    from rill_core.wire.types import EvmAssetIdentity

    from rill_provider.live_session_store import RequestContext

BTC_BLOCK_SECONDS = 600  # RS-010 cross-chain timing assumes this per Bitcoin block
SATS_PER_BTC = 100_000_000
EVM_PROFILES = ("erc20-to-ln/v1", "ln-to-erc20/v1")


@dataclass(frozen=True, slots=True)
class EvmSchedule:
    """Operator-chosen EVM-side parameters every ERC20 offer carries."""

    funding_confirmations: int
    settlement_confirmations: int
    # erc20-to-ln: the client's lock becomes refundable this many EVM blocks
    # after the reference block (the client may ask for an earlier timelock).
    forward_timelock_delay_blocks: int
    # ln-to-erc20: our lock becomes refundable this many blocks after the reference.
    reverse_timelock_delay_blocks: int
    learn_and_claim_seconds: int
    refund_and_ln_resolution_seconds: int

    def __post_init__(self) -> None:
        """Refuse a schedule that could never satisfy RS-010's timing inequalities."""
        values = (
            self.funding_confirmations,
            self.settlement_confirmations,
            self.forward_timelock_delay_blocks,
            self.reverse_timelock_delay_blocks,
            self.learn_and_claim_seconds,
            self.refund_and_ln_resolution_seconds,
        )
        if not all(isinstance(value, int) and value > 0 for value in values):
            raise ValueError("EVM schedule values must be positive integers")
        if (
            self.funding_confirmations >= self.forward_timelock_delay_blocks
            or self.funding_confirmations + self.settlement_confirmations
            >= self.reverse_timelock_delay_blocks
        ):
            raise ValueError("EVM confirmations must fit before the timelock")


@dataclass(frozen=True, slots=True)
class EvmQuotePrices:
    """One live rate and gas-charge snapshot, both required for each quoted token."""

    rates: Mapping[str, int]
    network_fees_token_base: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class EvmQuoteContext:
    """The served assets, their current prices, and the EVM tip, fixed per answer."""

    assets: tuple[EvmAssetIdentity, ...]
    rates: Mapping[str, int]  # token_contract -> rate_token_base_per_btc; absent: not quoted now
    provider_evm_address: str
    schedule: EvmSchedule
    tip: int | None  # EVM block number observed now; None defers firm offers
    # None is legacy pricing (gas absorbed in the fixed service fee). A live
    # snapshot must measure both rate and gas for a token before quoting it.
    network_fees_token_base: Mapping[str, int] | None = None

    def asset(self, ref: EvmAssetRef) -> EvmAssetIdentity | None:
        """Return the served asset a request names, if any."""
        for asset in self.assets:
            if asset.chain_id == ref.chain_id and asset.token_contract == ref.token_contract:
                return asset
        return None

    def rate(self, asset: EvmAssetIdentity) -> int | None:
        """Return the current integer token-base-per-BTC rate for an asset."""
        rate = self.rates.get(asset.token_contract)
        if self.network_fees_token_base is not None:
            gas = self.network_fees_token_base.get(asset.token_contract)
            if type(gas) is not int or gas < 0:
                return None
        return rate if type(rate) is int and rate > 0 else None

    def network_fee(self, asset: EvmAssetIdentity) -> int:
        """Return a quoted asset's frozen gas charge, or zero for legacy pricing."""
        return (
            0
            if self.network_fees_token_base is None
            else self.network_fees_token_base[asset.token_contract]
        )


def sats_to_token_base(sats: int, rate: int) -> int:
    """Convert satoshis to token base units at ``rate`` (rounded up)."""
    return ceil_div(sats * rate, SATS_PER_BTC)


def token_base_to_sats(token_base: int, rate: int) -> int:
    """Convert token base units to satoshis at ``rate`` (rounded up)."""
    return ceil_div(token_base * SATS_PER_BTC, rate)


def _token(asset: EvmAssetIdentity, rate: int) -> TokenPricing:
    return TokenPricing(asset.token_contract, asset.token_decimals, rate)


def _gas_token_base(terms: QuoteTerms, asset: EvmAssetIdentity) -> int:
    return 0 if terms.evm is None else terms.evm.network_fee(asset)


def erc20_to_ln_economics(
    terms: QuoteTerms, principal: int, rate: int, asset: EvmAssetIdentity
) -> dict[str, str]:
    """RS-010 forward economics: ``lock = ceil(L * rate / 1e8) + S_token``.

    A rebate (negative fee) rounds toward the provider like any other fee.
    """
    fee_token = sats_to_token_base(success_fee(terms, principal, _token(asset, rate)), rate)
    fee_token += _gas_token_base(terms, asset)
    return {
        "kind": "erc20-to-ln",
        "lightning_principal_sat": str(principal),
        "rate_token_base_per_btc": str(rate),
        "success_fee_token_base": str(fee_token),
        "lock_amount_token_base": str(sats_to_token_base(principal, rate) + fee_token),
    }


def ln_to_erc20_economics(
    terms: QuoteTerms, payout_token: int, rate: int, asset: EvmAssetIdentity
) -> dict[str, str]:
    """RS-010 reverse economics: ``E = ceil(D * 1e8 / rate)``, ``H = E + S_sat``."""
    equivalent = token_base_to_sats(payout_token, rate)
    fee = success_fee(terms, equivalent, _token(asset, rate))
    fee += token_base_to_sats(_gas_token_base(terms, asset), rate)
    return {
        "kind": "ln-to-erc20",
        "payout_token_base": str(payout_token),
        "rate_token_base_per_btc": str(rate),
        "payout_sat_equivalent": str(equivalent),
        "success_fee_sat": str(fee),
        "hold_invoice_sat": str(equivalent + fee),
    }


def ln_to_erc20_hold_msat(terms: QuoteTerms, request: LnToErc20FirmQuoteRequest) -> int | None:
    """Return the hold amount ``H`` in msat for a reverse firm request, or None if unquotable."""
    evm = terms.evm
    if evm is None:
        return None
    asset = evm.asset(request.evm_asset)
    rate = evm.rate(asset) if asset is not None else None
    if asset is None or rate is None:
        return None
    economics = ln_to_erc20_economics(terms, int(request.payout_token_base), rate, asset)
    equivalent = int(economics["payout_sat_equivalent"])
    if not any(low <= equivalent <= high for low, high in terms.amount_bands):
        return None
    return int(economics["hold_invoice_sat"]) * 1000


def answer_evm_quote(  # noqa: PLR0911 - one closed answer per rule
    request: Envelope, prior: tuple[Envelope, ...], context: RequestContext, terms: QuoteTerms
) -> Answer:
    """Answer one admitted ERC20 quote request."""
    earlier = [item.payload.get("mode") for item in prior]
    if "firm" in earlier:  # RS-003: unconditional, whatever the payload
        return _error("unsupported_request", "no request may follow a firm request")
    try:
        parsed = parse_quote_request(canonicalize(request.payload))
    except ValueError:
        return _error("request_unacceptable", "malformed quote request")
    if parsed.kind != terms.profile.split("/")[0]:
        return _error("unsupported_request", "profile not served in this session")
    if terms.evm is None:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    if isinstance(parsed, Erc20FirmQuoteRequest | LnToErc20FirmQuoteRequest):
        if earlier:
            return _error("unsupported_request", "a firm request must open a fresh session")
        if isinstance(parsed, LnToErc20FirmQuoteRequest):
            return _ln_to_erc20_firm(parsed, context, terms, terms.evm)
        return _erc20_firm(parsed, context, terms, terms.evm)
    if len(earlier) >= MAX_INDICATIVE_REQUESTS_PER_SESSION:
        return _error("unsupported_request", "indicative request limit reached")
    if isinstance(parsed, LnToErc20IndicativeQuoteRequest):
        return _ln_to_erc20_indicative(parsed, terms, terms.evm)
    assert isinstance(parsed, Erc20IndicativeQuoteRequest)  # noqa: S101 - closed union
    return _erc20_indicative(parsed, terms, terms.evm)


def _priced(ref: EvmAssetRef, evm: EvmQuoteContext) -> tuple[EvmAssetIdentity, int] | Answer:
    asset = evm.asset(ref)
    if asset is None:
        return _error("unsupported_request", "asset not served")
    rate = evm.rate(asset)
    if rate is None or evm.tip is None or evm.tip <= 0:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    return asset, rate


def _erc20_indicative(
    request: Erc20IndicativeQuoteRequest, terms: QuoteTerms, evm: EvmQuoteContext
) -> Answer:
    principal = int(request.lightning_principal_sat)
    if not any(low <= principal <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    priced = _priced(request.evm_asset, evm)
    if isinstance(priced, Answer):
        return priced
    asset, rate = priced
    offer: dict[str, Any] = {
        "kind": "erc20-to-ln",
        "indicative": True,
        "economics": erc20_to_ln_economics(terms, principal, rate, asset),
        "evm_asset": asset.model_dump(mode="json"),
        "funding_confirmations": evm.schedule.funding_confirmations,
        "settlement_confirmations": evm.schedule.settlement_confirmations,
        "evm_reference_block": evm.tip,
        "max_timelock_delay_blocks": evm.schedule.forward_timelock_delay_blocks,
        "minimum_invoice_remaining_seconds": terms.schedule.minimum_invoice_remaining_seconds,
        "expires_at": terms.now + terms.schedule.lifetime,
        "extensions": {},
    }
    try:  # never sign a payload the wire model would refuse (e.g. overflow)
        parse_model_json(Erc20QuoteOffer, canonicalize(offer))
    except ValueError:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    return Answer("quote_offer", offer)


def _ln_to_erc20_indicative(
    request: LnToErc20IndicativeQuoteRequest, terms: QuoteTerms, evm: EvmQuoteContext
) -> Answer:
    priced = _priced(request.evm_asset, evm)
    if isinstance(priced, Answer):
        return priced
    asset, rate = priced
    economics = ln_to_erc20_economics(terms, int(request.payout_token_base), rate, asset)
    equivalent = int(economics["payout_sat_equivalent"])
    if not any(low <= equivalent <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    offer: dict[str, Any] = {
        "kind": "ln-to-erc20",
        "indicative": True,
        "economics": economics,
        "evm_asset": asset.model_dump(mode="json"),
        "funding_confirmations": evm.schedule.funding_confirmations,
        "settlement_confirmations": evm.schedule.settlement_confirmations,
        "evm_reference_block": evm.tip,
        "timelock_delay_blocks": evm.schedule.reverse_timelock_delay_blocks,
        "incoming_htlc_expiry_delta_blocks": terms.schedule.incoming_htlc_expiry_delta_blocks,
        "expires_at": terms.now + terms.schedule.lifetime,
        "extensions": {},
    }
    try:
        parse_model_json(LnToErc20QuoteOffer, canonicalize(offer))
    except ValueError:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    return Answer("quote_offer", offer)


def _erc20_firm(  # noqa: PLR0911 - one closed answer per rule
    request: Erc20FirmQuoteRequest, context: RequestContext, terms: QuoteTerms, evm: EvmQuoteContext
) -> Answer:
    firm, schedule, tip = terms.firm, terms.schedule, terms.tip_height
    if firm is None:
        return _error("unsupported_request", "firm requests are not offered")
    principal = int(request.lightning_principal_sat)
    if not any(low <= principal <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    binding = terms.invoice
    if (
        tip is None
        or tip <= 0
        or binding is None
        or binding == "unavailable"
        or not context.economic_capacity_available
    ):
        return _error("capacity_unavailable", "firm quotes temporarily unavailable")
    if binding == "rejected":
        return _error("invoice_unacceptable", "invoice could not be decoded")
    if context.is_payment_hash_reserved(binding.payment_hash):  # no ownership oracle
        return _error("request_unacceptable", "request cannot be offered")
    problem = _invoice_problem(binding, principal, terms)
    if problem is not None:
        return _error("invoice_unacceptable", problem)
    priced = _priced(request.evm_asset, evm)
    if isinstance(priced, Answer):
        return priced
    asset, rate = priced
    evm_tip = int(evm.tip or 0)
    if request.client_evm_address == evm.provider_evm_address:
        return _error("request_unacceptable", "client address collides with the provider's")
    economics = erc20_to_ln_economics(terms, principal, rate, asset)
    rebate = granted_rebate(terms, context, service_fee(terms, principal, _token(asset, rate)))
    if rebate is None:
        return rebate_exhausted()
    limits = request.limits
    htlc_expiry = tip + schedule.outgoing_cltv_budget_blocks
    timelock = min(
        evm_tip + evm.schedule.forward_timelock_delay_blocks, limits.max_htlc_timelock_block
    )
    if (
        int(economics["success_fee_token_base"]) > int(limits.max_success_fee_token_base)
        or (htlc_expiry - tip) * BTC_BLOCK_SECONDS + evm.schedule.learn_and_claim_seconds
        >= (timelock - evm_tip) * asset.block_seconds
    ):
        return _error("limits_unsatisfiable", "client limits cannot be met")
    contract: dict[str, Any] = {
        "protocol": "rillswap",
        "contract_version": "1",
        "profile_id": "erc20-to-ln/v1",
        "network_identity": firm.network.model_dump(mode="json"),
        "evm_asset": asset.model_dump(mode="json"),
        "provider_identity_key": firm.provider_identity_key,
        "client_evm_address": request.client_evm_address,
        "provider_evm_address": evm.provider_evm_address,
        "claimant": "provider",
        "refund_party": "client",
        "invoice_binding": binding.model_dump(mode="json"),
        "economics": economics,
        "htlc_timelock_block": timelock,
        "evm_reference_block": evm_tip,
        "btc_reference_height": tip,
        "funding_confirmations": evm.schedule.funding_confirmations,
        "settlement_confirmations": evm.schedule.settlement_confirmations,
        "recovery_authorization_xonly_key": request.recovery_authorization_xonly_key,
        # Never outlive the invoice time the payment still needs.
        "terms_expiry": min(
            terms.now + schedule.terms_lifetime,
            binding.expires_at - schedule.minimum_invoice_remaining_seconds,
        ),
        "timing_policy": {
            "kind": "erc20-to-ln",
            "max_outgoing_htlc_expiry_height": htlc_expiry,
            "learn_and_claim_seconds": evm.schedule.learn_and_claim_seconds,
        },
        "required_features": [],
        "extensions": {},
    }
    return _signed_offer(
        contract, context, firm.sign, payment_hash=binding.payment_hash, rebate_sat=rebate
    )


def _ln_to_erc20_firm(  # noqa: PLR0911 - one closed answer per rule
    request: LnToErc20FirmQuoteRequest,
    context: RequestContext,
    terms: QuoteTerms,
    evm: EvmQuoteContext,
) -> Answer:
    firm, schedule, tip = terms.firm, terms.schedule, terms.tip_height
    if firm is None:
        return _error("unsupported_request", "firm requests are not offered")
    priced = _priced(request.evm_asset, evm)
    if isinstance(priced, Answer):
        return priced
    asset, rate = priced
    evm_tip = int(evm.tip or 0)
    economics = ln_to_erc20_economics(terms, int(request.payout_token_base), rate, asset)
    equivalent = int(economics["payout_sat_equivalent"])
    if not any(low <= equivalent <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    rebate = granted_rebate(terms, context, service_fee(terms, equivalent, _token(asset, rate)))
    if rebate is None:
        return rebate_exhausted()
    if context.is_payment_hash_reserved(request.payment_hash):  # no ownership oracle
        return _error("request_unacceptable", "request cannot be offered")
    hold = terms.hold
    if (
        tip is None
        or tip <= 0
        or hold is None
        or hold == "unavailable"
        or not context.economic_capacity_available
    ):
        return _error("capacity_unavailable", "firm quotes temporarily unavailable")
    bolt11, binding = hold
    if (
        binding.payment_hash != request.payment_hash
        or binding.amount_msat != str(int(economics["hold_invoice_sat"]) * 1000)
        or binding.min_final_cltv_delta < schedule.incoming_htlc_expiry_delta_blocks
    ):
        return _error("capacity_unavailable", "firm quotes temporarily unavailable")
    if request.client_evm_address == evm.provider_evm_address:
        return _error("request_unacceptable", "client address collides with the provider's")
    limits = request.limits
    timelock = evm_tip + evm.schedule.reverse_timelock_delay_blocks
    min_incoming = tip + schedule.incoming_htlc_expiry_delta_blocks
    if (
        int(economics["success_fee_sat"]) > int(limits.max_success_fee_sat)
        or timelock < limits.min_htlc_timelock_block
        or min_incoming > limits.max_incoming_htlc_expiry_height
        or (timelock - evm_tip) * asset.block_seconds
        + evm.schedule.refund_and_ln_resolution_seconds
        >= (min_incoming - tip) * BTC_BLOCK_SECONDS
    ):
        return _error("limits_unsatisfiable", "client limits cannot be met")
    contract: dict[str, Any] = {
        "protocol": "rillswap",
        "contract_version": "1",
        "profile_id": "ln-to-erc20/v1",
        "network_identity": firm.network.model_dump(mode="json"),
        "evm_asset": asset.model_dump(mode="json"),
        "provider_identity_key": firm.provider_identity_key,
        "client_evm_address": request.client_evm_address,
        "provider_evm_address": evm.provider_evm_address,
        "claimant": "client",
        "refund_party": "provider",
        "invoice_binding": binding.model_dump(mode="json"),
        "economics": economics,
        "htlc_timelock_block": timelock,
        "evm_reference_block": evm_tip,
        "btc_reference_height": tip,
        "funding_confirmations": evm.schedule.funding_confirmations,
        "settlement_confirmations": evm.schedule.settlement_confirmations,
        "recovery_authorization_xonly_key": request.recovery_authorization_xonly_key,
        "terms_expiry": terms.now + schedule.terms_lifetime,
        "timing_policy": {
            "kind": "ln-to-erc20",
            "min_incoming_htlc_expiry_height": min_incoming,
            "refund_and_ln_resolution_seconds": evm.schedule.refund_and_ln_resolution_seconds,
        },
        "required_features": [],
        "extensions": {},
    }
    return _signed_offer(
        contract,
        context,
        firm.sign,
        payment_hash=binding.payment_hash,
        hold_invoice=bolt11,
        rebate_sat=rebate,
    )


def _signed_offer(  # noqa: PLR0913 - one offer's explicit parts
    contract: dict[str, Any],
    context: RequestContext,
    sign: Callable[[ProviderTerms], str],
    *,
    payment_hash: str,
    hold_invoice: str | None = None,
    rebate_sat: int = 0,
) -> Answer:
    try:
        contract_terms = parse_model_json(EvmContractTerms, canonicalize(contract))
    except ValueError:  # e.g. a timing inequality the wire model refuses
        return _error("request_unacceptable", "request cannot form valid terms")
    offer = ProviderTerms(
        contract_hash=contract_hash(contract_terms).hex(),
        contract_terms=contract_terms,
        handshake_hash=context.handshake_hash,
    )
    payload: dict[str, Any] = {
        "terms": offer.model_dump(mode="json"),
        "provider_terms_signature": sign(offer),
    }
    if hold_invoice is not None:
        payload["hold_invoice"] = hold_invoice
    return Answer(
        "terms_offer",
        payload,
        payment_hash=payment_hash,
        contract_hash=offer.contract_hash,
        rebate_sat=rebate_sat,
    )
