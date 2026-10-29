"""Signed success and service fees: providers may pay rebates, amounts stay positive."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from rill_core.wire.canonical import JsonValue, canonicalize, parse_model_json
from rill_core.wire.evm_quotes import Erc20QuoteOffer, LnToErc20QuoteOffer
from rill_core.wire.fee_policy import FEE_MODEL, FEE_POLICY_EXTENSION, check_fee_breakdown
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import ContractTerms, EvmContractTerms, LnToBtcEconomics
from rill_core.wire.quotes import (
    FirmQuoteRequest,
    QuoteOffer,
    TermsOfferPayload,
    check_terms_offer,
    parse_quote_request,
)
from rill_core.wire.reverse_quotes import ReverseQuoteOffer
from rill_core.wire.types import validate_signed_sats, validate_signed_token_units

FIXTURES = Path(__file__).parents[1] / "fixtures"
QUOTE_VECTORS: dict[str, Any] = json.loads((FIXTURES / "wire-v1" / "quote-v1.json").read_text())
FORWARD_OFFER: dict[str, Any] = QUOTE_VECTORS["valid"]["termsOffer"][0]
REVERSE_TERMS: dict[str, Any] = json.loads(
    (FIXTURES / "recovery-v1" / "initial-ln-to-btc-no-prepayment-v1.json").read_text()
)["contract_terms"]
EVM_KEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
EVM_ASSET = {
    "family": "evm",
    "chain_id": 31337,
    "name": "anvil-dev",
    "htlc_contract": "0x" + "11" * 20,
    "htlc_version": 6,
    "token_contract": "0x" + "22" * 20,
    "token_symbol": "fUSDC",
    "token_decimals": 6,
    "block_seconds": 2,
    "deployment_namespace": "dev",
}
RATE = "100000000000"  # 6-decimal token at 100,000 per BTC


def forward_terms(fee: str, contract: str) -> dict[str, Any]:
    """BTC to LN terms over the shared vector: principal 100,000 sat."""
    terms: dict[str, Any] = copy.deepcopy(FORWARD_OFFER["terms"]["contract_terms"])
    terms["economics"] = {
        "kind": "btc-to-ln",
        "lightning_principal_sat": "100000",
        "success_fee_sat": fee,
        "contract_amount_sat": contract,
    }
    return terms


def reverse_economics(fee: str, prepayment: str, hold: str) -> dict[str, Any]:
    """LN to BTC economics with V = 100,000 + 500."""
    return {
        "kind": "ln-to-btc",
        "contract_amount_sat": "100500",
        "nominal_payout_sat": "100000",
        "claim_fee_reserve_sat": "500",
        "success_fee_sat": fee,
        "mining_prepayment_sat": prepayment,
        "hold_invoice_sat": hold,
    }


def reverse_terms(fee: str, hold: str) -> dict[str, Any]:
    terms: dict[str, Any] = copy.deepcopy(REVERSE_TERMS)
    terms["economics"] = reverse_economics(fee, "0", hold)
    terms["invoice_binding"] = {**terms["invoice_binding"], "amount_msat": hold + "000"}
    return terms


def evm_terms(direction: str, economics: dict[str, Any], amount_msat: str) -> dict[str, Any]:
    forward = direction == "erc20-to-ln"
    return {
        "protocol": "rillswap",
        "contract_version": "1",
        "profile_id": f"{direction}/v1",
        "network_identity": {
            "family": "bitcoin",
            "name": "regtest",
            "genesis_hash": "0f" * 32,
            "signet_challenge": None,
            "consensus_profile": "bitcoin-core/regtest",
            "deployment_namespace": "dev",
        },
        "evm_asset": EVM_ASSET,
        "provider_identity_key": EVM_KEY,
        "client_evm_address": "0x" + "aa" * 20,
        "provider_evm_address": "0x" + "bb" * 20,
        "invoice_binding": {
            "bolt11_sha256": "ab" * 32,
            "payment_hash": "cd" * 32,
            "amount_msat": amount_msat,
            "payee_compressed_pubkey": "02" + EVM_KEY,
            "created_at": 1000,
            "expires_at": 4600,
            "min_final_cltv_delta": 40,
        },
        "evm_reference_block": 1000,
        "btc_reference_height": 200,
        "funding_confirmations": 3,
        "settlement_confirmations": 6,
        "recovery_authorization_xonly_key": (
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        ),
        "terms_expiry": 2000,
        "required_features": [],
        "extensions": {},
        "claimant": "provider" if forward else "client",
        "refund_party": "client" if forward else "provider",
        "economics": economics,
        "htlc_timelock_block": 51000 if forward else 4000,
        "timing_policy": (
            {
                "kind": direction,
                "max_outgoing_htlc_expiry_height": 300,
                "learn_and_claim_seconds": 3600,
            }
            if forward
            else {
                "kind": direction,
                "min_incoming_htlc_expiry_height": 300,
                "refund_and_ln_resolution_seconds": 3600,
            }
        ),
    }


def erc20_economics(fee: str, lock: str) -> dict[str, Any]:
    """1,000 sat at RATE is 1,000,000 token units before the fee."""
    return {
        "kind": "erc20-to-ln",
        "lightning_principal_sat": "1000",
        "rate_token_base_per_btc": RATE,
        "success_fee_token_base": fee,
        "lock_amount_token_base": lock,
    }


def payout_economics(fee: str, hold: str) -> dict[str, Any]:
    """1,000,000 token units at RATE are E = 1,000 sat."""
    return {
        "kind": "ln-to-erc20",
        "payout_token_base": "1000000",
        "rate_token_base_per_btc": RATE,
        "payout_sat_equivalent": "1000",
        "success_fee_sat": fee,
        "hold_invoice_sat": hold,
    }


def bitcoin(document: dict[str, Any]) -> ContractTerms:
    return parse_model_json(ContractTerms, canonicalize(document))


def evm(document: dict[str, Any]) -> EvmContractTerms:
    return parse_model_json(EvmContractTerms, canonicalize(document))


def test_btc_to_ln_rebate_lowers_the_contract_amount() -> None:
    assert bitcoin(forward_terms("-100", "99900")).economics.success_fee_sat == "-100"
    with pytest.raises(ValidationError, match="V = L"):
        bitcoin(forward_terms("-100", "100100"))
    with pytest.raises(ValidationError, match="contract_amount_sat"):
        bitcoin(forward_terms("-100000", "0"))


def test_ln_to_btc_rebate_lowers_the_hold_invoice_and_forbids_prepayment() -> None:
    economics = bitcoin(reverse_terms("-100", "100400")).economics
    assert isinstance(economics, LnToBtcEconomics)
    assert economics.hold_invoice_sat == "100400"
    with pytest.raises(ValidationError, match="H = V"):
        bitcoin(reverse_terms("-100", "100600"))
    with pytest.raises(ValidationError, match="positive success fee"):
        LnToBtcEconomics.model_validate(reverse_economics("-100", "1", "100399"))
    with pytest.raises(ValidationError, match="positive success fee"):
        LnToBtcEconomics.model_validate(reverse_economics("0", "1", "100499"))
    prepaid = LnToBtcEconomics.model_validate(reverse_economics("300", "300", "100500"))
    assert prepaid.mining_prepayment_sat == "300"
    with pytest.raises(ValidationError, match="hold_invoice_sat"):
        LnToBtcEconomics.model_validate(reverse_economics("-100500", "0", "0"))


def test_erc20_to_ln_token_rebate_lowers_the_lock() -> None:
    terms = evm(evm_terms("erc20-to-ln", erc20_economics("-1000", "999000"), "1000000"))
    assert terms.htlc_amount_token_base == 999_000
    with pytest.raises(ValidationError, match="lock = ceil"):
        evm(evm_terms("erc20-to-ln", erc20_economics("-1000", "999001"), "1000000"))
    with pytest.raises(ValidationError, match="lock_amount_token_base"):
        evm(evm_terms("erc20-to-ln", erc20_economics("-1000000", "0"), "1000000"))


def test_ln_to_erc20_rebate_lowers_the_hold_invoice() -> None:
    terms = evm(evm_terms("ln-to-erc20", payout_economics("-10", "990"), "990000"))
    assert terms.htlc_amount_token_base == 1_000_000
    with pytest.raises(ValidationError, match="H = E"):
        evm(evm_terms("ln-to-erc20", payout_economics("-10", "991"), "991000"))


@pytest.mark.parametrize("value", ["-0", "+1", "01", "-01", " 1", "1.0", "--1", "-", "", "-1e3"])
def test_malformed_signed_fees_are_refused(value: str) -> None:
    with pytest.raises(ValueError, match="canonical"):
        validate_signed_sats(value, field="fee")
    with pytest.raises(ValueError, match="canonical"):
        validate_signed_token_units(value, field="fee")
    with pytest.raises(ValidationError):
        bitcoin(forward_terms(value, "100000"))


def test_signed_fees_are_bounded_in_magnitude() -> None:
    assert validate_signed_sats("-2100000000000000", field="fee") == -2_100_000_000_000_000
    with pytest.raises(ValueError, match="maximum"):
        validate_signed_sats("-2100000000000001", field="fee")
    assert validate_signed_token_units("-" + "9" * 39, field="fee") == -(10**39 - 1)
    with pytest.raises(ValueError, match="maximum"):
        validate_signed_token_units("-1" + "0" * 39, field="fee")


def _forward_offer(terms: dict[str, Any]) -> TermsOfferPayload:
    document = copy.deepcopy(FORWARD_OFFER)
    document["terms"]["contract_terms"] = terms
    document["terms"]["contract_hash"] = contract_hash(bitcoin(terms)).hex()
    return parse_model_json(TermsOfferPayload, canonicalize(document))


def test_a_rebate_always_honors_the_client_fee_limit() -> None:
    request = parse_quote_request(canonicalize(QUOTE_VECTORS["valid"]["quoteRequest"][1]))
    assert isinstance(request, FirmQuoteRequest)
    offer = _forward_offer(forward_terms("-100", "99900"))
    check_terms_offer(
        request,
        offer,
        handshake_hash=offer.terms.handshake_hash,
        invoice_binding=offer.terms.contract_terms.invoice_binding,
    )


def test_indicative_offers_carry_rebates() -> None:
    forward = copy.deepcopy(QUOTE_VECTORS["valid"]["quoteOffer"][0])
    forward["economics"] = forward_terms("-100", "99900")["economics"]
    assert parse_model_json(QuoteOffer, canonicalize(forward)).economics.success_fee_sat == "-100"
    reverse = ReverseQuoteOffer.model_validate(
        {
            "kind": "ln-to-btc",
            "indicative": True,
            "economics": reverse_economics("-100", "0", "100400"),
            "funding_confirmations": 2,
            "settlement_confirmations": 3,
            "refund_resolution_confirmations": 4,
            "reference_height": 1000,
            "refund_delay_blocks": 100,
            "incoming_htlc_expiry_delta_blocks": 130,
            "max_funding_fee_sat": "1000",
            "max_claim_fee_sat": "400",
            "max_refund_fee_sat": "400",
            "expires_at": 1700000600,
            "extensions": {},
        }
    )
    assert reverse.economics.hold_invoice_sat == "100400"
    common = {
        "indicative": True,
        "evm_asset": EVM_ASSET,
        "funding_confirmations": 3,
        "settlement_confirmations": 6,
        "evm_reference_block": 1000,
        "expires_at": 2000,
        "extensions": {},
    }
    erc20 = Erc20QuoteOffer.model_validate(
        common
        | {
            "kind": "erc20-to-ln",
            "economics": erc20_economics("-1000", "999000"),
            "max_timelock_delay_blocks": 50000,
            "minimum_invoice_remaining_seconds": 600,
        }
    )
    assert erc20.economics.success_fee_token_base == "-1000"  # noqa: S105 - an amount
    payout = LnToErc20QuoteOffer.model_validate(
        common
        | {
            "kind": "ln-to-erc20",
            "economics": payout_economics("-10", "990"),
            "timelock_delay_blocks": 3000,
            "incoming_htlc_expiry_delta_blocks": 100,
        }
    )
    assert payout.economics.success_fee_sat == "-10"


POLICY: dict[str, JsonValue] = {
    "model": FEE_MODEL,
    "base_sat": "50",
    "proportional_millionths": 1000,
    "max_network_feerate_sat_kvb": "10000",
    "max_routing_fee_ppm": 1000,
}


def _breakdown(service: str, success: int) -> None:
    check_fee_breakdown(
        {
            FEE_POLICY_EXTENSION: {
                "offer_event_id": "11" * 32,
                "policy": POLICY,
                "feerate_sat_kvb": "2500",
                "estimated_at": 998,
                "issued_at": 1000,
                "service_fee_sat": service,
                "network_fee_sat": "385",
            }
        },
        required=True,
        principal_sat=100_000,
        success_fee_sat=success,
        expires_at=1060,
    )


def test_fee_breakdown_allows_discounts_below_zero_but_never_a_surcharge() -> None:
    _breakdown("150", 535)  # the advertised 50 sat + 0.1 %
    _breakdown("20", 405)
    _breakdown("-100", 285)  # the network cost is still charged in full
    _breakdown("-500", -115)
    with pytest.raises(ValueError, match="exceeds the advertised policy"):
        _breakdown("151", 536)
    with pytest.raises(ValueError, match="does not sum"):
        _breakdown("-100", 284)
    with pytest.raises(ValueError, match="canonical"):
        _breakdown("-0", 385)
