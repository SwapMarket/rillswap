"""RS-010 ERC20 profile wire objects: terms equations, timing, quotes, observations."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import EvmContractTerms, ProviderTerms, ceil_div
from rill_core.wire.quotes import TermsOfferPayload, parse_quote_request
from rill_core.wire.settlement_messages import EvmLockupObserved, parse_observation

PROVIDER_KEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
RECOVERY_KEY = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
ASSET = {
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
NETWORK = {
    "family": "bitcoin",
    "name": "regtest",
    "genesis_hash": "0f" * 32,
    "signet_challenge": None,
    "consensus_profile": "bitcoin-core/regtest",
    "deployment_namespace": "dev",
}
RATE = "100000000000"  # 6-decimal token at 100,000 per BTC


def _invoice(amount_msat: str) -> dict[str, Any]:
    return {
        "bolt11_sha256": "ab" * 32,
        "payment_hash": "cd" * 32,
        "amount_msat": amount_msat,
        "payee_compressed_pubkey": "02" + PROVIDER_KEY,
        "created_at": 1000,
        "expires_at": 4600,
        "min_final_cltv_delta": 40,
    }


def _base(amount_msat: str) -> dict[str, Any]:
    return {
        "protocol": "rillswap",
        "contract_version": "1",
        "network_identity": NETWORK,
        "evm_asset": ASSET,
        "provider_identity_key": PROVIDER_KEY,
        "client_evm_address": "0x" + "aa" * 20,
        "provider_evm_address": "0x" + "bb" * 20,
        "invoice_binding": _invoice(amount_msat),
        "evm_reference_block": 1000,
        "btc_reference_height": 200,
        "funding_confirmations": 3,
        "settlement_confirmations": 6,
        "recovery_authorization_xonly_key": RECOVERY_KEY,
        "terms_expiry": 2000,
        "required_features": (),
        "extensions": {},
    }


def forward_terms(**overrides: object) -> dict[str, Any]:
    terms = {
        **_base("1000000"),
        "profile_id": "erc20-to-ln/v1",
        "claimant": "provider",
        "refund_party": "client",
        "economics": {
            "kind": "erc20-to-ln",
            "lightning_principal_sat": "1000",
            "rate_token_base_per_btc": RATE,
            "success_fee_token_base": "5000",
            "lock_amount_token_base": "1005000",
        },
        "htlc_timelock_block": 51000,  # 50,000 blocks * 2 s = 100,000 s of EVM time
        "timing_policy": {
            "kind": "erc20-to-ln",
            "max_outgoing_htlc_expiry_height": 300,  # 100 blocks * 600 s = 60,000 s
            "learn_and_claim_seconds": 3600,
        },
    }
    terms.update(overrides)
    return terms


def reverse_terms(**overrides: object) -> dict[str, Any]:
    terms = {
        **_base("1100000"),
        "profile_id": "ln-to-erc20/v1",
        "claimant": "client",
        "refund_party": "provider",
        "economics": {
            "kind": "ln-to-erc20",
            "payout_token_base": "1000000",
            "rate_token_base_per_btc": RATE,
            "payout_sat_equivalent": "1000",
            "success_fee_sat": "100",
            "hold_invoice_sat": "1100",
        },
        "htlc_timelock_block": 4000,  # 3,000 blocks * 2 s = 6,000 s
        "timing_policy": {
            "kind": "ln-to-erc20",
            "min_incoming_htlc_expiry_height": 300,  # 60,000 s of Bitcoin time
            "refund_and_ln_resolution_seconds": 3600,
        },
    }
    terms.update(overrides)
    return terms


def test_forward_terms_expose_htlc_roles_and_hash_into_provider_terms() -> None:
    terms = EvmContractTerms.model_validate(forward_terms())
    assert terms.htlc_claim_address == "0x" + "bb" * 20
    assert terms.htlc_refund_address == "0x" + "aa" * 20
    assert terms.htlc_amount_token_base == 1_005_000
    assert terms.evm_blocks_until_timelock == 50_000
    provider_terms = ProviderTerms.model_validate(
        {
            "contract_hash": contract_hash(terms).hex(),
            "contract_terms": forward_terms(),
            "handshake_hash": "00" * 32,
        }
    )
    assert isinstance(provider_terms.contract_terms, EvmContractTerms)
    offer = TermsOfferPayload.model_validate(
        {"terms": provider_terms.model_dump(), "provider_terms_signature": "01" * 64}
    )
    assert "hold_invoice" not in json.loads(offer.model_dump_json())


def test_reverse_terms_expose_htlc_roles_and_require_a_hold_invoice() -> None:
    terms = EvmContractTerms.model_validate(reverse_terms())
    assert terms.htlc_claim_address == "0x" + "aa" * 20
    assert terms.htlc_refund_address == "0x" + "bb" * 20
    assert terms.htlc_amount_token_base == 1_000_000
    provider_terms = {
        "contract_hash": contract_hash(terms).hex(),
        "contract_terms": reverse_terms(),
        "handshake_hash": "00" * 32,
    }
    with pytest.raises(ValidationError, match="requires a hold invoice"):
        TermsOfferPayload.model_validate(
            {"terms": provider_terms, "provider_terms_signature": "01" * 64}
        )
    TermsOfferPayload.model_validate(
        {"terms": provider_terms, "provider_terms_signature": "01" * 64, "hold_invoice": "lnbcrt1"}
    )


def test_ceil_div_rounds_toward_the_provider() -> None:
    assert ceil_div(0, 7) == 0
    assert ceil_div(7, 7) == 1
    assert ceil_div(8, 7) == 2


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {
                "economics": {
                    "kind": "erc20-to-ln",
                    "lightning_principal_sat": "1000",
                    "rate_token_base_per_btc": RATE,
                    "success_fee_token_base": "5000",
                    "lock_amount_token_base": "1005001",
                }
            },
            "lock = ceil",
        ),
        ({"htlc_timelock_block": 31000}, "does not fit before the EVM timelock"),
        ({"htlc_timelock_block": 1000}, "after the EVM reference block"),
        ({"claimant": "client", "refund_party": "provider"}, "roles are reversed"),
        ({"provider_evm_address": "0x" + "aa" * 20}, "must be distinct"),
        ({"invoice_binding": _invoice("1001000")}, "does not equal ERC20 to LN principal"),
        ({"profile_id": "btc-to-ln/v1"}, "profile_id"),
        ({"evm_asset": {**ASSET, "deployment_namespace": None}}, "deployment namespace"),
        ({"evm_asset": {**ASSET, "htlc_contract": ASSET["token_contract"]}}, "must differ"),
        ({"evm_asset": {**ASSET, "htlc_contract": "0x" + "AB" * 20}}, "htlc_contract"),
    ],
)
def test_forward_terms_reject_broken_commitments(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        EvmContractTerms.model_validate(forward_terms(**overrides))


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {
                "economics": {
                    "kind": "ln-to-erc20",
                    "payout_token_base": "1000001",
                    "rate_token_base_per_btc": RATE,
                    "payout_sat_equivalent": "1000",
                    "success_fee_sat": "100",
                    "hold_invoice_sat": "1100",
                }
            },
            "E = ceil",
        ),
        (
            {
                "economics": {
                    "kind": "ln-to-erc20",
                    "payout_token_base": "1000000",
                    "rate_token_base_per_btc": RATE,
                    "payout_sat_equivalent": "1000",
                    "success_fee_sat": "100",
                    "hold_invoice_sat": "1101",
                }
            },
            "H = E \\+ S",
        ),
        ({"htlc_timelock_block": 40000}, "does not cover the EVM refund resolution"),
        ({"claimant": "provider", "refund_party": "client"}, "roles are reversed"),
        ({"invoice_binding": _invoice("1000000")}, "does not equal LN to ERC20 held amount"),
    ],
)
def test_reverse_terms_reject_broken_commitments(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        EvmContractTerms.model_validate(reverse_terms(**overrides))


def test_quote_requests_dispatch_on_the_erc20_kinds() -> None:
    asset_ref = {"chain_id": 31337, "token_contract": ASSET["token_contract"]}
    indicative = parse_quote_request(
        json.dumps(
            {
                "kind": "erc20-to-ln",
                "mode": "indicative",
                "lightning_principal_sat": "1000",
                "evm_asset": asset_ref,
                "extensions": {},
            }
        ).encode()
    )
    assert type(indicative).__name__ == "Erc20IndicativeQuoteRequest"
    firm = parse_quote_request(
        json.dumps(
            {
                "kind": "ln-to-erc20",
                "mode": "firm",
                "payout_token_base": "1000000",
                "payment_hash": "cd" * 32,
                "evm_asset": asset_ref,
                "client_evm_address": "0x" + "aa" * 20,
                "recovery_authorization_xonly_key": RECOVERY_KEY,
                "limits": {
                    "max_success_fee_sat": "100",
                    "min_htlc_timelock_block": 1,
                    "max_incoming_htlc_expiry_height": 500,
                },
                "extensions": {},
            }
        ).encode()
    )
    assert type(firm).__name__ == "LnToErc20FirmQuoteRequest"
    with pytest.raises(ValidationError):
        parse_quote_request(
            json.dumps(
                {
                    "kind": "erc20-to-ln",
                    "mode": "firm",
                    "lightning_principal_sat": "1000",
                    "invoice": "LNBC1",
                    "evm_asset": asset_ref,
                    "client_evm_address": "0x" + "aa" * 20,
                    "recovery_authorization_xonly_key": RECOVERY_KEY,
                    "limits": {"max_success_fee_token_base": "0", "max_htlc_timelock_block": 1},
                    "extensions": {},
                }
            ).encode()
        )


def test_evm_lockup_observation_round_trips() -> None:
    observed = parse_observation(
        json.dumps(
            {
                "kind": "evm_lockup_observed",
                "lock_tx_hash": "ee" * 32,
                "log_index": 0,
                "block_number": 12,
            }
        ).encode()
    )
    assert isinstance(observed, EvmLockupObserved)
    assert observed.block_number == 12
