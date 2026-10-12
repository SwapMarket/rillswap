"""Shared RS-010 EVM terms fixtures for provider tests."""

from __future__ import annotations

import hashlib

from rill_core.wire.messages import EvmContractTerms

PROVIDER_KEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
RECOVERY_KEY = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
PREIMAGE = "11" * 32
PAYMENT_HASH = hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest()
HTLC = "0x" + "1a" * 20
TOKEN = "0x" + "2b" * 20
CLIENT = "0x" + "ac" * 20
PROVIDER = "0x" + "bd" * 20
# Deterministic Anvil development accounts; never funded anywhere else.
ANVIL_KEYS = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
)


def evm_terms(  # noqa: PLR0913 - one keyword per terms field under test
    profile: str,
    *,
    htlc: str = HTLC,
    token: str = TOKEN,
    client: str = CLIENT,
    provider: str = PROVIDER,
    timelock: int = 500,
    terms_expiry: int = 2000,
) -> EvmContractTerms:
    """Return valid signed-shape EVM terms for one RS-010 profile."""
    forward = profile == "erc20-to-ln/v1"
    return EvmContractTerms.model_validate(
        {
            "protocol": "rillswap",
            "contract_version": "1",
            "profile_id": profile,
            "network_identity": {
                "family": "bitcoin",
                "name": "regtest",
                "genesis_hash": "0f" * 32,
                "signet_challenge": None,
                "consensus_profile": "bitcoin-core/regtest",
                "deployment_namespace": "dev",
            },
            "evm_asset": {
                "family": "evm",
                "chain_id": 31337,
                "name": "anvil-dev",
                "htlc_contract": htlc,
                "htlc_version": 6,
                "token_contract": token,
                "token_symbol": "fUSDC",
                "token_decimals": 6,
                "block_seconds": 2,
                "deployment_namespace": "dev",
            },
            "provider_identity_key": PROVIDER_KEY,
            "client_evm_address": client,
            "provider_evm_address": provider,
            "claimant": "provider" if forward else "client",
            "refund_party": "client" if forward else "provider",
            "invoice_binding": {
                "bolt11_sha256": "ab" * 32,
                "payment_hash": PAYMENT_HASH,
                "amount_msat": "1000000" if forward else "1100000",
                "payee_compressed_pubkey": "02" + PROVIDER_KEY,
                "created_at": 1000,
                "expires_at": 4600,
                "min_final_cltv_delta": 40,
            },
            "economics": (
                {
                    "kind": "erc20-to-ln",
                    "lightning_principal_sat": "1000",
                    "rate_token_base_per_btc": "100000000000",
                    "success_fee_token_base": "5000",
                    "lock_amount_token_base": "1005000",
                }
                if forward
                else {
                    "kind": "ln-to-erc20",
                    "payout_token_base": "1000000",
                    "rate_token_base_per_btc": "100000000000",
                    "payout_sat_equivalent": "1000",
                    "success_fee_sat": "100",
                    "hold_invoice_sat": "1100",
                }
            ),
            "htlc_timelock_block": timelock,
            "evm_reference_block": 0,
            "btc_reference_height": 200,
            "funding_confirmations": 1,
            "settlement_confirmations": 1,
            "recovery_authorization_xonly_key": RECOVERY_KEY,
            "terms_expiry": terms_expiry,
            "timing_policy": (
                {
                    "kind": "erc20-to-ln",
                    "max_outgoing_htlc_expiry_height": 201,
                    "learn_and_claim_seconds": 1,
                }
                if forward
                else {
                    "kind": "ln-to-erc20",
                    "min_incoming_htlc_expiry_height": 10_000,
                    "refund_and_ln_resolution_seconds": 1,
                }
            ),
            "required_features": (),
            "extensions": {},
        }
    )
