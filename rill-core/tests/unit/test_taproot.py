from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import pytest

from rill_core.errors import ValidationError
from rill_core.settlement.taproot import reconstruct_taproot_contract
from rill_core.wire.messages import ContractTerms

G = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
G2 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
G3 = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
G4 = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
G5 = "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
PAYMENT_HASH = bytes.fromhex("42" * 32)


def tagged_hash(tag: str, message: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def terms_data(
    profile_id: str = "btc-to-ln/v1",
    *,
    refund_lock_height: int = 1_100,
) -> dict[str, object]:
    common: dict[str, object] = {
        "protocol": "rillswap",
        "contract_version": "1",
        "profile_id": profile_id,
        "network_identity": {
            "family": "bitcoin",
            "name": "regtest",
            "genesis_hash": "01" * 32,
            "signet_challenge": None,
            "consensus_profile": "bitcoin-core/v30",
            "deployment_namespace": "test/taproot",
        },
        "provider_identity_key": G3,
        "client_contract_compressed_key": "02" + G,
        "provider_contract_compressed_key": "02" + G2,
        "refund_lock_height": refund_lock_height,
        "funding_confirmations": 1,
        "settlement_confirmations": 2,
        "refund_resolution_confirmations": 3,
        "max_funding_fee_sat": "10",
        "max_claim_fee_sat": "11",
        "max_refund_fee_sat": "12",
        "client_destination_script": "0014" + "11" * 20,
        "provider_destination_script": "5120" + G5,
        "recovery_authorization_xonly_key": G4,
        "terms_expiry": 3_000,
        "required_features": (),
        "extensions": {},
    }
    invoice = {
        "bolt11_sha256": "02" * 32,
        "payment_hash": PAYMENT_HASH.hex(),
        "payee_compressed_pubkey": "02" + G5,
        "created_at": 1_000,
        "expires_at": 2_000,
        "min_final_cltv_delta": 18,
    }
    if profile_id == "btc-to-ln/v1":
        common.update(
            {
                "claimant": "provider",
                "refund_party": "client",
                "invoice_binding": {**invoice, "amount_msat": "100000"},
                "economics": {
                    "kind": "btc-to-ln",
                    "lightning_principal_sat": "100",
                    "success_fee_sat": "5",
                    "contract_amount_sat": "105",
                },
                "timing_policy": {
                    "kind": "btc-to-ln",
                    "max_outgoing_htlc_expiry_height": max(0, refund_lock_height - 2),
                    "learn_and_claim_blocks": 1,
                    "client_response_blocks": 2,
                    "claim_confirmation_blocks": 3,
                },
            },
        )
    else:
        common.update(
            {
                "claimant": "client",
                "refund_party": "provider",
                "invoice_binding": {**invoice, "amount_msat": "105000"},
                "economics": {
                    "kind": "ln-to-btc",
                    "contract_amount_sat": "100",
                    "nominal_payout_sat": "98",
                    "claim_fee_reserve_sat": "2",
                    "success_fee_sat": "5",
                    "mining_prepayment_sat": "0",
                    "hold_invoice_sat": "105",
                },
                "timing_policy": {
                    "kind": "ln-to-btc",
                    "min_incoming_htlc_expiry_height": refund_lock_height + 3,
                    "refund_and_ln_resolution_blocks": 1,
                    "client_response_blocks": 2,
                    "claim_confirmation_blocks": 3,
                },
            },
        )
    return common


@dataclass
class FakeKeyOperations:
    internal_key: bytes = b"\x21" * 32
    internal_parity: int = 0
    output_key: bytes = b"\x22" * 32
    output_parity: int = 1
    calls: list[tuple[bytes, ...]] = field(default_factory=list)

    def musig_internal_key(
        self,
        user_public_key: bytes,
        provider_public_key: bytes,
    ) -> tuple[bytes, int]:
        self.calls.append((user_public_key, provider_public_key))
        return self.internal_key, self.internal_parity

    def musig_output_key(
        self,
        user_public_key: bytes,
        provider_public_key: bytes,
        tap_tweak: bytes,
    ) -> tuple[bytes, int]:
        self.calls.append((user_public_key, provider_public_key, tap_tweak))
        return self.output_key, self.output_parity


def test_reconstructs_exact_two_leaf_contract() -> None:
    terms = ContractTerms.model_validate(terms_data())
    keys = FakeKeyOperations()
    contract = reconstruct_taproot_contract(terms, keys=keys)

    expected_claim = (
        bytes.fromhex("82012088a820")
        + PAYMENT_HASH
        + bytes.fromhex("8820")
        + bytes.fromhex(G2)
        + bytes.fromhex("ac")
    )
    expected_refund = bytes.fromhex("024c04b17520") + bytes.fromhex(G) + bytes.fromhex("ac")
    assert contract.claim_script == expected_claim
    assert contract.refund_script == expected_refund
    assert contract.claim_leaf_preimage == b"\xc0\x49" + expected_claim
    assert contract.refund_leaf_preimage == b"\xc0\x27" + expected_refund
    assert contract.claim_leaf_hash == tagged_hash("TapLeaf", contract.claim_leaf_preimage)
    assert contract.refund_leaf_hash == tagged_hash("TapLeaf", contract.refund_leaf_preimage)
    assert (contract.branch_left_hash, contract.branch_right_hash) == tuple(
        sorted((contract.claim_leaf_hash, contract.refund_leaf_hash)),
    )
    assert contract.merkle_root == tagged_hash(
        "TapBranch",
        contract.branch_left_hash + contract.branch_right_hash,
    )
    assert contract.tap_tweak == tagged_hash(
        "TapTweak",
        contract.internal_key + contract.merkle_root,
    )
    assert contract.script_pubkey == bytes.fromhex("5120") + b"\x22" * 32
    assert contract.claim_control_block == b"\xc1" + b"\x21" * 32 + contract.refund_leaf_hash
    assert contract.refund_control_block == b"\xc1" + b"\x21" * 32 + contract.claim_leaf_hash
    assert len(contract.claim_control_block) == 65
    assert len(contract.refund_control_block) == 65
    assert keys.calls[1][2] == contract.tap_tweak


def test_control_block_uses_output_parity_not_internal_parity() -> None:
    terms = ContractTerms.model_validate(terms_data())
    contract = reconstruct_taproot_contract(
        terms,
        keys=FakeKeyOperations(internal_parity=1, output_parity=0),
    )
    assert contract.internal_parity == 1
    assert contract.output_parity == 0
    assert contract.claim_control_block[0] == 0xC0
    assert contract.refund_control_block[0] == 0xC0


@pytest.mark.parametrize("profile_id", ["btc-to-ln/v1", "ln-to-btc/v1"])
def test_key_aggregation_order_never_follows_claimant_role(profile_id: str) -> None:
    terms = ContractTerms.model_validate(terms_data(profile_id))
    keys = FakeKeyOperations()
    contract = reconstruct_taproot_contract(terms, keys=keys)
    ordered_keys = (bytes.fromhex("02" + G), bytes.fromhex("02" + G2))
    assert keys.calls[0] == ordered_keys
    assert keys.calls[1][:2] == ordered_keys
    expected_claimant = G2 if profile_id == "btc-to-ln/v1" else G
    expected_refund = G if profile_id == "btc-to-ln/v1" else G2
    assert contract.claim_script[-33:-1].hex() == expected_claimant
    assert contract.refund_script[-33:-1].hex() == expected_refund


@pytest.mark.parametrize(
    ("height", "encoded"),
    [
        (1, "51"),
        (16, "60"),
        (17, "0111"),
        (127, "017f"),
        (128, "028000"),
        (255, "02ff00"),
        (256, "020001"),
        (32_767, "02ff7f"),
        (32_768, "03008000"),
        (8_388_607, "03ffff7f"),
        (8_388_608, "0400008000"),
        (499_999_999, "04ff64cd1d"),
    ],
)
def test_refund_height_uses_minimal_positive_script_number(height: int, encoded: str) -> None:
    terms = ContractTerms.model_validate(terms_data(refund_lock_height=height))
    contract = reconstruct_taproot_contract(terms, keys=FakeKeyOperations())
    assert contract.refund_script.startswith(bytes.fromhex(encoded + "b17520"))


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("internal_key", b"\x21" * 31),
        ("internal_parity", 2),
        ("output_key", b"\x22" * 31),
        ("output_parity", -1),
    ],
)
def test_rejects_malformed_curve_boundary_results(field_name: str, value: object) -> None:
    terms = ContractTerms.model_validate(terms_data())
    keys = FakeKeyOperations()
    setattr(keys, field_name, value)
    with pytest.raises(ValidationError):
        reconstruct_taproot_contract(terms, keys=keys)
