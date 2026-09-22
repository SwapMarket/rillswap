"""Offline checks for a synthetic, unfunded RS-007 plaintext export fixture.

This is vector verification, not a recovery importer or a decryption test.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import rfc8785

from tests.test_schemas import load_json, schema_registry
from tests.test_taproot_vectors import _reconstruct
from tests.vendor.bip327_reference import individual_public_key
from tests.vendor.bip340_reference import tagged_hash, verify

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "vectors" / "recovery" / "initial-btc-to-ln-v1.json"


def build_initial_fixture() -> dict[str, Any]:
    """Compose an initial export entirely from already published synthetic vectors."""
    auth = next(
        case
        for case in load_json(ROOT / "vectors" / "authentication" / "cases-v1.json")["valid"]
        if case["id"] == "regtest-btc-to-ln"
    )
    economics = next(
        case
        for case in load_json(ROOT / "vectors" / "economics" / "cases-v1.json")["valid"]
        if case["id"] == "btc-to-ln-success-fee"
    )
    taproot = next(
        case
        for case in load_json(ROOT / "vectors" / "taproot" / "cases-v1.json")["valid"]
        if case["id"] == "btc-to-ln-success-fee"
    )
    terms = economics["contract_terms"]["object"]
    artifacts = taproot["artifacts"]
    return {
        "format": "rillswap-recovery",
        "format_version": "1-pre.1",
        "specification_version": "0.1.0-pre.1",
        "created_at": 1700000100,
        "updated_at": 1700000100,
        "network_identity": terms["network_identity"],
        "profile_id": terms["profile_id"],
        "contract_hash": economics["contract_terms"]["tagged_hash"],
        "contract_terms": terms,
        "verification_context": {
            "handshake_init": auth["handshake_init"]["object"],
            "handshake_accept": auth["handshake_accept"]["object"],
            "provider_identity_signature": auth["handshake_accept"]["signature"],
            "handshake_hash": auth["transcript"]["tagged_hash"],
            "client_session_xonly_key": auth["handshake_init"]["object"]["client_session_xonly_key"],
            "provider_session_xonly_key": auth["handshake_accept"]["object"]["provider_session_xonly_key"],
            "expected_provider_identity_source": {
                "kind": "manual",
                "advertisement_digest": None,
            },
            "provider_terms_signature": economics["provider_terms"]["signature"],
            "client_acceptance_signature": economics["client_acceptance"]["signature"],
        },
        "taproot_contract": {
            "internal_xonly_key": artifacts["internal_key"],
            "internal_key_parity": artifacts["internal_parity"],
            "claim_script": artifacts["claim_script"],
            "refund_script": artifacts["refund_script"],
            "claim_leaf_hash": artifacts["claim_leaf_hash"],
            "refund_leaf_hash": artifacts["refund_leaf_hash"],
            "merkle_root": artifacts["merkle_root"],
            "tap_tweak": artifacts["tap_tweak"],
            "output_xonly_key": artifacts["output_key"],
            "output_key_parity": artifacts["output_parity"],
            "script_pubkey": artifacts["script_pubkey"],
            "claim_control_block": artifacts["claim_control_block"],
            "refund_control_block": artifacts["refund_control_block"],
        },
        "user_secret": {
            "kind": "raw-secp256k1-v1",
            "contract_secret_key": taproot["fixture_keys"]["client_contract_secret_key"],
        },
        "funding_history": [],
        "chain_scan_birthday_height": 900,
        "fee_policy": {
            "max_claim_fee_sat": terms["max_claim_fee_sat"],
            "max_refund_fee_sat": terms["max_refund_fee_sat"],
        },
        "recovery_authorization_xonly_key": terms["recovery_authorization_xonly_key"],
        "monotonic_knowledge": {
            "preimage_known": False,
            "preimage": None,
            "dangerous_signature_issued": False,
        },
        "extensions": {},
    }


def _schema_validator() -> jsonschema.Draft202012Validator:
    registry, _ = schema_registry()
    schema = load_json(ROOT / "schemas" / "recovery" / "recovery-v1.schema.json")
    return jsonschema.Draft202012Validator(schema, registry=registry)


def _signed_context_is_valid(package: dict[str, Any]) -> bool:
    terms = package["contract_terms"]
    context = package["verification_context"]
    initiation, acceptance = context["handshake_init"], context["handshake_accept"]
    contract_hash = tagged_hash("RillSwap/contract/v1", rfc8785.dumps(terms)).hex()
    initiation_hash = tagged_hash("RillSwap/handshake-init/v1", rfc8785.dumps(initiation)).hex()
    handshake_hash = tagged_hash(
        "RillSwap/transcript/v1", rfc8785.dumps({"accept": acceptance, "init": initiation})
    ).hex()
    provider_terms = {
        "contract_hash": contract_hash,
        "contract_terms": terms,
        "handshake_hash": handshake_hash,
    }
    client_acceptance = {
        "contract_hash": contract_hash,
        "handshake_hash": handshake_hash,
        "session_id": initiation["session_id"],
        "client_session_xonly_key": context["client_session_xonly_key"],
        "provider_session_xonly_key": context["provider_session_xonly_key"],
    }
    provider_key = bytes.fromhex(terms["provider_identity_key"])
    client_key = bytes.fromhex(context["client_session_xonly_key"])

    def verifies(tag: str, payload: dict[str, Any], key: bytes, signature: str) -> bool:
        return verify(
            tagged_hash(tag, rfc8785.dumps(payload)), key, bytes.fromhex(signature)
        )

    return (
        package["contract_hash"] == contract_hash
        and package["network_identity"] == terms["network_identity"]
        and package["profile_id"] == terms["profile_id"] == initiation["profile_id"]
        and acceptance["profile_id"] == initiation["profile_id"]
        and initiation["network_identity"] == acceptance["network_identity"] == terms["network_identity"]
        and acceptance["session_id"] == initiation["session_id"]
        and acceptance["handshake_init_hash"] == initiation_hash
        and acceptance["provider_identity_xonly_key"] == provider_key.hex()
        and initiation["expected_provider_identity_xonly_key"] == provider_key.hex()
        and context["handshake_hash"] == handshake_hash
        and context["client_session_xonly_key"] == initiation["client_session_xonly_key"]
        and context["provider_session_xonly_key"] == acceptance["provider_session_xonly_key"]
        and verifies(
            "RillSwap/handshake/v1", acceptance, provider_key,
            context["provider_identity_signature"],
        )
        and verifies(
            "RillSwap/provider-terms/v1", provider_terms, provider_key,
            context["provider_terms_signature"],
        )
        and verifies(
            "RillSwap/client-acceptance/v1", client_acceptance, client_key,
            context["client_acceptance_signature"],
        )
    )


def test_initial_recovery_vector_matches_sources_and_offline_commitments() -> None:
    package = load_json(FIXTURE)
    assert package == build_initial_fixture()
    _schema_validator().validate(package)
    assert _signed_context_is_valid(package)
    assert package["funding_history"] == []
    assert package["monotonic_knowledge"] == {
        "preimage_known": False,
        "preimage": None,
        "dangerous_signature_issued": False,
    }
    assert package["updated_at"] >= package["created_at"]
    assert package["chain_scan_birthday_height"] <= package["contract_terms"]["refund_lock_height"]
    assert package["fee_policy"] == {
        "max_claim_fee_sat": package["contract_terms"]["max_claim_fee_sat"],
        "max_refund_fee_sat": package["contract_terms"]["max_refund_fee_sat"],
    }
    assert package["recovery_authorization_xonly_key"] == package["contract_terms"][
        "recovery_authorization_xonly_key"
    ]
    taproot = next(
        case
        for case in load_json(ROOT / "vectors" / "taproot" / "cases-v1.json")["valid"]
        if case["id"] == "btc-to-ln-success-fee"
    )
    assert individual_public_key(
        bytes.fromhex(package["user_secret"]["contract_secret_key"])
    ).hex() == package["contract_terms"]["client_contract_compressed_key"]
    assert _reconstruct(taproot) == taproot["artifacts"]
    for stored_field, reference_field in (
        ("internal_xonly_key", "internal_key"),
        ("internal_key_parity", "internal_parity"),
        ("output_xonly_key", "output_key"),
        ("output_key_parity", "output_parity"),
    ):
        assert package["taproot_contract"][stored_field] == taproot["artifacts"][reference_field]
    for field in set(package["taproot_contract"]) - {
        "internal_xonly_key", "internal_key_parity", "output_xonly_key", "output_key_parity"
    }:
        assert package["taproot_contract"][field] == taproot["artifacts"][field]


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("verification_context", "provider_identity_signature", "00" * 64),
        ("verification_context", "provider_terms_signature", "00" * 64),
        ("verification_context", "client_acceptance_signature", "00" * 64),
        ("verification_context", "handshake_hash", "00" * 32),
        ("", "contract_hash", "00" * 32),
    ],
)
def test_tampered_signed_context_is_detected(section: str, field: str, value: str) -> None:
    package = copy.deepcopy(load_json(FIXTURE))
    location = package[section] if section else package
    location[field] = value
    assert not _signed_context_is_valid(package)


@pytest.mark.parametrize(
    ("field", "value"),
    [("format_version", "1-pre.0"), ("verification_context", {}), ("extra", "unknown")],
)
def test_unsupported_or_partial_recovery_shape_is_rejected(field: str, value: object) -> None:
    package = copy.deepcopy(load_json(FIXTURE))
    package[field] = value
    assert not _schema_validator().is_valid(package)
