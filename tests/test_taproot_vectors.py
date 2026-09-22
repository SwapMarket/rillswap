from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest
import rfc8785

from tests.test_schemas import load_json
from tests.vendor.bip327_reference import (
    individual_public_key,
    key_aggregate,
    tagged_hash,
    xonly_tweak_add,
)

ROOT = Path(__file__).parents[1]
TAPROOT_PATH = ROOT / "vectors" / "taproot" / "cases-v1.json"
ECONOMICS_PATH = ROOT / "vectors" / "economics" / "cases-v1.json"

LEAF_VERSION = 0xC0
OP_1 = 0x51


def _compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("CompactSize cannot encode a negative value")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise ValueError("CompactSize value is too large")


def _minimal_script_number(value: int) -> bytes:
    if value <= 0:
        raise ValueError("refund lock height must be positive")
    if value <= 16:
        return bytes([OP_1 - 1 + value])

    encoded = bytearray()
    remaining = value
    while remaining:
        encoded.append(remaining & 0xFF)
        remaining >>= 8
    if encoded[-1] & 0x80:
        encoded.append(0)
    if len(encoded) > 75:
        raise ValueError("script number is too large for a direct push")
    return bytes([len(encoded)]) + encoded


def _tapleaf(script: bytes) -> tuple[bytes, bytes]:
    preimage = bytes([LEAF_VERSION]) + _compact_size(len(script)) + script
    return preimage, tagged_hash("TapLeaf", preimage)


def _contract_keys(case: dict[str, Any]) -> tuple[bytes, bytes]:
    terms = case["contract_terms"]
    client_key = bytes.fromhex(terms["client_contract_compressed_key"])
    provider_key = bytes.fromhex(terms["provider_contract_compressed_key"])
    return client_key, provider_key


def _claim_preimage_is_valid(preimage_hex: str, payment_hash_hex: str) -> bool:
    try:
        preimage = bytes.fromhex(preimage_hex)
        payment_hash = bytes.fromhex(payment_hash_hex)
    except ValueError:
        return False
    return (
        len(preimage) == 32
        and len(payment_hash) == 32
        and hashlib.sha256(preimage).digest() == payment_hash
    )


def _reconstruct(case: dict[str, Any]) -> dict[str, str | int]:
    terms = case["contract_terms"]
    client_key, provider_key = _contract_keys(case)
    if client_key == provider_key:
        raise ValueError("duplicate contract keys")

    internal_key, internal_parity = key_aggregate([client_key, provider_key])
    role_keys = {"client": client_key[1:], "provider": provider_key[1:]}
    claimant_key = role_keys[terms["claimant"]]
    refund_key = role_keys[terms["refund_party"]]
    payment_hash = bytes.fromhex(terms["invoice_binding"]["payment_hash"])

    claim_script = (
        b"\x82\x01\x20\x88\xa8\x20"
        + payment_hash
        + b"\x88\x20"
        + claimant_key
        + b"\xac"
    )
    refund_script = (
        _minimal_script_number(terms["refund_lock_height"])
        + b"\xb1\x75\x20"
        + refund_key
        + b"\xac"
    )
    claim_leaf_preimage, claim_leaf_hash = _tapleaf(claim_script)
    refund_leaf_preimage, refund_leaf_hash = _tapleaf(refund_script)
    branch_left_hash, branch_right_hash = sorted(
        (claim_leaf_hash, refund_leaf_hash),
    )
    merkle_root = tagged_hash(
        "TapBranch",
        branch_left_hash + branch_right_hash,
    )
    tap_tweak = tagged_hash("TapTweak", internal_key + merkle_root)
    output_key, output_parity = xonly_tweak_add(internal_key, tap_tweak)
    control_prefix = bytes([LEAF_VERSION | output_parity]) + internal_key

    return {
        "internal_key": internal_key.hex(),
        "internal_parity": internal_parity,
        "claim_script": claim_script.hex(),
        "refund_script": refund_script.hex(),
        "claim_leaf_preimage": claim_leaf_preimage.hex(),
        "refund_leaf_preimage": refund_leaf_preimage.hex(),
        "claim_leaf_hash": claim_leaf_hash.hex(),
        "refund_leaf_hash": refund_leaf_hash.hex(),
        "branch_left_hash": branch_left_hash.hex(),
        "branch_right_hash": branch_right_hash.hex(),
        "merkle_root": merkle_root.hex(),
        "tap_tweak": tap_tweak.hex(),
        "output_key": output_key.hex(),
        "output_parity": output_parity,
        "script_pubkey": (b"\x51\x20" + output_key).hex(),
        "claim_control_block": (control_prefix + refund_leaf_hash).hex(),
        "refund_control_block": (control_prefix + claim_leaf_hash).hex(),
    }


def _control_block_commits_to_output(
    control_block_hex: str,
    script_hex: str,
    output_key_hex: str,
) -> bool:
    control_block = bytes.fromhex(control_block_hex)
    if len(control_block) != 65 or control_block[0] & 0xFE != LEAF_VERSION:
        return False
    _, leaf_hash = _tapleaf(bytes.fromhex(script_hex))
    sibling_hash = control_block[33:]
    branch_left, branch_right = sorted((leaf_hash, sibling_hash))
    merkle_root = tagged_hash("TapBranch", branch_left + branch_right)
    internal_key = control_block[1:33]
    output_key, output_parity = xonly_tweak_add(
        internal_key,
        tagged_hash("TapTweak", internal_key + merkle_root),
    )
    return output_key.hex() == output_key_hex and output_parity == control_block[0] & 1


def _case_is_valid(
    case: dict[str, Any],
    economics_by_id: dict[str, dict[str, Any]],
) -> bool:
    try:
        economics = economics_by_id[case["economic_vector"]]
        terms_artifact = economics["contract_terms"]
        client_key, provider_key = _contract_keys(case)
        client_secret = bytes.fromhex(
            case["fixture_keys"]["client_contract_secret_key"],
        )
        provider_secret = bytes.fromhex(
            case["fixture_keys"]["provider_contract_secret_key"],
        )
        artifacts = case["artifacts"]
        canonical_terms = rfc8785.dumps(case["contract_terms"])
        return (
            case["profile_id"] == case["contract_terms"]["profile_id"]
            and case["contract_terms"] == terms_artifact["object"]
            and canonical_terms.decode() == terms_artifact["canonical_utf8"]
            and case["contract_hash"] == terms_artifact["tagged_hash"]
            and tagged_hash("RillSwap/contract/v1", canonical_terms).hex()
            == case["contract_hash"]
            and client_key != provider_key
            and individual_public_key(client_secret) == client_key
            and individual_public_key(provider_secret) == provider_key
            and _claim_preimage_is_valid(
                case["claim_preimage"],
                case["contract_terms"]["invoice_binding"]["payment_hash"],
            )
            and artifacts == _reconstruct(case)
            and _control_block_commits_to_output(
                artifacts["claim_control_block"],
                artifacts["claim_script"],
                artifacts["output_key"],
            )
            and _control_block_commits_to_output(
                artifacts["refund_control_block"],
                artifacts["refund_script"],
                artifacts["output_key"],
            )
        )
    except (KeyError, TypeError, ValueError):
        return False


def _apply_replacement(base: dict[str, Any], invalid: dict[str, Any]) -> dict[str, Any]:
    changed = copy.deepcopy(base)
    target: Any = changed
    components = invalid["path"].removeprefix("/").split("/")
    for component in components[:-1]:
        target = target[component]
    target[components[-1]] = invalid["replacement"]
    return changed


def test_taproot_vectors_reconstruct_with_independent_oracles() -> None:
    vectors = load_json(TAPROOT_PATH)
    economics = load_json(ECONOMICS_PATH)
    economics_by_id = {case["id"]: case for case in economics["valid"]}

    assert vectors["vector_version"] == "rillswap-taproot-contract-v1-pre.1"
    assert vectors["fixture_key_warning"] == (
        "public deterministic test keys; never use for funds"
    )
    assert vectors["references"] == {
        "contract": "RS-002",
        "key_aggregation": "BIP327-v1.0.4",
        "taproot": "BIP341",
        "tapscript": "BIP342",
    }
    assert {case["profile_id"] for case in vectors["valid"]} == {
        "btc-to-ln/v1",
        "ln-to-btc/v1",
    }
    assert len({case["id"] for case in vectors["valid"]}) == len(vectors["valid"])
    assert vectors["invalid"]
    assert all(_case_is_valid(case, economics_by_id) for case in vectors["valid"])


def test_taproot_invalid_transformations_are_rejected() -> None:
    vectors = load_json(TAPROOT_PATH)
    economics = load_json(ECONOMICS_PATH)
    economics_by_id = {case["id"]: case for case in economics["valid"]}
    by_id = {case["id"]: case for case in vectors["valid"]}

    for invalid in vectors["invalid"]:
        base = by_id[invalid["base"]]
        if invalid["id"] == "swapped-key-aggregation-order":
            client_key, provider_key = _contract_keys(base)
            swapped_key, _ = key_aggregate([provider_key, client_key])
            assert swapped_key.hex() == invalid["replacement_internal_key"]
            assert swapped_key.hex() != base["artifacts"]["internal_key"]
            changed = copy.deepcopy(base)
            changed["artifacts"]["internal_key"] = swapped_key.hex()
        elif invalid["id"] == "extra-tree-leaf":
            claim_leaf = bytes.fromhex(base["artifacts"]["claim_leaf_hash"])
            refund_leaf = bytes.fromhex(base["artifacts"]["refund_leaf_hash"])
            extra_leaf = bytes.fromhex(invalid["extra_leaf_hash"])
            left, right = sorted((claim_leaf, extra_leaf))
            extra_branch = tagged_hash("TapBranch", left + right)
            left, right = sorted((refund_leaf, extra_branch))
            replacement = tagged_hash("TapBranch", left + right).hex()
            assert replacement == invalid["replacement_merkle_root"]
            changed = copy.deepcopy(base)
            changed["artifacts"]["merkle_root"] = replacement
        else:
            changed = _apply_replacement(base, invalid)

        if invalid["reason"] == "client-and-provider-contract-keys-must-differ":
            client_key, provider_key = _contract_keys(changed)
            assert client_key == provider_key
            with pytest.raises(ValueError, match="duplicate contract keys"):
                _reconstruct(changed)
        elif invalid["reason"] == "claim-preimage-must-be-32-bytes":
            preimage = bytes.fromhex(changed["claim_preimage"])
            assert len(preimage) in {31, 33}
            assert not _claim_preimage_is_valid(
                preimage.hex(),
                hashlib.sha256(preimage).hexdigest(),
            )
        elif invalid["reason"] == "control-block-output-parity-mismatch":
            artifacts = changed["artifacts"]
            assert not _control_block_commits_to_output(
                artifacts["claim_control_block"],
                artifacts["claim_script"],
                artifacts["output_key"],
            )

        assert not _case_is_valid(changed, economics_by_id), invalid["id"]


def test_claim_preimage_validation_separates_length_and_hash() -> None:
    preimage = bytes.fromhex("42" * 32)
    payment_hash = hashlib.sha256(preimage).hexdigest()

    assert _claim_preimage_is_valid(preimage.hex(), payment_hash)
    assert not _claim_preimage_is_valid(preimage.hex(), "00" * 32)
