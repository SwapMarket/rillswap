from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

from tests.settlement_support import (
    CODESEPARATOR_POSITION,
    INPUT_SEQUENCE,
    Spend,
    build_spend,
    destination_script,
    spend_artifact,
    spend_is_authorized,
)
from tests.test_schemas import load_json
from tests.vendor.bip340_reference import verify
from tests.vendor.bitcoin_core_v30_reference import (
    SIGHASH_ALL,
    SIGHASH_DEFAULT,
    OutPoint,
    TxInput,
    TxOutput,
    taproot_signature_hash,
)

ROOT = Path(__file__).parents[1]
SETTLEMENT_PATH = ROOT / "vectors" / "settlement" / "cases-v1.json"
TAPROOT_PATH = ROOT / "vectors" / "taproot" / "cases-v1.json"


def _funding(case: dict[str, Any]) -> tuple[OutPoint, TxOutput]:
    funding = case["synthetic_funding"]
    return (
        OutPoint(bytes.fromhex(funding["txid"]), funding["vout"]),
        TxOutput(
            int(funding["value_sat"]),
            bytes.fromhex(funding["script_pubkey"]),
        ),
    )


def _role_public_key(taproot_case: dict[str, Any], path: str) -> bytes:
    terms = taproot_case["contract_terms"]
    role = terms["claimant"] if path == "claim" else terms["refund_party"]
    return bytes.fromhex(terms[f"{role}_contract_compressed_key"])[1:]


def _declared_signature_is_valid(
    spend: Spend,
    taproot_case: dict[str, Any],
    path: str,
) -> bool:
    encoded_signature = spend.witnesses[0][0]
    signature = encoded_signature[:64]
    if spend.hash_type == SIGHASH_DEFAULT:
        if encoded_signature not in (signature, signature + b"\x00"):
            return False
    elif len(encoded_signature) != 65 or encoded_signature[-1] != spend.hash_type:
        return False
    digest = taproot_signature_hash(
        spend.transaction,
        spend.spent_outputs,
        0,
        spend.tapleaf_hash,
        hash_type=spend.hash_type,
        annex=spend.annex,
        codeseparator_position=CODESEPARATOR_POSITION,
    )
    return verify(digest, _role_public_key(taproot_case, path), signature)


def _invalid_spend(
    invalid_id: str,
    taproot_case: dict[str, Any],
    path: str,
    outpoint: OutPoint,
    spent_output: TxOutput,
) -> Spend:
    terms = taproot_case["contract_terms"]
    fee = int(terms[f"max_{path}_fee_sat"])
    auxiliary = hashlib.sha256(f"RillSwap/invalid/{invalid_id}".encode()).digest()
    expected_destination = destination_script(terms, path)

    if invalid_id == "wrong-version":
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            version=3,
        )
    if invalid_id == "extra-input":
        second_output = TxOutput(50_000, b"\x00\x14" + b"\x22" * 20)
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            inputs=(
                TxInput(outpoint, INPUT_SEQUENCE),
                TxInput(OutPoint(b"\x33" * 32, 1), INPUT_SEQUENCE),
            ),
            spent_outputs=(spent_output, second_output),
        )
    if invalid_id == "extra-output":
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            outputs=(
                TxOutput(spent_output.value_sat - fee - 1_000, expected_destination),
                TxOutput(1_000, b"\x00\x14" + b"\x44" * 20),
            ),
        )
    if invalid_id == "wrong-outpoint":
        return build_spend(
            taproot_case,
            path,
            outpoint=OutPoint(b"\x55" * 32, 1),
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
        )
    if invalid_id in {"wrong-prevout-amount", "wrong-prevout-script"}:
        wrong_spent_output = (
            TxOutput(spent_output.value_sat + 1, spent_output.script_pubkey)
            if invalid_id == "wrong-prevout-amount"
            else TxOutput(spent_output.value_sat, b"\x51\x20" + b"\x66" * 32)
        )
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=wrong_spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
        )
    if invalid_id == "wrong-destination":
        authorized_role = (
            terms["claimant"] if path == "claim" else terms["refund_party"]
        )
        other_role = "client" if authorized_role == "provider" else "provider"
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            outputs=(
                TxOutput(
                    spent_output.value_sat - fee,
                    bytes.fromhex(terms[f"{other_role}_destination_script"]),
                ),
            ),
        )
    if invalid_id in {"over-claim-fee-cap", "over-refund-fee-cap"}:
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee + 1,
            auxiliary_random=auxiliary,
        )
    if invalid_id == "dust-output":
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=spent_output.value_sat - 329,
            auxiliary_random=auxiliary,
        )
    if invalid_id == "nonpositive-output":
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=spent_output.value_sat,
            auxiliary_random=auxiliary,
        )
    if invalid_id == "wrong-sequence":
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            sequence=0xFFFFFFFE,
        )
    if invalid_id == "wrong-claim-locktime":
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            lock_time=1,
        )
    if invalid_id == "wrong-refund-locktime":
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            lock_time=terms["refund_lock_height"] + 1,
        )
    if invalid_id == "nondefault-sighash":
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            hash_type=SIGHASH_ALL,
        )
    if invalid_id == "annex-present":
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            annex=b"\x50rillswap-invalid-annex",
        )
    if invalid_id in {
        "wrong-preimage-hash",
        "short-preimage",
        "long-preimage",
    }:
        preimages = {
            "wrong-preimage-hash": b"\x00" * 32,
            "short-preimage": b"\x42" * 31,
            "long-preimage": b"\x42" * 33,
        }
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            preimage=preimages[invalid_id],
        )
    if invalid_id in {"wrong-claim-script", "wrong-control-block"}:
        return build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
            script=b"\x51" if invalid_id == "wrong-claim-script" else None,
            control_block=(
                b"\xc0" + b"\x77" * 64 if invalid_id == "wrong-control-block" else None
            ),
        )
    if invalid_id == "explicit-default-sighash-byte":
        spend = build_spend(
            taproot_case,
            path,
            outpoint=outpoint,
            spent_output=spent_output,
            fee_sat=fee,
            auxiliary_random=auxiliary,
        )
        witness = spend.witnesses[0]
        return replace(
            spend,
            witnesses=((witness[0] + b"\x00", *witness[1:]),),
        )
    raise AssertionError(f"unhandled invalid settlement vector {invalid_id}")


def test_settlement_vectors_rebuild_every_signed_artifact() -> None:
    vectors = load_json(SETTLEMENT_PATH)
    taproot_vectors = load_json(TAPROOT_PATH)
    taproot_by_id = {case["id"]: case for case in taproot_vectors["valid"]}

    assert vectors["vector_version"] == "rillswap-unilateral-settlement-v1-pre.1"
    assert "synthetic outpoints" in vectors["fixture_key_warning"]
    assert "not outputs created" in vectors["funding_notice"]
    assert {case["profile_id"] for case in vectors["valid"]} == {
        "btc-to-ln/v1",
        "ln-to-btc/v1",
    }

    for case in vectors["valid"]:
        taproot_case = taproot_by_id[case["taproot_vector"]]
        assert case["id"] == taproot_case["id"]
        assert case["profile_id"] == taproot_case["profile_id"]
        assert case["contract_hash"] == taproot_case["contract_hash"]
        outpoint, spent_output = _funding(case)
        assert (
            outpoint.txid
            == hashlib.sha256(
                f"RillSwap/settlement-fixture/v1/{case['id']}".encode(),
            ).digest()
        )
        assert spent_output == TxOutput(
            int(taproot_case["contract_terms"]["economics"]["contract_amount_sat"]),
            bytes.fromhex(taproot_case["artifacts"]["script_pubkey"]),
        )

        for path in ("claim", "refund"):
            artifact = case[path]
            fee = int(artifact["fee_sat"])
            assert fee == int(taproot_case["contract_terms"][f"max_{path}_fee_sat"])
            spend = build_spend(
                taproot_case,
                path,
                outpoint=outpoint,
                spent_output=spent_output,
                fee_sat=fee,
                auxiliary_random=bytes.fromhex(artifact["auxiliary_random"]),
            )
            assert spend_artifact(spend) == {
                key: value for key, value in artifact.items() if key != "fee_sat"
            }
            assert _declared_signature_is_valid(spend, taproot_case, path)
            assert spend_is_authorized(
                spend,
                taproot_case,
                path,
                expected_outpoint=outpoint,
                expected_spent_output=spent_output,
            )


def test_settlement_authorization_rejects_resigned_policy_mutations() -> None:
    vectors = load_json(SETTLEMENT_PATH)
    taproot_vectors = load_json(TAPROOT_PATH)
    settlement_by_id = {case["id"]: case for case in vectors["valid"]}
    taproot_by_id = {case["id"]: case for case in taproot_vectors["valid"]}

    assert vectors["invalid"]
    assert len({case["id"] for case in vectors["invalid"]}) == len(
        vectors["invalid"],
    )
    for invalid in vectors["invalid"]:
        settlement_case = settlement_by_id[invalid["base"]]
        taproot_case = taproot_by_id[settlement_case["taproot_vector"]]
        outpoint, spent_output = _funding(settlement_case)
        spend = _invalid_spend(
            invalid["id"],
            taproot_case,
            invalid["path"],
            outpoint,
            spent_output,
        )

        assert _declared_signature_is_valid(
            spend,
            taproot_case,
            invalid["path"],
        ), invalid["id"]
        assert not spend_is_authorized(
            spend,
            taproot_case,
            invalid["path"],
            expected_outpoint=outpoint,
            expected_spent_output=spent_output,
        ), invalid["id"]


def test_dust_boundaries_and_zero_are_rejected_within_fee_cap() -> None:
    vectors = load_json(SETTLEMENT_PATH)
    taproot_vectors = load_json(TAPROOT_PATH)
    for index, (below_dust, at_dust) in enumerate(((329, 330), (293, 294))):
        settlement_case = vectors["valid"][index]
        taproot_case = copy.deepcopy(taproot_vectors["valid"][index])
        outpoint, spent_output = _funding(settlement_case)
        taproot_case["contract_terms"]["max_claim_fee_sat"] = str(
            spent_output.value_sat,
        )

        spends = [
            build_spend(
                taproot_case,
                "claim",
                outpoint=outpoint,
                spent_output=spent_output,
                fee_sat=spent_output.value_sat - output_value,
                auxiliary_random=hashlib.sha256(
                    f"RillSwap/dust-boundary/{index}/{output_value}".encode(),
                ).digest(),
            )
            for output_value in (below_dust, at_dust, 0)
        ]
        assert all(
            _declared_signature_is_valid(spend, taproot_case, "claim")
            for spend in spends
        )
        assert not spend_is_authorized(
            spends[0],
            taproot_case,
            "claim",
            expected_outpoint=outpoint,
            expected_spent_output=spent_output,
        )
        assert spend_is_authorized(
            spends[1],
            taproot_case,
            "claim",
            expected_outpoint=outpoint,
            expected_spent_output=spent_output,
        )
        assert not spend_is_authorized(
            spends[2],
            taproot_case,
            "claim",
            expected_outpoint=outpoint,
            expected_spent_output=spent_output,
        )
