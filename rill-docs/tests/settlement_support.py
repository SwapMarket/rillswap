"""Shared construction and authorization helpers for settlement conformance tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from tests.vendor.bip340_reference import sign, verify
from tests.vendor.bitcoin_core_v30_reference import (
    SIGHASH_DEFAULT,
    OutPoint,
    Transaction,
    TxInput,
    TxOutput,
    taproot_signature_hash,
    transaction_id,
    transaction_weight,
    witness_transaction_id,
)

INPUT_SEQUENCE = 0xFFFFFFFD
CODESEPARATOR_POSITION = 0xFFFFFFFF


@dataclass(frozen=True)
class Spend:
    transaction: Transaction
    spent_outputs: tuple[TxOutput, ...]
    witnesses: tuple[tuple[bytes, ...], ...]
    hash_type: int
    annex: bytes | None
    tapleaf_hash: bytes
    auxiliary_random: bytes


def _role_secret(case: dict[str, Any], role: str) -> bytes:
    return bytes.fromhex(case["fixture_keys"][f"{role}_contract_secret_key"])


def _path_parameters(
    taproot_case: dict[str, Any],
    path: str,
) -> tuple[str, bytes, bytes, bytes, int, str]:
    terms = taproot_case["contract_terms"]
    artifacts = taproot_case["artifacts"]
    if path == "claim":
        role = terms["claimant"]
        script = bytes.fromhex(artifacts["claim_script"])
        control_block = bytes.fromhex(artifacts["claim_control_block"])
        tapleaf_hash = bytes.fromhex(artifacts["claim_leaf_hash"])
        lock_time = 0
        fee_field = "max_claim_fee_sat"
    elif path == "refund":
        role = terms["refund_party"]
        script = bytes.fromhex(artifacts["refund_script"])
        control_block = bytes.fromhex(artifacts["refund_control_block"])
        tapleaf_hash = bytes.fromhex(artifacts["refund_leaf_hash"])
        lock_time = terms["refund_lock_height"]
        fee_field = "max_refund_fee_sat"
    else:
        raise ValueError("settlement path must be claim or refund")
    return role, script, control_block, tapleaf_hash, lock_time, fee_field


def destination_script(terms: dict[str, Any], path: str) -> bytes:
    if path == "claim":
        role = terms["claimant"]
    elif path == "refund":
        role = terms["refund_party"]
    else:
        raise ValueError("settlement path must be claim or refund")
    return bytes.fromhex(terms[f"{role}_destination_script"])


def build_spend(
    taproot_case: dict[str, Any],
    path: str,
    *,
    outpoint: OutPoint,
    spent_output: TxOutput,
    fee_sat: int,
    auxiliary_random: bytes,
    version: int = 2,
    sequence: int = INPUT_SEQUENCE,
    lock_time: int | None = None,
    inputs: tuple[TxInput, ...] | None = None,
    outputs: tuple[TxOutput, ...] | None = None,
    spent_outputs: tuple[TxOutput, ...] | None = None,
    hash_type: int = SIGHASH_DEFAULT,
    annex: bytes | None = None,
    preimage: bytes | None = None,
    script: bytes | None = None,
    control_block: bytes | None = None,
) -> Spend:
    role, expected_script, expected_control, tapleaf_hash, expected_lock, _ = (
        _path_parameters(taproot_case, path)
    )
    if lock_time is None:
        lock_time = expected_lock
    if inputs is None:
        inputs = (TxInput(outpoint, sequence),)
    if spent_outputs is None:
        spent_outputs = (spent_output,)
    if outputs is None:
        outputs = (
            TxOutput(
                spent_output.value_sat - fee_sat,
                destination_script(taproot_case["contract_terms"], path),
            ),
        )
    transaction = Transaction(
        version=version,
        inputs=inputs,
        outputs=outputs,
        lock_time=lock_time,
    )
    script = expected_script if script is None else script
    control_block = expected_control if control_block is None else control_block
    digest = taproot_signature_hash(
        transaction,
        spent_outputs,
        0,
        tapleaf_hash,
        hash_type=hash_type,
        annex=annex,
        codeseparator_position=CODESEPARATOR_POSITION,
    )
    signature = sign(
        digest,
        _role_secret(taproot_case, role),
        auxiliary_random,
    )
    if hash_type != SIGHASH_DEFAULT:
        signature += bytes([hash_type])
    if path == "claim":
        if preimage is None:
            preimage = bytes.fromhex(taproot_case["claim_preimage"])
        stack = (signature, preimage, script, control_block)
    else:
        stack = (signature, script, control_block)
    if annex is not None:
        stack += (annex,)
    witnesses = (stack,) + ((),) * (len(inputs) - 1)
    return Spend(
        transaction=transaction,
        spent_outputs=spent_outputs,
        witnesses=witnesses,
        hash_type=hash_type,
        annex=annex,
        tapleaf_hash=tapleaf_hash,
        auxiliary_random=auxiliary_random,
    )


def spend_artifact(spend: Spend) -> dict[str, Any]:
    transaction = spend.transaction
    witness = spend.witnesses[0]
    digest = taproot_signature_hash(
        transaction,
        spend.spent_outputs,
        0,
        spend.tapleaf_hash,
        hash_type=spend.hash_type,
        annex=spend.annex,
        codeseparator_position=CODESEPARATOR_POSITION,
    )
    raw = transaction.serialize_with_witness(spend.witnesses)
    weight = transaction_weight(transaction, spend.witnesses)
    return {
        "version": transaction.version,
        "input_sequence": transaction.inputs[0].sequence,
        "lock_time": transaction.lock_time,
        "output_value_sat": str(transaction.outputs[0].value_sat),
        "destination_script": transaction.outputs[0].script_pubkey.hex(),
        "sighash_type": spend.hash_type,
        "tapleaf_hash": spend.tapleaf_hash.hex(),
        "key_version": 0,
        "codeseparator_position": CODESEPARATOR_POSITION,
        "auxiliary_random": spend.auxiliary_random.hex(),
        "signature_hash": digest.hex(),
        "signature": witness[0].hex(),
        "witness": [item.hex() for item in witness],
        "base_transaction": transaction.serialize().hex(),
        "raw_transaction": raw.hex(),
        "txid": transaction_id(transaction),
        "wtxid": witness_transaction_id(transaction, spend.witnesses),
        "weight": weight,
        "vsize": (weight + 3) // 4,
    }


def _dust_threshold(script_pubkey: bytes) -> int:
    if len(script_pubkey) == 22 and script_pubkey[:2] == b"\x00\x14":
        return 294
    if len(script_pubkey) == 34 and script_pubkey[:2] == b"\x51\x20":
        return 330
    raise ValueError("RS-002 destination is not native P2WPKH or P2TR")


def spend_is_authorized(
    spend: Spend,
    taproot_case: dict[str, Any],
    path: str,
    *,
    expected_outpoint: OutPoint,
    expected_spent_output: TxOutput,
) -> bool:
    """Check a spend after terms, Taproot artifacts, and prevout were validated."""
    try:
        role, script, control_block, tapleaf_hash, lock_time, fee_field = (
            _path_parameters(taproot_case, path)
        )
        transaction = spend.transaction
        if (
            transaction.version != 2
            or len(transaction.inputs) != 1
            or transaction.inputs[0].prevout != expected_outpoint
            or transaction.inputs[0].sequence != INPUT_SEQUENCE
            or transaction.inputs[0].script_sig
            or len(transaction.outputs) != 1
            or transaction.lock_time != lock_time
            or spend.spent_outputs != (expected_spent_output,)
            or spend.hash_type != SIGHASH_DEFAULT
            or spend.annex is not None
            or spend.tapleaf_hash != tapleaf_hash
            or len(spend.witnesses) != 1
        ):
            return False
        output = transaction.outputs[0]
        expected_destination = destination_script(taproot_case["contract_terms"], path)
        fee = expected_spent_output.value_sat - output.value_sat
        if (
            output.script_pubkey != expected_destination
            or output.value_sat <= 0
            or output.value_sat < _dust_threshold(output.script_pubkey)
            or not 0 <= fee <= int(taproot_case["contract_terms"][fee_field])
        ):
            return False

        witness = spend.witnesses[0]
        if path == "claim":
            if len(witness) != 4:
                return False
            signature, preimage, witness_script, witness_control = witness
            payment_hash = bytes.fromhex(
                taproot_case["contract_terms"]["invoice_binding"]["payment_hash"],
            )
            if len(preimage) != 32 or hashlib.sha256(preimage).digest() != payment_hash:
                return False
        else:
            if len(witness) != 3:
                return False
            signature, witness_script, witness_control = witness
        if (
            len(signature) != 64
            or witness_script != script
            or witness_control != control_block
        ):
            return False
        digest = taproot_signature_hash(
            transaction,
            spend.spent_outputs,
            0,
            tapleaf_hash,
            hash_type=spend.hash_type,
            annex=spend.annex,
            codeseparator_position=CODESEPARATOR_POSITION,
        )
        public_key = bytes.fromhex(
            taproot_case["contract_terms"][f"{role}_contract_compressed_key"],
        )[1:]
        return verify(digest, public_key, signature)
    except (KeyError, TypeError, ValueError):
        return False
