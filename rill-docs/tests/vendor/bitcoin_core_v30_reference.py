"""Test-only Bitcoin Core v30.0 transaction and BIP341 reference subset.

Derived from bitcoin/bitcoin v30.0 functional test framework modules
test_framework/{messages,script,key}.py under the MIT license. See
THIRD_PARTY_NOTICES.md. This is not a production transaction implementation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + data)


def compact_size(value: int) -> bytes:
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


def serialize_string(value: bytes) -> bytes:
    return compact_size(len(value)) + value


@dataclass(frozen=True)
class OutPoint:
    """Transaction outpoint with txid bytes in display order."""

    txid: bytes
    index: int

    def serialize(self) -> bytes:
        if len(self.txid) != 32:
            raise ValueError("txid must contain 32 bytes")
        return self.txid[::-1] + self.index.to_bytes(4, "little")


@dataclass(frozen=True)
class TxInput:
    prevout: OutPoint
    sequence: int
    script_sig: bytes = b""

    def serialize(self) -> bytes:
        return (
            self.prevout.serialize()
            + serialize_string(self.script_sig)
            + self.sequence.to_bytes(4, "little")
        )


@dataclass(frozen=True)
class TxOutput:
    value_sat: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        if not 0 <= self.value_sat <= 21_000_000 * 100_000_000:
            raise ValueError("transaction output value is outside the money range")
        return self.value_sat.to_bytes(8, "little") + serialize_string(
            self.script_pubkey,
        )


@dataclass(frozen=True)
class Transaction:
    version: int
    inputs: tuple[TxInput, ...]
    outputs: tuple[TxOutput, ...]
    lock_time: int

    def serialize(self) -> bytes:
        return (
            self.version.to_bytes(4, "little", signed=True)
            + compact_size(len(self.inputs))
            + b"".join(tx_input.serialize() for tx_input in self.inputs)
            + compact_size(len(self.outputs))
            + b"".join(tx_output.serialize() for tx_output in self.outputs)
            + self.lock_time.to_bytes(4, "little")
        )

    def serialize_with_witness(self, witnesses: tuple[tuple[bytes, ...], ...]) -> bytes:
        if len(witnesses) != len(self.inputs):
            raise ValueError("one witness stack is required for every input")
        if not any(witnesses):
            return self.serialize()
        return (
            self.version.to_bytes(4, "little", signed=True)
            + b"\x00\x01"
            + compact_size(len(self.inputs))
            + b"".join(tx_input.serialize() for tx_input in self.inputs)
            + compact_size(len(self.outputs))
            + b"".join(tx_output.serialize() for tx_output in self.outputs)
            + b"".join(
                compact_size(len(stack))
                + b"".join(serialize_string(item) for item in stack)
                for stack in witnesses
            )
            + self.lock_time.to_bytes(4, "little")
        )


def transaction_id(transaction: Transaction) -> str:
    return hash256(transaction.serialize())[::-1].hex()


def witness_transaction_id(
    transaction: Transaction,
    witnesses: tuple[tuple[bytes, ...], ...],
) -> str:
    return hash256(transaction.serialize_with_witness(witnesses))[::-1].hex()


def transaction_weight(
    transaction: Transaction,
    witnesses: tuple[tuple[bytes, ...], ...],
) -> int:
    base_size = len(transaction.serialize())
    total_size = len(transaction.serialize_with_witness(witnesses))
    return 3 * base_size + total_size


def taproot_signature_hash(
    transaction: Transaction,
    spent_outputs: tuple[TxOutput, ...],
    input_index: int,
    tapleaf_hash: bytes,
    *,
    hash_type: int = SIGHASH_DEFAULT,
    annex: bytes | None = None,
    codeseparator_position: int = 0xFFFFFFFF,
) -> bytes:
    """Return the BIP341/BIP342 script-path signature hash."""
    valid_hash_types = {
        SIGHASH_DEFAULT,
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
    }
    if hash_type not in valid_hash_types:
        raise ValueError("undefined Taproot signature hash type")
    if len(spent_outputs) != len(transaction.inputs):
        raise ValueError("spent output data must cover every transaction input")
    if not 0 <= input_index < len(transaction.inputs):
        raise ValueError("input index is out of range")
    if len(tapleaf_hash) != 32:
        raise ValueError("TapLeaf hash must contain 32 bytes")
    if annex is not None and (not annex or annex[0] != 0x50):
        raise ValueError("Taproot annex must begin with 0x50")

    output_type = hash_type & 0x03
    anyone_can_pay = bool(hash_type & SIGHASH_ANYONECANPAY)
    if output_type == SIGHASH_SINGLE and input_index >= len(transaction.outputs):
        raise ValueError("SIGHASH_SINGLE requires a corresponding output")

    message = (
        bytes([hash_type])
        + transaction.version.to_bytes(4, "little", signed=True)
        + transaction.lock_time.to_bytes(4, "little")
    )
    if not anyone_can_pay:
        message += sha256(
            b"".join(tx_input.prevout.serialize() for tx_input in transaction.inputs),
        )
        message += sha256(
            b"".join(
                spent_output.value_sat.to_bytes(8, "little")
                for spent_output in spent_outputs
            ),
        )
        message += sha256(
            b"".join(
                serialize_string(spent_output.script_pubkey)
                for spent_output in spent_outputs
            ),
        )
        message += sha256(
            b"".join(
                tx_input.sequence.to_bytes(4, "little")
                for tx_input in transaction.inputs
            ),
        )
    if output_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        message += sha256(
            b"".join(tx_output.serialize() for tx_output in transaction.outputs),
        )

    message += bytes([2 + int(annex is not None)])
    if anyone_can_pay:
        tx_input = transaction.inputs[input_index]
        spent_output = spent_outputs[input_index]
        message += tx_input.prevout.serialize()
        message += spent_output.value_sat.to_bytes(8, "little")
        message += serialize_string(spent_output.script_pubkey)
        message += tx_input.sequence.to_bytes(4, "little")
    else:
        message += input_index.to_bytes(4, "little")
    if annex is not None:
        message += sha256(serialize_string(annex))
    if output_type == SIGHASH_SINGLE:
        message += sha256(transaction.outputs[input_index].serialize())

    message += tapleaf_hash + b"\x00" + codeseparator_position.to_bytes(4, "little")
    return tagged_hash("TapSighash", b"\x00" + message)
