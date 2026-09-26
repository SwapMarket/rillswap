"""Authorize one RS-002 funding transaction against an explicit wallet plan.

Plan prevouts are caller-approved declarations, not independently verified UTXOs.
This module checks transaction bytes, not signatures, finality, chain state, or
whether a replacement belongs to a durable funding-attempt lineage.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rill_core.domain.amounts import MAX_SATS
from rill_core.errors import ValidationError
from rill_core.networks import SUPPORTED_CONSENSUS_PROFILES, require_supported_network
from rill_core.settlement.taproot import TaprootKeyOperations, reconstruct_taproot_contract
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import FundingBinding

if TYPE_CHECKING:
    from rill_core.wire.messages import ContractTerms

MAX_RAW_BYTES = 100_000
MAX_INPUTS = 100
MAX_OUTPUTS = 100
MAX_SCRIPT_BYTES = 10_000
MAX_WITNESS_ITEMS = 100
MAX_WITNESS_ITEM_BYTES = MAX_RAW_BYTES
MAX_UINT32 = 0xFFFFFFFF
MAX_UINT16 = 0xFFFF
COMPACT_SIZE_UINT16_PREFIX = 253
FUNDING_VERSION = 2
HASH_LENGTH = 32
P2WPKH_SCRIPT_LENGTH = 22
P2WSH_SCRIPT_LENGTH = 34
P2TR_SCRIPT_LENGTH = 34


@dataclass(frozen=True, slots=True)
class FundingPrevout:
    """Wallet-approved prevout declaration, not evidence of an actual UTXO."""

    txid: bytes
    output_index: int
    value_sat: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.txid, bytes) or len(self.txid) != HASH_LENGTH:
            raise ValidationError("approved input txid must contain 32 bytes")
        _require_uint32(self.output_index, field="approved input index")
        _require_sats(self.value_sat, field="approved input value")
        if not isinstance(self.script_pubkey, bytes) or not _native_input(self.script_pubkey):
            raise ValidationError("funding input must be native P2WPKH, P2WSH, or P2TR")
        if self.txid == b"\x00" * 32 and self.output_index == MAX_UINT32:
            raise ValidationError("coinbase null outpoint cannot fund a contract")


@dataclass(frozen=True, slots=True)
class PlannedFundingOutput:
    """One exact wallet-approved change or destination output."""

    value_sat: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        _require_sats(self.value_sat, field="approved output value")
        if not isinstance(self.script_pubkey, bytes) or not _noncontract_output(
            self.script_pubkey,
        ):
            raise ValidationError("funding change/destination must be native P2WPKH or P2TR")


@dataclass(frozen=True, slots=True)
class FundingPlan:
    """Explicit approved input set, lineage anchor, and exact other outputs."""

    approved_inputs: tuple[FundingPrevout, ...]
    lineage_anchor: FundingPrevout
    approved_noncontract_outputs: tuple[PlannedFundingOutput, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.approved_inputs, tuple)
            or not 0 < len(self.approved_inputs) <= MAX_INPUTS
        ):
            raise ValidationError("funding plan needs a bounded nonempty input set")
        if any(not isinstance(item, FundingPrevout) for item in self.approved_inputs):
            raise ValidationError("approved inputs must be FundingPrevout instances")
        outpoints = {(item.txid, item.output_index) for item in self.approved_inputs}
        if len(outpoints) != len(self.approved_inputs):
            raise ValidationError("funding plan repeats an input outpoint")
        if not isinstance(self.lineage_anchor, FundingPrevout) or (
            self.lineage_anchor not in self.approved_inputs
        ):
            raise ValidationError("lineage anchor must be an exact approved input")
        if (
            not isinstance(self.approved_noncontract_outputs, tuple)
            or len(
                self.approved_noncontract_outputs,
            )
            >= MAX_OUTPUTS
        ):
            raise ValidationError("funding plan has too many noncontract outputs")
        if any(
            not isinstance(item, PlannedFundingOutput) for item in self.approved_noncontract_outputs
        ):
            raise ValidationError("other outputs must be PlannedFundingOutput instances")


@dataclass(frozen=True, slots=True)
class FundingPlanAuthorization:
    """Byte-level plan match only, not confirmed or spendable funding evidence."""

    raw_transaction: bytes
    txid: str
    contract_vout: int
    contract_value_sat: int
    contract_script_pubkey: bytes
    fee_sat: int
    outputs: tuple[PlannedFundingOutput, ...]
    input_sequences: tuple[int, ...]
    lock_time: int
    has_witness_serialization: bool


@dataclass(frozen=True, slots=True)
class FundingBindingTransactionMatch:
    """Static byte match, NOT a signed binding or live funding observation."""

    funding_txid: str
    contract_vout: int
    lineage_anchor_txid: str
    lineage_anchor_vout: int


@dataclass(frozen=True, slots=True)
class _ParsedInput:
    txid: bytes
    output_index: int
    script_sig: bytes
    sequence: int


@dataclass(frozen=True, slots=True)
class _ParsedTransaction:
    version: int
    inputs: tuple[_ParsedInput, ...]
    outputs: tuple[tuple[int, bytes], ...]
    lock_time: int
    has_witness_serialization: bool
    base_bytes: bytes


def authorize_funding_transaction(  # noqa: PLR0912
    raw_transaction: bytes,
    terms: ContractTerms,
    plan: FundingPlan,
    *,
    keys: TaprootKeyOperations,
) -> FundingPlanAuthorization:
    """Match a funding transaction to signed terms and an exact local plan.

    The plan's input values/scripts and the terms' signatures must be verified
    by the caller before using this result to permit an irreversible action.
    """
    if terms.network_identity.consensus_profile not in SUPPORTED_CONSENSUS_PROFILES:
        raise ValidationError("unsupported funding consensus profile")
    require_supported_network(terms.network_identity)
    if not isinstance(plan, FundingPlan):
        raise ValidationError("funding requires an explicit approved plan")
    contract = reconstruct_taproot_contract(terms, keys=keys)
    parsed = _parse(raw_transaction)
    if parsed.version != FUNDING_VERSION:
        raise ValidationError("funding transaction version must be two")
    if len(parsed.inputs) != len(plan.approved_inputs):
        raise ValidationError("funding input set differs from the approved plan")
    declared = {(item.txid, item.output_index): item for item in plan.approved_inputs}
    seen: set[tuple[bytes, int]] = set()
    for tx_input in parsed.inputs:
        outpoint = (tx_input.txid, tx_input.output_index)
        if outpoint in seen or outpoint not in declared:
            raise ValidationError("funding input is duplicate or unapproved")
        if tx_input.script_sig:
            raise ValidationError("funding native witness input scriptSig must be empty")
        seen.add(outpoint)
    if (
        set(declared) != seen
        or (
            plan.lineage_anchor.txid,
            plan.lineage_anchor.output_index,
        )
        not in seen
    ):
        raise ValidationError("funding input set omits an approved input or anchor")

    contract_outputs = [
        (index, output)
        for index, output in enumerate(parsed.outputs)
        if output[1] == contract.script_pubkey
    ]
    if len(contract_outputs) != 1:
        raise ValidationError("funding requires exactly one contract-script output")
    contract_vout, contract_output = contract_outputs[0]
    amount = int(terms.economics.contract_amount_sat)
    if contract_output[0] != amount:
        raise ValidationError("funding contract output value must be exact")
    others = tuple(output for index, output in enumerate(parsed.outputs) if index != contract_vout)
    if any(not _noncontract_output(script) for _, script in others):
        raise ValidationError("funding has an unsupported change/destination output")
    approved_others = tuple(
        (output.value_sat, output.script_pubkey) for output in plan.approved_noncontract_outputs
    )
    if Counter(others) != Counter(approved_others):
        raise ValidationError("funding contains an unapproved or missing output")

    input_total = sum(prevout.value_sat for prevout in plan.approved_inputs)
    output_total = sum(value for value, _ in parsed.outputs)
    if input_total > MAX_SATS or output_total > MAX_SATS:
        raise ValidationError("funding aggregate value exceeds Bitcoin money range")
    fee = input_total - output_total
    if fee < 0 or fee > int(terms.max_funding_fee_sat):
        raise ValidationError("funding fee is negative or exceeds the signed cap")
    return FundingPlanAuthorization(
        raw_transaction=raw_transaction,
        txid=_hash256(parsed.base_bytes)[::-1].hex(),
        contract_vout=contract_vout,
        contract_value_sat=amount,
        contract_script_pubkey=contract.script_pubkey,
        fee_sat=fee,
        outputs=tuple(PlannedFundingOutput(value, script) for value, script in parsed.outputs),
        input_sequences=tuple(tx_input.sequence for tx_input in parsed.inputs),
        lock_time=parsed.lock_time,
        has_witness_serialization=parsed.has_witness_serialization,
    )


def check_funding_binding_transaction(
    raw_transaction: bytes,
    binding: FundingBinding,
    terms: ContractTerms,
    *,
    keys: TaprootKeyOperations,
) -> FundingBindingTransactionMatch:
    """Check a binding's exact transaction bytes without trusting its signature.

    The host MUST separately authenticate the terms and funder session signature,
    select the attempt ID, validate input prevouts and wallet approval, enforce
    revision lineage, and obtain a current chain/mempool view. This result is
    never evidence of a spendable UTXO or permission to fund, pay or settle.
    """
    if not isinstance(binding, FundingBinding):
        raise ValidationError("funding byte check requires a parsed binding")
    if terms.network_identity.consensus_profile not in SUPPORTED_CONSENSUS_PROFILES:
        raise ValidationError("unsupported funding consensus profile")
    require_supported_network(terms.network_identity)
    contract = reconstruct_taproot_contract(terms, keys=keys)
    if (
        binding.contract_hash != contract_hash(terms).hex()
        or binding.funder_role != ("client" if terms.profile_id == "btc-to-ln/v1" else "provider")
        or binding.contract_value_sat != terms.economics.contract_amount_sat
        or binding.contract_script_pubkey != contract.script_pubkey.hex()
    ):
        raise ValidationError("funding binding differs from the expected contract")
    _require_uint32(binding.contract_vout, field="bound contract output index")
    _require_uint32(binding.lineage_anchor_vout, field="bound anchor output index")
    parsed = _parse(raw_transaction)
    if parsed.version != FUNDING_VERSION:
        raise ValidationError("funding transaction version must be two")
    txid = _hash256(parsed.base_bytes)[::-1].hex()
    if binding.funding_txid != txid:
        raise ValidationError("funding binding transaction ID differs from the bytes")
    anchor = (bytes.fromhex(binding.lineage_anchor_txid), binding.lineage_anchor_vout)
    outpoints = {(item.txid, item.output_index) for item in parsed.inputs}
    if len(outpoints) != len(parsed.inputs) or anchor not in outpoints:
        raise ValidationError("funding inputs repeat or omit the binding anchor")
    if any(item.script_sig for item in parsed.inputs):
        raise ValidationError("funding native witness input scriptSig must be empty")
    contract_outputs = [
        (index, value)
        for index, (value, script) in enumerate(parsed.outputs)
        if script == contract.script_pubkey
    ]
    if contract_outputs != [(binding.contract_vout, int(binding.contract_value_sat))]:
        raise ValidationError("funding contract output differs from the binding")
    if any(
        not _noncontract_output(script)
        for index, (_, script) in enumerate(parsed.outputs)
        if index != binding.contract_vout
    ):
        raise ValidationError("funding has an unsupported change/destination output")
    if sum(value for value, _ in parsed.outputs) > MAX_SATS:
        raise ValidationError("funding aggregate value exceeds Bitcoin money range")
    return FundingBindingTransactionMatch(
        txid, binding.contract_vout, binding.lineage_anchor_txid, binding.lineage_anchor_vout
    )


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0

    def read(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.raw):
            raise ValidationError("funding transaction is truncated")
        value = self.raw[self.offset : self.offset + size]
        self.offset += size
        return value

    def compact_size(self) -> int:
        prefix = self.read(1)[0]
        if prefix < COMPACT_SIZE_UINT16_PREFIX:
            return prefix
        width = {253: 2, 254: 4, 255: 8}[prefix]
        value = int.from_bytes(self.read(width), "little")
        if value < {2: 253, 4: 0x10000, 8: 0x100000000}[width]:
            raise ValidationError("funding transaction has noncanonical CompactSize")
        return value

    def string(self, *, limit: int) -> bytes:
        size = self.compact_size()
        if size > limit:
            raise ValidationError("funding transaction item exceeds local size limit")
        return self.read(size)


def _parse(raw: bytes) -> _ParsedTransaction:  # noqa: PLR0912
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_RAW_BYTES:
        raise ValidationError("funding transaction must be bounded nonempty bytes")
    reader = _Reader(raw)
    version = int.from_bytes(reader.read(4), "little", signed=True)
    input_count = reader.compact_size()
    has_witness = input_count == 0
    if has_witness:
        if reader.read(1) != b"\x01":
            raise ValidationError("funding witness marker requires flag one")
        input_count = reader.compact_size()
    if not 0 < input_count <= MAX_INPUTS:
        raise ValidationError("funding input count is outside the local limit")
    inputs: list[_ParsedInput] = []
    for _ in range(input_count):
        txid = reader.read(32)[::-1]
        index = int.from_bytes(reader.read(4), "little")
        script_sig = reader.string(limit=MAX_SCRIPT_BYTES)
        sequence = int.from_bytes(reader.read(4), "little")
        if txid == b"\x00" * 32 and index == MAX_UINT32:
            raise ValidationError("funding cannot contain a coinbase null outpoint")
        inputs.append(_ParsedInput(txid, index, script_sig, sequence))
    output_count = reader.compact_size()
    if not 0 < output_count <= MAX_OUTPUTS:
        raise ValidationError("funding output count is outside the local limit")
    outputs: list[tuple[int, bytes]] = []
    for _ in range(output_count):
        value_sat = int.from_bytes(reader.read(8), "little")
        _require_sats(value_sat, field="funding output value")
        script_pubkey = reader.string(limit=MAX_SCRIPT_BYTES)
        outputs.append((value_sat, script_pubkey))
    output_end = reader.offset
    if has_witness:
        has_items = False
        for _ in range(input_count):
            item_count = reader.compact_size()
            if item_count > MAX_WITNESS_ITEMS:
                raise ValidationError("funding witness stack exceeds local item limit")
            has_items |= item_count > 0
            for _ in range(item_count):
                reader.string(limit=MAX_WITNESS_ITEM_BYTES)
        if not has_items:
            raise ValidationError("funding witness marker is superfluous")
    lock_time = int.from_bytes(reader.read(4), "little")
    if reader.offset != len(raw):
        raise ValidationError("funding transaction has trailing bytes")
    base_bytes = raw[:4] + raw[6:output_end] + raw[-4:] if has_witness else raw
    return _ParsedTransaction(
        version=version,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        lock_time=lock_time,
        has_witness_serialization=has_witness,
        base_bytes=base_bytes,
    )


def _native_input(script: bytes) -> bool:
    return _noncontract_output(script) or (
        len(script) == P2WSH_SCRIPT_LENGTH and script[:2] == b"\x00\x20"
    )


def _noncontract_output(script: bytes) -> bool:
    return (len(script) == P2WPKH_SCRIPT_LENGTH and script[:2] == b"\x00\x14") or (
        len(script) == P2TR_SCRIPT_LENGTH and script[:2] == b"\x51\x20"
    )


def _require_uint32(value: int, *, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_UINT32:
        raise ValidationError(f"{field} must be a uint32")


def _require_sats(value: int, *, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SATS:
        raise ValidationError(f"{field} is outside the Bitcoin money range")


def _hash256(value: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()
