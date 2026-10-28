"""RS-002 unilateral transaction construction and authorization."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

from rill_core.domain.amounts import MAX_SATS
from rill_core.errors import ValidationError
from rill_core.networks import SUPPORTED_CONSENSUS_PROFILES, require_supported_network
from rill_core.settlement.taproot import (
    CLAIM_SCRIPT_LENGTH,
    TaprootKeyOperations,
    reconstruct_taproot_contract,
)
from rill_core.wire.hashes import tagged_hash

if TYPE_CHECKING:
    from rill_core.wire.messages import ContractTerms

type UnilateralPath = Literal["claim", "refund"]

TRANSACTION_VERSION = 2
INPUT_SEQUENCE = 0xFFFFFFFD
SIGHASH_DEFAULT = 0
CODESEPARATOR_POSITION = 0xFFFFFFFF
MAX_UINT32 = 0xFFFFFFFF
MAX_UINT64 = 0xFFFFFFFFFFFFFFFF
MAX_TRANSACTION_BYTES = 100_000
MAX_TRANSACTION_INPUTS = 16
MAX_TRANSACTION_OUTPUTS = 16
MAX_SCRIPT_BYTES = 10_000
MAX_WITNESS_ITEMS = 100
MAX_WITNESS_ITEM_BYTES = 10_000
P2WPKH_DUST_SAT = 294
P2TR_DUST_SAT = 330
# Bitcoin Core v30 default dust relay policy uses 3,000 sat/kvB and a 67-byte
# witness-input spend estimate: (31 + 67) * 3 and (43 + 67) * 3 respectively.
HASH_LENGTH = 32
SIGNATURE_LENGTH = 64
CONTROL_BLOCK_LENGTH = 65
CLAIM_WITNESS_ITEMS = 4
REFUND_WITNESS_ITEMS = 3
P2WPKH_SCRIPT_LENGTH = 22
P2TR_SCRIPT_LENGTH = 34
COMPACT_SIZE_UINT16_PREFIX = 253
MAX_UINT16 = 0xFFFF


class SchnorrVerifier(Protocol):
    """Narrow BIP340 verification boundary implemented by a crypto adapter."""

    def schnorr_verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> None:
        """Verify a signature or raise an exception."""
        ...


@dataclass(frozen=True, slots=True)
class FundingOutput:
    """Trusted live contract outpoint data required by BIP341 signing."""

    txid: bytes
    output_index: int
    value_sat: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.txid, bytes) or len(self.txid) != HASH_LENGTH:
            raise ValidationError("funding txid must contain exactly 32 bytes")
        _require_uint32(self.output_index, field="funding output index")
        _require_satoshis(self.value_sat, field="funding value", positive=True)
        if not isinstance(self.script_pubkey, bytes) or not self.script_pubkey:
            raise ValidationError("funding scriptPubKey must be nonempty bytes")
        if len(self.script_pubkey) > MAX_SCRIPT_BYTES:
            raise ValidationError("funding scriptPubKey exceeds the size limit")


@dataclass(frozen=True, slots=True, init=False)
class UnilateralAuthorization:
    """Internally reconstructed RS-002 authority for one unilateral path."""

    path: UnilateralPath
    funding: FundingOutput
    destination_script: bytes
    fee_cap_sat: int
    lock_time: int
    tapleaf_hash: bytes
    witness_script: bytes
    control_block: bytes
    signer_public_key: bytes
    payment_hash: bytes | None
    consensus_profile: str

    def __init__(self) -> None:
        """Forbid direct construction without reconstructing the contract."""
        raise TypeError("use UnilateralAuthorization.from_terms")

    @classmethod
    def from_terms(
        cls,
        terms: ContractTerms,
        funding: FundingOutput,
        path: UnilateralPath,
        *,
        keys: TaprootKeyOperations,
    ) -> UnilateralAuthorization:
        """Reconstruct and bind authenticated terms to trusted live prevout data."""
        _require_supported_profile(terms.network_identity.consensus_profile)
        require_supported_network(terms.network_identity)
        if path not in ("claim", "refund"):
            raise ValidationError("unilateral path must be claim or refund")
        contract = reconstruct_taproot_contract(terms, keys=keys)
        contract_amount = int(terms.economics.contract_amount_sat)
        if funding.value_sat != contract_amount:
            raise ValidationError("funding value does not match the signed contract amount")
        if funding.script_pubkey != contract.script_pubkey:
            raise ValidationError("funding scriptPubKey does not match the Taproot contract")

        if path == "claim":
            role = terms.claimant
            destination = _role_destination(terms, role)
            fee_cap = int(terms.max_claim_fee_sat)
            lock_time = 0
            tapleaf_hash = contract.claim_leaf_hash
            witness_script = contract.claim_script
            control_block = contract.claim_control_block
            payment_hash: bytes | None = bytes.fromhex(terms.invoice_binding.payment_hash)
        else:
            role = terms.refund_party
            destination = _role_destination(terms, role)
            fee_cap = int(terms.max_refund_fee_sat)
            lock_time = terms.refund_lock_height
            tapleaf_hash = contract.refund_leaf_hash
            witness_script = contract.refund_script
            control_block = contract.refund_control_block
            payment_hash = None
        signer_key = bytes.fromhex(
            terms.client_contract_compressed_key
            if role == "client"
            else terms.provider_contract_compressed_key,
        )[1:]
        _dust_threshold(destination)
        _require_artifacts(
            tapleaf_hash=tapleaf_hash,
            witness_script=witness_script,
            control_block=control_block,
            signer_public_key=signer_key,
        )
        return cls._create(
            {
                "path": path,
                "funding": funding,
                "destination_script": destination,
                "fee_cap_sat": fee_cap,
                "lock_time": lock_time,
                "tapleaf_hash": tapleaf_hash,
                "witness_script": witness_script,
                "control_block": control_block,
                "signer_public_key": signer_key,
                "payment_hash": payment_hash,
                "consensus_profile": terms.network_identity.consensus_profile,
            },
        )

    @classmethod
    def _create(cls, values: dict[str, object]) -> UnilateralAuthorization:
        authorization = object.__new__(cls)
        for field_name, value in values.items():
            object.__setattr__(authorization, field_name, value)
        return authorization


@dataclass(frozen=True, slots=True)
class UnilateralSpendPlan:
    """Authorized bytes and digest ready for an external one-shot signer."""

    authorization: UnilateralAuthorization
    fee_sat: int
    claim_preimage: bytes | None
    base_transaction: bytes
    signature_hash: bytes
    output_value_sat: int


@dataclass(frozen=True, slots=True)
class ValidatedUnilateralSpend:
    """A parsed, authorized, and signature-verified unilateral transaction."""

    raw_transaction: bytes
    signature_hash: bytes
    fee_sat: int
    txid: str
    wtxid: str
    weight: int
    vsize: int


@dataclass(frozen=True, slots=True)
class CooperativeClaimPlan:
    """Frozen one-input claim transaction and BIP341 key-path signing digest."""

    authorization: UnilateralAuthorization
    fee_sat: int
    base_transaction: bytes
    signature_hash: bytes
    output_value_sat: int


@dataclass(frozen=True, slots=True)
class ValidatedCooperativeClaim:
    """Exact tweaked-key claim with a single BIP340 witness signature."""

    raw_transaction: bytes
    signature_hash: bytes
    fee_sat: int
    txid: str
    wtxid: str
    weight: int
    vsize: int


@dataclass(frozen=True, slots=True)
class _Outpoint:
    txid: bytes
    output_index: int

    def serialize(self) -> bytes:
        return self.txid[::-1] + self.output_index.to_bytes(4, "little")


@dataclass(frozen=True, slots=True)
class _TxInput:
    prevout: _Outpoint
    script_sig: bytes
    sequence: int

    def serialize(self) -> bytes:
        return (
            self.prevout.serialize()
            + _serialize_string(self.script_sig)
            + self.sequence.to_bytes(4, "little")
        )


@dataclass(frozen=True, slots=True)
class _TxOutput:
    value_sat: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return self.value_sat.to_bytes(8, "little") + _serialize_string(
            self.script_pubkey,
        )


@dataclass(frozen=True, slots=True)
class _Transaction:
    version: int
    inputs: tuple[_TxInput, ...]
    outputs: tuple[_TxOutput, ...]
    witnesses: tuple[tuple[bytes, ...], ...]
    lock_time: int

    def serialize_base(self) -> bytes:
        return (
            self.version.to_bytes(4, "little", signed=True)
            + _compact_size(len(self.inputs))
            + b"".join(tx_input.serialize() for tx_input in self.inputs)
            + _compact_size(len(self.outputs))
            + b"".join(tx_output.serialize() for tx_output in self.outputs)
            + self.lock_time.to_bytes(4, "little")
        )

    def serialize(self) -> bytes:
        if not any(self.witnesses):
            return self.serialize_base()
        return (
            self.version.to_bytes(4, "little", signed=True)
            + b"\x00\x01"
            + _compact_size(len(self.inputs))
            + b"".join(tx_input.serialize() for tx_input in self.inputs)
            + _compact_size(len(self.outputs))
            + b"".join(tx_output.serialize() for tx_output in self.outputs)
            + b"".join(
                _compact_size(len(stack)) + b"".join(_serialize_string(item) for item in stack)
                for stack in self.witnesses
            )
            + self.lock_time.to_bytes(4, "little")
        )


def build_unilateral_spend(
    authorization: UnilateralAuthorization,
    *,
    fee_sat: int,
    claim_preimage: bytes | None = None,
) -> UnilateralSpendPlan:
    """Build an authorized one-input, one-output transaction and signing digest."""
    _require_fee_and_output(authorization, fee_sat)
    if authorization.path == "claim":
        _require_claim_preimage(claim_preimage, authorization.payment_hash)
    elif claim_preimage is not None:
        raise ValidationError("refund construction does not accept a claim preimage")

    output_value = authorization.funding.value_sat - fee_sat
    transaction = _build_transaction(authorization, fee_sat, witness=())
    digest = _taproot_script_path_sighash(transaction, authorization)
    return UnilateralSpendPlan(
        authorization=authorization,
        fee_sat=fee_sat,
        claim_preimage=claim_preimage,
        base_transaction=transaction.serialize_base(),
        signature_hash=digest,
        output_value_sat=output_value,
    )


def finalize_unilateral_spend(
    plan: UnilateralSpendPlan,
    signature: bytes,
    *,
    verifier: SchnorrVerifier,
) -> ValidatedUnilateralSpend:
    """Verify a BIP340 signature, attach the exact witness, and reauthorize bytes."""
    _require_signature(signature)
    _require_supported_profile(plan.authorization.consensus_profile)
    witness: tuple[bytes, ...]
    if plan.authorization.path == "claim":
        if plan.claim_preimage is None:
            raise ValidationError("claim plan is missing its preimage")
        witness = (
            signature,
            plan.claim_preimage,
            plan.authorization.witness_script,
            plan.authorization.control_block,
        )
    else:
        witness = (
            signature,
            plan.authorization.witness_script,
            plan.authorization.control_block,
        )
    transaction = _build_transaction(
        plan.authorization,
        plan.fee_sat,
        witness=witness,
    )
    digest = _taproot_script_path_sighash(transaction, plan.authorization)
    if (
        plan.base_transaction != transaction.serialize_base()
        or plan.signature_hash != digest
        or plan.output_value_sat != transaction.outputs[0].value_sat
    ):
        raise ValidationError("unilateral spend plan is internally inconsistent")
    _verify_signature(
        verifier,
        plan.authorization.signer_public_key,
        digest,
        signature,
    )
    return validate_unilateral_spend(
        transaction.serialize(),
        plan.authorization,
        verifier=verifier,
    )


def validate_unilateral_spend(  # noqa: PLR0912
    raw_transaction: bytes,
    authorization: UnilateralAuthorization,
    *,
    verifier: SchnorrVerifier,
) -> ValidatedUnilateralSpend:
    """Strictly parse and authorize untrusted unilateral transaction bytes."""
    transaction = _parse_transaction(raw_transaction)
    funding = authorization.funding
    if transaction.version != TRANSACTION_VERSION:
        raise ValidationError("unilateral transaction version must be two")
    if len(transaction.inputs) != 1:
        raise ValidationError("unilateral transaction must contain exactly one input")
    tx_input = transaction.inputs[0]
    if tx_input.prevout != _Outpoint(funding.txid, funding.output_index):
        raise ValidationError("unilateral transaction spends the wrong outpoint")
    if tx_input.script_sig:
        raise ValidationError("unilateral contract input scriptSig must be empty")
    if tx_input.sequence != INPUT_SEQUENCE:
        raise ValidationError("unilateral contract input sequence is incorrect")
    if len(transaction.outputs) != 1:
        raise ValidationError("unilateral transaction must contain exactly one output")
    tx_output = transaction.outputs[0]
    if tx_output.script_pubkey != authorization.destination_script:
        raise ValidationError("unilateral output uses the wrong role destination")
    if transaction.lock_time != authorization.lock_time:
        raise ValidationError("unilateral transaction locktime is incorrect")
    fee = funding.value_sat - tx_output.value_sat
    _require_fee_and_output(authorization, fee)
    if len(transaction.witnesses) != 1:
        raise ValidationError("unilateral transaction must contain one witness")
    witness = transaction.witnesses[0]
    if authorization.path == "claim":
        if len(witness) != CLAIM_WITNESS_ITEMS:
            raise ValidationError("claim witness must contain exactly four items")
        signature, preimage, witness_script, control_block = witness
        _require_claim_preimage(preimage, authorization.payment_hash)
    else:
        if len(witness) != REFUND_WITNESS_ITEMS:
            raise ValidationError("refund witness must contain exactly three items")
        signature, witness_script, control_block = witness
    _require_signature(signature)
    if witness_script != authorization.witness_script:
        raise ValidationError("unilateral witness script does not match the contract")
    if control_block != authorization.control_block:
        raise ValidationError("unilateral control block does not match the contract")
    digest = _taproot_script_path_sighash(transaction, authorization)
    _verify_signature(verifier, authorization.signer_public_key, digest, signature)

    base = transaction.serialize_base()
    raw = transaction.serialize()
    weight = 3 * len(base) + len(raw)
    return ValidatedUnilateralSpend(
        raw_transaction=raw,
        signature_hash=digest,
        fee_sat=fee,
        txid=_hash256(base)[::-1].hex(),
        wtxid=_hash256(raw)[::-1].hex(),
        weight=weight,
        vsize=(weight + 3) // 4,
    )


def build_cooperative_claim(
    authorization: UnilateralAuthorization, *, fee_sat: int
) -> CooperativeClaimPlan:
    """Freeze the same authorized claim output for a tweaked key-path attempt.

    The caller must independently establish directional LN/preimage authority
    and durably burn a unique cooperation ID before allocating a nonce handle.
    This function neither signs nor grants permission to disclose a preimage.
    """
    if authorization.path != "claim" or authorization.lock_time != 0:
        raise ValidationError("cooperative key path is only for a claim")
    _require_fee_and_output(authorization, fee_sat)
    transaction = _build_transaction(authorization, fee_sat, witness=())
    return CooperativeClaimPlan(
        authorization=authorization,
        fee_sat=fee_sat,
        base_transaction=transaction.serialize_base(),
        signature_hash=_taproot_key_path_sighash(transaction, authorization),
        output_value_sat=authorization.funding.value_sat - fee_sat,
    )


def verify_cooperative_claim_proposal(
    raw_transaction: bytes, authorization: UnilateralAuthorization
) -> CooperativeClaimPlan:
    """Reconstruct an exact one-input key-path claim before any client signing.

    This checks transaction and fee policy only. The caller must separately
    authenticate the proposal, establish payment and selected funding evidence,
    and enforce a one-shot nonce/partial-signature boundary.
    """
    if not isinstance(raw_transaction, bytes) or not raw_transaction:
        raise ValidationError("cooperative proposal must be nonempty bytes")
    if len(raw_transaction) > MAX_TRANSACTION_BYTES:
        raise ValidationError("cooperative proposal exceeds the size limit")
    reader = _Reader(raw_transaction)
    reader.read(4)  # version: the reconstructed plan fixes the only supported value
    if reader.compact_size() != 1:
        raise ValidationError("cooperative proposal requires one input")
    reader.read(32 + 4)  # prevout: checked by exact reconstruction below
    reader.string(maximum=MAX_SCRIPT_BYTES, field="input scriptSig")
    reader.read(4)  # sequence
    if reader.compact_size() != 1:
        raise ValidationError("cooperative proposal requires one output")
    output_value_sat = int.from_bytes(reader.read(8), "little")
    _require_satoshis(output_value_sat, field="transaction output value")
    reader.string(maximum=MAX_SCRIPT_BYTES, field="output scriptPubKey")
    reader.read(4)  # locktime
    if reader.offset != len(raw_transaction):
        raise ValidationError("cooperative proposal contains trailing bytes")
    plan = build_cooperative_claim(
        authorization, fee_sat=authorization.funding.value_sat - output_value_sat
    )
    if raw_transaction != plan.base_transaction:
        raise ValidationError("cooperative proposal differs from authorized claim")
    return plan


def finalize_cooperative_claim(
    plan: CooperativeClaimPlan, signature: bytes, *, verifier: SchnorrVerifier
) -> ValidatedCooperativeClaim:
    """Attach only a 64-byte SIGHASH_DEFAULT signature to the frozen plan."""
    _require_signature(signature)
    if plan.authorization.path != "claim" or plan.authorization.lock_time != 0:
        raise ValidationError("cooperative key path is only for a claim")
    _require_fee_and_output(plan.authorization, plan.fee_sat)
    transaction = _build_transaction(plan.authorization, plan.fee_sat, witness=(signature,))
    if (
        plan.base_transaction != transaction.serialize_base()
        or plan.signature_hash != _taproot_key_path_sighash(transaction, plan.authorization)
        or plan.output_value_sat != transaction.outputs[0].value_sat
    ):
        raise ValidationError("cooperative claim plan is internally inconsistent")
    return validate_cooperative_claim(
        transaction.serialize(), plan.authorization, verifier=verifier
    )


def validate_cooperative_claim(
    raw_transaction: bytes,
    authorization: UnilateralAuthorization,
    *,
    verifier: SchnorrVerifier,
) -> ValidatedCooperativeClaim:
    """Authorize every untrusted transaction byte before a key-path claim is used."""
    if authorization.path != "claim" or authorization.lock_time != 0:
        raise ValidationError("cooperative key path is only for a claim")
    transaction = _parse_transaction(raw_transaction)
    if transaction.version != TRANSACTION_VERSION or transaction.lock_time != 0:
        raise ValidationError("cooperative claim requires version two and locktime zero")
    if len(transaction.inputs) != 1 or len(transaction.outputs) != 1:
        raise ValidationError("cooperative claim requires one input and one output")
    tx_input = transaction.inputs[0]
    if tx_input.prevout != _Outpoint(
        authorization.funding.txid, authorization.funding.output_index
    ):
        raise ValidationError("cooperative claim spends the wrong outpoint")
    if tx_input.script_sig or tx_input.sequence != INPUT_SEQUENCE:
        raise ValidationError("cooperative claim scriptSig or sequence is incorrect")
    tx_output = transaction.outputs[0]
    if tx_output.script_pubkey != authorization.destination_script:
        raise ValidationError("cooperative claim uses the wrong role destination")
    fee_sat = authorization.funding.value_sat - tx_output.value_sat
    _require_fee_and_output(authorization, fee_sat)
    if len(transaction.witnesses) != 1 or len(transaction.witnesses[0]) != 1:
        raise ValidationError("cooperative claim requires one signature and no annex")
    signature = transaction.witnesses[0][0]
    _require_signature(signature)
    digest = _taproot_key_path_sighash(transaction, authorization)
    try:
        verifier.schnorr_verify(authorization.funding.script_pubkey[2:], digest, signature)
    except Exception as error:
        raise ValidationError("cooperative claim BIP340 signature is invalid") from error
    base = transaction.serialize_base()
    raw = transaction.serialize()
    weight = 3 * len(base) + len(raw)
    return ValidatedCooperativeClaim(
        raw_transaction=raw,
        signature_hash=digest,
        fee_sat=fee_sat,
        txid=_hash256(base)[::-1].hex(),
        wtxid=_hash256(raw)[::-1].hex(),
        weight=weight,
        vsize=(weight + 3) // 4,
    )


def _role_destination(terms: ContractTerms, role: str) -> bytes:
    value = (
        terms.client_destination_script if role == "client" else terms.provider_destination_script
    )
    return bytes.fromhex(value)


def _require_artifacts(
    *,
    tapleaf_hash: bytes,
    witness_script: bytes,
    control_block: bytes,
    signer_public_key: bytes,
) -> None:
    if len(tapleaf_hash) != HASH_LENGTH:
        raise ValidationError("TapLeaf hash must contain exactly 32 bytes")
    if not witness_script or len(witness_script) > MAX_SCRIPT_BYTES:
        raise ValidationError("witness script has an invalid size")
    if len(control_block) != CONTROL_BLOCK_LENGTH:
        raise ValidationError("RS-002 control block must contain exactly 65 bytes")
    if len(signer_public_key) != HASH_LENGTH:
        raise ValidationError("signer public key must contain exactly 32 bytes")


def _require_claim_preimage(preimage: bytes | None, payment_hash: bytes | None) -> None:
    if not isinstance(preimage, bytes) or len(preimage) != HASH_LENGTH:
        raise ValidationError("claim preimage must contain exactly 32 bytes")
    if payment_hash is None or hashlib.sha256(preimage).digest() != payment_hash:
        raise ValidationError("claim preimage does not match the payment hash")


def _require_signature(signature: bytes) -> None:
    if not isinstance(signature, bytes) or len(signature) != SIGNATURE_LENGTH:
        raise ValidationError("SIGHASH_DEFAULT Taproot signature must contain 64 bytes")


def _verify_signature(
    verifier: SchnorrVerifier,
    public_key: bytes,
    message: bytes,
    signature: bytes,
) -> None:
    try:
        verifier.schnorr_verify(public_key, message, signature)
    except Exception as error:
        raise ValidationError("unilateral BIP340 signature is invalid") from error


def claim_vsizes(destination_script: bytes) -> tuple[int, int]:
    """Exact vsizes of a client claim paying ``destination_script``.

    Returns ``(cooperative, unilateral)``: the key-path claim (one 64-byte
    signature) and the script-path claim (signature, preimage, 73-byte claim
    script, control block), each one contract input and one output. Pricing
    the claim reserve at the cooperative size means the same absolute fee
    pays the larger script-path fallback at a lower rate.
    """
    _dust_threshold(destination_script)  # P2WPKH or P2TR only
    # version, input count, outpoint, empty scriptSig, sequence, output count,
    # value, script length, script, locktime
    stripped = 4 + 1 + 36 + 1 + 4 + 1 + 8 + 1 + len(destination_script) + 4
    witnesses = (
        1 + 1 + SIGNATURE_LENGTH,
        1
        + (1 + SIGNATURE_LENGTH)
        + (1 + HASH_LENGTH)
        + (1 + CLAIM_SCRIPT_LENGTH)
        + (1 + CONTROL_BLOCK_LENGTH),
    )
    cooperative, unilateral = ((4 * stripped + 2 + witness + 3) // 4 for witness in witnesses)
    return cooperative, unilateral


def max_spendable_fee(authorization: UnilateralAuthorization) -> int:
    """Return the highest fee this spend can carry: the signed cap or the dust floor.

    A fee schedule that targets the signed cap alone can select a transaction
    that no build accepts once the remaining output would be dust.
    """
    _require_supported_profile(authorization.consensus_profile)
    floor = _dust_threshold(authorization.destination_script)
    return max(0, min(authorization.fee_cap_sat, authorization.funding.value_sat - floor))


def _require_fee_and_output(
    authorization: UnilateralAuthorization,
    fee_sat: int,
) -> None:
    _require_supported_profile(authorization.consensus_profile)
    _require_satoshis(fee_sat, field="unilateral fee")
    if fee_sat > authorization.fee_cap_sat:
        raise ValidationError("unilateral fee exceeds the signed cap")
    output_value = authorization.funding.value_sat - fee_sat
    if output_value <= 0:
        raise ValidationError("unilateral output must be positive")
    if output_value < _dust_threshold(authorization.destination_script):
        raise ValidationError("unilateral output is dust under the pinned policy")


def _dust_threshold(script_pubkey: bytes) -> int:
    if len(script_pubkey) == P2WPKH_SCRIPT_LENGTH and script_pubkey[:2] == b"\x00\x14":
        return P2WPKH_DUST_SAT
    if len(script_pubkey) == P2TR_SCRIPT_LENGTH and script_pubkey[:2] == b"\x51\x20":
        return P2TR_DUST_SAT
    raise ValidationError("unsupported version-one destination script")


def _require_supported_profile(consensus_profile: str) -> None:
    if consensus_profile not in SUPPORTED_CONSENSUS_PROFILES:
        raise ValidationError("unsupported settlement consensus profile")


def _build_transaction(
    authorization: UnilateralAuthorization,
    fee_sat: int,
    *,
    witness: tuple[bytes, ...],
) -> _Transaction:
    return _Transaction(
        version=TRANSACTION_VERSION,
        inputs=(
            _TxInput(
                prevout=_Outpoint(
                    authorization.funding.txid,
                    authorization.funding.output_index,
                ),
                script_sig=b"",
                sequence=INPUT_SEQUENCE,
            ),
        ),
        outputs=(
            _TxOutput(
                authorization.funding.value_sat - fee_sat,
                authorization.destination_script,
            ),
        ),
        witnesses=(witness,),
        lock_time=authorization.lock_time,
    )


def _taproot_script_path_sighash(
    transaction: _Transaction,
    authorization: UnilateralAuthorization,
) -> bytes:
    message = (
        _taproot_common_sighash_message(transaction, authorization)
        + b"\x02"  # spend_type = 2 * ext_flag + annex_present (1, 0)
        + (0).to_bytes(4, "little")
        + authorization.tapleaf_hash
        + b"\x00"
        + CODESEPARATOR_POSITION.to_bytes(4, "little")
    )
    return tagged_hash("TapSighash", b"\x00" + message)


def _taproot_key_path_sighash(
    transaction: _Transaction, authorization: UnilateralAuthorization
) -> bytes:
    """BIP341 SIGHASH_DEFAULT with ext_flag=0 and no annex, all prevouts."""
    message = (
        _taproot_common_sighash_message(transaction, authorization)
        + b"\x00"
        + (0).to_bytes(4, "little")
    )
    return tagged_hash("TapSighash", b"\x00" + message)


def _taproot_common_sighash_message(
    transaction: _Transaction, authorization: UnilateralAuthorization
) -> bytes:
    funding = authorization.funding
    return (
        bytes([SIGHASH_DEFAULT])
        + transaction.version.to_bytes(4, "little", signed=True)
        + transaction.lock_time.to_bytes(4, "little")
        + hashlib.sha256(
            b"".join(tx_input.prevout.serialize() for tx_input in transaction.inputs),
        ).digest()
        + hashlib.sha256(funding.value_sat.to_bytes(8, "little")).digest()
        + hashlib.sha256(_serialize_string(funding.script_pubkey)).digest()
        + hashlib.sha256(
            b"".join(tx_input.sequence.to_bytes(4, "little") for tx_input in transaction.inputs),
        ).digest()
        + hashlib.sha256(
            b"".join(tx_output.serialize() for tx_output in transaction.outputs),
        ).digest()
    )


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0

    def read(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.raw):
            raise ValidationError("transaction encoding is truncated")
        value = self.raw[self.offset : self.offset + size]
        self.offset += size
        return value

    def compact_size(self) -> int:
        prefix = self.read(1)[0]
        if prefix < COMPACT_SIZE_UINT16_PREFIX:
            return prefix
        widths = {253: 2, 254: 4, 255: 8}
        width = widths[prefix]
        value = int.from_bytes(self.read(width), "little")
        minimum = {2: 253, 4: 0x10000, 8: 0x100000000}[width]
        if value < minimum:
            raise ValidationError("transaction contains noncanonical CompactSize")
        return value

    def string(self, *, maximum: int, field: str) -> bytes:
        size = self.compact_size()
        if size > maximum:
            raise ValidationError(f"{field} exceeds the size limit")
        return self.read(size)


def _parse_transaction(raw: bytes) -> _Transaction:
    if not isinstance(raw, bytes) or not raw:
        raise ValidationError("raw transaction must be nonempty bytes")
    if len(raw) > MAX_TRANSACTION_BYTES:
        raise ValidationError("raw transaction exceeds the size limit")
    reader = _Reader(raw)
    version = int.from_bytes(reader.read(4), "little", signed=True)
    marker = reader.read(1)[0]
    if marker != 0:
        raise ValidationError("unilateral transaction must use witness serialization")
    if reader.read(1) != b"\x01":
        raise ValidationError("transaction witness flag must be one")
    input_count = reader.compact_size()
    if input_count > MAX_TRANSACTION_INPUTS:
        raise ValidationError("transaction input count exceeds the limit")
    inputs: list[_TxInput] = []
    for _ in range(input_count):
        txid = reader.read(32)[::-1]
        output_index = int.from_bytes(reader.read(4), "little")
        script_sig = reader.string(maximum=MAX_SCRIPT_BYTES, field="input scriptSig")
        sequence = int.from_bytes(reader.read(4), "little")
        inputs.append(_TxInput(_Outpoint(txid, output_index), script_sig, sequence))
    output_count = reader.compact_size()
    if output_count > MAX_TRANSACTION_OUTPUTS:
        raise ValidationError("transaction output count exceeds the limit")
    outputs: list[_TxOutput] = []
    for _ in range(output_count):
        value_sat = int.from_bytes(reader.read(8), "little")
        _require_satoshis(value_sat, field="transaction output value")
        script_pubkey = reader.string(
            maximum=MAX_SCRIPT_BYTES,
            field="output scriptPubKey",
        )
        outputs.append(_TxOutput(value_sat, script_pubkey))
    witnesses: list[tuple[bytes, ...]] = []
    for _ in range(input_count):
        item_count = reader.compact_size()
        if item_count > MAX_WITNESS_ITEMS:
            raise ValidationError("witness item count exceeds the limit")
        witnesses.append(
            tuple(
                reader.string(
                    maximum=MAX_WITNESS_ITEM_BYTES,
                    field="witness item",
                )
                for _ in range(item_count)
            ),
        )
    lock_time = int.from_bytes(reader.read(4), "little")
    if reader.offset != len(raw):
        raise ValidationError("transaction encoding contains trailing bytes")
    if not any(witnesses):
        raise ValidationError("transaction contains a superfluous witness marker")
    return _Transaction(
        version=version,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        witnesses=tuple(witnesses),
        lock_time=lock_time,
    )


def _require_uint32(value: int, *, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_UINT32:
        raise ValidationError(f"{field} must be a uint32")


def _require_satoshis(value: int, *, field: str, positive: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    minimum = 1 if positive else 0
    if not minimum <= value <= MAX_SATS:
        raise ValidationError(f"{field} is outside the monetary range")


def _compact_size(value: int) -> bytes:
    if value < 0:
        raise ValidationError("CompactSize cannot encode a negative value")
    if value < COMPACT_SIZE_UINT16_PREFIX:
        return bytes([value])
    if value <= MAX_UINT16:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= MAX_UINT32:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= MAX_UINT64:
        return b"\xff" + value.to_bytes(8, "little")
    raise ValidationError("CompactSize value exceeds uint64")


def _serialize_string(value: bytes) -> bytes:
    return _compact_size(len(value)) + value


def _hash256(value: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()
