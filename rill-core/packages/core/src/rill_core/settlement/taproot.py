"""Exact RS-002 two-leaf Taproot contract reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from rill_core.errors import ValidationError
from rill_core.wire.hashes import tagged_hash

if TYPE_CHECKING:
    from rill_core.wire.messages import ContractTerms

TAPLEAF_VERSION = 0xC0
OP_1 = 0x51
OP_16 = 0x60
OP_SIZE = 0x82
OP_EQUALVERIFY = 0x88
OP_SHA256 = 0xA8
OP_CHECKLOCKTIMEVERIFY = 0xB1
OP_DROP = 0x75
OP_CHECKSIG = 0xAC
DIRECT_PUSH_32 = 0x20
CLAIM_SCRIPT_LENGTH = 73
XONLY_KEY_LENGTH = 32
COMPACT_SIZE_UINT16_PREFIX = 253
MAX_UINT16 = 0xFFFF
MAX_UINT32 = 0xFFFFFFFF
MAX_UINT64 = 0xFFFFFFFFFFFFFFFF
MAX_LOCK_HEIGHT_EXCLUSIVE = 500_000_000
MAX_SCRIPT_SMALL_INTEGER = 16


class TaprootKeyOperations(Protocol):
    """Narrow curve boundary required by deterministic contract reconstruction."""

    def musig_internal_key(
        self,
        user_public_key: bytes,
        provider_public_key: bytes,
    ) -> tuple[bytes, int]:
        """Return ordered BIP327 aggregate x-only key and full-point parity."""
        ...

    def musig_output_key(
        self,
        user_public_key: bytes,
        provider_public_key: bytes,
        tap_tweak: bytes,
    ) -> tuple[bytes, int]:
        """Apply an x-only tweak and return output key and parity."""
        ...


@dataclass(frozen=True, slots=True)
class TaprootContract:
    """Complete deterministic artifacts needed to reconstruct an RS-002 output."""

    internal_key: bytes
    internal_parity: int
    claim_script: bytes
    refund_script: bytes
    claim_leaf_preimage: bytes
    refund_leaf_preimage: bytes
    claim_leaf_hash: bytes
    refund_leaf_hash: bytes
    branch_left_hash: bytes
    branch_right_hash: bytes
    merkle_root: bytes
    tap_tweak: bytes
    output_key: bytes
    output_parity: int
    script_pubkey: bytes
    claim_control_block: bytes
    refund_control_block: bytes


def _compact_size(value: int) -> bytes:
    if value < 0:
        raise ValidationError("CompactSize value cannot be negative")
    if value < COMPACT_SIZE_UINT16_PREFIX:
        return bytes([value])
    if value <= MAX_UINT16:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= MAX_UINT32:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= MAX_UINT64:
        return b"\xff" + value.to_bytes(8, "little")
    raise ValidationError("CompactSize value exceeds uint64")


def _push_positive_script_number(value: int) -> bytes:
    if not 0 < value < MAX_LOCK_HEIGHT_EXCLUSIVE:
        raise ValidationError("refund lock height is outside the RS-002 range")
    if value <= MAX_SCRIPT_SMALL_INTEGER:
        return bytes([OP_1 + value - 1])
    encoded = bytearray()
    remaining = value
    while remaining:
        encoded.append(remaining & 0xFF)
        remaining >>= 8
    if encoded[-1] & 0x80:
        encoded.append(0)
    return bytes([len(encoded)]) + bytes(encoded)


def _claim_script(payment_hash: bytes, claimant_key: bytes) -> bytes:
    if len(payment_hash) != XONLY_KEY_LENGTH or len(claimant_key) != XONLY_KEY_LENGTH:
        raise ValidationError("claim script inputs must contain exactly 32 bytes")
    script = bytes(
        [
            OP_SIZE,
            0x01,
            0x20,
            OP_EQUALVERIFY,
            OP_SHA256,
            DIRECT_PUSH_32,
        ],
    )
    script += payment_hash
    script += bytes([OP_EQUALVERIFY, DIRECT_PUSH_32]) + claimant_key
    script += bytes([OP_CHECKSIG])
    if len(script) != CLAIM_SCRIPT_LENGTH:
        raise AssertionError("RS-002 claim script has an unexpected length")
    return script


def _refund_script(lock_height: int, refund_key: bytes) -> bytes:
    if len(refund_key) != XONLY_KEY_LENGTH:
        raise ValidationError("refund key must contain exactly 32 bytes")
    return (
        _push_positive_script_number(lock_height)
        + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP, DIRECT_PUSH_32])
        + refund_key
        + bytes([OP_CHECKSIG])
    )


def _tapleaf(script: bytes) -> tuple[bytes, bytes]:
    preimage = bytes([TAPLEAF_VERSION]) + _compact_size(len(script)) + script
    return preimage, tagged_hash("TapLeaf", preimage)


def _require_key_result(value: bytes, parity: int, *, field: str) -> None:
    if not isinstance(value, bytes) or len(value) != XONLY_KEY_LENGTH:
        raise ValidationError(f"{field} must contain exactly 32 bytes")
    if parity not in (0, 1):
        raise ValidationError(f"{field} parity must be zero or one")


def reconstruct_taproot_contract(
    terms: ContractTerms,
    *,
    keys: TaprootKeyOperations,
) -> TaprootContract:
    """Reconstruct every committed RS-002 Taproot artifact from validated terms."""
    user_public_key = bytes.fromhex(terms.client_contract_compressed_key)
    provider_public_key = bytes.fromhex(terms.provider_contract_compressed_key)
    user_xonly_key = user_public_key[1:]
    provider_xonly_key = provider_public_key[1:]
    claimant_key = user_xonly_key if terms.claimant == "client" else provider_xonly_key
    refund_key = user_xonly_key if terms.refund_party == "client" else provider_xonly_key

    internal_key, internal_parity = keys.musig_internal_key(
        user_public_key,
        provider_public_key,
    )
    _require_key_result(internal_key, internal_parity, field="internal key")

    claim_script = _claim_script(
        bytes.fromhex(terms.invoice_binding.payment_hash),
        claimant_key,
    )
    refund_script = _refund_script(terms.refund_lock_height, refund_key)
    claim_preimage, claim_leaf = _tapleaf(claim_script)
    refund_preimage, refund_leaf = _tapleaf(refund_script)
    branch_left, branch_right = sorted((claim_leaf, refund_leaf))
    merkle_root = tagged_hash("TapBranch", branch_left + branch_right)
    tap_tweak = tagged_hash("TapTweak", internal_key + merkle_root)

    output_key, output_parity = keys.musig_output_key(
        user_public_key,
        provider_public_key,
        tap_tweak,
    )
    _require_key_result(output_key, output_parity, field="output key")
    control_prefix = bytes([TAPLEAF_VERSION | output_parity])
    return TaprootContract(
        internal_key=internal_key,
        internal_parity=internal_parity,
        claim_script=claim_script,
        refund_script=refund_script,
        claim_leaf_preimage=claim_preimage,
        refund_leaf_preimage=refund_preimage,
        claim_leaf_hash=claim_leaf,
        refund_leaf_hash=refund_leaf,
        branch_left_hash=branch_left,
        branch_right_hash=branch_right,
        merkle_root=merkle_root,
        tap_tweak=tap_tweak,
        output_key=output_key,
        output_parity=output_parity,
        script_pubkey=bytes([OP_1, DIRECT_PUSH_32]) + output_key,
        claim_control_block=control_prefix + internal_key + refund_leaf,
        refund_control_block=control_prefix + internal_key + claim_leaf,
    )
