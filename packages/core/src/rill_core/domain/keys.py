"""Opaque fixed-width protocol identifiers and encoded public keys."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from rill_core.errors import ValidationError

HASH_SIZE = 32
COMPRESSED_PUBLIC_KEY_SIZE = 33


def _decode_lower_hex(value: str, *, size: int, field: str) -> bytes:
    if not isinstance(value, str):
        msg = f"{field} must be lowercase hexadecimal"
        raise ValidationError(msg)
    if len(value) != size * 2 or value.lower() != value:
        msg = f"{field} must be exactly {size} lowercase hexadecimal bytes"
        raise ValidationError(msg)
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        msg = f"{field} contains invalid hexadecimal"
        raise ValidationError(msg) from error
    if len(decoded) != size:
        msg = f"{field} has an invalid length"
        raise ValidationError(msg)
    return decoded


@dataclass(frozen=True, slots=True)
class Hash32:
    """A semantically named immutable 32-byte value."""

    value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes) or len(self.value) != HASH_SIZE:
            raise ValidationError("hash must contain exactly 32 bytes")

    @classmethod
    def from_hex(cls, value: str) -> Self:
        """Construct from exact lowercase hexadecimal."""
        return cls(_decode_lower_hex(value, size=HASH_SIZE, field=cls.__name__))

    def to_hex(self) -> str:
        """Return exact lowercase hexadecimal."""
        return self.value.hex()


@dataclass(frozen=True, slots=True)
class XOnlyPubkey(Hash32):
    """A correctly encoded x-only key pending curve validation at crypto boundary."""


@dataclass(frozen=True, slots=True)
class ContractId(Hash32):
    """Tagged hash of canonical contract terms."""


@dataclass(frozen=True, slots=True)
class PaymentHash(Hash32):
    """SHA256 hash committed by the Lightning invoice and claim leaf."""


@dataclass(frozen=True, slots=True)
class Txid(Hash32):
    """Bitcoin transaction identifier in display byte order."""


@dataclass(frozen=True, slots=True)
class CompressedPubkey:
    """A compressed SEC key encoding pending curve validation at crypto boundary."""

    value: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.value, bytes)
            or len(self.value) != COMPRESSED_PUBLIC_KEY_SIZE
            or self.value[0] not in (2, 3)
        ):
            raise ValidationError("compressed public key must be a 02/03-prefixed 33-byte value")

    @classmethod
    def from_hex(cls, value: str) -> CompressedPubkey:
        """Construct from exact lowercase hexadecimal encoding."""
        return cls(
            _decode_lower_hex(value, size=COMPRESSED_PUBLIC_KEY_SIZE, field=cls.__name__),
        )

    def to_hex(self) -> str:
        """Return exact lowercase hexadecimal."""
        return self.value.hex()
