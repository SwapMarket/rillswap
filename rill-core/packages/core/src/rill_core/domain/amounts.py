"""Bounded monetary values with explicit units."""

from __future__ import annotations

from dataclasses import dataclass

from rill_core.errors import ValidationError

MAX_SATS = 2_100_000_000_000_000
MAX_MILLISATS = MAX_SATS * 1_000


def parse_canonical_decimal(value: str, *, field: str, maximum: int) -> int:
    """Parse a canonical nonnegative decimal integer within a protocol bound."""
    if not isinstance(value, str):
        msg = f"{field} must be a decimal string"
        raise ValidationError(msg)
    if value == "0":
        parsed = 0
    elif value and value[0] in "123456789" and value.isascii() and value.isdecimal():
        parsed = int(value)
    else:
        msg = f"{field} is not a canonical nonnegative decimal string"
        raise ValidationError(msg)
    if parsed > maximum:
        msg = f"{field} exceeds the protocol maximum"
        raise ValidationError(msg)
    return parsed


@dataclass(frozen=True, slots=True, order=True)
class Sats:
    """Satoshi amount bounded by the RillSwap protocol maximum."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise ValidationError("satoshi value must be an integer")
        if not 0 <= self.value <= MAX_SATS:
            raise ValidationError("satoshi value is outside the protocol range")

    @classmethod
    def from_wire(cls, value: str) -> Sats:
        """Construct from a canonical wire decimal string."""
        return cls(parse_canonical_decimal(value, field="sats", maximum=MAX_SATS))

    def to_wire(self) -> str:
        """Return the canonical wire representation."""
        return str(self.value)

    def checked_add(self, other: Sats) -> Sats:
        """Add without exceeding the protocol bound."""
        return Sats(self.value + other.value)

    def checked_sub(self, other: Sats) -> Sats:
        """Subtract without producing a negative value."""
        if other.value > self.value:
            raise ValidationError("satoshi subtraction underflow")
        return Sats(self.value - other.value)


@dataclass(frozen=True, slots=True, order=True)
class Millisats:
    """Millisatoshi amount bounded by the exact protocol maximum."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise ValidationError("millisatoshi value must be an integer")
        if not 0 <= self.value <= MAX_MILLISATS:
            raise ValidationError("millisatoshi value is outside the protocol range")

    @classmethod
    def from_wire(cls, value: str) -> Millisats:
        """Construct from a canonical wire decimal string."""
        return cls(
            parse_canonical_decimal(value, field="millisats", maximum=MAX_MILLISATS),
        )

    @classmethod
    def from_whole_sats(cls, value: Sats) -> Millisats:
        """Convert whole satoshis exactly."""
        return cls(value.value * 1_000)

    def to_wire(self) -> str:
        """Return the canonical wire representation."""
        return str(self.value)

    def require_whole_sats(self) -> Sats:
        """Return whole satoshis or reject a fractional-satoshi value."""
        quotient, remainder = divmod(self.value, 1_000)
        if remainder != 0:
            raise ValidationError("invoice amount must be whole satoshis")
        return Sats(quotient)
