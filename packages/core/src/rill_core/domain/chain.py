"""Chain height and wall-clock values kept as distinct types."""

from __future__ import annotations

from dataclasses import dataclass

from rill_core.errors import ValidationError

MAX_EXACT_JSON_INTEGER = 9_007_199_254_740_991
MAX_LOCK_HEIGHT = 499_999_999


@dataclass(frozen=True, slots=True, order=True)
class BlockHeight:
    """Nonnegative Bitcoin block height."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise ValidationError("block height must be an integer")
        if not 0 <= self.value <= MAX_EXACT_JSON_INTEGER:
            raise ValidationError("block height is outside the wire range")

    def require_contract_lock(self) -> BlockHeight:
        """Validate that this height is encoded as CLTV block height, not time."""
        if not 0 < self.value <= MAX_LOCK_HEIGHT:
            raise ValidationError("refund lock height must be below 500000000")
        return self


@dataclass(frozen=True, slots=True, order=True)
class UnixSeconds:
    """Nonnegative Unix timestamp in the exact JSON integer range."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise ValidationError("Unix time must be an integer")
        if not 0 <= self.value <= MAX_EXACT_JSON_INTEGER:
            raise ValidationError("Unix time is outside the wire range")
