from __future__ import annotations

import pytest

from rill_core.domain.amounts import MAX_SATS, Millisats, Sats
from rill_core.errors import ValidationError


@pytest.mark.parametrize("value", ["00", "01", "-1", "+1", " 1", "1.0", "١"])
def test_sats_reject_noncanonical_decimal(value: str) -> None:
    with pytest.raises(ValidationError):
        Sats.from_wire(value)


def test_sats_round_trip_maximum() -> None:
    value = Sats.from_wire(str(MAX_SATS))
    assert value.to_wire() == str(MAX_SATS)


@pytest.mark.parametrize("value", [str(MAX_SATS + 1), "1" * 17, "9" * 5_000])
def test_sats_reject_values_above_maximum_as_validation_errors(value: str) -> None:
    # Over-long digit strings must not surface int()'s own ValueError.
    with pytest.raises(ValidationError, match="exceeds the protocol maximum"):
        Sats.from_wire(value)


def test_checked_amount_arithmetic_rejects_range_errors() -> None:
    with pytest.raises(ValidationError):
        Sats(MAX_SATS).checked_add(Sats(1))
    with pytest.raises(ValidationError):
        Sats(0).checked_sub(Sats(1))


def test_invoice_requires_whole_satoshis() -> None:
    assert Millisats(2_000).require_whole_sats() == Sats(2)
    with pytest.raises(ValidationError):
        Millisats(2_001).require_whole_sats()
