from __future__ import annotations

import pytest

from rill_core.domain.chain import BlockHeight, UnixSeconds
from rill_core.errors import ValidationError


def test_height_and_time_are_distinct_values() -> None:
    height = BlockHeight(100)
    timestamp = UnixSeconds(100)
    assert height.__class__.__name__ != timestamp.__class__.__name__
    assert height.value == timestamp.value


@pytest.mark.parametrize("height", [0, 500_000_000])
def test_contract_height_must_select_cltv_height_mode(height: int) -> None:
    with pytest.raises(ValidationError):
        BlockHeight(height).require_contract_lock()
