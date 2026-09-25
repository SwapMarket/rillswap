from __future__ import annotations

import pytest

from rill_core.domain.keys import CompressedPubkey, Hash32
from rill_core.errors import ValidationError


def test_hash_requires_lowercase_exact_hex() -> None:
    value = Hash32.from_hex("ab" * 32)
    assert value.to_hex() == "ab" * 32
    with pytest.raises(ValidationError):
        Hash32.from_hex("AB" * 32)


def test_compressed_key_requires_valid_prefix() -> None:
    assert CompressedPubkey.from_hex("02" + "01" * 32).value[0] == 2
    with pytest.raises(ValidationError):
        CompressedPubkey.from_hex("04" + "01" * 32)
