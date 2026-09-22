from __future__ import annotations

import pytest

from rill_core.errors import CanonicalizationError
from rill_core.wire.canonical import canonicalize, parse_and_canonicalize, parse_json_strict


def test_rejects_duplicate_keys_before_model_validation() -> None:
    with pytest.raises(CanonicalizationError, match="duplicate"):
        parse_json_strict(b'{"amount":"1","amount":"2"}')


@pytest.mark.parametrize("document", [b"1.0", b"1e0", b"NaN", b"Infinity"])
def test_rejects_floating_point_numbers(document: bytes) -> None:
    with pytest.raises(CanonicalizationError):
        parse_json_strict(document)


def test_canonicalizes_rfc8785_object_order() -> None:
    value, encoded = parse_and_canonicalize(b'{"z":0,"a":[true,null,"text"]}')
    assert encoded == b'{"a":[true,null,"text"],"z":0}'
    assert canonicalize(value) == encoded
