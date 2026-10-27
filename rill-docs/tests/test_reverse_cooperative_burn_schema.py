"""A closed pre-nonce burn shape is historical evidence, never authority."""

from __future__ import annotations

import pytest

from tests.test_recovery_vectors import FIXTURE, _schema_validator
from tests.test_schemas import load_json

KEY = "rillswap/reverse-cooperative-reservation"


@pytest.mark.parametrize(
    "variation", ["valid", "missing id", "missing binding", "extra", "null", "bad id"]
)
def test_reverse_burn_closed_shape(variation: str) -> None:
    document = load_json(FIXTURE)
    marker = {"funding_binding_hash": "aa" * 32, "cooperation_id": "bb" * 32}
    document["extensions"][KEY] = marker
    if variation == "missing id":
        del marker["cooperation_id"]
    elif variation == "missing binding":
        del marker["funding_binding_hash"]
    elif variation == "extra":
        marker["version"] = 1
    elif variation == "null":
        document["extensions"][KEY] = None
    elif variation == "bad id":
        marker["cooperation_id"] = "not-hex"
    assert _schema_validator().is_valid(document) == (variation == "valid")
