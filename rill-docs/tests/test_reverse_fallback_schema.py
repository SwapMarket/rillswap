"""The reverse fallback schema promises representation, not native validity."""

from __future__ import annotations

import jsonschema
import pytest

from tests.test_recovery_vectors import ROOT, _schema_validator
from tests.test_schemas import load_json

EXTENSION = "rillswap/reverse-claim-fallback"


def test_reverse_fallback_schema_acceptance_is_shape_only() -> None:
    document = load_json(ROOT / "vectors" / "recovery" / "initial-ln-to-btc-no-prepayment-v1.json")
    document["extensions"][EXTENSION] = {
        "version": 1,
        "funding_binding_hash": "ab" * 32,
        "transaction": "00ff",
    }
    # A real importer must additionally validate the authenticated binding and
    # native transaction. Schema acceptance cannot establish either fact.
    _schema_validator().validate(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", True),
        ("version", 2),
        ("transaction", ""),
        ("transaction", "0"),
        ("transaction", "0F"),
        ("transaction", "00" * 131072),
        ("funding_binding_hash", "ab" * 31),
        ("disclosure_authority", True),
    ],
)
def test_reverse_fallback_schema_rejects_malformed_or_open_records(
    field: str, value: object
) -> None:
    document = load_json(ROOT / "vectors" / "recovery" / "initial-ln-to-btc-no-prepayment-v1.json")
    marker = {"version": 1, "funding_binding_hash": "ab" * 32, "transaction": "00ff"}
    marker[field] = value
    document["extensions"][EXTENSION] = marker
    with pytest.raises(jsonschema.ValidationError):
        _schema_validator().validate(document)
