"""The prepared reverse fallback extension has a bounded closed representation."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from rill_core.recovery.inspection import MAX_RECOVERY_BYTES, _ReverseClaimFallback
from rill_core.wire.canonical import canonicalize


def test_private_prepared_record_has_no_live_authority_or_extra_fields() -> None:
    record = {"version": 1, "funding_binding_hash": "ab" * 32, "transaction": "00ff"}
    parsed = _ReverseClaimFallback.model_validate_json(canonicalize(record), strict=True)
    assert parsed.model_dump(mode="json") == record


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", True),
        ("version", 1.0),
        ("version", "1"),
        ("version", 2),
        ("funding_binding_hash", "ab" * 31),
        ("funding_binding_hash", "AB" * 32),
        ("transaction", ""),
        ("transaction", "0"),
        ("transaction", "0F"),
        ("transaction", "zz"),
        ("transaction", "00" * MAX_RECOVERY_BYTES),
        ("transaction", None),
        ("submission_authority", True),
    ],
)
def test_malformed_partial_or_unsupported_extension_is_refused(field: str, value: object) -> None:
    record = {"version": 1, "funding_binding_hash": "ab" * 32, "transaction": "00ff"}
    record[field] = value
    with pytest.raises(ValidationError):
        _ReverseClaimFallback.model_validate_json(json.dumps(record), strict=True)


@pytest.mark.parametrize("field", ["version", "funding_binding_hash", "transaction"])
def test_missing_record_field_is_refused(field: str) -> None:
    record = {"version": 1, "funding_binding_hash": "ab" * 32, "transaction": "00ff"}
    del record[field]
    with pytest.raises(ValidationError):
        _ReverseClaimFallback.model_validate_json(canonicalize(record), strict=True)
