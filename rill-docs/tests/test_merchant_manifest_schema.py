"""Closed advisory manifest shape, not origin or receiver authentication."""

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "schemas/checkout/native-lightning-manifest.schema.json").read_text()
)
FIXTURE = json.loads(
    (ROOT / "fixtures/checkout/native-lightning-manifest.json").read_text()
)


def test_manifest_fixture_and_schema_are_compatible() -> None:
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    jsonschema.Draft202012Validator(SCHEMA).validate(FIXTURE)
    assert FIXTURE["productionEnabled"] is False
    assert FIXTURE["allowedPayerAssets"] == FIXTURE["acceptedReceiptAssets"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("productionEnabled", True),
        ("version", "merchant-manifest/native-lightning/2"),
        ("receiptVerification", {"algorithm": "none"}),
        ("routingProfiles", []),
        ("approvedAdapters", [{"id": "unproven-bridge", "version": "1"}]),
    ],
)
def test_manifest_unsupported_capabilities_are_rejected(
    field: str, value: object
) -> None:
    manifest = deepcopy(FIXTURE)
    manifest[field] = value
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(SCHEMA).validate(manifest)


@pytest.mark.parametrize(
    "field",
    [
        "receiptVerification",
        "publicPolicy",
        "allowedPayerAssets",
        "acceptedReceiptAssets",
        "routingProfiles",
        "approvedAdapters",
    ],
)
def test_manifest_nested_extensions_are_rejected(field: str) -> None:
    manifest = deepcopy(FIXTURE)
    nested = manifest[field]
    if isinstance(nested, list):
        nested = nested[0]
    nested["extra"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(SCHEMA).validate(manifest)


def test_manifest_shape_does_not_authenticate_the_receiver_or_origin() -> None:
    manifest = deepcopy(FIXTURE)
    manifest["publicPolicy"]["receiver"] = "03" + "ab" * 32
    manifest["intentApi"] = "https://foreign.example/v1/intents"
    jsonschema.Draft202012Validator(SCHEMA).validate(manifest)
    # Runtime exact-origin/endpoint checks and authenticated delivery remain
    # independent. No signature is inferred from a declared public key.
