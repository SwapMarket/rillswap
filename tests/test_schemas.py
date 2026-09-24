from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import rfc8785
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
SCHEMA_PATHS = tuple(sorted((ROOT / "schemas").glob("**/*.json")))
NETWORK_PATHS = tuple(sorted((ROOT / "networks").glob("*.json")))


def load_json(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        value: dict[str, Any] = json.load(stream)
    return value


def schema_registry() -> tuple[Registry[Any], dict[Path, dict[str, Any]]]:
    registry: Registry[Any] = Registry()
    schemas: dict[Path, dict[str, Any]] = {}
    for path in SCHEMA_PATHS:
        schema = load_json(path)
        schemas[path] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry, schemas


@pytest.mark.parametrize(
    "path", SCHEMA_PATHS, ids=lambda path: str(path.relative_to(ROOT))
)
def test_json_schema_is_valid(path: Path) -> None:
    jsonschema.Draft202012Validator.check_schema(load_json(path))


@pytest.mark.parametrize("path", NETWORK_PATHS, ids=lambda path: path.name)
def test_network_fixture_matches_wire_schema(path: Path) -> None:
    registry, schemas = schema_registry()
    validator = jsonschema.Draft202012Validator(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": (
                "https://spec.rillswap.invalid/schemas/wire/"
                "common-v1.schema.json#/$defs/networkIdentity"
            ),
        },
        registry=registry,
    )
    validator.validate(load_json(path))


def test_canonicalization_vectors_match_rfc8785() -> None:
    vectors = load_json(ROOT / "vectors" / "canonicalization" / "cases-v1.json")
    for case in vectors["valid"]:
        canonical = rfc8785.dumps(case["value"])
        assert canonical.decode("utf-8") == case["canonical_utf8"]

        assert hashlib.sha256(canonical).hexdigest() == case["canonical_sha256"]


def test_disposable_manual_advertisement_is_schema_valid_and_signed() -> None:
    """Test-only expired fixture for application verification, not live Nostr discovery."""
    from tests.vendor.bip340_reference import verify

    registry, _schemas = schema_registry()
    validator = jsonschema.Draft202012Validator(
        {
            "$ref": "https://spec.rillswap.invalid/schemas/advertisements/advertisement-v1.schema.json"
        },
        registry=registry,
    )
    fixture = load_json(ROOT / "vectors/discovery/manual-advertisement-regtest-v1.json")
    validator.validate(fixture)
    ad = fixture["advertisement"]
    assert ad["profiles"] == ["btc-to-ln/v1", "ln-to-btc/v1"]
    assert ad["network_identities"][0]["name"] == "regtest"
    assert ad["expires_at"] == 1703025088  # Historical test data, never live.
    digest = hashlib.sha256(
        hashlib.sha256(b"RillSwap/advertisement/v1").digest() * 2 + rfc8785.dumps(ad)
    ).digest()
    assert (
        digest.hex()
        == "676eb596e2b4754b4488f1526d83a8765d6163cb98e34ae2193a38e27688d8f5"
    )
    assert verify(
        digest,
        bytes.fromhex(ad["provider_identity_xonly_key"]),
        bytes.fromhex(fixture["signature"]),
    )
