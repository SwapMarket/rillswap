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


def test_private_regtest_announcement_binds_application_signature_and_address() -> None:
    """Pin NIP-01 event bytes independently of RS-001's application digest."""
    from tests.vendor.bip340_reference import verify

    fixture = load_json(ROOT / "vectors/discovery/manual-advertisement-regtest-v1.json")
    vector = load_json(ROOT / "vectors/discovery/nostr-announcement-regtest-v1.json")
    ad = fixture["advertisement"]
    content = rfc8785.dumps(fixture)
    assert len(content) == vector["content_utf8_length"]
    assert hashlib.sha256(content).hexdigest() == vector["content_sha256"]
    assert vector["kind"] == 39417
    assert vector["pubkey"] == ad["provider_identity_xonly_key"]
    assert vector["created_at"] == ad["created_at"]
    assert ad["network_identities"][0]["name"] == "regtest"
    assert len(ad["network_identities"]) == 1
    assert ad["extensions"] == {}
    d = hashlib.sha256(
        rfc8785.dumps(
            [
                "rillswap",
                ad["binding_version"],
                ad["network_identities"][0],
                ad["slot"],
            ]
        )
    ).hexdigest()
    assert vector["tags"] == [
        ["rillswap", "nostr-experimental-1"],
        ["network", "regtest"],
        ["d", d],
    ]
    message = json.dumps(
        [
            0,
            vector["pubkey"],
            vector["created_at"],
            vector["kind"],
            vector["tags"],
            content.decode("utf-8"),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(message).digest()
    assert digest.hex() == vector["id"]
    assert verify(digest, bytes.fromhex(vector["pubkey"]), bytes.fromhex(vector["sig"]))


QUOTE_SCHEMA = "https://spec.rillswap.invalid/schemas/wire/quote-v1.schema.json"
QUOTE_VECTORS = load_json(ROOT / "vectors/wire/quote-v1.json")


def _quote_validator(definition: str) -> jsonschema.Draft202012Validator:
    registry, _schemas = schema_registry()
    return jsonschema.Draft202012Validator(
        {"$ref": f"{QUOTE_SCHEMA}#/$defs/{definition}"}, registry=registry
    )


@pytest.mark.parametrize("definition", sorted(QUOTE_VECTORS["valid"]))
def test_quote_vectors_valid_cases_match_schema(definition: str) -> None:
    validator = _quote_validator(definition)
    for case in QUOTE_VECTORS["valid"][definition]:
        validator.validate(case)


@pytest.mark.parametrize("definition", sorted(QUOTE_VECTORS["invalid"]))
def test_quote_vectors_invalid_cases_are_refused(definition: str) -> None:
    validator = _quote_validator(definition)
    for case in QUOTE_VECTORS["invalid"][definition]:
        assert not validator.is_valid(case), case


def test_quote_terms_offer_vector_binds_recovery_contract_hash() -> None:
    (offer,) = QUOTE_VECTORS["valid"]["termsOffer"]
    terms = offer["terms"]
    tag = hashlib.sha256(b"RillSwap/contract/v1").digest()
    digest = hashlib.sha256(tag + tag + rfc8785.dumps(terms["contract_terms"])).hexdigest()
    assert digest == terms["contract_hash"]


SETTLEMENT_SCHEMA = "https://spec.rillswap.invalid/schemas/wire/settlement-v1.schema.json"
SETTLEMENT_VECTORS = load_json(ROOT / "vectors/wire/settlement-v1.json")


@pytest.mark.parametrize("definition", sorted(SETTLEMENT_VECTORS["valid"]))
def test_settlement_vectors_match_schema(definition: str) -> None:
    registry, _schemas = schema_registry()
    validator = jsonschema.Draft202012Validator(
        {"$ref": f"{SETTLEMENT_SCHEMA}#/$defs/{definition}"}, registry=registry
    )
    for case in SETTLEMENT_VECTORS["valid"][definition]:
        validator.validate(case)
    for case in SETTLEMENT_VECTORS["invalid"][definition]:
        assert not validator.is_valid(case), case
