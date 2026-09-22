from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
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


@pytest.mark.parametrize("path", SCHEMA_PATHS, ids=lambda path: str(path.relative_to(ROOT)))
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
