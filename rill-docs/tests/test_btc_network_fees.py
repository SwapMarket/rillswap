"""Structural conformance for the versioned pricing extension's shared vector."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).parents[1]


def test_fee_policy_request_and_breakdown_conform() -> None:
    schema = json.loads((ROOT / "schemas/wire/btc-network-fees-v1.schema.json").read_text())
    vector = json.loads((ROOT / "vectors/wire/btc-network-fees-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for key in ("policy", "request", "breakdown"):
        validator.validate(vector[key])
