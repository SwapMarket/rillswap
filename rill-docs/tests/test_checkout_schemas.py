from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).parents[1]
SCHEMA = json.loads((ROOT / "schemas/checkout/native-lightning.schema.json").read_text())
FIXTURE = json.loads((ROOT / "fixtures/checkout/native-lightning.json").read_text())


def test_native_lightning_terms_fixture() -> None:
    jsonschema.Draft202012Validator(SCHEMA).validate(FIXTURE)


@pytest.mark.parametrize(
    "patch",
    [
        {"version": "checkout/2"},
        {"amountMsat": "-1"},
        {"amountMsat": "01000"},
        {"amountMsat": "1.5"},
        {"network": "unknown"},
        {"paymentHash": "ff"},
        {"receiver": "ff"},
        {"expiresAt": 0},
        {"paid": True},
    ],
)
def test_native_lightning_invalid_terms(patch: dict[str, object]) -> None:
    terms = copy.deepcopy(FIXTURE)
    terms.update(patch)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(SCHEMA).validate(terms)
