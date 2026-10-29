"""Signed fee strings: rebates are negative fees, amounts stay unsigned."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from tests.test_schemas import load_json, schema_registry

ROOT = Path(__file__).parents[1]
WIRE = "https://spec.rillswap.invalid/schemas/wire/"
NETWORK_FEES = load_json(ROOT / "vectors" / "wire" / "btc-network-fees-v1.json")


def validator(reference: str) -> jsonschema.Draft202012Validator:
    registry, _ = schema_registry()
    return jsonschema.Draft202012Validator(
        {"$schema": "https://json-schema.org/draft/2020-12/schema", "$ref": WIRE + reference},
        registry=registry,
    )


SIGNED_SATS = validator("contract-terms-v1.schema.json#/$defs/signedDecimalSats")
SIGNED_TOKENS = validator("evm-contract-terms-v1.schema.json#/$defs/signedDecimalTokenUnits")


@pytest.mark.parametrize("value", ["0", "1", "-1", "-2100000000000000", "9999999999999999"])
def test_canonical_signed_sats_are_accepted(value: str) -> None:
    SIGNED_SATS.validate(value)


@pytest.mark.parametrize(
    "value", ["-0", "+1", "01", "-01", " 1", "1.0", "--1", "-", "", "-10000000000000000", 1]
)
def test_noncanonical_signed_sats_are_refused(value: object) -> None:
    assert not SIGNED_SATS.is_valid(value)


def test_signed_token_units_allow_wide_magnitudes_but_not_noncanonical_strings() -> None:
    assert SIGNED_TOKENS.is_valid("-" + "9" * 39)
    for value in ("-0", "-01", "-" + "1" * 40, "+5"):
        assert not SIGNED_TOKENS.is_valid(value)


def test_evm_economics_carry_signed_fees() -> None:
    forward = validator("evm-contract-terms-v1.schema.json#/$defs/erc20ToLnEconomics")
    forward.validate(
        {
            "kind": "erc20-to-ln",
            "lightning_principal_sat": "1000",
            "rate_token_base_per_btc": "100000000000",
            "success_fee_token_base": "-1000",
            "lock_amount_token_base": "999000",
        }
    )
    reverse = validator("evm-contract-terms-v1.schema.json#/$defs/lnToErc20Economics")
    document: dict[str, Any] = {
        "kind": "ln-to-erc20",
        "payout_token_base": "1000000",
        "rate_token_base_per_btc": "100000000000",
        "payout_sat_equivalent": "1000",
        "success_fee_sat": "-10",
        "hold_invoice_sat": "990",
    }
    reverse.validate(document)
    assert not reverse.is_valid({**document, "hold_invoice_sat": "-990"})


def test_fee_breakdown_service_fee_may_be_a_rebate() -> None:
    schema = validator("btc-network-fees-v1.schema.json")
    breakdown = copy.deepcopy(NETWORK_FEES["breakdown"])
    breakdown["service_fee_sat"] = "-100"
    schema.validate(breakdown)
    breakdown["service_fee_sat"] = "-0"
    assert not schema.is_valid(breakdown)
    breakdown["service_fee_sat"] = "0"
    breakdown["network_fee_sat"] = "-385"
    assert not schema.is_valid(breakdown)
