from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from rill_core.wire.fee_policy import (
    FEE_MODEL,
    FEE_POLICY_EXTENSION,
    NETWORK_FEE_VBYTES,
    BtcFeePolicy,
    FeeBreakdown,
    check_fee_breakdown,
)
from rill_core.wire.hashes import FEE_POLICY_FEATURE, contract_hash
from rill_core.wire.messages import ContractTerms

POLICY = {
    "model": FEE_MODEL,
    "base_sat": "50",
    "proportional_millionths": 1000,
    "max_network_feerate_sat_kvb": "10000",
    "max_routing_fee_ppm": 1000,
}
BREAKDOWN = {
    "offer_event_id": "11" * 32,
    "policy": POLICY,
    "feerate_sat_kvb": "2500",
    "estimated_at": 998,
    "issued_at": 1000,
    "service_fee_sat": "150",
    "network_fee_sat": "385",
}


def check(
    *,
    breakdown: dict[str, Any] | None = None,
    expires_at: int = 1060,
    request_change: dict[str, Any] | None = None,
    now: int | None = 1000,
) -> FeeBreakdown | None:
    request = {
        "offer_event_id": "11" * 32,
        "policy_hash": BtcFeePolicy.model_validate(POLICY).commitment(),
        "max_network_feerate_sat_kvb": "3000",
    } | (request_change or {})
    return check_fee_breakdown(
        {FEE_POLICY_EXTENSION: BREAKDOWN if breakdown is None else breakdown},
        required=True,
        principal_sat=100_000,
        success_fee_sat=535,
        expires_at=expires_at,
        request_extensions={FEE_POLICY_EXTENSION: request},
        now=now,
    )


def test_one_input_two_p2tr_outputs_cooperative_weight() -> None:
    # One empty-scriptSig input, two P2TR outputs, one 64-byte Schnorr witness.
    stripped = 4 + 1 + (32 + 4 + 1 + 4) + 1 + 2 * (8 + 1 + 34) + 4
    witness = 2 + 1 + 1 + 64
    assert -(-(stripped * 4 + witness) // 4) == NETWORK_FEE_VBYTES == 154


def test_offer_bound_estimate_keeps_service_fee_and_sixty_second_window() -> None:
    assert check() == FeeBreakdown.model_validate(BREAKDOWN)
    assert check(now=1059) is not None


@pytest.mark.parametrize("expires_at", [1000, 1061])
def test_quote_lifetime_is_bounded(expires_at: int) -> None:
    with pytest.raises(ValueError, match="lifetime"):
        check(expires_at=expires_at)


@pytest.mark.parametrize("now", [1060, 1061, 994])
def test_expiry_equality_and_future_issuance_are_rejected(now: int) -> None:
    with pytest.raises(ValueError, match=r"expired|future"):
        check(now=now)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"offer_event_id": "22" * 32}, "different announcement"),
        ({"policy_hash": "22" * 32}, "advertised pricing policy"),
        ({"max_network_feerate_sat_kvb": "2499"}, "independent ceiling"),
    ],
)
def test_request_cannot_be_silently_substituted(change: dict[str, Any], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        check(request_change=change)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"service_fee_sat": "151"}, "service fee"),
        ({"network_fee_sat": "386"}, "transaction-size"),
        ({"feerate_sat_kvb": "10001"}, "advertised maximum"),
        ({"estimated_at": 989}, "stale"),
        ({"estimated_at": 1001}, "future"),
        ({"vbytes": 9999}, "Extra inputs"),
    ],
)
def test_provider_cannot_inflate_charge_or_evidence(change: dict[str, Any], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        check(breakdown=BREAKDOWN | change)


def test_policy_hash_covers_all_coefficients() -> None:
    original = BtcFeePolicy.model_validate(POLICY).commitment()
    for change in (
        {"base_sat": "51"},
        {"proportional_millionths": 1001},
        {"max_network_feerate_sat_kvb": "10001"},
        {"max_routing_fee_ppm": 1001},
    ):
        assert BtcFeePolicy.model_validate(POLICY | change).commitment() != original


def test_historical_validation_does_not_reprice_or_expire_accepted_terms() -> None:
    assert check(now=None) is not None


def test_legacy_terms_are_unchanged_and_no_optional_downgrade_is_allowed() -> None:
    assert (
        check_fee_breakdown(
            {}, required=False, principal_sat=100_000, success_fee_sat=150, expires_at=1120
        )
        is None
    )
    with pytest.raises(ValueError, match="required"):
        check_fee_breakdown(
            {FEE_POLICY_EXTENSION: BREAKDOWN},
            required=False,
            principal_sat=100_000,
            success_fee_sat=535,
            expires_at=1060,
        )


def test_proportional_and_network_fees_round_up_independently() -> None:
    assert BtcFeePolicy.model_validate(POLICY).service_fee(1) == 51
    value = FeeBreakdown.model_validate(
        BREAKDOWN | {"feerate_sat_kvb": "1001", "network_fee_sat": "155"}
    )
    assert value.network_fee_sat == "155"


def test_shared_protocol_vector_binds_canonical_policy_bytes() -> None:
    path = Path(__file__).parents[3] / "rill-docs/vectors/wire/btc-network-fees-v1.json"
    vector = json.loads(path.read_text())
    policy = BtcFeePolicy.model_validate(vector["policy"])
    assert policy.commitment() == vector["policy_hash"]
    assert (
        check_fee_breakdown(
            {FEE_POLICY_EXTENSION: vector["breakdown"]},
            required=True,
            principal_sat=int(vector["principal_sat"]),
            success_fee_sat=int(vector["success_fee_sat"]),
            expires_at=vector["expires_at"],
            request_extensions={FEE_POLICY_EXTENSION: vector["request"]},
        )
        is not None
    )


def test_contract_hash_authenticates_the_fee_policy_not_only_total_amounts() -> None:
    fixture = Path(__file__).parents[1] / "fixtures/wire-v1/quote-v1.json"
    raw = json.loads(fixture.read_text())["valid"]["termsOffer"][0]["terms"]["contract_terms"]
    issued_at = raw["invoice_binding"]["created_at"]
    raw["economics"].update(success_fee_sat="535", contract_amount_sat="100535")
    raw["required_features"] = [FEE_POLICY_FEATURE]
    raw["terms_expiry"] = issued_at + 60
    raw["extensions"] = {
        FEE_POLICY_EXTENSION: BREAKDOWN
        | {
            "issued_at": issued_at,
            "estimated_at": issued_at - 2,
        }
    }
    original = ContractTerms.model_validate_json(json.dumps(raw))
    raw["extensions"][FEE_POLICY_EXTENSION]["offer_event_id"] = "22" * 32
    substituted = ContractTerms.model_validate_json(json.dumps(raw))
    assert original.economics == substituted.economics
    assert contract_hash(original) != contract_hash(substituted)
