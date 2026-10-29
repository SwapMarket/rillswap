from __future__ import annotations

import pytest
from rill_core.wire.fee_policy import FEE_MODEL, FEE_POLICY_EXTENSION

from rill_cli.live_swap import SwapError, announced_fee_policy, network_fee_request

POLICY = {
    "model": FEE_MODEL,
    "base_sat": "50",
    "proportional_millionths": 1500,
    "max_network_feerate_sat_kvb": "10000000",
    "max_routing_fee_ppm": 1000,
}
ADVERTISEMENT = {
    "profiles": ["btc-to-ln/v1"],
    "indicative_fee_policy": {"base_sat": "50", "proportional_millionths": 1500},
    "extensions": {FEE_POLICY_EXTENSION: POLICY},
    "_fee_offer_event_id": "11" * 32,
}


def test_independent_node_evidence_not_provider_maximum_sets_request_ceiling() -> None:
    request = network_fee_request(ADVERTISEMENT, independent_rate_sat_kvb=1000)
    policy = announced_fee_policy(ADVERTISEMENT)
    assert policy is not None
    assert request == {
        FEE_POLICY_EXTENSION: {
            "offer_event_id": "11" * 32,
            "policy_hash": policy.commitment(),
            "max_network_feerate_sat_kvb": "2000",
        }
    }


def test_advertised_limit_can_further_restrict_independent_ceiling() -> None:
    advertisement = ADVERTISEMENT | {
        "extensions": {
            FEE_POLICY_EXTENSION: POLICY | {"max_network_feerate_sat_kvb": "1500"},
        }
    }
    request = network_fee_request(advertisement, independent_rate_sat_kvb=1000)
    assert request[FEE_POLICY_EXTENSION]["max_network_feerate_sat_kvb"] == "1500"


def test_legacy_offer_does_not_enable_or_require_new_fee_evidence() -> None:
    assert network_fee_request({"extensions": {}}, independent_rate_sat_kvb=0) == {}


def test_missing_independent_evidence_cannot_select_an_unlimited_ceiling() -> None:
    with pytest.raises(SwapError, match="independent"):
        network_fee_request(ADVERTISEMENT, independent_rate_sat_kvb=0)


def test_policy_cannot_hide_different_service_coefficients() -> None:
    with pytest.raises(SwapError, match="contradicts"):
        announced_fee_policy(
            ADVERTISEMENT
            | {
                "extensions": {
                    FEE_POLICY_EXTENSION: POLICY | {"base_sat": "1"},
                }
            }
        )


def test_malformed_known_extension_is_not_treated_as_legacy() -> None:
    with pytest.raises(ValueError, match="BtcFeePolicy"):
        announced_fee_policy(ADVERTISEMENT | {"extensions": {FEE_POLICY_EXTENSION: None}})
