"""Economical next-block advice: Core target 2 with the node's own floors."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from test_core_tx_bytes import _cookie, _server
from test_core_wallet_funding import _by_method
from test_network_adapters import _network

from rill_provider.core_tx_bytes import (
    CoreProtocolError,
    CoreTransactionReader,
    CoreUnavailableError,
    NextBlockFee,
)

if TYPE_CHECKING:
    from pathlib import Path

UNAVAILABLE = {"errors": ["Insufficient data or no feerate found"], "blocks": 0}


def _sample(
    tmp_path: Path,
    network_name: str,
    estimate: dict[str, Any],
    *,
    mempool_min: float = 0.000001,
    ceiling: int | None = None,
) -> tuple[NextBlockFee, list[dict[str, Any]]]:
    replies = {
        "getmempoolinfo": {"minrelaytxfee": 0.000001, "mempoolminfee": mempool_min},
        "estimatesmartfee": estimate,
    }
    requests: list[dict[str, Any]] = []
    with _server(_by_method(replies), requests) as port:
        reader = CoreTransactionReader(
            port=port,
            cookie_path=_cookie(tmp_path),
            network=_network(network_name),
            max_fee_estimate_sat_vb=ceiling,
        )
        return reader.next_block_fee(), requests


@pytest.mark.parametrize("network_name", ["signet", "mainnet", "regtest-rillswap-e2e-v1"])
def test_economical_two_block_estimate_with_node_floors(tmp_path: Path, network_name: str) -> None:
    fee, requests = _sample(tmp_path, network_name, {"feerate": 0.00001234, "blocks": 2})
    assert [(r["method"], r["params"]) for r in requests] == [
        ("getmempoolinfo", []),
        ("estimatesmartfee", [2, "ECONOMICAL"]),
    ]
    assert fee == NextBlockFee(relay_sat_kvb=100, mempool_min_sat_kvb=100, estimate_sat_kvb=1234)
    assert (fee.floor_sat_kvb, fee.rate_sat_kvb) == (100, 1234)


def test_full_mempool_minimum_raises_the_rate(tmp_path: Path) -> None:
    fee, _ = _sample(tmp_path, "signet", {"feerate": 0.00001, "blocks": 2}, mempool_min=0.00002)
    assert (fee.floor_sat_kvb, fee.rate_sat_kvb) == (2_000, 2_000)


def test_ceiling_lowers_only_the_estimate(tmp_path: Path) -> None:
    skewed = {"feerate": 0.00231893, "blocks": 2}
    fee, _ = _sample(tmp_path, "signet", skewed, ceiling=2)
    assert (fee.estimate_sat_kvb, fee.rate_sat_kvb) == (2_000, 2_000)
    fee, _ = _sample(tmp_path, "signet", skewed, mempool_min=0.00005, ceiling=2)
    assert fee.rate_sat_kvb == 5_000


@pytest.mark.parametrize("network_name", ["signet", "testnet4", "mainnet"])
def test_public_networks_refuse_without_an_estimate(tmp_path: Path, network_name: str) -> None:
    with pytest.raises(CoreUnavailableError, match="estimate unavailable"):
        _sample(tmp_path, network_name, UNAVAILABLE, ceiling=2)


def test_regtest_falls_back_to_the_node_minimum(tmp_path: Path) -> None:
    fee, _ = _sample(tmp_path, "regtest-rillswap-e2e-v1", UNAVAILABLE, mempool_min=0.0000015)
    assert fee == NextBlockFee(100, 150, None)
    assert fee.rate_sat_kvb == 150


@pytest.mark.parametrize(
    "estimate",
    [{"feerate": 1.5, "blocks": 2}, {"feerate": "0.0001", "blocks": 2}, {"feerate": -0.0001}],
)
def test_malformed_advice_is_refused(tmp_path: Path, estimate: dict[str, Any]) -> None:
    with pytest.raises(CoreProtocolError):
        _sample(tmp_path, "signet", estimate)
