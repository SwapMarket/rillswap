"""The private ``dynamic_fees`` operator section and its safety validation."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import ValidationError
from test_cli import _config
from test_evm_operator_config import _evm_config

from rill_provider import cli
from rill_provider._lnd_proto import lightning_pb2 as pb
from rill_provider.core_tx_bytes import CoreTransactionReader
from rill_provider.dynamic_pricing import FeeLimits, LiquiditySample
from rill_provider.lnd_payment_observation import LndProtocolError
from rill_provider.notification_balances import channel_amount_msat
from rill_provider.operator_config import OperatorConfig

if TYPE_CHECKING:
    from pathlib import Path

LND = {"port": 10009, "tls_certificate": "tls.cert", "macaroon": "read.macaroon"}
CORE = {"port": 18443, "cookie_file": "cookie"}
NETWORK_FEES = {"max_feerate_sat_kvb": 50_000, "max_routing_fee_ppm": 1000}
TERMS = {
    "profiles": ["btc-to-ln/v1"],
    "amount_bands": [[1000, 100000]],
    "base_fee_sat": 100,
    "proportional_millionths": 1000,
    "slot": "regtest-main",
    "network_fees": NETWORK_FEES,
}


def _document(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_text())
    return document


def _validate(document: dict[str, Any]) -> OperatorConfig:
    return OperatorConfig.model_validate_json(json.dumps(document))


def _bitcoin(tmp_path: Path, **overrides: Any) -> dict[str, Any]:  # noqa: ANN401 - JSON fields
    fields = {"lnd": LND, "bitcoin_core": CORE, "terms": TERMS} | overrides
    return _document(_config(tmp_path, **fields))


def test_defaults_floor_at_minus_a_tenth_of_a_percent_with_a_bounded_budget(
    tmp_path: Path,
) -> None:
    config = _validate(_bitcoin(tmp_path, dynamic_fees={"btc_reserve_target_sat": 1_000_000}))
    assert config.dynamic_fees is not None
    assert config.dynamic_fees.min_service_fee_ppm == -1000
    assert config.dynamic_fees.rebate_budget_sat_24h == 100_000
    assert _validate(_bitcoin(tmp_path)).dynamic_fees is None


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"terms": TERMS | {"network_fees": None}}, "requires terms.network_fees"),
        ({"dynamic_fees": {}}, "btc_reserve_target_sat"),
        ({"lnd": None}, "requires lnd"),
        ({"terms": TERMS | {"base_fee_sat": 0}}, "positive terms.base_fee_sat"),
        # A floor deeper than the proportional fee would pay round trips.
        ({"terms": TERMS | {"proportional_millionths": 500}}, "smallest proportional fee"),
        ({"dynamic_fees": {"btc_reserve_target_sat": 1, "min_service_fee_ppm": 1}}, "less than"),
        (
            {"dynamic_fees": {"btc_reserve_target_sat": 1, "min_service_fee_ppm": -10_001}},
            "greater than or equal",
        ),
        ({"dynamic_fees": {"btc_reserve_target_sat": 0}}, "greater than 0"),
        ({"dynamic_fees": {"btc_reserve_target_sat": 1, "rebate_budget_sat_24h": -1}}, "greater"),
        ({"dynamic_fees": {"btc_reserve_target_sat": 1, "surprise": 1}}, "Extra inputs"),
    ],
)
def test_unsafe_or_incomplete_settings_are_refused(
    tmp_path: Path, change: dict[str, Any], reason: str
) -> None:
    document = _bitcoin(tmp_path, dynamic_fees={"btc_reserve_target_sat": 1_000_000}) | change
    with pytest.raises(ValidationError, match=reason):
        _validate(document)


def test_evm_profiles_need_a_usd_reserve_target(tmp_path: Path) -> None:
    document = _document(_evm_config(tmp_path)) | {"lnd": LND, "bitcoin_core": CORE}
    with pytest.raises(ValidationError, match="stable_reserve_target_usd"):
        _validate(document | {"dynamic_fees": {}})
    fees = {"stable_reserve_target_usd": 5_000, "min_service_fee_ppm": 0}
    config = _validate(document | {"dynamic_fees": fees})
    assert config.dynamic_fees is not None
    assert config.dynamic_fees.stable_reserve_target_usd == 5_000


def test_the_service_policy_carries_the_private_limits(tmp_path: Path) -> None:
    fees = {"btc_reserve_target_sat": 1_000_000, "rebate_budget_sat_24h": 5_000}
    config = _validate(_bitcoin(tmp_path, dynamic_fees=fees))
    assert config.service_policy().dynamic_fees == FeeLimits(
        min_service_fee_ppm=-1000, rebate_budget_sat=5_000, btc_reserve_target_sat=1_000_000
    )
    assert _validate(_bitcoin(tmp_path)).service_policy().dynamic_fees is None


def _channels(**missing: bool) -> pb.ChannelBalanceResponse:
    amounts = {
        "local_balance": 700_000_000,
        "remote_balance": 300_000_000,
        "unsettled_local_balance": 10_000_999,  # floored to whole sats
        "unsettled_remote_balance": 20_000_000,
    }
    return pb.ChannelBalanceResponse(
        **{
            field: pb.Amount(sat=msat // 1000, msat=msat)
            for field, msat in amounts.items()
            if not missing.get(field)
        }
    )


def test_the_bitcoin_sample_reads_the_channel_interval_and_core_wallet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "lnd_channel_balance", lambda _settings: _channels())
    monkeypatch.setattr(
        CoreTransactionReader, "balance_interval_sat", lambda _self: (400_000, 450_000)
    )
    config = _validate(_bitcoin(tmp_path, dynamic_fees={"btc_reserve_target_sat": 1}))
    sampler = cli._liquidity_sample(config)  # noqa: SLF001
    assert sampler is not None
    # In-flight HTLCs count as gone at the low end and as returned at the high end.
    assert sampler() == LiquiditySample(
        outbound_low_sat=700_000,
        outbound_high_sat=730_000,
        capacity_sat=1_030_000,
        reserves={"btc": (400_000, 450_000)},
    )
    assert cli._liquidity_sample(_validate(_bitcoin(tmp_path))) is None  # noqa: SLF001


def test_an_incomplete_channel_read_prices_normally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    incomplete = _channels(unsettled_remote_balance=True)
    with pytest.raises(LndProtocolError):
        channel_amount_msat(incomplete, "unsettled_remote_balance")
    monkeypatch.setattr(cli, "lnd_channel_balance", lambda _settings: incomplete)
    monkeypatch.setattr(CoreTransactionReader, "balance_interval_sat", lambda _self: (1, 1))
    config = _validate(_bitcoin(tmp_path, dynamic_fees={"btc_reserve_target_sat": 1}))
    sampler = cli._liquidity_sample(config)  # noqa: SLF001
    assert sampler is not None
    assert sampler() is None


def test_the_evm_sample_reads_every_token_pool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pools = {"0x" + "2b" * 20: 5_000_000}
    monkeypatch.setattr(cli, "lnd_channel_balance", lambda _settings: _channels())
    monkeypatch.setattr(cli, "evm_token_balances", lambda _settings: pools)
    document = _document(_evm_config(tmp_path)) | {"lnd": LND}
    config = _validate(document | {"dynamic_fees": {"stable_reserve_target_usd": 5}})
    sampler = cli._liquidity_sample(config)  # noqa: SLF001
    assert sampler is not None
    sample = sampler()
    assert sample is not None
    assert sample.reserves == {"0x" + "2b" * 20: (5_000_000, 5_000_000)}
