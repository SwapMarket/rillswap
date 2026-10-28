"""Which liquidity each profile's announced amounts follow, and its settings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rill_provider import cli
from rill_provider.operator_config import OperatorConfig, OperatorConfigError, load_config

EXAMPLE = Path(__file__).parents[1] / "examples" / "provider.signet.json"


def _config(profile: str = "btc-to-ln/v1", **terms: object) -> OperatorConfig:
    config = load_config(EXAMPLE)
    return config.model_copy(
        update={
            "handshake": config.handshake.model_copy(update={"profile": profile}),
            "terms": config.terms.model_copy(update=terms),
            "bitcoin_core": config.bitcoin_core.model_copy(update={"wallet": "maker"}),  # type: ignore[union-attr]
        }
    )


def test_following_liquidity_is_the_default_with_a_ten_to_twenty_percent_margin() -> None:
    config = load_config(EXAMPLE)
    assert config.terms.follow_liquidity is True
    assert config.terms.liquidity_margin_percent == (10, 20)
    assert config.service_policy().liquidity_margin_percent == (10, 20)


@pytest.mark.parametrize("margin", [[20, 10], [0, 100], [-1, 5]])
def test_a_margin_outside_zero_to_under_100_percent_is_refused(
    tmp_path: Path, margin: list[int]
) -> None:
    document = json.loads(EXAMPLE.read_text())
    document["terms"]["liquidity_margin_percent"] = margin
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(document))
    with pytest.raises(OperatorConfigError):
        load_config(path)


@pytest.mark.parametrize("profile", ["btc-to-ln/v1", "erc20-to-ln/v1"])
def test_lightning_payouts_follow_the_best_channel(profile: str) -> None:
    source = cli._liquidity(_config(profile))  # noqa: SLF001
    assert source is not None
    assert source.__name__ == "largest_channel_send_sat"


def test_ln_to_btc_follows_the_funding_wallet() -> None:
    source = cli._liquidity(_config("ln-to-btc/v1"))  # noqa: SLF001
    assert source is not None
    assert source.__name__ == "trusted_balance_sat"
    assert source.__self__._wallet_path == "/wallet/maker"  # type: ignore[attr-defined]  # noqa: SLF001


def test_not_following_liquidity_keeps_the_source_for_the_funding_check() -> None:
    config = _config("ln-to-btc/v1", follow_liquidity=False)
    assert config.service_policy().follow_liquidity is False
    source = cli._liquidity(config)  # noqa: SLF001
    assert source is not None
    assert source.__name__ == "trusted_balance_sat"


def test_no_source_keeps_the_configured_bands() -> None:
    assert cli._liquidity(_config("ln-to-erc20/v1")) is None  # noqa: SLF001
    config = _config()
    unpaid = config.model_copy(
        update={"lnd": config.lnd.model_copy(update={"payment_macaroon": None})}  # type: ignore[union-attr]
    )
    assert cli._liquidity(unpaid) is None  # noqa: SLF001
