"""LN to BTC claim reserves: automatic unless configured, priced from the node."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock

from rill_provider import cli
from rill_provider.core_tx_bytes import CoreTransactionReader, NextBlockFee
from rill_provider.operator_config import OperatorConfig, load_config
from rill_provider.quote_policy import ClaimFeeRate

if TYPE_CHECKING:
    import pytest

EXAMPLE = Path(__file__).parents[1] / "examples" / "provider.signet.json"


def _config(profile: str = "ln-to-btc/v1", **quote: object) -> OperatorConfig:
    config = load_config(EXAMPLE)
    return config.model_copy(
        update={
            "handshake": config.handshake.model_copy(update={"profile": profile}),
            "quote": config.quote.model_copy(update=quote),
        }
    )


def test_an_absent_reserve_is_automatic_and_an_explicit_one_is_kept(tmp_path: Path) -> None:
    # Configs written before automatic pricing never set the reserve.
    assert load_config(EXAMPLE).quote.claim_fee_reserve_sat is None
    assert load_config(EXAMPLE).service_policy().quote.claim_fee_reserve_sat is None
    document = json.loads(EXAMPLE.read_text())
    document.setdefault("quote", {})["claim_fee_reserve_sat"] = 1_000
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(document))
    assert load_config(path).service_policy().quote.claim_fee_reserve_sat == 1_000


def test_automatic_reserves_sample_the_capped_next_block_fee(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = Mock(return_value=NextBlockFee(100, 150, 2_345))
    monkeypatch.setattr(CoreTransactionReader, "next_block_fee", sample)
    source = cli._claim_fee(_config())  # noqa: SLF001
    assert source is not None
    sample.assert_not_called()  # sampled per tick, never at startup
    assert source() == ClaimFeeRate(rate_sat_kvb=2_345, floor_sat_kvb=150)


def test_the_reader_carries_the_operator_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[dict[str, object]] = []
    original = CoreTransactionReader.__init__

    def record(self: CoreTransactionReader, **kwargs: object) -> None:
        built.append(kwargs)
        original(self, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(CoreTransactionReader, "__init__", record)
    config = _config()
    assert cli._claim_fee(config) is not None  # noqa: SLF001
    core = config.bitcoin_core
    assert core is not None
    assert built[-1]["max_fee_estimate_sat_vb"] == core.max_fee_estimate_sat_vb


def test_no_sampling_without_an_automatic_ln_to_btc_reserve() -> None:
    assert cli._claim_fee(_config(claim_fee_reserve_sat=800)) is None  # noqa: SLF001
    assert cli._claim_fee(_config("btc-to-ln/v1")) is None  # noqa: SLF001
    assert cli._claim_fee(_config("ln-to-erc20/v1")) is None  # noqa: SLF001
    assert cli._claim_fee(_config().model_copy(update={"bitcoin_core": None})) is None  # noqa: SLF001
