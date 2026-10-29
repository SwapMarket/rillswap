"""Live stablecoin prices and gas charges are one frozen, fail-closed quote input."""

from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.quotes import parse_quote_request
from test_dynamic_pricing import _evm_dynamic
from test_evm_operator_config import EVM as CONFIG_EVM
from test_evm_operator_config import _evm_config
from test_evm_quote_policy import (
    ASSET,
    EVM,
    FORWARD_FIRM,
    FORWARD_INDICATIVE,
    FORWARD_TERMS,
    HOLD,
    RATE,
    REVERSE_FIRM,
    REVERSE_INDICATIVE,
    REVERSE_TERMS,
    _offered,
)
from test_quote_policy import _context, _envelope

from rill_provider import cli
from rill_provider.evm_htlc import EvmBackendError, EvmHtlcClient
from rill_provider.evm_quote_policy import EvmQuotePrices, answer_evm_quote, ln_to_erc20_hold_msat
from rill_provider.evm_settlement import EvmSettlementEngine
from rill_provider.operator_config import OperatorConfig, OperatorConfigError, load_config
from rill_provider.price_feeds import PriceUnavailableError, UsdPrices

if TYPE_CHECKING:
    from pathlib import Path

    from rill_provider.quote_policy import QuoteTerms

PRICING = {"mempool_url": "https://mempool.example", "gas_units": 70_000}
TOKENS = [
    {key: value for key, value in token.items() if key != "rate_token_base_per_btc"}
    for token in CONFIG_EVM["tokens"]  # type: ignore[union-attr]
]
PRICES = UsdPrices(Fraction(80_000), Fraction("80400.10"), Fraction("2322.57"))


def _config(tmp_path: Path, profile: str = "erc20-to-ln/v1", **changes: Any) -> OperatorConfig:  # noqa: ANN401
    return load_config(
        _evm_config(tmp_path, profile, **({"pricing": PRICING, "tokens": TOKENS} | changes))
    )


@pytest.mark.parametrize(
    ("profile", "rate"), [("erc20-to-ln/v1", 80_400_100_000), ("ln-to-erc20/v1", 80_000_000_000)]
)
def test_live_rates_choose_the_btc_bound_worse_for_the_trader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, rate: int
) -> None:
    config = _config(tmp_path, profile)
    feed = Mock()
    feed.prices.return_value = PRICES
    factory = Mock(return_value=feed)
    monkeypatch.setattr(cli, "PriceFeed", factory)
    node = Mock()
    node.gas_price_wei.return_value = 10**9
    source = cli._evm_pricing(config, node)  # noqa: SLF001
    assert source is not None
    feed.prices.assert_not_called()  # no network access at startup
    assert source() == EvmQuotePrices({ASSET.token_contract: rate}, {ASSET.token_contract: 162_580})
    factory.assert_called_once_with(
        "https://mempool.example", proxy=config.relay_proxy, with_eth=True
    )
    assert config.evm is not None
    assert config.evm.rates() == {}  # there is no fixed fallback


def test_fixed_rate_config_keeps_legacy_gas_pricing(tmp_path: Path) -> None:
    config = load_config(_evm_config(tmp_path))
    node = Mock()
    assert cli._evm_pricing(config, node) is None  # noqa: SLF001
    node.gas_price_wei.assert_not_called()


def test_one_live_snapshot_reaches_indicative_and_firm_quotes_without_resampling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    feed = Mock()
    feed.prices.return_value = PRICES
    monkeypatch.setattr(cli, "PriceFeed", Mock(return_value=feed))
    node = Mock()
    node.signer_address = EVM.provider_evm_address
    node.block_number.return_value = 1000
    node.gas_price_wei.return_value = 10**9
    fixed = Mock()
    source = cli._evm_pricing(_config(tmp_path), node)  # noqa: SLF001
    engine = EvmSettlementEngine(
        Mock(),
        node,
        Mock(),
        assets=EVM.assets,
        rates=fixed,
        schedule=EVM.schedule,
        btc_tip=lambda: 850,
        quote_pricing=source,
    )
    terms = replace(FORWARD_TERMS, evm=engine.quote_context())
    indicative = answer_evm_quote(_envelope(FORWARD_INDICATIVE), (), _context(), terms)
    firm = answer_evm_quote(_envelope(FORWARD_FIRM), (), _context(), terms)
    assert firm.message_type == "terms_offer", firm.payload
    economics = _offered(firm).economics.model_dump()
    assert economics == indicative.payload["economics"]
    # ceil(200 sat * 80400.10 USD/BTC * 1e6 / 1e8) + 162580 gas token units.
    assert int(economics["success_fee_token_base"]) == 323_381
    assert int(economics["rate_token_base_per_btc"]) == 80_400_100_000
    feed.prices.assert_called_once()
    node.gas_price_wei.assert_called_once()
    fixed.assert_not_called()


@pytest.mark.parametrize("gas_price", [0, -1, True, "1000000000", 200_000_000_001])
def test_a_bad_or_excessive_gas_price_never_becomes_a_zero_gas_charge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gas_price: object
) -> None:
    feed = Mock()
    feed.prices.return_value = PRICES
    monkeypatch.setattr(cli, "PriceFeed", Mock(return_value=feed))
    node = Mock()
    node.gas_price_wei.return_value = gas_price
    source = cli._evm_pricing(_config(tmp_path), node)  # noqa: SLF001
    assert source is not None
    with pytest.raises(PriceUnavailableError):
        source()


@pytest.mark.parametrize(
    "change",
    [
        {"pricing": None},  # no fixed rate either
        {"tokens": CONFIG_EVM["tokens"]},  # live and fixed are mutually exclusive
        {"pricing": {"mempool_url": "https://mempool.example"}},  # units cannot be guessed
        {"pricing": PRICING | {"gas_units": 0}},
        {"pricing": PRICING | {"max_gas_price_wei": 0}},
        {"pricing": PRICING | {"mempool_url": "http://mempool.example"}},
    ],
)
def test_missing_or_partial_pricing_configuration_is_refused(
    tmp_path: Path, change: dict[str, Any]
) -> None:
    with pytest.raises(OperatorConfigError):
        _config(tmp_path, **change)


@pytest.mark.parametrize("price", [0, -1, True, "1000", 1000])
def test_the_gas_backend_requires_a_positive_integer(price: object) -> None:
    node = EvmHtlcClient(
        rpc_url="http://127.0.0.1:9",
        chain_id=31337,
        htlc_contract="0x" + "11" * 20,
        signer_private_key=None,
    )
    node._web3 = SimpleNamespace(eth=SimpleNamespace(gas_price=price))  # type: ignore[assignment]  # noqa: SLF001
    if type(price) is int and price > 0:
        assert node.gas_price_wei() == price
    else:
        with pytest.raises(EvmBackendError):
            node.gas_price_wei()


@pytest.mark.parametrize("failure", [PriceUnavailableError("stale BTC"), EvmBackendError("gas")])
def test_an_unavailable_live_snapshot_does_not_fall_back_to_fixed_rates(
    failure: Exception,
) -> None:
    fixed = Mock(return_value={ASSET.token_contract: RATE})
    node = Mock()
    node.block_number.return_value = 1000
    node.signer_address = EVM.provider_evm_address
    engine = EvmSettlementEngine(
        Mock(),
        node,
        Mock(),
        assets=EVM.assets,
        rates=fixed,
        schedule=EVM.schedule,
        btc_tip=lambda: 850,
        quote_pricing=Mock(side_effect=failure),
    )
    context = engine.quote_context()
    fixed.assert_not_called()
    assert context.rate(ASSET) is None
    terms = replace(REVERSE_TERMS, evm=context)
    request = parse_quote_request(canonicalize(REVERSE_FIRM | {"extensions": {}}))
    assert ln_to_erc20_hold_msat(terms, request) is None  # type: ignore[arg-type]
    for quote_terms, payloads in (
        (terms, (REVERSE_FIRM, REVERSE_INDICATIVE)),
        (replace(FORWARD_TERMS, evm=context), (FORWARD_FIRM, FORWARD_INDICATIVE)),
    ):
        for payload in payloads:
            answer = answer_evm_quote(_envelope(payload), (), _context(), quote_terms)
            assert answer.payload["code"] == "capacity_unavailable"


@pytest.mark.parametrize("gas", [{}, {ASSET.token_contract: -1}, {ASSET.token_contract: True}])
def test_a_partial_snapshot_cannot_quote_a_rate_without_its_gas_charge(gas: dict[str, int]) -> None:
    context = replace(EVM, network_fees_token_base=gas)
    assert context.rate(ASSET) is None


def _with_gas(terms: QuoteTerms, outbound: int, reserve: int) -> QuoteTerms:
    return replace(
        terms,
        evm=replace(EVM, network_fees_token_base={ASSET.token_contract: 250_000}),
        dynamic=_evm_dynamic(outbound, reserve),
    )


def test_gas_is_added_after_the_forward_discount_and_the_rebate_still_reserves_its_budget() -> None:
    terms = _with_gas(FORWARD_TERMS, 900_000, 0)  # service = -100 sat = -100,000 token units
    context = replace(_context(), rebates_committed_sat=0)
    indicative = answer_evm_quote(_envelope(FORWARD_INDICATIVE), (), context, terms)
    firm = answer_evm_quote(_envelope(FORWARD_FIRM), (), context, terms)
    assert firm.message_type == "terms_offer", firm.payload
    assert firm.rebate_sat == 100  # reserve service rebate even though the total fee is positive
    economics = _offered(firm).economics.model_dump()
    assert economics["success_fee_token_base"] == "150000"  # noqa: S105 - token units, not a password
    assert indicative.payload["economics"] == economics
    no_budget = answer_evm_quote(_envelope(FORWARD_FIRM), (), _context(), terms)
    assert no_budget.payload["code"] == "capacity_unavailable"  # gas does not erase the rebate
    request = FORWARD_FIRM | {
        "limits": FORWARD_FIRM["limits"] | {"max_success_fee_token_base": "149999"}
    }
    refused = answer_evm_quote(_envelope(request), (), context, terms)
    assert refused.payload["code"] == "limits_unsatisfiable"  # cap covers gas too


def test_gas_and_service_are_frozen_together_before_a_reverse_hold() -> None:
    terms = _with_gas(REVERSE_TERMS, 100_000, 10**12)
    context = replace(_context(), rebates_committed_sat=0)
    request = parse_quote_request(canonicalize(REVERSE_FIRM | {"extensions": {}}))
    hold_msat = ln_to_erc20_hold_msat(terms, request)  # type: ignore[arg-type]
    assert hold_msat == 100_150_000  # 100,000 principal -100 service +250 gas
    hold = HOLD.model_copy(update={"amount_msat": str(hold_msat)})
    terms = replace(terms, hold=("lnbcrt1hold", hold))
    indicative = answer_evm_quote(_envelope(REVERSE_INDICATIVE), (), context, terms)
    firm = answer_evm_quote(_envelope(REVERSE_FIRM), (), context, terms)
    assert firm.message_type == "terms_offer", firm.payload
    assert firm.rebate_sat == 100
    economics = _offered(firm).economics.model_dump()
    assert economics["success_fee_sat"] == "150"
    assert indicative.payload["economics"] == economics
