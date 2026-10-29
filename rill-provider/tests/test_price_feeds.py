"""Guarded BTC/USD and ETH/USD prices: shapes, freshness, divergence and caching."""

from __future__ import annotations

from fractions import Fraction

import pytest

from rill_provider.price_feeds import (
    KRAKEN_TRADES_URL,
    PriceFeed,
    PriceUnavailableError,
    UsdPrices,
    gas_wei_as_token_base,
    rate_token_base_per_btc,
    usd_as_sats,
)

NOW = 1_793_275_000
MEMPOOL = "https://mempool.example"
PRICES_URL = MEMPOOL + "/api/v1/prices"


def kraken(pair: str, price: str, traded_at: float = NOW - 5.5) -> dict[str, object]:
    return {
        "error": [],
        "result": {pair: [[price, "0.1", traded_at, "b", "l", "", 1]], "last": "1"},
    }


class Sources:
    def __init__(self) -> None:
        self.mempool: object = {"time": NOW - 900, "USD": 80_000, "EUR": 70_000}
        self.btc: object = kraken("XXBTZUSD", "80400.10")
        self.eth: object = kraken("XETHZUSD", "2322.57000")
        self.calls: list[str] = []
        self.fail = False

    def __call__(self, url: str, params: dict[str, str]) -> object:
        self.calls.append(params.get("pair", url))
        if self.fail:
            raise OSError("unreachable")
        if url == PRICES_URL:
            return self.mempool
        assert url == KRAKEN_TRADES_URL
        assert params["count"] == "1"
        return self.btc if params["pair"] == "XBTUSD" else self.eth


class Clock:
    def __init__(self) -> None:
        self.now = float(NOW)

    def __call__(self) -> float:
        return self.now


def feed(sources: Sources, clock: Clock | None = None, *, with_eth: bool = True) -> PriceFeed:
    return PriceFeed(MEMPOOL, with_eth=with_eth, fetch_json=sources, clock=clock or Clock())


def test_valid_sources_give_both_btc_bounds_and_eth() -> None:
    prices = feed(Sources()).prices()
    assert prices == UsdPrices(Fraction(80_000), Fraction("80400.10"), Fraction("2322.57"))


def test_eth_is_fetched_only_when_needed() -> None:
    sources = Sources()
    assert feed(sources, with_eth=False).prices().eth_usd is None
    assert sources.calls == [PRICES_URL, "XBTUSD"]


@pytest.mark.parametrize(
    "mempool",
    [
        {"time": NOW, "USD": 0},  # mempool's unknown sentinels
        {"time": NOW, "USD": -1},
        {"time": NOW, "USD": 80_000.5},
        {"time": NOW, "USD": True},
        {"time": str(NOW), "USD": 80_000},
        {"time": NOW - 3_601, "USD": 80_000},  # older than the refresh cadence
        {"time": NOW + 11, "USD": 80_000},  # from the future
        {"USD": 80_000},
        [],
    ],
)
def test_bad_mempool_documents_decline(mempool: object) -> None:
    sources = Sources()
    sources.mempool = mempool
    with pytest.raises(PriceUnavailableError):
        feed(sources).prices()


@pytest.mark.parametrize(
    "trade",
    [
        kraken("XETHZUSD", "2322.57", NOW - 121),  # stale trade
        kraken("XETHZUSD", "2322.57", NOW + 11),
        kraken("XETHZUSD", "2322.57", float("nan")),
        kraken("XETHZUSD", "0"),
        kraken("XETHZUSD", "-1"),
        kraken("XETHZUSD", "1e3"),
        kraken("XETHZUSD", "NaN"),
        kraken("XXBTZUSD", "2322.57"),  # wrong pair
        {"error": ["EGeneral:Too many requests"], "result": {}},
        {"error": [], "result": {"XETHZUSD": []}},
    ],
)
def test_bad_eth_trades_decline(trade: object) -> None:
    sources = Sources()
    sources.eth = trade
    with pytest.raises(PriceUnavailableError):
        feed(sources).prices()


def test_btc_sources_more_than_two_percent_apart_decline() -> None:
    sources = Sources()
    sources.btc = kraken("XXBTZUSD", "81600.01")
    with pytest.raises(PriceUnavailableError, match="disagree"):
        feed(sources).prices()
    sources.btc = kraken("XXBTZUSD", "81600")
    assert feed(sources).prices().btc_usd_high == 81_600


def test_results_and_failures_are_cached_for_thirty_seconds() -> None:
    sources, clock = Sources(), Clock()
    prices = feed(sources, clock)
    first = prices.prices()
    clock.now += 29
    assert prices.prices() is first
    assert len(sources.calls) == 3
    clock.now += 1
    sources.fail = True
    with pytest.raises(PriceUnavailableError):
        prices.prices()
    calls = len(sources.calls)
    clock.now += 29
    with pytest.raises(PriceUnavailableError, match="recently failed"):
        prices.prices()
    assert len(sources.calls) == calls  # an outage is not hammered
    sources.fail = False
    clock.now += 1
    assert prices.prices() == first


def test_a_cached_price_cannot_outlive_its_source_freshness() -> None:
    sources, clock = Sources(), Clock()
    sources.btc = kraken("XXBTZUSD", "80400.10", NOW - 119)
    prices = feed(sources, clock)
    prices.prices()
    clock.now += 2  # still within the cache TTL, but the source is stale
    with pytest.raises(PriceUnavailableError, match="stale"):
        prices.prices()


def test_a_cold_read_cannot_return_prices_that_expired_while_other_sources_loaded() -> None:
    sources, clock = Sources(), Clock()

    def slow(url: str, params: dict[str, str]) -> object:
        result = sources(url, params)
        if params.get("pair") == "ETHUSD":
            clock.now += 121
        return result

    prices = PriceFeed(MEMPOOL, with_eth=True, fetch_json=slow, clock=clock)
    with pytest.raises(PriceUnavailableError, match="expired"):
        prices.prices()


def test_a_wall_clock_rollback_cannot_extend_the_price_cache() -> None:
    sources, clock = Sources(), Clock()
    prices = feed(sources, clock)
    prices.prices()
    clock.now -= 1
    prices.prices()
    assert len(sources.calls) == 6


@pytest.mark.parametrize(
    "url",
    ["https://", "https://user:password@mempool.example", "https://mempool.example/#fragment"],
)
def test_price_source_urls_must_not_hide_credentials_or_fragments(url: str) -> None:
    with pytest.raises(ValueError, match="https base URL"):
        PriceFeed(url, fetch_json=Sources())


def test_conversions_round_for_the_provider() -> None:
    prices = UsdPrices(Fraction(80_000), Fraction("80400.10"), Fraction("2322.57"))
    # LN to token: the provider pays tokens, at the low BTC price, rounded down.
    assert rate_token_base_per_btc(prices, "provider_buys_btc", 6) == 80_000_000_000
    # Token to LN: the provider receives tokens, at the high BTC price, rounded up.
    assert rate_token_base_per_btc(prices, "provider_sells_btc", 6) == 80_400_100_000
    assert rate_token_base_per_btc(prices, "provider_sells_btc", 0) == 80_401
    # 21000 gas at 1 gwei is 0.000021 ETH = 0.04877397 USD, rounded up in USDC units.
    assert gas_wei_as_token_base(prices, 21_000 * 10**9, 6) == 48_774
    assert usd_as_sats(prices, 1_000, "provider_buys_btc") == 1_250_000
    assert usd_as_sats(prices, 1_000, "provider_sells_btc") == 1_243_779
    with pytest.raises(PriceUnavailableError):
        gas_wei_as_token_base(UsdPrices(Fraction(1), Fraction(1), None), 1, 6)


def test_only_an_https_base_url_is_accepted() -> None:
    for url in ("http://mempool.example", "https://mempool.example/api?x=1"):
        with pytest.raises(ValueError, match="https base URL"):
            PriceFeed(url, fetch_json=Sources())
