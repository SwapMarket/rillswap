"""Guarded USD prices for stablecoin and gas valuation.

Stablecoins are valued at exactly 1 USD. BTC/USD comes from the operator's
own mempool instance (``/api/v1/prices``); its ``time`` is shared by every
currency and the instance may refresh only hourly, so it is cross-checked
against Kraken's most recent XBT/USD trade. ETH/USD (EVM gas) comes from
Kraken's most recent ETH/USD trade, which carries its own trade time.

Safeguards: bounded requests through the operator's relay proxy when one is
set, strict shapes, finite positive decimals, freshness and future-skew
limits, a maximum divergence between the two BTC sources, a short shared
cache and a cached failure so an outage is not hammered. Any failure raises
``PriceUnavailableError``: callers decline the quote, never substitute zero.

Quotes use whichever BTC price is worse for the trader within the allowed
divergence, so a stale mempool price cannot be arbitraged against the
provider.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass
from fractions import Fraction
from typing import TYPE_CHECKING, Literal

import httpx

if TYPE_CHECKING:
    from collections.abc import Callable

LOG = logging.getLogger(__name__)

MEMPOOL_PRICES_PATH = "/api/v1/prices"
KRAKEN_TRADES_URL = "https://api.kraken.com/0/public/Trades"
KRAKEN_PAIRS = {"btc": ("XBTUSD", "XXBTZUSD"), "eth": ("ETHUSD", "XETHZUSD")}
REQUEST_SECONDS = 5.0
CACHE_SECONDS = 30
MAX_TRADE_AGE_SECONDS = 120
MAX_MEMPOOL_AGE_SECONDS = 3_600  # the instance's own refresh cadence
MAX_FUTURE_SKEW_SECONDS = 10
MAX_BTC_DIVERGENCE = Fraction(2, 100)
MAX_USD_PER_UNIT = 10**9  # far above any plausible price; refuses unit errors
_DECIMAL = re.compile(r"^(0|[1-9][0-9]{0,11})(\.[0-9]{1,12})?$")
WEI_PER_ETH = 10**18
SATS_PER_BTC = 100_000_000

type FetchJson = Callable[[str, dict[str, str]], object]
type Side = Literal["provider_buys_btc", "provider_sells_btc"]


class PriceUnavailableError(RuntimeError):
    """No trustworthy price right now; decline rather than guess."""


@dataclass(frozen=True, slots=True)
class UsdPrices:
    """One validated observation: BTC/USD bounds and optional ETH/USD."""

    btc_usd_low: Fraction
    btc_usd_high: Fraction
    eth_usd: Fraction | None

    def btc_usd(self, side: Side) -> Fraction:
        """Return the BTC price worse for the trader.

        ``provider_buys_btc``: the provider receives BTC/LN for tokens it pays
        out (LN to token), so fewer tokens per BTC: the low bound.
        ``provider_sells_btc``: the provider pays LN for tokens it receives
        (token to LN), so more tokens per BTC: the high bound.
        """
        return self.btc_usd_low if side == "provider_buys_btc" else self.btc_usd_high


def rate_token_base_per_btc(prices: UsdPrices, side: Side, decimals: int) -> int:
    """Return the integer token rate at 1 USD per token, rounded for the provider."""
    scale: int = 10**decimals
    rate = prices.btc_usd(side) * scale
    floor = rate.numerator // rate.denominator
    return floor if side == "provider_buys_btc" else -((-rate.numerator) // rate.denominator)


def gas_wei_as_token_base(prices: UsdPrices, gas_wei: int, decimals: int) -> int:
    """Return the token-unit value of ``gas_wei`` at 1 USD per token, rounded up."""
    if prices.eth_usd is None:
        raise PriceUnavailableError("ETH/USD not observed")
    scale: int = 10**decimals
    value = prices.eth_usd * gas_wei * scale / WEI_PER_ETH
    return -((-value.numerator) // value.denominator)


def usd_as_sats(prices: UsdPrices, usd: int, side: Side) -> int:
    """Return ``usd`` (a balance or target) in sats at the quote's own price.

    Converting a whole stablecoin view at the side's price scales its potential
    against the trader: depleting payouts (``provider_buys_btc``) are valued at
    the low BTC bound, repairing deposits (``provider_sells_btc``) at the high.
    """
    value = Fraction(usd * SATS_PER_BTC) / prices.btc_usd(side)
    return value.numerator // value.denominator


def check_mempool_url(value: str) -> str:
    """Require an HTTPS base URL without credentials, query or fragment."""
    try:
        url = httpx.URL(value)
    except httpx.InvalidURL:
        raise ValueError("mempool price source must be an https base URL") from None
    if (
        url.scheme != "https"
        or not url.host
        or url.username
        or url.password
        or url.query
        or url.fragment
    ):
        raise ValueError("mempool price source must be an https base URL")
    return value


def _decimal(value: object) -> Fraction:
    if isinstance(value, str) and _DECIMAL.fullmatch(value):
        parsed = Fraction(value)
        if 0 < parsed <= MAX_USD_PER_UNIT:
            return parsed
    raise PriceUnavailableError("price malformed")


def _kraken_trade(document: object, pair: str, now: float) -> tuple[Fraction, float]:
    if not (
        isinstance(document, dict)
        and document.get("error") == []
        and isinstance(result := document.get("result"), dict)
        and isinstance(trades := result.get(pair), list)
        and trades
        and isinstance(trade := trades[-1], list)
        and len(trade) >= 3  # noqa: PLR2004 - [price, volume, time, ...]
        and type(trade[2]) in {int, float}
    ):
        raise PriceUnavailableError("Kraken trades malformed")
    traded_at = float(trade[2])
    if not (now - MAX_TRADE_AGE_SECONDS <= traded_at <= now + MAX_FUTURE_SKEW_SECONDS):
        raise PriceUnavailableError("Kraken trade stale")
    return _decimal(trade[0]), traded_at + MAX_TRADE_AGE_SECONDS


def _mempool_usd(document: object, now: float) -> tuple[Fraction, float]:
    if not (
        isinstance(document, dict)
        and type(observed := document.get("time")) is int
        and type(usd := document.get("USD")) is int
        and 0 < usd <= MAX_USD_PER_UNIT  # mempool reports 0 or -1 when unknown
    ):
        raise PriceUnavailableError("mempool prices malformed")
    if not (now - MAX_MEMPOOL_AGE_SECONDS <= observed <= now + MAX_FUTURE_SKEW_SECONDS):
        raise PriceUnavailableError("mempool price stale")
    return Fraction(usd), float(observed + MAX_MEMPOOL_AGE_SECONDS)


class PriceFeed:
    """A cached, thread-safe source of ``UsdPrices`` for one provider process."""

    def __init__(
        self,
        mempool_url: str,
        *,
        proxy: str | None = None,
        with_eth: bool = False,
        fetch_json: FetchJson | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Read from ``mempool_url`` (an ``https://`` base) and Kraken."""
        check_mempool_url(mempool_url)
        self._prices_url = mempool_url.rstrip("/") + MEMPOOL_PRICES_PATH
        self._with_eth = with_eth
        self._fetch: FetchJson = fetch_json or _http_fetcher(proxy)
        self._clock = clock
        self._lock = threading.Lock()
        self._cached: tuple[float, float, UsdPrices | None] | None = None

    def prices(self) -> UsdPrices:
        """Return fresh prices or raise ``PriceUnavailableError`` (blocking)."""
        with self._lock:
            now = self._clock()
            if (
                self._cached is not None
                and 0 <= now - self._cached[0] < CACHE_SECONDS
                and now <= self._cached[1]
            ):
                cached = self._cached[2]
                if cached is None:
                    raise PriceUnavailableError("price sources recently failed")
                return cached
            try:
                prices, fresh_until = self._observe(now)
                # A cold read can consume several RPC deadlines. Never hand
                # a quote prices that expired while the other source loaded.
                if not now <= self._clock() <= fresh_until:
                    raise PriceUnavailableError("price expired during observation")  # noqa: TRY301
            except PriceUnavailableError as error:
                LOG.warning("prices unavailable (%s)", error)
                failed_at = self._clock()
                self._cached = (failed_at, failed_at + CACHE_SECONDS, None)
                raise
            self._cached = (now, fresh_until, prices)
            return prices

    def _observe(self, now: float) -> tuple[UsdPrices, float]:
        try:
            mempool, mempool_until = _mempool_usd(self._fetch(self._prices_url, {}), now)
            kraken, btc_until = self._kraken("btc", now)
            eth, eth_until = self._kraken("eth", now) if self._with_eth else (None, btc_until)
        except PriceUnavailableError:
            raise
        except Exception as error:  # noqa: BLE001 - any transport or JSON failure
            raise PriceUnavailableError(type(error).__name__) from None
        low, high = min(mempool, kraken), max(mempool, kraken)
        if high - low > MAX_BTC_DIVERGENCE * low:
            raise PriceUnavailableError("BTC price sources disagree")
        return (
            UsdPrices(btc_usd_low=low, btc_usd_high=high, eth_usd=eth),
            min(mempool_until, btc_until, eth_until),
        )

    def _kraken(self, asset: str, now: float) -> tuple[Fraction, float]:
        query, pair = KRAKEN_PAIRS[asset]
        document = self._fetch(KRAKEN_TRADES_URL, {"pair": query, "count": "1"})
        return _kraken_trade(document, pair, now)


def _http_fetcher(proxy: str | None) -> FetchJson:
    def fetch(url: str, params: dict[str, str]) -> object:
        with httpx.Client(
            proxy=proxy, timeout=REQUEST_SECONDS, follow_redirects=False, trust_env=False
        ) as client:
            response = client.get(url, params=params, headers={"Accept": "application/json"})
            response.raise_for_status()
            return response.json()

    return fetch
