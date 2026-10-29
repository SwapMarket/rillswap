"""Per-quote balance evidence for discounts-only service fees (``balance_pricing``).

Liquidity is sampled before the store transaction, cached briefly so quote
traffic cannot load the backends, and never announced, logged or used to
authorize anything. Any missing or unsupported part prices the normal fee.

The rebate allowance read here is advisory: the store recomputes committed
rebates inside the quote's own transaction, and the firm offer is declined
when its rebate no longer fits the budget.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rill_provider.balance_pricing import (
    BalancePricingError,
    BalanceView,
    ChannelPosition,
    Reserve,
    Trade,
    balance_adjustment_sat,
    dynamic_service_fee,
    quantized_adjustment_sat,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

LOG = logging.getLogger(__name__)

SATS_PER_BTC = 100_000_000
BTC_RESERVE = "btc"
SAMPLE_CACHE_SECONDS = 15.0
# Profiles where the provider pays Lightning and receives the reserve asset.
PAYS_LIGHTNING = frozenset({"btc-to-ln/v1", "erc20-to-ln/v1"})


@dataclass(frozen=True, slots=True)
class FeeLimits:
    """The operator's private ``dynamic_fees`` settings."""

    min_service_fee_ppm: int
    rebate_budget_sat: int
    btc_reserve_target_sat: int | None = None
    stable_reserve_target_usd: int | None = None


@dataclass(frozen=True, slots=True)
class LiquiditySample:
    """Backend balances as intervals: settled low end, pending-credited high end.

    ``reserves`` maps ``"btc"`` to sats, or a token contract to base units.
    """

    outbound_low_sat: int
    outbound_high_sat: int
    capacity_sat: int
    reserves: Mapping[str, tuple[int, int]]


@dataclass(frozen=True, slots=True)
class TokenPricing:
    """How one token reserve converts to sats for this quote (1 token = 1 USD)."""

    contract: str
    decimals: int
    rate_token_base_per_btc: int


@dataclass(frozen=True, slots=True)
class DynamicPricing:
    """One quote's balance evidence, fixed before the store transaction."""

    limits: FeeLimits
    sample: LiquiditySample
    open_volume_sat: int  # this store's open firm offers, same direction
    rebates_committed_sat: int  # advisory; the store rechecks in-transaction

    def service_fee(
        self,
        *,
        profile: str,
        normal_fee_sat: int,
        principal_sat: int,
        token: TokenPricing | None = None,
    ) -> int:
        """Return the signed service fee, or ``normal_fee_sat`` when unpriceable."""
        try:
            view = self._view(profile, token)
        except BalancePricingError:
            return normal_fee_sat
        if view is None or normal_fee_sat <= 0:
            return normal_fee_sat
        reserve = next(iter(view.reserves))
        pays = profile in PAYS_LIGHTNING
        try:
            trade = Trade(
                outbound_delta_sat=-principal_sat if pays else principal_sat,
                reserve=reserve,
                reserve_delta_sat=principal_sat if pays else -principal_sat,
            )
            adjustment = quantized_adjustment_sat(
                balance_adjustment_sat(view, trade), principal_sat
            )
            return dynamic_service_fee(
                normal_fee_sat=normal_fee_sat,
                principal_sat=principal_sat,
                adjustment_sat=adjustment,
                min_service_fee_ppm=self.limits.min_service_fee_ppm,
                rebate_allowance_sat=max(
                    0, self.limits.rebate_budget_sat - self.rebates_committed_sat
                ),
            )
        except BalancePricingError:
            return normal_fee_sat

    def _view(self, profile: str, token: TokenPricing | None) -> BalanceView | None:
        sample, limits = self.sample, self.limits
        if token is None:
            name, target = BTC_RESERVE, limits.btc_reserve_target_sat
            balance = sample.reserves.get(BTC_RESERVE)
        else:
            rate = token.rate_token_base_per_btc
            usd = limits.stable_reserve_target_usd
            name, balance = token.contract, sample.reserves.get(token.contract)
            if usd is None or rate <= 0:
                return None
            target = usd * 10**token.decimals * SATS_PER_BTC // rate
            if balance is not None:
                balance = (balance[0] * SATS_PER_BTC // rate, balance[1] * SATS_PER_BTC // rate)
        if balance is None or target is None or target <= 0:
            return None
        low, high = balance
        outbound_low, outbound_high = sample.outbound_low_sat, sample.outbound_high_sat
        # Open offers widen the intervals toward their pending effect.
        if profile in PAYS_LIGHTNING:
            outbound_low, high = outbound_low - self.open_volume_sat, high + self.open_volume_sat
        else:
            outbound_high, low = outbound_high + self.open_volume_sat, low - self.open_volume_sat
        return BalanceView(
            channels=ChannelPosition(max(0, outbound_low), outbound_high, sample.capacity_sat),
            reserves={name: Reserve(max(0, low), high, target)},
        )


class LiquiditySampler:
    """Cache one blocking backend read, failures included, for a short time."""

    def __init__(
        self,
        read: Callable[[], LiquiditySample],
        *,
        cache_seconds: float = SAMPLE_CACHE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Wrap ``read``; nothing is contacted until the first sample."""
        self._read = read
        self._cache_seconds = cache_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._cached: tuple[float, LiquiditySample | None] | None = None

    def __call__(self) -> LiquiditySample | None:
        """Return the cached or a fresh sample; None while the backends fail."""
        with self._lock:
            now = self._clock()
            if self._cached is not None and now - self._cached[0] < self._cache_seconds:
                return self._cached[1]
            try:
                sample: LiquiditySample | None = self._read()
            except Exception as error:  # noqa: BLE001 - unknown balances price normally
                LOG.warning("liquidity sample unavailable (%s)", type(error).__name__)
                sample = None
            self._cached = (now, sample)
            return sample
