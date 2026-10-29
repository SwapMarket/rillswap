"""Balance-aware service fees: one shared curve over the provider's liquidity.

Every swap moves the provider's Lightning position and exactly one reserve
(the on-chain BTC wallet or one stablecoin payout pool) in opposite
directions. Each of those components has a convex potential, in satoshis,
that is zero while the component is healthy and grows quadratically with the
distance into scarcity:

* Lightning: outbound liquidity outside the 45-55 % band of usable capacity
  (inbound is the complement, so both sides are covered by one position).
* A reserve: the shortfall below the operator's soft target.

A swap's balance adjustment is the change in total potential it causes,
``Phi(after) - Phi(before)``, i.e. the trade-average of the marginal price
along the way, not the marginal price at either end. Pricing the whole path
makes the result path independent: splitting a swap, or worsening a balance
and then repairing it, can never earn more than the normal fees it pays. A
swap that deepens a shortage pays a surcharge, a swap that repairs one earns a
discount that may take the service fee below zero, down to the operator's
floor and the remaining rebate allowance. Healthy balances keep normal fees.

Balances are intervals, not points. The low end debits every pending output
and the high end credits every pending input, never netting the two. Each
component is priced at whichever end is worse for the trader, so a quote,
open offer or unresolved HTLC can only make later quotes more expensive, never
manufacture a shortage that earns a rebate. Because each potential is convex,
the worst point of an interval is always one of its ends.

Pure arithmetic in exact fractions; the caller supplies sat-equivalent
balances (stablecoins converted at the quote's own rate) and the allowance.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

MILLIONTHS = 1_000_000
# Marginal adjustment, per moved satoshi, at full depletion of a component.
FULL_SHORTAGE_PPM = 6_000
SHORTAGE_RATE = Fraction(FULL_SHORTAGE_PPM, MILLIONTHS)
# Lightning outbound target (half of usable capacity) and healthy half-band.
LN_TARGET = Fraction(1, 2)
LN_HALF_BAND = Fraction(1, 20)
LN_SPAN = LN_TARGET - LN_HALF_BAND  # band edge to an empty side
# Operators may not configure a floor below -1 % (an error, not a policy).
MIN_SERVICE_FEE_PPM_LIMIT = -10_000
DEFAULT_MIN_SERVICE_FEE_PPM = -1_000


class BalancePricingError(ValueError):
    """Inputs that cannot be priced; callers decline the quote."""


@dataclass(frozen=True, slots=True)
class ChannelPosition:
    """Plausible Lightning outbound interval over usable capacity, in sats."""

    outbound_low_sat: int
    outbound_high_sat: int
    capacity_sat: int

    def __post_init__(self) -> None:
        """Refuse an empty capacity or an inverted interval."""
        if not (
            _is_int(self.outbound_low_sat, self.outbound_high_sat, self.capacity_sat)
            and self.capacity_sat > 0
            and self.outbound_low_sat <= self.outbound_high_sat
        ):
            raise BalancePricingError("channel position unsupported")


@dataclass(frozen=True, slots=True)
class Reserve:
    """Plausible balance interval of one reserve and its soft target, in sats."""

    low_sat: int
    high_sat: int
    target_sat: int

    def __post_init__(self) -> None:
        """Refuse a non-positive target or an inverted interval."""
        if not (
            _is_int(self.low_sat, self.high_sat, self.target_sat)
            and self.target_sat > 0
            and self.low_sat <= self.high_sat
        ):
            raise BalancePricingError("reserve unsupported")


@dataclass(frozen=True, slots=True)
class BalanceView:
    """Everything the curve prices against, fixed for one quote."""

    channels: ChannelPosition
    reserves: Mapping[str, Reserve]


@dataclass(frozen=True, slots=True)
class Trade:
    """The provider-side effect of one swap.

    ``outbound_delta_sat`` is positive when the provider receives Lightning
    (LN to BTC or token) and negative when it pays (BTC or token to LN).
    ``reserve_delta_sat`` is the opposite move of the named reserve.
    """

    outbound_delta_sat: int
    reserve: str
    reserve_delta_sat: int

    def __post_init__(self) -> None:
        """Require one move into and one move out of the provider."""
        if not (
            _is_int(self.outbound_delta_sat, self.reserve_delta_sat)
            and (
                self.outbound_delta_sat > 0 > self.reserve_delta_sat
                or self.outbound_delta_sat < 0 < self.reserve_delta_sat
            )
        ):
            raise BalancePricingError("trade must move Lightning and a reserve oppositely")


def _is_int(*values: object) -> bool:
    return all(type(value) is int for value in values)


def _ceil(value: Fraction) -> int:
    return -((-value.numerator) // value.denominator)


def reserve_potential(balance_sat: int, target_sat: int) -> Fraction:
    """Return the potential of one reserve: zero at or above its target."""
    shortfall = max(0, target_sat - balance_sat)
    return SHORTAGE_RATE * shortfall * shortfall / (2 * target_sat)


def channel_potential(outbound_sat: int, capacity_sat: int) -> Fraction:
    """Return the potential of the Lightning position: zero inside the band."""
    low_edge = (LN_TARGET - LN_HALF_BAND) * capacity_sat
    high_edge = (LN_TARGET + LN_HALF_BAND) * capacity_sat
    excess = max(Fraction(0), low_edge - outbound_sat, outbound_sat - high_edge)
    return SHORTAGE_RATE * excess * excess / (2 * LN_SPAN * capacity_sat)


def _worst_change(
    low: int, high: int, delta: int, potential: Callable[[int], Fraction]
) -> Fraction:
    return max(potential(point + delta) - potential(point) for point in (low, high))


def balance_adjustment_sat(view: BalanceView, trade: Trade) -> int:
    """Return the signed adjustment, in sats, rounded against the trader."""
    reserve = view.reserves.get(trade.reserve)
    if reserve is None:
        raise BalancePricingError("reserve not observed")
    channels = view.channels
    change = _worst_change(
        channels.outbound_low_sat,
        channels.outbound_high_sat,
        trade.outbound_delta_sat,
        lambda outbound: channel_potential(outbound, channels.capacity_sat),
    ) + _worst_change(
        reserve.low_sat,
        reserve.high_sat,
        trade.reserve_delta_sat,
        lambda balance: reserve_potential(balance, reserve.target_sat),
    )
    return _ceil(change)


def service_fee_floor_sat(principal_sat: int, min_service_fee_ppm: int) -> int:
    """Return the most negative service fee allowed, rounded toward zero."""
    check_min_service_fee_ppm(min_service_fee_ppm)
    return -((-min_service_fee_ppm * principal_sat) // MILLIONTHS)


def check_min_service_fee_ppm(value: int) -> int:
    """Return ``value`` if it is an allowed floor, in signed millionths."""
    if not (type(value) is int and MIN_SERVICE_FEE_PPM_LIMIT <= value <= 0):
        raise BalancePricingError("minimum service fee must be between -10000 and 0 ppm")
    return value


def dynamic_service_fee(
    *,
    normal_fee_sat: int,
    principal_sat: int,
    adjustment_sat: int,
    min_service_fee_ppm: int,
    rebate_allowance_sat: int,
) -> int:
    """Return the signed service fee: normal fee plus adjustment, bounded below.

    The floor applies to the service component only; expected network costs
    are charged on top by the caller and never discounted. A positive
    ``normal_fee_sat`` is required so every round trip pays a strict margin.
    """
    if not (
        _is_int(normal_fee_sat, principal_sat, adjustment_sat, rebate_allowance_sat)
        and normal_fee_sat > 0
        and principal_sat > 0
        and rebate_allowance_sat >= 0
    ):
        raise BalancePricingError("service fee inputs unsupported")
    floor = max(service_fee_floor_sat(principal_sat, min_service_fee_ppm), -rebate_allowance_sat)
    return max(normal_fee_sat + adjustment_sat, floor)
