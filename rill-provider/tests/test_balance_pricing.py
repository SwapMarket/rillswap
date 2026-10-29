"""The balance-aware fee curve: worked examples and the properties that stop abuse."""

from __future__ import annotations

import random

import pytest

from rill_provider.balance_pricing import (
    BalancePricingError,
    BalanceView,
    ChannelPosition,
    Reserve,
    Trade,
    balance_adjustment_sat,
    dynamic_service_fee,
    service_fee_floor_sat,
)

CAPACITY = 4_000_000
TARGET = 1_000_000
AMOUNT = 100_000
FORWARD_NORMAL = 100 + AMOUNT // 1_000  # 100 sat + 0.1 %
REVERSE_NORMAL = 100 + AMOUNT * 5 // 1_000  # 100 sat + 0.5 %


def view(outbound: int, btc: int, *, pending_out: int = 0, pending_in: int = 0) -> BalanceView:
    return BalanceView(
        channels=ChannelPosition(outbound, outbound, CAPACITY),
        reserves={"btc": Reserve(btc - pending_out, btc + pending_in, TARGET)},
    )


def forward(amount: int = AMOUNT) -> Trade:
    """BTC to LN: the provider pays Lightning and receives on-chain BTC."""
    return Trade(outbound_delta_sat=-amount, reserve="btc", reserve_delta_sat=amount)


def reverse(amount: int = AMOUNT) -> Trade:
    """LN to BTC: the provider receives Lightning and pays on-chain BTC."""
    return Trade(outbound_delta_sat=amount, reserve="btc", reserve_delta_sat=-amount)


def fee(normal: int, adjustment: int, *, allowance: int = 10**9, floor_ppm: int = -1_000) -> int:
    return dynamic_service_fee(
        normal_fee_sat=normal,
        principal_sat=AMOUNT,
        adjustment_sat=adjustment,
        min_service_fee_ppm=floor_ppm,
        rebate_allowance_sat=allowance,
    )


@pytest.mark.parametrize(
    ("outbound", "btc", "forward_fee", "reverse_fee"),
    [
        (2_000_000, 2_000_000, 200, 600),  # healthy: normal fees both ways
        (2_000_000, 900_000, 170, 690),  # BTC slightly short
        (2_000_000, 200_000, -100, 1_110),  # BTC deeply short: rebate hits the floor
        (400_000, 2_000_000, 684, 150),  # outbound short: forward surcharged
        (400_000, 200_000, 234, 660),  # both short: the two pressures offset
    ],
)
def test_worked_examples_with_default_fees(
    outbound: int, btc: int, forward_fee: int, reverse_fee: int
) -> None:
    state = view(outbound, btc)
    assert fee(FORWARD_NORMAL, balance_adjustment_sat(state, forward())) == forward_fee
    assert fee(REVERSE_NORMAL, balance_adjustment_sat(state, reverse())) == reverse_fee


def test_healthy_trades_that_stay_healthy_are_unadjusted() -> None:
    state = view(2_000_000, 3_000_000)
    assert balance_adjustment_sat(state, forward(150_000)) == 0
    assert balance_adjustment_sat(state, reverse(150_000)) == 0


def test_crossing_into_scarcity_pays_only_for_the_part_beyond_the_threshold() -> None:
    # BTC sits 10k above target; a 100k payout ends 90k short.
    adjustment = balance_adjustment_sat(view(2_000_000, TARGET + 10_000), reverse())
    assert adjustment == 25  # ceil(0.006 * 90_000**2 / (2 * 1_000_000)) = ceil(24.3)


def test_floor_rounds_toward_zero_and_allowance_bounds_the_rebate() -> None:
    assert service_fee_floor_sat(99_999, -1_000) == -99
    assert service_fee_floor_sat(100_000, 0) == 0
    assert fee(FORWARD_NORMAL, -10_000) == -100
    assert fee(FORWARD_NORMAL, -10_000, allowance=30) == -30
    assert fee(FORWARD_NORMAL, -10_000, allowance=0) == 0
    assert fee(FORWARD_NORMAL, -10_000, floor_ppm=0) == 0
    assert fee(FORWARD_NORMAL, -150) == 50  # above the floor: unchanged


def random_state(rng: random.Random) -> BalanceView:
    outbound = rng.randrange(0, CAPACITY + 1)
    btc = rng.randrange(0, 3 * TARGET)
    return view(outbound, btc)


def test_round_trips_never_pay_less_than_the_normal_fees() -> None:
    """Worsening a balance and repairing it (either order) is never profitable."""
    rng = random.Random(1)  # noqa: S311 - reproducible fixtures, not keys
    for _ in range(2_000):
        state = random_state(rng)
        amount = rng.randrange(1, 500_000)
        position, btc = state.channels.outbound_low_sat, state.reserves["btc"].low_sat
        out = balance_adjustment_sat(state, forward(amount))
        back = balance_adjustment_sat(view(position - amount, btc + amount), reverse(amount))
        assert out + back >= 0
        rev = balance_adjustment_sat(state, reverse(amount))
        undo = balance_adjustment_sat(view(position + amount, btc - amount), forward(amount))
        assert rev + undo >= 0


def test_splitting_a_swap_never_earns_a_larger_discount() -> None:
    rng = random.Random(2)  # noqa: S311 - reproducible fixtures, not keys
    for _ in range(500):
        state = random_state(rng)
        pieces = [rng.randrange(1, 60_000) for _ in range(rng.randrange(2, 6))]
        whole = balance_adjustment_sat(state, forward(sum(pieces)))
        position, btc, total = state.channels.outbound_low_sat, state.reserves["btc"].low_sat, 0
        for piece in pieces:
            total += balance_adjustment_sat(view(position, btc), forward(piece))
            position, btc = position - piece, btc + piece
        assert total >= whole


@pytest.mark.parametrize("trade", [forward(), reverse()])
def test_pending_amounts_only_ever_make_a_quote_more_expensive(trade: Trade) -> None:
    """An attacker's open offers cannot fake a shortage that earns a rebate."""
    rng = random.Random(3)  # noqa: S311 - reproducible fixtures, not keys
    for _ in range(1_000):
        state = random_state(rng)
        position, btc = state.channels.outbound_low_sat, state.reserves["btc"].low_sat
        base = balance_adjustment_sat(state, trade)
        out, into = rng.randrange(0, 800_000), rng.randrange(0, 800_000)
        widened = BalanceView(
            channels=ChannelPosition(position - out, position + into, CAPACITY),
            reserves={"btc": Reserve(btc - out, btc + into, TARGET)},
        )
        assert balance_adjustment_sat(widened, trade) >= base


def test_draining_btc_through_pending_payouts_earns_no_forward_rebate() -> None:
    """Reverse swaps funded but unclaimed stay refundable: the high end keeps them."""
    honest = view(2_000_000, 2_000_000)
    drained = view(2_000_000, 2_000_000, pending_out=1_900_000)
    assert balance_adjustment_sat(honest, forward()) == 0
    assert balance_adjustment_sat(drained, forward()) == 0
    assert balance_adjustment_sat(drained, reverse()) > 0  # but further payouts cost more


def test_unpriceable_inputs_are_refused() -> None:
    with pytest.raises(BalancePricingError):
        ChannelPosition(1, 0, CAPACITY)
    with pytest.raises(BalancePricingError):
        ChannelPosition(0, 0, 0)
    with pytest.raises(BalancePricingError):
        Reserve(0, 0, 0)
    with pytest.raises(BalancePricingError):
        Trade(outbound_delta_sat=1, reserve="btc", reserve_delta_sat=1)
    with pytest.raises(BalancePricingError):
        Trade(outbound_delta_sat=0, reserve="btc", reserve_delta_sat=0)
    with pytest.raises(BalancePricingError, match="reserve not observed"):
        balance_adjustment_sat(view(2_000_000, TARGET), Trade(-1, "usdc", 1))
    with pytest.raises(BalancePricingError):
        fee(0, 0)  # a zero normal fee gives round trips no margin
    for floor_ppm in (-10_001, 1):
        with pytest.raises(BalancePricingError):
            fee(FORWARD_NORMAL, 0, floor_ppm=floor_ppm)
    with pytest.raises(BalancePricingError):
        fee(FORWARD_NORMAL, 0, allowance=-1)
