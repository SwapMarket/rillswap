"""Announced amounts follow liquidity down, with a fresh margin per step."""

from __future__ import annotations

import pytest

from rill_provider.liquidity_cap import LiquidityCap, check_margin_percent

BANDS = ((10_000, 10_000_000),)


class _Draws:
    """Deterministic margins in basis points, recording each draw's bounds."""

    def __init__(self, *margins: int) -> None:
        self.margins = list(margins)
        self.calls: list[tuple[int, int]] = []

    def randint(self, a: int, b: int) -> int:
        self.calls.append((a, b))
        return self.margins.pop(0)


def test_configured_bands_until_the_first_reading() -> None:
    assert LiquidityCap(BANDS).bands() == BANDS


def test_ample_liquidity_announces_the_configured_bands_without_a_draw() -> None:
    draws = _Draws()
    cap = LiquidityCap(BANDS, rng=draws)
    cap.observe(12_500_000)  # 20 % below still covers 10M
    assert cap.bands() == BANDS
    cap.observe(50_000_000)
    assert cap.bands() == BANDS
    assert draws.calls == []


def test_the_cap_is_a_random_margin_below_liquidity_within_the_range() -> None:
    draws = _Draws(1_500)
    cap = LiquidityCap(BANDS, rng=draws)
    cap.observe(4_000_000)
    assert cap.bands() == ((10_000, 3_400_000),)
    assert draws.calls == [(1_000, 2_000)]  # 10-20 % in basis points


def test_the_cap_holds_until_liquidity_falls_below_it_then_redraws() -> None:
    draws = _Draws(1_000, 2_000)
    cap = LiquidityCap(BANDS, rng=draws)
    cap.observe(4_000_000)
    assert cap.bands() == ((10_000, 3_600_000),)
    for liquidity in (3_600_000, 3_900_000, 12_000_000):  # covered: nothing to reveal
        cap.observe(liquidity)
        assert cap.bands() == ((10_000, 3_600_000),)
    cap.observe(3_599_999)  # below the announced maximum: a fresh margin
    assert cap.bands() == ((10_000, 2_879_999),)
    assert len(draws.calls) == 2


def test_liquidity_covering_every_band_lifts_the_cap() -> None:
    cap = LiquidityCap(BANDS, rng=_Draws(1_000))
    cap.observe(4_000_000)
    cap.observe(12_499_999)
    assert cap.bands() == ((10_000, 3_600_000),)
    cap.observe(12_500_000)
    assert cap.bands() == BANDS


def test_bands_above_the_cap_are_dropped_and_the_top_one_clamped() -> None:
    bands = ((1_000, 50_000), (100_000, 1_000_000), (2_000_000, 5_000_000))
    cap = LiquidityCap(bands, margin_percent=(0, 0))
    cap.observe(500_000)
    assert cap.bands() == ((1_000, 50_000), (100_000, 500_000))
    cap.observe(100_000)
    assert cap.bands() == ((1_000, 50_000), (100_000, 100_000))
    cap.observe(99_999)
    assert cap.bands() == ((1_000, 50_000),)


def test_nothing_is_served_below_the_smallest_band_until_liquidity_returns() -> None:
    cap = LiquidityCap(BANDS, margin_percent=(10, 10))
    cap.observe(10_000)
    assert cap.bands() == ()
    cap.observe(0)
    assert cap.bands() == ()
    cap.observe(1_000_000)  # recovering is visible anyway: announce again
    assert cap.bands() == ((10_000, 900_000),)


@pytest.mark.parametrize("liquidity", [-1, 1.5, True, None])
def test_invalid_readings_are_refused_and_change_nothing(liquidity: object) -> None:
    cap = LiquidityCap(BANDS, margin_percent=(0, 0))
    cap.observe(2_000_000)
    with pytest.raises(ValueError, match="liquidity"):
        cap.observe(liquidity)  # type: ignore[arg-type]
    assert cap.bands() == ((10_000, 2_000_000),)


@pytest.mark.parametrize("margin", [(-1, 10), (20, 10), (0, 100), (1.0, 2)])
def test_margins_must_be_an_ordered_percent_range_below_100(margin: tuple[int, int]) -> None:
    with pytest.raises(ValueError, match="margin"):
        check_margin_percent(margin)
    with pytest.raises(ValueError, match="margin"):
        LiquidityCap(BANDS, margin_percent=margin)


def test_default_margin_draws_stay_within_ten_to_twenty_percent() -> None:
    for _ in range(200):
        cap = LiquidityCap(BANDS)
        cap.observe(1_000_000)
        ((_, high),) = cap.bands()
        assert 800_000 <= high <= 900_000
