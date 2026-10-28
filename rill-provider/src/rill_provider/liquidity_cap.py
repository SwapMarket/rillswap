"""Announced amount bands that follow the provider's liquidity.

The announced maximum is the configured maximum whenever liquidity covers it,
and otherwise liquidity less a random margin drawn from a configured percent
range (10-20 by default). It is re-evaluated only when the caller samples
liquidity (each scheduled announcement), in both directions: a fresh margin is
drawn when liquidity no longer covers the cap, or when it has grown so far
that the cap sits more than the largest margin below it. Otherwise the cap
stays, so an unchanged balance is not resampled into revealing itself, and a
provider holding more than ``maximum / (1 - largest margin)`` never reveals
changes to its liquidity. The configured maximum is never exceeded.

Pure state: the caller samples liquidity and publishes the bands.
"""

from __future__ import annotations

import random
from typing import Protocol

BASIS_POINTS = 10_000
MAX_MARGIN_PERCENT = 100

type Bands = tuple[tuple[int, int], ...]


class _Random(Protocol):
    def randint(self, a: int, b: int) -> int: ...


def check_margin_percent(margin: tuple[int, int]) -> tuple[int, int]:
    """Return ``margin`` if it is a ``(low, high)`` percent range below 100."""
    low, high = margin
    if not (type(low) is int and type(high) is int and 0 <= low <= high < MAX_MARGIN_PERCENT):
        raise ValueError("liquidity margin must be 0 <= low <= high < 100 percent")
    return margin


class LiquidityCap:
    """One integer of state: the current cap, or none before the first observation."""

    def __init__(
        self,
        bands: Bands,
        *,
        margin_percent: tuple[int, int] = (10, 20),
        rng: _Random | None = None,
    ) -> None:
        """Cap ``bands`` (the configured terms) by observed liquidity."""
        if not bands or not all(0 < low <= high for low, high in bands):
            raise ValueError("amount bands unsupported")
        low, high = check_margin_percent(margin_percent)
        self._configured = bands
        self._maximum = max(high for _, high in bands)
        self._margin_bp = (low * 100, high * 100)
        self._rng: _Random = rng if rng is not None else random.SystemRandom()
        self._cap: int | None = None

    def observe(self, liquidity_sat: int) -> None:
        """Re-evaluate the cap against one liquidity reading."""
        if type(liquidity_sat) is not int or liquidity_sat < 0:
            raise ValueError("liquidity must be a non-negative integer of satoshis")
        lowest, highest = self._margin_bp
        floor = liquidity_sat * (BASIS_POINTS - highest) // BASIS_POINTS  # largest margin below
        if floor >= self._maximum:
            self._cap = self._maximum  # liquidity is not the bottleneck
        elif self._cap is None or not floor <= self._cap <= liquidity_sat:
            margin = self._rng.randint(lowest, highest)
            drawn = liquidity_sat * (BASIS_POINTS - margin) // BASIS_POINTS
            self._cap = min(self._maximum, drawn)

    def bands(self) -> Bands:
        """Return the bands to announce and admit; empty when none fits the cap."""
        cap = self._cap
        if cap is None:
            return self._configured
        return tuple((low, min(high, cap)) for low, high in self._configured if low <= cap)
