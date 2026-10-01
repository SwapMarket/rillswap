"""Nonrenewing time and height bounds for one reverse cooperative attempt."""

from __future__ import annotations

import math
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


class ReverseCooperationWindow:
    """Bound work after fresh authenticated admission, never authorize admission.

    Construct once under the owner's reverse gate, before any RPC or native
    work. The caller must separately authenticate the original session, burn
    the one-shot identity, and verify financial prerequisites. A window cannot
    prove payment, chain freshness, signing permission, or original provenance.
    It is not serialized or reconstructed after restart. Its clock-only guard
    can fence transport handoff; it does not stop a started RPC or release the
    gate before actual worker drainage.
    """

    def __init__(
        self,
        *,
        signed_deadline_at: int,
        signed_deadline_height: int,
        claim_height_cutoff: int,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Freeze the first admitted proposal's exclusive time and inclusive height bounds."""
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        self._lock = threading.Lock()
        self._stopped = False
        monotonic = monotonic_clock()
        wall = wall_clock()
        if (
            type(signed_deadline_at) is not int
            or type(signed_deadline_height) is not int
            or type(claim_height_cutoff) is not int
            or not math.isfinite(wall)
            or not math.isfinite(monotonic)
            or signed_deadline_at <= wall
            or not 0 < signed_deadline_height <= claim_height_cutoff
        ):
            raise ValueError("invalid reverse cooperation bounds")
        self._wall_deadline = signed_deadline_at
        self._height_deadline = signed_deadline_height
        self._wall_high_water = wall
        self._monotonic_high_water = monotonic
        self._deadline = monotonic + min(30.0, signed_deadline_at - wall)

    @property
    def monotonic_deadline(self) -> float:
        """Frozen timeout boundary; sampling and queued work already consume it."""
        return self._deadline

    def abandon(self) -> None:
        """Permanently refuse further work, without canceling owed settlement."""
        with self._lock:
            self._stopped = True

    def time_allowed(self) -> bool:
        """Check transport timing only, not chain or financial authority."""
        with self._lock:
            return self._time_allowed()

    def _time_allowed(self) -> bool:
        if self._stopped:
            return False
        try:
            wall = self._wall_clock()
            monotonic = self._monotonic_clock()
        except Exception:  # noqa: BLE001 - clock failure cannot grant renewed permission
            self._stopped = True
            return False
        if (
            not math.isfinite(wall)
            or not math.isfinite(monotonic)
            or monotonic < self._monotonic_high_water
        ):
            self._stopped = True
            return False
        self._wall_high_water = max(self._wall_high_water, wall)
        self._monotonic_high_water = max(self._monotonic_high_water, monotonic)
        if (
            self._wall_high_water >= self._wall_deadline
            or self._monotonic_high_water >= self._deadline
        ):
            self._stopped = True
        return not self._stopped

    def check(self, *, tip_height: int) -> None:
        """Recheck before economic effects using independently fresh chain data."""
        with self._lock:
            if type(tip_height) is not int or not 0 <= tip_height <= self._height_deadline:
                self._stopped = True
            if not self._time_allowed():
                raise TimeoutError("reverse cooperation window closed")
