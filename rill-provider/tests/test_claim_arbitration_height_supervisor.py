"""Fresh chain height can end WAITING without delaying its wall-clock fallback."""

from __future__ import annotations

import asyncio
import threading
import time
from unittest.mock import AsyncMock, Mock

import pytest

from rill_provider.handshake_service import HandshakeService


@pytest.mark.parametrize("scenario", ["fresh_height", "hung_core", "stale_height", "zero_height"])
def test_independent_height_sampler_preserves_wall_deadline(  # noqa: PLR0915 - one concurrent supervisor lifecycle
    monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    async def exercise() -> None:  # noqa: PLR0915 - one scheduler and RPC lifecycle
        stop, release_tick, broadcasted = asyncio.Event(), asyncio.Event(), asyncio.Event()
        release_core = threading.Event()
        clock = [1010]
        candidate, settlement = Mock(), Mock()
        settlement.has_current_waiting_claim.return_value = True
        settlement.recover_cooperative_winners.return_value = ()
        settlement.recorded_cooperative_winners.return_value = ()
        settlement.recorded_fallbacks.return_value = ()
        observed: list[int | None] = []
        tip_calls = [0]

        def tip() -> int:
            tip_calls[0] += 1
            if scenario == "hung_core":
                release_core.wait(timeout=5)
            if scenario == "zero_height":
                return 0
            return 1094

        def select(
            now: int, *, closed_only: bool = False, height: int | None = None
        ) -> tuple[Mock, ...]:
            if closed_only:
                return ()
            observed.append(height)
            if scenario == "fresh_height":
                return (candidate,) if height == 1094 else ()
            return (candidate,) if now >= 1030 else ()

        settlement.select_due_fallbacks.side_effect = select

        async def broadcast(selected: Mock) -> None:
            assert selected is candidate
            assert not release_tick.is_set()  # tick is blocked, supervisor owns selection
            broadcasted.set()
            release_tick.set()
            stop.set()

        settlement.broadcast_selected_fallback.side_effect = broadcast
        service = HandshakeService(
            Mock(),
            Mock(),
            Mock(),
            Mock(relay_urls=()),
            clock=lambda: clock[0],
            chain_tip=tip,
            settlement=settlement,
        )
        if scenario == "stale_height":
            monkeypatch.setattr(
                service,
                "_fresh_tip_evidence",
                AsyncMock(return_value=(1094, time.monotonic() - 3)),
            )

        async def hung_tick(_relays: object) -> None:
            if scenario != "fresh_height":
                clock[0] = 1030
            await release_tick.wait()

        monkeypatch.setattr(service, "tick", hung_tick)
        try:
            await asyncio.wait_for(service.run(stop, tick_seconds=10), timeout=2)
        finally:
            release_core.set()  # never strand a fake Core RPC thread after cancellation
        assert broadcasted.is_set()
        if scenario == "fresh_height":
            assert 1094 in observed
            assert clock[0] < 1030
        elif scenario == "hung_core":
            assert tip_calls[0] == 1  # no replacement worker while the first is hung
            assert None in observed
        elif scenario == "stale_height":
            assert None in observed
            assert 1094 not in observed
            assert tip_calls[0] == 0
        else:
            assert None in observed
            assert 0 not in observed
            assert tip_calls[0] >= 1

    asyncio.run(exercise())


def test_no_waiting_window_does_not_poll_core(monkeypatch: pytest.MonkeyPatch) -> None:
    async def exercise() -> None:
        stop = asyncio.Event()
        settlement = Mock()
        settlement.has_current_waiting_claim.return_value = False
        settlement.select_due_fallbacks.return_value = ()
        settlement.recover_cooperative_winners.return_value = ()
        settlement.recorded_cooperative_winners.return_value = ()
        settlement.recorded_fallbacks.return_value = ()
        chain_tip = Mock(return_value=1094)
        service = HandshakeService(
            Mock(),
            Mock(),
            Mock(),
            Mock(relay_urls=()),
            chain_tip=chain_tip,
            settlement=settlement,
        )

        async def blocked_tick(_relays: object) -> None:
            await asyncio.sleep(0.35)
            stop.set()

        monkeypatch.setattr(service, "tick", blocked_tick)
        await asyncio.wait_for(service.run(stop), timeout=2)
        chain_tip.assert_not_called()
        assert settlement.has_current_waiting_claim.call_count >= 1

    asyncio.run(exercise())


def test_fresh_lower_tip_replaces_prior_height_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        stop, release = asyncio.Event(), asyncio.Event()
        settlement = Mock()
        settlement.has_current_waiting_claim.return_value = True
        settlement.recover_cooperative_winners.return_value = ()
        settlement.recorded_cooperative_winners.return_value = ()
        settlement.recorded_fallbacks.return_value = ()
        tip_values = iter((1094, 1092))
        observed: list[int] = []

        def select(_now: int, *, closed_only: bool = False, height: int | None = None) -> tuple[()]:
            if not closed_only and height is not None:
                observed.append(height)
                if height == 1092:
                    stop.set()
                    release.set()
            return ()

        settlement.select_due_fallbacks.side_effect = select
        service = HandshakeService(
            Mock(),
            Mock(),
            Mock(),
            Mock(relay_urls=()),
            clock=lambda: 1010,
            chain_tip=lambda: next(tip_values, 1092),
            settlement=settlement,
        )

        async def hung_tick(_relays: object) -> None:
            await release.wait()

        monkeypatch.setattr(service, "tick", hung_tick)
        await asyncio.wait_for(service.run(stop, tick_seconds=10), timeout=2)
        assert observed[0] == 1094
        assert observed[-1] == 1092

    asyncio.run(exercise())
