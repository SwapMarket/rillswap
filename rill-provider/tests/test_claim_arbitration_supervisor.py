"""The local fallback selector runs even while the normal tick is suspended."""

from __future__ import annotations

import asyncio
from unittest.mock import Mock

import pytest

from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import LiveSessionStoreError


@pytest.mark.parametrize("scenario", ["expiry", "failure", "partial", "clock_rollback"])
def test_supervisor_selects_and_dispatches_without_waiting_for_tick(
    monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    async def exercise() -> None:
        stop = asyncio.Event()
        release_tick = asyncio.Event()
        clock = [1019]
        candidate = Mock()
        settlement = Mock()
        calls: list[tuple[int, bool]] = []
        failures = [0]

        def select(now: int, *, closed_only: bool = False) -> tuple[Mock, ...]:
            calls.append((now, closed_only))
            if closed_only:
                if scenario == "partial":
                    raise LiveSessionStoreError("second candidate failed after first committed")
                return ()
            if scenario == "failure" and failures[0] == 0:
                failures[0] += 1
                raise LiveSessionStoreError("temporary selector failure")
            return (candidate,) if now >= 1020 else ()

        settlement.select_due_fallbacks.side_effect = select
        settlement.recorded_fallbacks.side_effect = (
            (lambda: (candidate,)) if scenario == "partial" else (lambda: ())
        )

        async def broadcast(selected: Mock) -> None:
            assert selected is candidate
            assert not release_tick.is_set()  # main tick is still suspended
            release_tick.set()
            stop.set()

        settlement.broadcast_selected_fallback.side_effect = broadcast
        policy = Mock(relay_urls=())
        service = HandshakeService(
            Mock(), Mock(), Mock(), policy, clock=lambda: clock[0], settlement=settlement
        )

        async def blocked_tick(_relays: object) -> None:
            if scenario == "failure":
                await asyncio.sleep(0.35)
                assert not release_tick.is_set()  # transient error did not shorten the wait
            clock[0] = 0 if scenario == "clock_rollback" else 1020
            await release_tick.wait()

        monkeypatch.setattr(service, "tick", blocked_tick)
        await asyncio.wait_for(service.run(stop, tick_seconds=10), timeout=2)
        assert release_tick.is_set()
        assert calls[0] == (1019, True)  # startup barrier before serving
        if scenario != "partial":
            assert any(now == 1020 and not closed for now, closed in calls)
        if scenario == "clock_rollback":
            assert clock[0] == 0
        if scenario in ("failure", "partial"):
            if scenario == "failure":
                assert any(now == 1019 and not closed for now, closed in calls)
            assert service._deadline_healthy is False  # noqa: SLF001
            settlement.disable_new_exposure.assert_called_once()
            assert await service.handle(b"unprocessed event", []) == "unavailable"
        else:
            settlement.disable_new_exposure.assert_not_called()

    asyncio.run(exercise())
