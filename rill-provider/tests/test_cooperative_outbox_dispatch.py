"""Outbox delivery cannot bypass current cooperative proposal authority."""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

from rill_provider import handshake_service
from rill_provider.handshake_service import HandshakeService

if TYPE_CHECKING:
    import pytest


def test_proposal_uses_fresh_tip_not_cached_quote_height() -> None:
    store, tip = Mock(), Mock(return_value=1100)
    store.pending_sendable.side_effect = lambda _message_id, *, now, tip_height=None: (
        now == 1001 and tip_height is not None and tip_height < 1100
    )
    service = HandshakeService(store, Mock(), Mock(), Mock(), clock=lambda: 1001, chain_tip=tip)
    service._state.tip = 1090  # noqa: SLF001 - old indicative quote tip is not authority
    relay = Mock(publish=AsyncMock(return_value=True))
    asyncio.run(service._send_pending("proposal", [relay]))  # noqa: SLF001
    tip.assert_called_once_with()
    store.wrap_pending.assert_not_called()
    relay.publish.assert_not_called()


def test_window_closed_during_wrap_suppresses_publish() -> None:
    store, tip = Mock(), Mock(return_value=1090)
    store.pending_sendable.side_effect = [False, True, False]
    store.wrap_pending.return_value = b"sealed proposal"
    relay = Mock(publish=AsyncMock(return_value=True))
    service = HandshakeService(store, Mock(), Mock(), Mock(), clock=lambda: 1001, chain_tip=tip)
    asyncio.run(service._send_pending("proposal", [relay]))  # noqa: SLF001
    tip.assert_called_once_with()
    store.wrap_pending.assert_called_once()
    relay.publish.assert_not_called()


def test_ordinary_pending_message_never_needs_core() -> None:
    store, tip = Mock(), Mock(side_effect=OSError("Core unavailable"))
    store.pending_sendable.return_value = True
    store.wrap_pending.return_value = b"sealed ordinary reply"
    relay = Mock(publish=AsyncMock(return_value=True))
    service = HandshakeService(store, Mock(), Mock(), Mock(), clock=lambda: 1001, chain_tip=tip)
    asyncio.run(service._send_pending("ordinary", [relay]))  # noqa: SLF001
    tip.assert_not_called()
    relay.publish.assert_awaited_once_with(b"sealed ordinary reply")


def test_hung_tip_is_single_flight_and_does_not_stall_ordinary_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started, release = threading.Event(), threading.Event()
    calls = [0]

    def blocked_tip() -> int:
        calls[0] += 1
        started.set()
        release.wait(timeout=2)
        return 1090

    monkeypatch.setattr(handshake_service, "TIP_LOOKUP_WAIT_SECONDS", 0.02)
    store = Mock()
    store.pending_sendable.side_effect = lambda message_id, **_kwargs: message_id == "ordinary"
    store.wrap_pending.return_value = b"sealed ordinary reply"
    relay = Mock(publish=AsyncMock(return_value=True))
    service = HandshakeService(
        store, Mock(), Mock(), Mock(), clock=lambda: 1001, chain_tip=blocked_tip
    )

    async def scenario() -> None:
        try:
            await service._refresh_tip()  # noqa: SLF001 - shares the pending Core lookup
            assert started.is_set()
            assert service._state.tip is None  # noqa: SLF001
            for _ in range(3):
                await service._send_pending("proposal", [relay])  # noqa: SLF001
            assert calls[0] == 1  # timeout did not cancel the underlying thread
            store.wrap_pending.assert_not_called()
            await service._send_pending("ordinary", [relay])  # noqa: SLF001
            relay.publish.assert_awaited_once_with(b"sealed ordinary reply")
        finally:
            release.set()
            if service._tip_lookup is not None:  # noqa: SLF001 - ensure no test worker leaks
                await asyncio.wait_for(service._tip_lookup, timeout=1)  # noqa: SLF001

    asyncio.run(scenario())
    assert calls[0] == 1


def test_forward_clock_jump_cannot_reopen_window_on_correction() -> None:
    clock = [1019]
    service = HandshakeService(Mock(), Mock(), Mock(), Mock(), clock=lambda: clock[0])
    clock[0] = 1025
    assert service._deadline_now() == 1025  # noqa: SLF001
    clock[0] = 1000
    assert service._deadline_now() == 1025  # noqa: SLF001
