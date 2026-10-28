"""One bad relay event cannot stop the serving loop; ownership loss still does."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Self
from unittest.mock import AsyncMock, Mock

import pytest

from rill_provider import handshake_service
from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import StaleOwnerError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class _Connection:
    def __init__(self, events: list[bytes]) -> None:
        self._events = events

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def events(self) -> AsyncIterator[bytes]:
        for event in self._events:
            yield event
        await asyncio.Event().wait()  # stay connected until cancelled


def _service(
    monkeypatch: pytest.MonkeyPatch,
    events: list[bytes],
    handle: Any,  # noqa: ANN401
) -> HandshakeService:
    service = HandshakeService(
        Mock(), Mock(), Mock(), Mock(relay_urls=("ws://fake/",), relay_proxy=None)
    )
    monkeypatch.setattr(
        handshake_service, "RelayConnection", lambda *_args, **_kwargs: _Connection(events)
    )
    monkeypatch.setattr(service, "subscribe", AsyncMock())
    monkeypatch.setattr(service, "tick", AsyncMock())
    monkeypatch.setattr(service, "_has_work", lambda _event: True)
    monkeypatch.setattr(service, "handle", handle)
    return service


def test_a_failing_event_is_dropped_and_the_loop_keeps_serving(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def exercise() -> None:
        stop, handled = asyncio.Event(), []

        async def handle(event: bytes, _relays: object) -> str:
            if event.startswith(b"hostile"):
                raise ValueError("secret-bearing detail " + event.decode())
            handled.append(event)
            stop.set()
            return "init-accepted"

        service = _service(monkeypatch, [b"hostile one", b"hostile two", b"honest"], handle)
        with caplog.at_level(logging.WARNING, logger=handshake_service.LOG.name):
            await asyncio.wait_for(service.run(stop, tick_seconds=10), timeout=2)
        assert handled == [b"honest"]
        assert caplog.messages.count("relay event failed: ValueError") == 2
        assert "secret-bearing" not in caplog.text  # type only, never event content

    asyncio.run(exercise())


def test_ownership_loss_in_an_event_still_stops_the_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        async def handle(_event: bytes, _relays: object) -> str:
            raise StaleOwnerError("another owner")

        service = _service(monkeypatch, [b"event"], handle)
        with pytest.raises(StaleOwnerError):
            await asyncio.wait_for(service.run(asyncio.Event(), tick_seconds=10), timeout=2)

    asyncio.run(exercise())


def test_a_failing_deferred_frame_does_not_drop_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        handled = []

        async def handle(event: bytes, _relays: object) -> str:
            if event == b"hostile":
                raise TypeError("not an object")
            handled.append(event)
            return "request-answered"

        service = _service(monkeypatch, [], handle)
        session = "aa" * 32
        service._state.deferred = [  # noqa: SLF001 - frames held until the confirm
            (session, "01", 0, b"hostile"),
            (session, "02", 0, b"honest"),
        ]
        await service._handle_deferred(session, [])  # noqa: SLF001
        assert handled == [b"honest"]
        assert service._state.deferred == []  # noqa: SLF001

    asyncio.run(exercise())
