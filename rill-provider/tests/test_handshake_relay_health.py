"""Relay health logs describe transitions, not every reconnection attempt."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self
from unittest.mock import AsyncMock, Mock

import pytest

from rill_provider import handshake_service
from rill_provider.handshake_service import HandshakeService
from rill_provider.relay_client import RelayError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@dataclass
class _Attempt:
    opening_error: Exception | None = None
    subscription_error: Exception | None = None
    stream_error: Exception | None = None
    stable: bool = False


class _Connection:
    def __init__(self, url: str, attempt: _Attempt, ready: set[str], stop: asyncio.Event) -> None:
        self.url = url
        self.attempt = attempt
        self.ready = ready
        self.stop = stop

    async def __aenter__(self) -> Self:
        if self.attempt.opening_error is not None:
            raise self.attempt.opening_error
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def events(self) -> AsyncIterator[bytes]:
        yield b"ignored"
        if self.attempt.stream_error is not None:
            raise self.attempt.stream_error
        if self.attempt.stable:
            self.ready.add(self.url)
            if len(self.ready) == 2:
                self.stop.set()
            await asyncio.Event().wait()


async def _run_attempts(
    monkeypatch: pytest.MonkeyPatch, attempts: dict[str, list[_Attempt]]
) -> None:
    stop = asyncio.Event()
    ready: set[str] = set()
    scripts = {url: iter(script) for url, script in attempts.items()}
    real_sleep = asyncio.sleep

    def connection(url: str, *, proxy: str | None) -> _Connection:
        assert proxy is None
        return _Connection(url, next(scripts[url]), ready, stop)

    async def subscribe(relay: _Connection) -> None:
        if relay.attempt.subscription_error is not None:
            raise relay.attempt.subscription_error

    async def retry(_delay: float) -> None:
        await real_sleep(0)  # yield fairly without waiting for reconnect backoff

    service = HandshakeService(
        Mock(), Mock(), Mock(), Mock(relay_urls=tuple(attempts), relay_proxy=None)
    )
    monkeypatch.setattr(handshake_service, "RelayConnection", connection)
    monkeypatch.setattr(handshake_service.asyncio, "sleep", retry)
    monkeypatch.setattr(service, "subscribe", subscribe)
    monkeypatch.setattr(service, "tick", AsyncMock())
    monkeypatch.setattr(service, "_has_work", lambda _event: False)
    await asyncio.wait_for(service.run(stop, tick_seconds=10), timeout=2)
    assert ready == set(attempts)
    assert all(next(script, None) is None for script in scripts.values())


@pytest.mark.parametrize("failure", [RelayError, ValueError])
def test_outages_and_recoveries_are_logged_once_per_relay(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure: type[Exception],
) -> None:
    urls = ("ws://first/", "ws://second/")
    attempts = {
        url: [
            _Attempt(),  # initial healthy connection is not a recovery
            _Attempt(opening_error=failure("private opening detail")),
            _Attempt(opening_error=RelayError("private retry detail")),
            _Attempt(subscription_error=ValueError("private subscription detail")),
            _Attempt(stream_error=RelayError("private stream detail")),
            _Attempt(opening_error=failure("private retry detail")),
            _Attempt(stable=True),
        ]
        for url in urls
    }
    with caplog.at_level(logging.INFO, logger=handshake_service.LOG.name):
        asyncio.run(_run_attempts(monkeypatch, attempts))

    first_warning = "relay unavailable" if failure is RelayError else "relay connection failed"
    for url in urls:
        assert [
            (record.levelno, record.getMessage())
            for record in caplog.records
            if record.name == handshake_service.LOG.name and url in record.getMessage()
        ] == [
            (logging.WARNING, f"{first_warning}: {url}"),
            (logging.INFO, f"relay available: {url}"),
            (logging.WARNING, f"relay unavailable: {url}"),
            (logging.INFO, f"relay available: {url}"),
        ]
    assert "private" not in caplog.text


def test_healthy_reconnections_do_not_log_outages_or_recoveries(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    attempts = {
        url: [_Attempt(), _Attempt(), _Attempt(stable=True)]
        for url in ("ws://first/", "ws://second/")
    }
    with caplog.at_level(logging.INFO, logger=handshake_service.LOG.name):
        asyncio.run(_run_attempts(monkeypatch, attempts))
    assert not [record for record in caplog.records if record.name == handshake_service.LOG.name]
