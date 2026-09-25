"""Minimal NIP-01 relay connection: publish with OK, one replaceable subscription.

Relay frames are untrusted. This module only enforces frame shape and size and
hands raw event JSON to callers, which must verify it (the NIP-59 decoders do).
Publication success means one relay stored the event, never peer delivery.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from typing import TYPE_CHECKING, Any, Self

import aiohttp

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

MAX_FRAME_BYTES = 256 * 1024  # a 128 KiB event plus relay framing
MAX_QUEUED_EVENTS = 1024
SUBSCRIPTION_ID = "rill-provider"


class RelayError(RuntimeError):
    """The relay connection is unavailable; nothing about peers is implied."""


def _event_json(event: object) -> bytes | None:
    if type(event) is not dict:
        return None
    return json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class RelayConnection:
    """One WebSocket to one relay, owned by one task."""

    def __init__(self, url: str, *, open_timeout: float = 10.0) -> None:
        """Prepare, but do not open, a connection to ``url``."""
        if not url.startswith(("wss://", "ws://")):
            raise RelayError("relay URL must be ws:// or wss://")
        self.url = url
        self._open_timeout = open_timeout
        self._session: aiohttp.ClientSession | None = None
        self._socket: aiohttp.ClientWebSocketResponse | None = None
        self._reader: asyncio.Task[None] | None = None
        self._events: asyncio.Queue[bytes] = asyncio.Queue(MAX_QUEUED_EVENTS)
        self._pending_ok: dict[str, asyncio.Future[bool]] = {}
        self.dropped_events = 0

    async def __aenter__(self) -> Self:
        """Open the socket and start reading frames."""
        timeout = aiohttp.ClientTimeout(total=None, connect=self._open_timeout)
        self._session = aiohttp.ClientSession(timeout=timeout)
        try:
            self._socket = await self._session.ws_connect(
                self.url, max_msg_size=MAX_FRAME_BYTES, heartbeat=30.0
            )
        except (aiohttp.ClientError, TimeoutError):
            await self._session.close()
            raise RelayError("relay unavailable") from None
        self._reader = asyncio.create_task(self._read())
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Close the socket and fail any outstanding publications."""
        if self._reader is not None:
            self._reader.cancel()
            with suppress(asyncio.CancelledError):
                await self._reader
        if self._socket is not None:
            await self._socket.close()
        if self._session is not None:
            await self._session.close()
        self._fail_pending()

    @property
    def closed(self) -> bool:
        """Whether the socket can no longer be used."""
        return self._socket is None or self._socket.closed

    def _fail_pending(self) -> None:
        for future in self._pending_ok.values():
            if not future.done():
                future.set_result(False)
        self._pending_ok.clear()

    async def _send(self, frame: list[Any]) -> None:
        if self._socket is None or self._socket.closed:
            raise RelayError("relay connection closed")
        try:
            await self._socket.send_str(
                json.dumps(frame, ensure_ascii=False, separators=(",", ":"))
            )
        except (aiohttp.ClientError, ConnectionError):
            raise RelayError("relay send failed") from None

    async def _read(self) -> None:
        assert self._socket is not None  # noqa: S101 - set before the task starts
        try:
            async for message in self._socket:
                if message.type != aiohttp.WSMsgType.TEXT:
                    break
                self._dispatch(message.data)
        finally:
            self._fail_pending()

    def _dispatch(self, data: str) -> None:
        try:
            frame = json.loads(data)
        except ValueError:
            return
        if type(frame) is not list or not frame or type(frame[0]) is not str:
            return
        kind = frame[0]
        if kind == "EVENT" and len(frame) == 3 and frame[1] == SUBSCRIPTION_ID:  # noqa: PLR2004
            raw = _event_json(frame[2])
            if raw is None:
                return
            try:
                self._events.put_nowait(raw)
            except asyncio.QueueFull:
                self.dropped_events += 1  # relays replay; the store is idempotent
        elif kind == "OK" and len(frame) >= 3 and type(frame[1]) is str:  # noqa: PLR2004
            future = self._pending_ok.pop(frame[1], None)
            if future is not None and not future.done():
                future.set_result(frame[2] is True)

    async def publish(self, event: bytes, *, timeout: float = 10.0) -> bool:  # noqa: ASYNC109
        """Send one signed event; return True only on an explicit relay OK."""
        parsed = json.loads(event)
        event_id = parsed["id"]
        future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
        self._pending_ok[event_id] = future
        try:
            await self._send(["EVENT", parsed])
            return await asyncio.wait_for(future, timeout)
        except TimeoutError:
            return False
        finally:
            self._pending_ok.pop(event_id, None)

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        """Replace the single subscription (NIP-01 REQ reuses the ID)."""
        await self._send(["REQ", SUBSCRIPTION_ID, *filters])

    async def events(self) -> AsyncIterator[bytes]:
        """Yield raw, UNVERIFIED event JSON until the connection closes."""
        while True:
            getter = asyncio.ensure_future(self._events.get())
            reader = self._reader
            if reader is None:
                getter.cancel()
                return
            done, _ = await asyncio.wait({getter, reader}, return_when=asyncio.FIRST_COMPLETED)
            if getter in done:
                yield getter.result()
                continue
            getter.cancel()
            while not self._events.empty():
                yield self._events.get_nowait()
            return
