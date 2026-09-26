"""Minimal NIP-01 relay connection: publish with OK, one replaceable subscription.

Relay frames are untrusted. This module only enforces frame shape and size and
hands raw event JSON to callers, which must verify it (the NIP-59 decoders do).
Publication success means one relay stored the event, never peer delivery.

Relay routing fails closed. On public networks a connection must go through a
local HTTP CONNECT proxy (Tor's ``HTTPTunnelPort``) unless direct connections
are explicitly allowed; there is never a silent fallback to a direct socket.
The proxy receives the relay host name, so no local DNS lookup reveals it.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit

import aiohttp

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from rill_core.wire.types import NetworkIdentity

MAX_FRAME_BYTES = 256 * 1024  # a 128 KiB event plus relay framing
MAX_QUEUED_EVENTS = 1024
SUBSCRIPTION_ID = "rill-provider"


class RelayError(RuntimeError):
    """The relay connection is unavailable; nothing about peers is implied."""


def relay_proxy(proxy: str | None) -> str | None:
    """Return a checked loopback ``http://host:port`` proxy URL, or ``None``."""
    if proxy is None:
        return None
    try:
        parts = urlsplit(proxy)
        port = parts.port
    except ValueError:
        port = None
        parts = None
    if (
        parts is None
        or parts.scheme != "http"
        or parts.hostname not in ("127.0.0.1", "::1")
        or port is None
        or parts.username is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise RelayError("relay proxy must be a loopback http://host:port (Tor HTTPTunnelPort)")
    return proxy


def require_relay_route(
    network: NetworkIdentity, proxy: str | None, *, allow_direct: bool
) -> str | None:
    """Refuse direct relay sockets on public networks unless explicitly allowed.

    A direct socket reveals the operator's or user's IP address to every relay.
    Regtest is local test infrastructure and may connect directly.
    """
    checked = relay_proxy(proxy)
    if checked is None and network.name != "regtest" and not allow_direct:
        raise RelayError(
            "public networks need a relay proxy; direct relay sockets must be allowed explicitly"
        )
    return checked


def _event_json(event: object) -> bytes | None:
    if type(event) is not dict:
        return None
    try:
        return json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError):
        return None  # e.g. lone surrogates from a hostile relay


class RelayConnection:
    """One WebSocket to one relay, owned by one task."""

    def __init__(self, url: str, *, open_timeout: float = 10.0, proxy: str | None = None) -> None:
        """Prepare, but do not open, a connection to ``url``."""
        if not url.startswith(("wss://", "ws://")):
            raise RelayError("relay URL must be ws:// or wss://")
        self._proxy = relay_proxy(proxy)
        if self._proxy is not None and not url.startswith("wss://"):
            # aiohttp only tunnels TLS targets with CONNECT; a plain ws:// request
            # would be forwarded in cleartext rather than tunneled.
            raise RelayError("a proxied relay must use wss://")
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
        # trust_env=False: environment proxies never silently reroute or bypass.
        self._session = aiohttp.ClientSession(timeout=timeout, trust_env=False)
        try:
            self._socket = await self._session.ws_connect(
                self.url, max_msg_size=MAX_FRAME_BYTES, heartbeat=30.0, proxy=self._proxy
            )
        except (aiohttp.ClientError, TimeoutError):
            await self._session.close()
            raise RelayError("relay unavailable") from None
        except BaseException:  # cancellation while opening: do not leak the session
            await self._session.close()
            raise
        self._reader = asyncio.create_task(self._read())
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Close the socket and fail any outstanding publications."""
        if self._reader is not None:
            self._reader.cancel()
            with suppress(asyncio.CancelledError, Exception):  # reader faults = closed relay
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
        except (aiohttp.ClientError, ConnectionError, ValueError):
            pass  # a broken or hostile relay only ends this connection
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
        reader = self._reader
        if reader is None:
            return
        while True:
            getter = asyncio.ensure_future(self._events.get())
            try:
                await asyncio.wait({getter, reader}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                if not getter.done():
                    getter.cancel()
                    await asyncio.gather(getter, return_exceptions=True)
            if not getter.cancelled():
                yield getter.result()
                continue
            while not self._events.empty():
                yield self._events.get_nowait()
            return
            done, _ = await asyncio.wait({getter, reader}, return_when=asyncio.FIRST_COMPLETED)
            if getter in done:
                yield getter.result()
                continue
            getter.cancel()
            while not self._events.empty():
                yield self._events.get_nowait()
            return
