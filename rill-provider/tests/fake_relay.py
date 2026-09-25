"""In-process NIP-01 relay double: stores events, answers OK, serves #p filters."""

from __future__ import annotations

import json
from typing import Any

from aiohttp import WSMsgType, web


class FakeRelay:
    """Test-only relay; accepts everything unless ``reject`` is set."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.reject = False
        self.subscribers: list[tuple[web.WebSocketResponse, str, list[dict[str, Any]]]] = []
        self._runner: web.AppRunner | None = None
        self._sockets: set[web.WebSocketResponse] = set()
        self.url = ""

    async def start(self) -> str:
        app = web.Application()
        app.router.add_get("/", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        port = self._runner.addresses[0][1]
        self.url = f"ws://127.0.0.1:{port}/"
        return self.url

    async def stop(self) -> None:
        for socket in list(self._sockets):
            await socket.close()
        if self._runner is not None:
            await self._runner.cleanup()

    @staticmethod
    def _matches(event: dict[str, Any], filters: list[dict[str, Any]]) -> bool:
        for selector in filters:
            kinds = selector.get("kinds")
            recipients = selector.get("#p")
            tagged = {tag[1] for tag in event["tags"] if tag[0] == "p"}
            if (kinds is None or event["kind"] in kinds) and (
                recipients is None or tagged & set(recipients)
            ):
                return True
        return False

    async def inject(self, event: bytes) -> None:
        parsed = json.loads(event)
        self.events.append(parsed)
        for socket, sub_id, filters in list(self.subscribers):
            if self._matches(parsed, filters) and not socket.closed:
                await socket.send_str(json.dumps(["EVENT", sub_id, parsed]))

    async def _handle(self, request: web.Request) -> web.WebSocketResponse:
        socket = web.WebSocketResponse()
        await socket.prepare(request)
        self._sockets.add(socket)
        async for message in socket:
            if message.type != WSMsgType.TEXT:
                break
            frame = json.loads(message.data)
            if frame[0] == "EVENT":
                event = frame[1]
                await socket.send_str(json.dumps(["OK", event["id"], not self.reject, ""]))
                if not self.reject:
                    await self.inject(json.dumps(event).encode())
            elif frame[0] == "REQ":
                sub_id, filters = frame[1], frame[2:]
                self.subscribers = [s for s in self.subscribers if s[0] is not socket]
                self.subscribers.append((socket, sub_id, filters))
                for event in self.events:
                    if self._matches(event, filters):
                        await socket.send_str(json.dumps(["EVENT", sub_id, event]))
                await socket.send_str(json.dumps(["EOSE", sub_id]))
        self.subscribers = [s for s in self.subscribers if s[0] is not socket]
        self._sockets.discard(socket)
        return socket
