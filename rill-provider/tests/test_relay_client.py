"""Relay client frames: explicit OK, replaceable subscription, untrusted input."""

from __future__ import annotations

import asyncio
import json

import pytest
from fake_relay import FakeRelay

from rill_provider.relay_client import SUBSCRIPTION_ID, RelayConnection, RelayError


def _event(event_id: str, recipient: str) -> bytes:
    return json.dumps(
        {
            "id": event_id,
            "pubkey": "aa" * 32,
            "created_at": 1,
            "kind": 1059,
            "tags": [["p", recipient]],
            "content": "x",
            "sig": "bb" * 64,
        }
    ).encode()


async def _next(connection: RelayConnection) -> bytes:
    async for event in connection.events():
        return event
    raise AssertionError("connection closed")


def test_publish_ok_subscription_replay_and_live_events() -> None:
    async def scenario() -> None:
        relay = FakeRelay()
        url = await relay.start()
        try:
            async with RelayConnection(url) as connection:
                assert await connection.publish(_event("01" * 32, "cc" * 32))
                await connection.subscribe([{"kinds": [1059], "#p": ["cc" * 32]}])
                stored = await asyncio.wait_for(_next(connection), 5)
                assert json.loads(stored)["id"] == "01" * 32
                await relay.inject(_event("02" * 32, "dd" * 32))  # not subscribed
                await relay.inject(_event("03" * 32, "cc" * 32))
                live = await asyncio.wait_for(_next(connection), 5)
                assert json.loads(live)["id"] == "03" * 32
                relay.reject = True
                assert not await connection.publish(_event("04" * 32, "cc" * 32))
        finally:
            await relay.stop()

    asyncio.run(scenario())


def test_malformed_and_foreign_frames_are_ignored() -> None:
    async def scenario() -> None:
        relay = FakeRelay()
        url = await relay.start()
        try:
            async with RelayConnection(url) as connection:
                for frame in ("not json", "[]", "[1,2]", '["EVENT","other",{}]', '["EVENT","x"]'):
                    connection._dispatch(frame)  # noqa: SLF001 - frame parser seam
                connection._dispatch(json.dumps(["EVENT", SUBSCRIPTION_ID, "str"]))  # noqa: SLF001
                connection._dispatch(json.dumps(["OK", "unknown", True]))  # noqa: SLF001
                assert connection._events.empty()  # noqa: SLF001
        finally:
            await relay.stop()

    asyncio.run(scenario())


def test_closed_relay_ends_events_and_fails_publication() -> None:
    async def scenario() -> None:
        relay = FakeRelay()
        url = await relay.start()
        async with RelayConnection(url) as connection:
            await relay.stop()
            events = [event async for event in connection.events()]
            assert events == []
            assert connection.closed
            with pytest.raises(RelayError):
                await connection.publish(_event("05" * 32, "cc" * 32))

    asyncio.run(scenario())


def test_unreachable_or_non_websocket_url_is_refused() -> None:
    with pytest.raises(RelayError):
        RelayConnection("https://relay.example/")

    async def scenario() -> None:
        with pytest.raises(RelayError):
            async with RelayConnection("ws://127.0.0.1:9/", open_timeout=2):
                pass

    asyncio.run(scenario())
