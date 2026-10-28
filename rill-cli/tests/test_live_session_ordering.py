"""Authenticated provider envelopes cannot cross sequence gaps or conflict."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from test_cooperative_readiness import PROVIDER_SIGNATURE, _context, _request

from rill_cli import live_swap
from rill_cli.live_swap import SwapError, _Session

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from rill_core.wire.messages import Envelope


class _Events:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()

    async def events(self) -> AsyncIterator[bytes]:
        while True:
            yield await self.queue.get()


def _live_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[_Session, _Events, dict[bytes, Envelope]]:
    terms, init, accept = _context()
    crypto = Mock(public_key=lambda _secret: bytes.fromhex("02" + "11" * 32))

    def verify(_key: bytes, _digest: bytes, signature: bytes) -> None:
        if signature != bytes.fromhex(PROVIDER_SIGNATURE):
            raise ValueError("invalid Schnorr signature")

    crypto.schnorr_verify.side_effect = verify
    events = _Events()
    session = _Session(events, crypto, terms.network_identity, timeout=0.1)  # type: ignore[arg-type]
    session.session_id = init.session_id
    session.key = init.client_session_xonly_key
    session.provider_key = accept.provider_session_xonly_key
    session._provider_next = 1  # noqa: SLF001 - authenticated sequence-zero accept fixture
    template = _request(terms, init, accept)
    frames: dict[bytes, Envelope] = {}
    for seq in (1, 2, 3, 17, 18):
        frames[f"seq{seq}".encode()] = template.model_copy(
            update={
                "sequence": seq,
                "message_id": f"{seq:064x}",
                "payload": {"action": "cooperative_claim_ready", "challenge": f"{seq:064x}"},
            }
        )
    frames[b"replay"] = frames[b"seq2"]
    frames[b"conflict-seq"] = frames[b"seq2"].model_copy(update={"message_id": "dd" * 32})
    frames[b"conflict-id"] = frames[b"seq2"].model_copy(
        update={"payload": {"action": "cooperative_claim_ready", "challenge": "ff" * 32}}
    )
    frames[b"forged"] = frames[b"seq2"].model_copy(update={"signature": "00" * 64})
    monkeypatch.setattr(
        live_swap,
        "_decode_gift_wrap_candidate",
        lambda raw, **_kwargs: SimpleNamespace(
            envelope=frames[raw], seal_author_xonly_key=frames[raw].sender_session_key
        ),
    )
    return session, events, frames


def test_receive_next_waits_for_gap_and_drains_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        session, events, frames = _live_provider(monkeypatch)
        first = asyncio.create_task(session.receive_next(timeout=0.2))
        await events.queue.put(b"seq2")
        await asyncio.sleep(0.02)
        assert not first.done()
        await events.queue.put(b"seq1")
        assert await first == frames[b"seq1"]
        assert await session.receive_next(timeout=0.1) == frames[b"seq2"]
        assert session._provider_pending == {}  # noqa: SLF001 - bounded inbox drained
        assert session._inbox_bytes == 0  # noqa: SLF001 - retained bytes drained
        assert session._provider_next == 3  # noqa: SLF001
        await events.queue.put(b"replay")
        with pytest.raises(TimeoutError):
            await session.receive_next(timeout=0.02)
        assert session._provider_next == 3  # noqa: SLF001 - replay grants no effect

    asyncio.run(exercise())


def test_gap_timeout_and_signed_conflicts_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        session, events, frames = _live_provider(monkeypatch)
        await events.queue.put(b"forged")
        await events.queue.put(b"seq2")
        with pytest.raises(TimeoutError):
            await session.receive_next(timeout=0.03)
        assert session._provider_next == 1  # noqa: SLF001 - no effect across gap
        assert len(session._provider_pending) == 1  # noqa: SLF001
        for raw in (b"conflict-seq", b"conflict-id"):
            with pytest.raises(SwapError, match="conflicting sequence or message ID"):
                session._admit(raw)  # noqa: SLF001 - authenticated stream boundary
        assert session._admit(b"replay") is None  # noqa: SLF001 - exact replay
        await events.queue.put(b"seq1")
        assert await session.receive_next(timeout=0.1) == frames[b"seq1"]
        assert await session.receive_next(timeout=0.1) == frames[b"seq2"]
        assert session._inbox_bytes == 0  # noqa: SLF001

    asyncio.run(exercise())


def test_selective_wait_cannot_reverse_later_fifo_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        session, events, frames = _live_provider(monkeypatch)
        await events.queue.put(b"seq2")
        await events.queue.put(b"seq1")
        with pytest.raises(TimeoutError):
            await session.receive(lambda _item: False, timeout=0.02)
        assert await session.receive_next(timeout=0.1) == frames[b"seq1"]
        assert await session.receive_next(timeout=0.1) == frames[b"seq2"]

    asyncio.run(exercise())


def test_future_distance_is_bounded_after_authentication(monkeypatch: pytest.MonkeyPatch) -> None:
    session, _, _ = _live_provider(monkeypatch)
    assert session._admit(b"seq17") is None  # noqa: SLF001 - last allowed future sequence
    with pytest.raises(SwapError, match="bounded live window"):
        session._admit(b"seq18")  # noqa: SLF001 - no unbounded signed reorder buffering


def test_byte_and_message_limits_reject_without_reserving_a_future_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, _, _ = _live_provider(monkeypatch)
    monkeypatch.setattr(live_swap, "MAX_PROVIDER_PENDING_BYTES", 1)
    with pytest.raises(SwapError, match="buffer exhausted"):
        session._admit(b"seq2")  # noqa: SLF001 - no pending authority on limit failure
    assert session._provider_pending == {}  # noqa: SLF001
    assert session._provider_by_sequence == {}  # noqa: SLF001
    assert session.seen == set()
    monkeypatch.setattr(live_swap, "MAX_PROVIDER_PENDING_BYTES", 256 * 1024)
    assert session._admit(b"seq2") is None  # noqa: SLF001
    monkeypatch.setattr(live_swap, "MAX_PROVIDER_MESSAGES", 1)
    with pytest.raises(SwapError, match="bounded live window"):
        session._admit(b"seq1")  # noqa: SLF001 - no ledger mutation when full
    assert session._provider_next == 1  # noqa: SLF001
    assert session._provider_pending.keys() == {2}  # noqa: SLF001
    assert session.seen == {session._provider_pending[2][0].message_id}  # noqa: SLF001


def test_selective_legacy_delivery_still_leaves_earlier_message_fifo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        session, events, frames = _live_provider(monkeypatch)
        await events.queue.put(b"seq2")
        await events.queue.put(b"seq1")
        assert (
            await session.receive(
                lambda item: item.message_id == frames[b"seq2"].message_id, timeout=0.1
            )
            == frames[b"seq2"]
        )
        assert await session.receive_next(timeout=0.1) == frames[b"seq1"]
        assert session._inbox_bytes == 0  # noqa: SLF001

    asyncio.run(exercise())


@pytest.mark.parametrize("limit", ["bytes", "count"])
def test_selectively_retained_inbox_is_bounded(monkeypatch: pytest.MonkeyPatch, limit: str) -> None:
    async def exercise() -> None:
        session, events, _ = _live_provider(monkeypatch)
        if limit == "bytes":
            monkeypatch.setattr(live_swap, "MAX_PROVIDER_INBOX_BYTES", 1)
        else:
            monkeypatch.setattr(live_swap, "MAX_PROVIDER_INBOX_MESSAGES", 1)
        await events.queue.put(b"seq1")
        await events.queue.put(b"seq2")
        with pytest.raises(SwapError, match="live inbox exhausted"):
            await session.receive(lambda _item: False, timeout=0.1)
        if limit == "bytes":
            assert session._inbox_bytes == 0  # noqa: SLF001
        else:
            assert len(session.inbox) == 1
            assert session._inbox_bytes > 0  # noqa: SLF001

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("payload", "shown"),
    [
        ({"code": "capacity_unavailable", "message": "busy"}, "capacity_unavailable"),
        ({"code": "\x1b[2J\x1b]0;pwned\x07", "message": ""}, "malformed error"),
        ({"code": "capacity_unavailable", "message": "\x1b[31mfake\x1b[0m"}, "malformed error"),
        ({"code": ["capacity_unavailable"]}, "malformed error"),
    ],
)
def test_provider_error_codes_reach_the_terminal_only_from_the_closed_set(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, object], shown: str
) -> None:
    async def exercise() -> None:
        session, _events, frames = _live_provider(monkeypatch)
        request = SimpleNamespace(message_id="ab" * 32, message_type="quote_request")
        error = frames[b"seq1"].model_copy(
            update={"message_type": "error", "in_reply_to": request.message_id, "payload": payload}
        )
        session.inbox.append(error)
        session._inbox_bytes += len(canonicalize(error.model_dump(mode="json")))  # noqa: SLF001
        with pytest.raises(SwapError) as refused:
            await session.reply_to(request, "quote_offer")  # type: ignore[arg-type]
        assert str(refused.value) == f"provider refused quote_request: {shown}"
        assert "\x1b" not in str(refused.value)

    asyncio.run(exercise())
