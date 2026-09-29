"""Original-session payment dispatch cannot skip actions or renew its lifetime."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from test_cooperative_readiness import PREIMAGE, _context
from test_live_session_ordering import _live_provider

from rill_cli import live_swap
from rill_cli.live_swap import SwapError, SwapLimits, _wait_for_payment, run_swap

RECOVERY_HINT = "funds are committed; inspect the invoice and funded recovery file"


def test_readiness_cannot_be_skipped_to_later_payment(monkeypatch: pytest.MonkeyPatch) -> None:
    async def exercise() -> None:
        terms, _, _ = _context()
        session, events, frames = _live_provider(monkeypatch)
        session.send = AsyncMock()
        readiness = AsyncMock(side_effect=AssertionError("incomplete handler must not echo"))
        monkeypatch.setattr(live_swap, "_answer_cooperative_readiness", readiness)
        frames[b"seq2"] = frames[b"seq2"].model_copy(
            update={
                "message_type": "observation",
                "payload": {"kind": "payment_settled", "payment_preimage": PREIMAGE},
            }
        )
        await events.queue.put(b"seq2")
        await events.queue.put(b"seq1")
        with pytest.raises(
            SwapError, match="cooperation unavailable; payment status unresolved"
        ) as error:
            await _wait_for_payment(
                session,
                terms,
                deadline=asyncio.get_running_loop().time() + 1,
                refund_hint=RECOVERY_HINT,
            )
        assert RECOVERY_HINT in str(error.value)
        readiness.assert_not_called()
        session.send.assert_not_called()
        session.crypto.schnorr_sign.assert_not_called()
        assert await session.receive_next(timeout=0.1) == frames[b"seq2"]

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("variation", "change", "expected"),
    [
        ("wrong contract", {"contract_hash": "ff" * 32}, "settlement context"),
        ("correlated observation", {"in_reply_to": "ff" * 32}, "settlement context"),
        ("unexpected type", {"message_type": "ack"}, "settlement message"),
        ("unknown kind", {"payload": {"kind": "unknown"}}, "invalid provider"),
        ("malformed payment", {"payload": {"kind": "payment_settled"}}, "invalid provider"),
        (
            "wrong preimage",
            {
                "payload": {
                    "kind": "payment_settled",
                    "payment_preimage": "00" * 32,
                }
            },
            "wrong preimage",
        ),
        ("failed payment", {"payload": {"kind": "payment_failed"}}, "payment failed"),
    ],
)
def test_dispatch_errors_preserve_recovery_guidance(
    monkeypatch: pytest.MonkeyPatch,
    variation: str,
    change: dict,
    expected: str,
) -> None:
    async def exercise() -> None:
        terms, _, _ = _context()
        session, events, frames = _live_provider(monkeypatch)
        frames[b"seq1"] = frames[b"seq1"].model_copy(
            update={
                "message_type": "observation",
                "payload": {"kind": "payment_settled", "payment_preimage": PREIMAGE},
            }
            | change
        )
        await events.queue.put(b"seq1")
        with pytest.raises(SwapError, match=expected) as error:
            await _wait_for_payment(
                session,
                terms,
                deadline=asyncio.get_running_loop().time() + 1,
                refund_hint=RECOVERY_HINT,
            )
        assert RECOVERY_HINT in str(error.value), variation

    asyncio.run(exercise())


def test_nonterminal_buffered_observations_do_not_renew_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        terms, _, _ = _context()
        session, _, frames = _live_provider(monkeypatch)
        for sequence in (1, 2, 3):
            session._buffer_inbox(  # noqa: SLF001 - exercise retained provider stream
                frames[f"seq{sequence}".encode()].model_copy(
                    update={
                        "message_type": "observation",
                        "payload": {"kind": "claim_broadcast", "claim_txid": "aa" * 32},
                    }
                )
            )
        clock = Mock(time=Mock(side_effect=[0.0, 0.1, 0.4, 0.5, 1.0]))
        with monkeypatch.context() as patch:
            patch.setattr(live_swap.asyncio, "get_running_loop", lambda: clock)
            with pytest.raises(SwapError, match="settlement not observed in time") as error:
                await _wait_for_payment(session, terms, deadline=1, refund_hint=RECOVERY_HINT)
        assert RECOVERY_HINT in str(error.value)
        assert len(session.inbox) == 1

    asyncio.run(exercise())


@pytest.mark.parametrize("already_expired", [True, False])
def test_expired_lifetime_rejects_buffered_payment(
    monkeypatch: pytest.MonkeyPatch,
    *,
    already_expired: bool,
) -> None:
    async def exercise() -> None:
        terms, _, _ = _context()
        session, _, frames = _live_provider(monkeypatch)
        session._buffer_inbox(  # noqa: SLF001 - exercise retained provider settlement
            frames[b"seq1"].model_copy(
                update={
                    "message_type": "observation",
                    "payload": {"kind": "payment_settled", "payment_preimage": PREIMAGE},
                }
            )
        )
        clock = Mock(time=Mock(side_effect=[1.0] if already_expired else [0.0, 1.0]))
        with monkeypatch.context() as patch:
            patch.setattr(live_swap.asyncio, "get_running_loop", lambda: clock)
            with pytest.raises(SwapError, match="settlement not observed in time"):
                await _wait_for_payment(session, terms, deadline=1, refund_hint=RECOVERY_HINT)
        assert len(session.inbox) == int(already_expired)

    asyncio.run(exercise())


@pytest.mark.parametrize("case", ["timeout", "sequence conflict"])
def test_receive_failure_is_recovery_aware(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def exercise() -> None:
        terms, _, _ = _context()
        session, events, _ = _live_provider(monkeypatch)
        if case == "sequence conflict":
            await events.queue.put(b"seq2")
            await events.queue.put(b"conflict-seq")
        expected = "settlement not observed in time" if case == "timeout" else "session stopped"
        with pytest.raises(SwapError, match=expected) as error:
            await _wait_for_payment(
                session,
                terms,
                deadline=asyncio.get_running_loop().time() + 0.02,
                refund_hint=RECOVERY_HINT,
            )
        assert RECOVERY_HINT in str(error.value)

    asyncio.run(exercise())


def test_invalid_queued_frames_cannot_starve_receive_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        session, events, _ = _live_provider(monkeypatch)
        for _ in range(100):
            events.queue.put_nowait(b"forged")
        clock = Mock(time=Mock(side_effect=[0.0, 0.1, 0.2, 0.3]))
        with monkeypatch.context() as patch:
            patch.setattr(live_swap.asyncio, "get_running_loop", lambda: clock)
            with pytest.raises(TimeoutError):
                await session.receive_next(timeout=0.25)
        # Queued frames never suspended. Expiry was checked inside the ingress
        # loop, independently of asyncio's scheduled timeout callback.
        assert events.queue.qsize() == 97
        assert not session.seen

    asyncio.run(exercise())


@pytest.mark.parametrize("duration", [0, -1, float("nan"), float("inf")])
def test_invalid_lifetime_rejected_before_any_swap_effect(duration: float) -> None:
    async def exercise() -> None:
        terms, _, _ = _context()
        decoder = Mock(
            side_effect=AssertionError("invalid lifetime must fail before invoice decode")
        )
        with pytest.raises(SwapError, match="timeout must be finite and positive"):
            await run_swap(
                Mock(),
                identity="",
                network=terms.network_identity,
                invoice="test invoice",
                decode_invoice=decoder,
                wallet=Mock(),
                write_recovery=Mock(),
                limits=SwapLimits(max_success_fee_sat=1),
                crypto=Mock(),
                settle_timeout=duration,
            )
        decoder.assert_not_called()

    asyncio.run(exercise())
