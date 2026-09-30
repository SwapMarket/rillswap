"""Reverse funding wait cannot skip earlier messages or renew its lifetime."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from test_live_session_ordering import _live_provider

from rill_cli import live_reverse_swap
from rill_cli.live_swap import SwapError

CONTRACT = "ab" * 32


async def _wait(session: object, *, timeout: float = 0.1) -> tuple:  # noqa: ASYNC109 - exercise the existing wait's budget
    return await live_reverse_swap._await_funding(  # noqa: SLF001 - bounded original-stream entry point
        session,
        contract=CONTRACT,
        timeout=timeout,
        terms=Mock(),
        provider_key="cd" * 32,
        script=b"script",
        crypto=Mock(),
    )


@pytest.mark.parametrize(
    "case", ["action", "foreign contract", "reply", "invalid observation", "unexpected type"]
)
def test_earlier_context_is_not_skipped_to_a_later_binding(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    async def exercise() -> None:
        session, _, frames = _live_provider(monkeypatch)
        updates = {
            "message_type": "observation",
            "contract_hash": CONTRACT,
            "in_reply_to": None,
            "payload": {"kind": "hold_accepted"},
        }
        if case == "action":
            updates["message_type"] = "action_request"
        elif case == "foreign contract":
            updates["contract_hash"] = "ee" * 32
        elif case == "reply":
            updates["in_reply_to"] = "ef" * 32
        elif case == "invalid observation":
            updates["payload"] = {"kind": "not_a_real_observation"}
        else:
            updates["message_type"] = "ack"
        session._buffer_inbox(frames[b"seq1"].model_copy(update=updates))  # noqa: SLF001 - already admitted FIFO fixture
        session._buffer_inbox(  # noqa: SLF001 - retained authenticated FIFO
            frames[b"seq2"].model_copy(
                update={
                    "message_type": "funding_binding",
                    "contract_hash": CONTRACT,
                    "in_reply_to": None,
                }
            )
        )
        check = Mock(side_effect=AssertionError("a later binding must not be checked"))
        monkeypatch.setattr(live_reverse_swap, "_check_funding", check)
        with pytest.raises(SwapError, match=r"funding (context|message|observation)") as error:
            await _wait(session)
        assert "do not retry payment" in str(error.value)
        assert len(session.inbox) == 1
        assert not session._settlement_active  # noqa: SLF001 - no second consumer remains owned
        check.assert_not_called()

    asyncio.run(exercise())


def test_nonterminal_observations_do_not_renew_the_absolute_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        session, _, frames = _live_provider(monkeypatch)
        for sequence in (1, 2, 3):
            session._buffer_inbox(  # noqa: SLF001 - retained authenticated FIFO
                frames[f"seq{sequence}".encode()].model_copy(
                    update={
                        "message_type": "observation",
                        "contract_hash": CONTRACT,
                        "in_reply_to": None,
                        "payload": {"kind": "claim_broadcast", "claim_txid": "aa" * 32},
                    }
                )
            )
        monkeypatch.setattr(
            live_reverse_swap, "time", Mock(monotonic=Mock(side_effect=[0.0, 0.1, 0.2, 0.3, 0.4]))
        )
        with pytest.raises(SwapError, match="funding not observed in time"):
            await _wait(session, timeout=0.4)
        assert len(session.inbox) == 1

    asyncio.run(exercise())


@pytest.mark.parametrize("boundary", ["before receive", "after receive"])
def test_due_binding_is_not_processed_even_when_buffered(
    monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    async def exercise() -> None:
        session, _, frames = _live_provider(monkeypatch)
        session._buffer_inbox(  # noqa: SLF001 - retained authenticated FIFO
            frames[b"seq1"].model_copy(
                update={
                    "message_type": "funding_binding",
                    "contract_hash": CONTRACT,
                    "in_reply_to": None,
                }
            )
        )
        clock = [0.0, 1.0] if boundary == "before receive" else [0.0, 0.5, 1.0]
        monkeypatch.setattr(live_reverse_swap, "time", Mock(monotonic=Mock(side_effect=clock)))
        check = Mock(side_effect=AssertionError("expired binding must not be verified"))
        monkeypatch.setattr(live_reverse_swap, "_check_funding", check)
        with pytest.raises(SwapError, match="funding not observed in time"):
            await _wait(session, timeout=1)
        check.assert_not_called()
        assert len(session.inbox) == (1 if boundary == "before receive" else 0)

    asyncio.run(exercise())


def test_fifo_observation_then_binding_uses_existing_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        session, _, frames = _live_provider(monkeypatch)
        observation = frames[b"seq1"].model_copy(
            update={
                "message_type": "observation",
                "contract_hash": CONTRACT,
                "in_reply_to": None,
                "payload": {"kind": "claim_broadcast", "claim_txid": "aa" * 32},
            }
        )
        binding = frames[b"seq2"].model_copy(
            update={
                "message_type": "funding_binding",
                "contract_hash": CONTRACT,
                "in_reply_to": None,
            }
        )
        session._buffer_inbox(observation)  # noqa: SLF001
        session._buffer_inbox(binding)  # noqa: SLF001
        marker = (Mock(), "signature", b"exact funded bytes")
        check = Mock(return_value=marker)
        monkeypatch.setattr(live_reverse_swap, "_check_funding", check)
        assert await _wait(session) == marker
        assert check.call_args.args == (binding,)
        assert session.inbox == []

    asyncio.run(exercise())


def test_reverse_funding_cannot_acquire_an_already_owned_settlement_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        session, _, _ = _live_provider(monkeypatch)
        async with session.settlement_stream():
            with pytest.raises(SwapError, match="stream already owned"):
                await _wait(session)
        assert not session._settlement_active  # noqa: SLF001

    asyncio.run(exercise())


def test_provider_timeout_preserves_held_payment_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    async def exercise() -> None:
        session, _, _ = _live_provider(monkeypatch)
        with pytest.raises(SwapError, match="funding not observed in time") as error:
            await _wait(session, timeout=0.01)
        assert "lncli listpayments" in str(error.value)
        assert "do not retry payment" in str(error.value)

    asyncio.run(exercise())


def test_receive_error_is_redacted_and_preserves_payment_guidance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        session, _, _ = _live_provider(monkeypatch)
        session.receive_next = AsyncMock(side_effect=SwapError("sensitive peer details"))
        with pytest.raises(SwapError, match="provider session stopped") as error:
            await _wait(session)
        assert "do not retry payment" in str(error.value)
        assert "sensitive peer details" not in str(error.value)

    asyncio.run(exercise())


def test_cancellation_releases_the_original_stream_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    async def exercise() -> None:
        session, _, _ = _live_provider(monkeypatch)
        running = asyncio.create_task(_wait(session, timeout=10))
        await asyncio.sleep(0)
        assert session._settlement_active  # noqa: SLF001 - sole FIFO consumer
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running
        assert not session._settlement_active  # noqa: SLF001

    asyncio.run(exercise())


@pytest.mark.parametrize("duration", [0, -1, float("nan"), float("inf")])
def test_invalid_reverse_lifetime_is_rejected_before_discovery_or_paying(
    monkeypatch: pytest.MonkeyPatch,
    duration: float,
) -> None:
    async def exercise() -> None:
        discover = AsyncMock(side_effect=AssertionError("no discovery"))
        payer = Mock(side_effect=AssertionError("no payment"))
        monkeypatch.setattr(live_reverse_swap, "discover", discover)
        with pytest.raises(SwapError, match="timeout must be finite and positive"):
            await live_reverse_swap.run_reverse_swap(
                Mock(),
                identity="",
                network=Mock(),
                payout_sat=1,
                decode_invoice=Mock(),
                payer=payer,
                wallet=Mock(),
                write_recovery=Mock(),
                limits=Mock(),
                crypto=Mock(),
                settle_timeout=duration,
            )
        discover.assert_not_called()
        assert payer.mock_calls == []

    asyncio.run(exercise())
