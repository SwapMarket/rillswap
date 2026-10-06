"""Original bound-debt resampling, not generic financial RPC retries.

Controller tests use mocked invoice observations and settlement callbacks with
the existing native reservation fixture. Adapter tests separately count dispatch.
Neither substitutes for actual funded conformance.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.messages import Envelope
from test_reverse_cosign_orchestration import _cosign, _funded_engine, native_marks
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider import reverse_settlement
from rill_provider.live_session_store import LiveSessionStoreError, StaleOwnerError
from rill_provider.lnd_hold_invoice import _BoundInvoiceSyncBeforeSubmissionError
from rill_provider.lnd_payment_observation import (
    LndNotSyncedError,
    LndProtocolError,
    LndUnavailableError,
)

if TYPE_CHECKING:
    from test_reverse_proposal_reservation import ReservationCase

pytestmark = native_marks
# ruff: noqa: SLF001 - original native reservation and explicit private boundaries


def _no_reply(reserved: ReservationCase, begin: Mock) -> None:
    begin.assert_not_called()
    assert reserved.store._connection.execute(
        "SELECT state FROM cooperation_attempts"
    ).fetchone() == ("BURNED",)
    assert (
        reserved.store._connection.execute(
            "SELECT 1 FROM outbox WHERE in_reply_to=?",
            (Envelope.model_validate_json(reserved.document, strict=True).message_id,),
        ).fetchone()
        is None
    )


@pytest.mark.parametrize("refusals", [1, 2, 3])
def test_original_debt_sync_refusals_then_one_repayment_and_one_archived_nonce(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch, refusals: int
) -> None:
    async def exercise() -> None:
        engine, _, hold = _funded_engine(reserved)
        crypto = reserved.origin.crypto.crypto
        begin = Mock(wraps=crypto.musig_begin)
        monkeypatch.setattr(crypto, "musig_begin", begin)
        attempts = 0
        successes = 0
        windows: list[object] = []

        def settle(*_args: object, **_kwargs: object) -> None:
            nonlocal attempts, successes
            attempts += 1
            if attempts <= refusals:
                raise _BoundInvoiceSyncBeforeSubmissionError("pre-submit sync refusal")
            successes += 1

        async def pause(seconds: float) -> None:
            assert seconds == reverse_settlement.TIP_AGREEMENT_PAUSE_SECONDS
            window = next(iter(reserved.store._reverse_proposals.values())).window
            windows.append(window)
            reserved.clock.advance(seconds)

        hold.settle_bound_invoice.side_effect = settle
        monkeypatch.setattr(reverse_settlement.asyncio, "sleep", pause)
        reply = await _cosign(engine, reserved)
        assert reply is not None
        assert attempts == refusals + 1
        assert successes == 1
        assert begin.call_count == 1
        assert len(windows) == refusals
        assert all(window is windows[0] for window in windows)
        assert reserved.store._connection.execute(
            "SELECT state,preimage FROM swaps"
        ).fetchone() == ("SETTLED", "52" * 32)
        assert await _cosign(engine, reserved) == reply
        assert attempts == refusals + 1
        assert begin.call_count == 1
        hold.settle.assert_not_called()

    asyncio.run(exercise())


def test_persistent_no_submission_sync_refusals_stop_after_four_attempts(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise() -> None:
        engine, _, hold = _funded_engine(reserved)
        begin = Mock(side_effect=AssertionError("no nonce for unpaid debt"))
        monkeypatch.setattr(reserved.origin.crypto.crypto, "musig_begin", begin)
        hold.settle_bound_invoice.side_effect = _BoundInvoiceSyncBeforeSubmissionError("sync")

        async def pause(seconds: float) -> None:
            reserved.clock.advance(seconds)

        monkeypatch.setattr(reverse_settlement.asyncio, "sleep", pause)
        with pytest.raises(LiveSessionStoreError):
            await _cosign(engine, reserved)
        assert hold.settle_bound_invoice.call_count == 4
        hold.observe_bound_settled_invoice.assert_not_called()
        _no_reply(reserved, begin)
        assert await _cosign(engine, reserved) is None
        assert hold.settle_bound_invoice.call_count == 4

    asyncio.run(exercise())


@pytest.mark.parametrize("failure", ["generic_sync", "unavailable", "protocol", "post_submit"])
def test_generic_and_ambiguous_errors_never_authorize_cooperative_resampling(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    async def exercise() -> None:
        engine, _, hold = _funded_engine(reserved)
        begin = Mock(side_effect=AssertionError("no nonce on uncertain settlement"))
        monkeypatch.setattr(reserved.origin.crypto.crypto, "musig_begin", begin)
        error = {
            "generic_sync": LndNotSyncedError("unknown backend provenance"),
            "unavailable": LndUnavailableError("unknown outcome"),
            "protocol": LndProtocolError("correspondence refused"),
            "post_submit": TimeoutError("unknown outcome after dispatch"),
        }[failure]
        hold.settle_bound_invoice.side_effect = error
        pause = Mock(side_effect=AssertionError("no resampling for generic failures"))
        monkeypatch.setattr(reverse_settlement.asyncio, "sleep", pause)
        with pytest.raises(type(error)):
            await _cosign(engine, reserved)
        hold.settle_bound_invoice.assert_called_once()
        pause.assert_not_called()
        _no_reply(reserved, begin)
        assert await _cosign(engine, reserved) is None
        hold.settle_bound_invoice.assert_called_once()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "failure",
    ["expired", "cancelled", "empty_funded", "binding_absent", "binding_mismatch", "owner_lost"],
)
def test_original_authority_refusal_prevents_any_retry_dispatch(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    async def exercise() -> None:
        engine, _, hold = _funded_engine(reserved)
        begin = Mock(side_effect=AssertionError("no renewed signing authority"))
        monkeypatch.setattr(reserved.origin.crypto.crypto, "musig_begin", begin)
        hold.settle_bound_invoice.side_effect = _BoundInvoiceSyncBeforeSubmissionError("sync")

        async def pause(_seconds: float) -> None:
            if failure == "expired":
                reserved.clock.advance(31)
            elif failure == "cancelled":
                raise asyncio.CancelledError
            elif failure == "empty_funded":
                monkeypatch.setattr(reserved.store, "settlement_work", lambda **_: ())
            elif failure == "owner_lost":
                reserved.store.close()
            elif failure == "binding_mismatch":
                binding = reserved.store._reverse_repayment_binding(reserved.origin.session_id)
                assert binding is not None
                wrong = binding.model_copy(update={"amount_msat": "1"})
                monkeypatch.setattr(reserved.store, "_reverse_repayment_binding", lambda _: wrong)
            else:
                monkeypatch.setattr(reserved.store, "_reverse_repayment_binding", lambda _: None)

        monkeypatch.setattr(reverse_settlement.asyncio, "sleep", pause)
        expected = (
            asyncio.CancelledError
            if failure == "cancelled"
            else StaleOwnerError
            if failure == "owner_lost"
            else LiveSessionStoreError
        )
        with pytest.raises(expected):
            await _cosign(engine, reserved)
        hold.settle_bound_invoice.assert_called_once()
        hold.settle.assert_not_called()
        if failure == "owner_lost":
            begin.assert_not_called()
        else:
            _no_reply(reserved, begin)

    asyncio.run(exercise())


def test_concurrently_repaid_original_debt_requires_positive_settled_join_no_extra_dispatch(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise() -> None:
        engine, _, hold = _funded_engine(reserved)
        hold.settle_bound_invoice.side_effect = [
            _BoundInvoiceSyncBeforeSubmissionError("sync"),
            None,
        ]
        crypto = reserved.origin.crypto.crypto
        begin = Mock(wraps=crypto.musig_begin)
        monkeypatch.setattr(crypto, "musig_begin", begin)

        async def concurrent_repayment(_seconds: float) -> None:
            # Model another legitimate debt caller, not an observed production
            # race. Use the real state transition, never mutate stored rows.
            work = reserved.store.settlement_work(session_id=reserved.origin.session_id)
            assert len(work) == 1
            assert await engine.advance(work[0], 1_700_000_001) == "SETTLED"

        monkeypatch.setattr(reverse_settlement.asyncio, "sleep", concurrent_repayment)
        reply = await _cosign(engine, reserved)
        assert reply is not None
        assert hold.settle_bound_invoice.call_count == 2
        assert begin.call_count == 1
        assert await _cosign(engine, reserved) == reply
        assert hold.settle_bound_invoice.call_count == 2
        assert begin.call_count == 1

    asyncio.run(exercise())


def test_expiration_while_waiting_for_the_owner_gate_prevents_retry_work(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise() -> None:
        engine, _, hold = _funded_engine(reserved)
        hold.settle_bound_invoice.side_effect = _BoundInvoiceSyncBeforeSubmissionError("sync")
        begin = Mock(side_effect=AssertionError("expired gate wait grants no nonce"))
        monkeypatch.setattr(reserved.origin.crypto.crypto, "musig_begin", begin)
        entered, release = asyncio.Event(), asyncio.Event()
        task: asyncio.Task[None] | None = None

        async def gate_owner() -> None:
            async with reserved.store.reverse_operations.operation():
                entered.set()
                await release.wait()

        async def pause(_seconds: float) -> None:
            nonlocal task
            task = asyncio.create_task(gate_owner())
            await entered.wait()

            def expire_before_release() -> None:
                reserved.clock.advance(31)
                release.set()

            asyncio.get_running_loop().call_soon(expire_before_release)

        monkeypatch.setattr(reverse_settlement.asyncio, "sleep", pause)
        try:
            with pytest.raises(LiveSessionStoreError):
                await _cosign(engine, reserved)
            hold.settle_bound_invoice.assert_called_once()
            _no_reply(reserved, begin)
        finally:
            release.set()
            if task is not None:
                await task

    asyncio.run(exercise())


def test_late_successful_retry_retains_original_debt_settlement_without_signing(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise() -> None:
        engine, _, hold = _funded_engine(reserved)
        attempts = 0

        def settle(*_args: object, **_kwargs: object) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise _BoundInvoiceSyncBeforeSubmissionError("sync")
            reserved.clock.advance(31)  # Known repayment success, not signing authority.

        async def pause(seconds: float) -> None:
            reserved.clock.advance(seconds)

        hold.settle_bound_invoice.side_effect = settle
        begin = Mock(side_effect=AssertionError("late repayment grants no nonce"))
        monkeypatch.setattr(reserved.origin.crypto.crypto, "musig_begin", begin)
        monkeypatch.setattr(reverse_settlement.asyncio, "sleep", pause)
        with pytest.raises(LiveSessionStoreError):
            await _cosign(engine, reserved)
        assert attempts == 2
        assert reserved.store._connection.execute(
            "SELECT state,preimage FROM swaps"
        ).fetchone() == ("SETTLED", "52" * 32)
        _no_reply(reserved, begin)
        assert await _cosign(engine, reserved) is None
        assert attempts == 2

    asyncio.run(exercise())


def test_cancellation_before_initial_context_acquisition_never_restores_burned_rights(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise() -> None:
        engine, _, hold = _funded_engine(reserved)
        hold.settle_bound_invoice.side_effect = _BoundInvoiceSyncBeforeSubmissionError("sync")
        begin = Mock(side_effect=AssertionError("cancellation grants no nonce"))
        monkeypatch.setattr(reserved.origin.crypto.crypto, "musig_begin", begin)
        original = engine._repay_original_unsynced_debt

        async def cancel_queued(document: bytes, now: int) -> None:
            async with reserved.store.reverse_operations.operation():
                task = asyncio.create_task(original(document, now))
                await asyncio.sleep(0)  # The helper waits behind this owner.
                assert not task.done()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            raise asyncio.CancelledError

        monkeypatch.setattr(engine, "_repay_original_unsynced_debt", cancel_queued)
        with pytest.raises(asyncio.CancelledError):
            await _cosign(engine, reserved)
        hold.settle_bound_invoice.assert_called_once()
        hold.observe_bound_settled_invoice.assert_not_called()
        _no_reply(reserved, begin)
        # No authenticated window was acquired to abandon. That is not a fresh
        # signing grant: the original reservation remains burned and replay empty.
        window = next(iter(reserved.store._reverse_proposals.values())).window
        assert window is not None
        assert window.time_allowed()
        assert await _cosign(engine, reserved) is None
        hold.settle_bound_invoice.assert_called_once()

    asyncio.run(exercise())
