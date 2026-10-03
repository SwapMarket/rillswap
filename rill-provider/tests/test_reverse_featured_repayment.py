"""Featured owed repayment stays bound independently of fresh cooperation."""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from test_reverse_proposal_debt import _commit, _facts, _prepare
from test_reverse_proposal_debt import (
    pytestmark as pytestmark,  # noqa: PLC0414 - native test policy
)
from test_reverse_proposal_reservation import NativeSigner
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider.live_session_store import LiveSessionStoreError
from rill_provider.lnd_payment_observation import LndProtocolError
from rill_provider.reverse_operations import ReverseOperation
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.wire.messages import InvoiceBinding
    from test_reverse_proposal_reservation import ReservationCase

    from rill_provider.live_session_store import LiveSessionStore

# ruff: noqa: SLF001 - store-owned debt and operation regression seams


def _owed(store: LiveSessionStore) -> None:
    assert store._connection.execute("SELECT state,preimage FROM swaps").fetchone() == (
        "FUNDED",
        "52" * 32,
    )
    assert store._connection.execute("SELECT state FROM economic_reservations").fetchone() == (
        "DISPATCHED",
    )


@pytest.mark.parametrize(
    "failure", [LndProtocolError("ambiguous bound failure"), OSError("backend unavailable")]
)
def test_bound_failure_retains_debt_without_fallback_and_next_tick_reconciles(
    reserved: ReservationCase,
    failure: Exception,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            terms, core, invoice = _facts(reserved)
            _commit(reserved, operation, core, invoice)
        attempts = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
        chain, hold = Mock(), Mock()
        callbacks = []

        def bound(
            expected: InvoiceBinding, preimage: str, *, submission_allowed: Callable[[], bool]
        ) -> None:
            assert expected == terms.invoice_binding
            assert preimage == "52" * 32
            assert submission_allowed() is True
            callbacks.append(submission_allowed)
            if len(callbacks) == 1:
                raise failure

        hold.settle_bound_invoice.side_effect = bound
        engine = ReverseSettlement(store, chain, hold, NativeSigner(reserved.origin))
        _owed(store)
        (item,) = store.settlement_work()
        with pytest.raises(type(failure), match=str(failure)):
            await engine.advance(item, 1_700_000_002)
        _owed(store)
        assert callbacks[0]() is False
        assert (
            store._connection.execute("SELECT * FROM cooperation_attempts").fetchall() == attempts
        )
        (item,) = store.settlement_work()
        assert await engine.advance(item, 1_700_000_003) == "SETTLED"
        assert len(callbacks) == 2
        assert callbacks[1]() is False
        hold.settle.assert_not_called()
        hold.lookup.assert_not_called()
        hold.cancel.assert_not_called()
        assert chain.mock_calls == []
        assert store.settlement_work() == ()
        assert store._connection.execute("SELECT state FROM economic_reservations").fetchone() == (
            "RELEASED",
        )
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("archive", ["init_bytes", "accept_bytes", "terms_accept"])
def test_missing_archive_quarantines_existing_debt_without_backend_or_refund(
    reserved: ReservationCase,
    archive: str,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
            _commit(reserved, operation, core, invoice)
        table = "swaps" if archive == "terms_accept" else "sessions"
        original = store._connection.execute(f"SELECT {archive} FROM {table}").fetchone()[0]  # noqa: S608
        # Keep required SQL columns non-null, but remove the archived document.
        store._connection.execute(f"UPDATE {table} SET {archive}=?", (b"",))  # noqa: S608
        chain, hold = Mock(), Mock()
        engine = ReverseSettlement(store, chain, hold, NativeSigner(reserved.origin))
        (item,) = store.settlement_work()
        with pytest.raises(LiveSessionStoreError, match="repayment context refused"):
            await engine.advance(item, 1_700_000_002)
        _owed(store)
        assert chain.mock_calls == hold.mock_calls == []
        store._connection.execute(f"UPDATE {table} SET {archive}=?", (original,))  # noqa: S608
        (item,) = store.settlement_work()
        assert await engine.advance(item, 1_700_000_003) == "SETTLED"
        hold.settle_bound_invoice.assert_called_once()
        hold.settle.assert_not_called()
        hold.lookup.assert_not_called()
        assert not store._cooperation_handles

    asyncio.run(exercise())


def test_canceled_bound_worker_retains_debt_and_stops_captured_predicate_during_drain(  # noqa: PLR0915 - one synchronized lifecycle
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:  # noqa: PLR0915 - same lifecycle
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            terms, core, invoice = _facts(reserved)
            _commit(reserved, operation, core, invoice)
        chain, hold = Mock(), Mock()
        entered, release = threading.Event(), threading.Event()
        draining = asyncio.Event()
        callbacks = []
        original_drain = ReverseOperation._drain

        async def checked_drain(token: ReverseOperation) -> None:
            assert callbacks[0]() is False
            assert store.owner_is_open
            assert store.reverse_operations._active_operation is token
            draining.set()
            await original_drain(token)

        def bound(
            expected: InvoiceBinding, preimage: str, *, submission_allowed: Callable[[], bool]
        ) -> None:
            assert expected == terms.invoice_binding
            assert preimage == "52" * 32
            assert submission_allowed() is True
            callbacks.append(submission_allowed)
            entered.set()
            assert release.wait(5)
            assert submission_allowed() is False
            raise LndProtocolError("submission stopped before dispatch")

        hold.settle_bound_invoice.side_effect = bound
        engine = ReverseSettlement(store, chain, hold, NativeSigner(reserved.origin))
        (item,) = store.settlement_work()
        with monkeypatch.context() as patch:
            patch.setattr(ReverseOperation, "_drain", checked_drain)
            running = asyncio.create_task(engine.advance(item, 1_700_000_002))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                running.cancel()
                await asyncio.wait_for(draining.wait(), 2)
                assert not running.done()
                _owed(store)
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await running
            finally:
                release.set()
                await asyncio.gather(running, return_exceptions=True)
        _owed(store)
        assert callbacks[0]() is False
        assert chain.mock_calls == []
        hold.settle.assert_not_called()
        hold.lookup.assert_not_called()
        hold.cancel.assert_not_called()
        hold.settle_bound_invoice.side_effect = None
        (item,) = store.settlement_work()
        assert await engine.advance(item, 1_700_000_003) == "SETTLED"
        assert not store._cooperation_handles

    asyncio.run(exercise())
