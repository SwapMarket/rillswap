"""Local paid lifecycle context never reconstructs payment or signing authority."""

from __future__ import annotations

import asyncio
import sys
import threading
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from _paid_refusal_probe import PaidRefusalProbe
from test_paid_refusal_probe import LIVE_GUARDS
from test_reverse_proposal_debt import _commit, _facts, _prepare
from test_reverse_proposal_debt import (
    pytestmark as pytestmark,  # noqa: PLC0414 - native test policy
)
from test_reverse_proposal_reservation import NativeSigner
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider.live_session_store import LiveSessionStoreError
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - exact owner memory and lifecycle regression seams


async def _debt(reserved: ReservationCase) -> None:
    async with reserved.store.reverse_operations.operation() as operation:
        _prepare(reserved, operation)
        _, core, invoice = _facts(reserved)
        _commit(reserved, operation, core, invoice)


async def _repay(reserved: ReservationCase) -> None:
    chain, hold = Mock(), Mock()
    engine = ReverseSettlement(reserved.store, chain, hold, NativeSigner(reserved.origin))
    (item,) = reserved.store.settlement_work()
    assert await engine.advance(item, 1_700_000_002) == "SETTLED"
    hold.settle_bound_invoice.assert_called_once()
    hold.lookup.assert_not_called()
    assert chain.mock_calls == []


def test_repayment_first_exposes_only_original_paid_context_without_backend_or_custody(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        window = reserved.store._reverse_proposals[reserved.origin.session_id].window
        await _repay(reserved)
        rows = reserved.store._connection.execute("SELECT * FROM swaps").fetchall()
        attempts = reserved.store._connection.execute(
            "SELECT * FROM cooperation_attempts"
        ).fetchall()
        outbox = reserved.store.pending_outbox()
        assert reserved.store._connection.execute(
            "SELECT state FROM economic_reservations"
        ).fetchone() == ("RELEASED",)
        async with reserved.store.reverse_operations.operation() as operation:
            context = reserved.store._reverse_live_proposal_context(
                reserved.document, operation=operation, purpose="paid-signing"
            )
            assert context.window is window
            assert context.terms.invoice_binding == _facts(reserved)[0].invoice_binding
            assert context.window.time_allowed()
        assert reserved.store._connection.execute("SELECT * FROM swaps").fetchall() == rows
        assert (
            reserved.store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
            == attempts
        )
        assert reserved.store.pending_outbox() == outbox
        assert not reserved.store._cooperation_handles

    asyncio.run(exercise())


def test_paid_refusal_probe_classifies_actual_missing_original_context_without_authority(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = PaidRefusalProbe(
        ((ValueError, "ValueError"), (LiveSessionStoreError, "LiveSessionStoreError"))
    )
    probe.preflight()
    original_trace, original_thread_trace = sys.gettrace(), threading.gettrace()

    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        # Inject the existing terminal missing-owner-memory fault. This never
        # reconstructs signing authority from durable historical paid evidence.
        store._reverse_proposals.clear()
        queries = (
            "SELECT * FROM swaps",
            "SELECT * FROM cooperation_attempts",
            "SELECT * FROM economic_reservations",
        )
        before = tuple(store._connection.execute(query).fetchall() for query in queries)
        outbox = store.pending_outbox()
        original = store._reverse_live_context_in_connection
        with monkeypatch.context() as patch:
            patch.setattr(
                store,
                "_reverse_live_context_in_connection",
                probe.synchronous(original, "live_context", LIVE_GUARDS),
            )
            async with store.reverse_operations.operation() as operation:
                with pytest.raises(LiveSessionStoreError) as caught:
                    store._reverse_live_proposal_context(
                        reserved.document, operation=operation, purpose="paid-signing"
                    )
                assert caught.value.args == ("reverse proposal live context refused",)
        assert store._reverse_live_context_in_connection == original
        assert tuple(store._connection.execute(query).fetchall() for query in queries) == before
        assert store.pending_outbox() == outbox
        assert not store._reverse_proposals
        assert not store._cooperation_handles

    asyncio.run(probe.paid_phase(exercise)())
    assert sys.gettrace() is original_trace
    assert threading.gettrace() is original_thread_trace
    assert [(event["method"], event["guard"], event["category"]) for event in probe.events] == [
        ("paid_scope", "enter", "none"),
        ("live_context", "original_reservation_absent", "ValueError"),
        ("live_context", "live_context_sanitized", "LiveSessionStoreError"),
        ("paid_scope", "exit", "none"),
    ]
    assert probe.unknown is False
    assert len(probe.events) <= 64
    for event in probe.events:
        assert set(event) == {"method", "guard", "category", "elapsed_ms"}
        assert isinstance(event["elapsed_ms"], int)
        assert 0 <= event["elapsed_ms"] <= 600_000


def test_early_paid_context_refusal_is_terminal_but_independent_repayment_survives(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        # Remote payment alone must not replace the selected local lifecycle.
        async with reserved.store.reverse_operations.operation() as operation:
            with pytest.raises(LiveSessionStoreError, match="live context refused"):
                reserved.store._reverse_live_proposal_context(
                    reserved.document, operation=operation, purpose="paid-signing"
                )
        window = reserved.store._reverse_proposals[reserved.origin.session_id].window
        assert window is not None
        assert not window.time_allowed()
        await _repay(reserved)
        async with reserved.store.reverse_operations.operation() as operation:
            with pytest.raises(LiveSessionStoreError, match="live context refused"):
                reserved.store._reverse_live_proposal_context(
                    reserved.document, operation=operation, purpose="paid-signing"
                )
        assert not reserved.store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "fault",
    [
        "missing preimage",
        "different preimage",
        "refund txid",
        "refund bytes",
        "refunding",
        "old binding",
        "partial binding",
        "generation",
        "memory",
        "expired",
    ],
)
def test_inconsistent_or_historical_paid_context_cannot_reconstruct_live_cooperation(
    reserved: ReservationCase,
    fault: str,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        if fault in (
            "missing preimage",
            "different preimage",
            "refund txid",
            "refund bytes",
            "refunding",
        ):
            store._connection.execute("PRAGMA ignore_check_constraints=ON")
            if fault in ("missing preimage", "different preimage"):
                store._connection.execute(
                    "UPDATE swaps SET preimage=?",
                    (None if fault == "missing preimage" else "ab" * 32,),
                )
            elif fault == "refund txid":
                store._connection.execute("UPDATE swaps SET refund_txid=?", ("ab" * 32,))
            elif fault == "refund bytes":
                store._connection.execute("UPDATE swaps SET refund_tx=?", (b"signed-refund",))
            else:
                store._connection.execute("UPDATE swaps SET state='REFUNDING'")
            store._connection.execute("PRAGMA ignore_check_constraints=OFF")
        elif fault in ("old binding", "partial binding"):
            store._connection.execute(
                "UPDATE cooperation_attempts SET binding=?",
                (b'{"version":1}' if fault == "old binding" else b"{}",),
            )
        elif fault == "generation":
            store._connection.execute(
                "UPDATE cooperation_attempts SET owner_generation=?", (store._generation + 1,)
            )
        elif fault == "memory":
            store._reverse_proposals.clear()
        else:
            reserved.clock.advance(30)
        before = store._connection.execute("SELECT * FROM swaps").fetchall()
        attempts = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
        async with store.reverse_operations.operation() as operation:
            with pytest.raises(LiveSessionStoreError, match="live context refused"):
                store._reverse_live_proposal_context(
                    reserved.document, operation=operation, purpose="paid-signing"
                )
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
        assert (
            store._connection.execute("SELECT * FROM cooperation_attempts").fetchall() == attempts
        )
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("purpose", [None, True, "unknown", "SETTLED"])
@pytest.mark.parametrize("live_attempt", [False, True])
def test_unknown_context_purpose_cannot_select_either_lifecycle(
    reserved: ReservationCase,
    purpose: object,
    *,
    live_attempt: bool,
) -> None:
    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:
            window = None
            if live_attempt:
                _prepare(reserved, operation)
                window = reserved.store._reverse_proposals[reserved.origin.session_id].window
            before = reserved.store._connection.execute("SELECT * FROM swaps").fetchall()
            attempts = reserved.store._connection.execute(
                "SELECT * FROM cooperation_attempts"
            ).fetchall()
            with pytest.raises(LiveSessionStoreError, match="purpose refused"):
                reserved.store._reverse_live_proposal_context(
                    reserved.document, operation=operation, purpose=purpose
                )
            assert reserved.store._connection.execute("SELECT * FROM swaps").fetchall() == before
            assert (
                reserved.store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
                == attempts
            )
            if window is not None:
                assert window.time_allowed()
            else:
                assert not reserved.store._reverse_proposals
        assert not reserved.store._cooperation_handles

    asyncio.run(exercise())


def test_context_purpose_cannot_be_omitted(reserved: ReservationCase) -> None:
    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:
            with pytest.raises(TypeError, match="purpose"):
                reserved.store._reverse_live_proposal_context(
                    reserved.document, operation=operation
                )
        assert not reserved.store._reverse_proposals

    asyncio.run(exercise())


def test_paid_lifecycle_after_restart_remains_history_without_live_context(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        reserved.store.close()
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=reserved.origin.crypto.crypto,
        ) as fresh:
            async with fresh.reverse_operations.operation() as operation:
                with pytest.raises(LiveSessionStoreError, match="live context refused"):
                    fresh._reverse_live_proposal_context(
                        reserved.document, operation=operation, purpose="paid-signing"
                    )
            assert fresh._connection.execute("SELECT state,preimage FROM swaps").fetchone() == (
                "SETTLED",
                "52" * 32,
            )
            assert not fresh._reverse_proposals
            assert not fresh._cooperation_handles

    asyncio.run(exercise())
