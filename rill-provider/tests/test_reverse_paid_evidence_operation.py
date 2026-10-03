"""Collected paid observations cannot cross operations or implicit transactions."""

from __future__ import annotations

import asyncio
import sqlite3
from typing import TYPE_CHECKING

import pytest
import test_reverse_paid_preflight as cases
from test_reverse_paid_context import _debt, _repay
from test_reverse_paid_preflight import _backends
from test_reverse_proposal_debt import (
    pytestmark as pytestmark,  # noqa: PLC0414 - native test policy
)
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider.live_session_store import LiveSessionStoreError
from rill_provider.reverse_cooperation import ReverseCooperationWindow
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - exact same-operation and explicit-transaction boundary


def test_same_operation_uses_one_explicit_transaction_and_no_nested_begin(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        before = store._connection.execute("SELECT * FROM swaps").fetchall()
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            assert evidence.operation is operation
            statements = []
            store._connection.set_trace_callback(statements.append)
            try:
                with store._write() as connection:
                    result = store._check_reverse_paid_evidence(
                        connection, reserved.document, operation=operation, evidence=evidence
                    )
                    assert result == evidence.context
            finally:
                store._connection.set_trace_callback(None)
            assert sum(sql == "BEGIN IMMEDIATE" for sql in statements) == 1
            assert statements[-1] == "COMMIT"
            assert not any(sql.startswith(("UPDATE", "INSERT", "DELETE")) for sql in statements)
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
        assert not store._cooperation_handles

    asyncio.run(exercise())


def test_unexpired_same_window_evidence_cannot_transfer_to_a_new_operation(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        async with store.reverse_operations.operation() as first:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=first,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
        assert evidence.context.window.time_allowed()
        before = store._connection.execute("SELECT * FROM swaps").fetchall()
        async with store.reverse_operations.operation() as second:
            assert first is not second
            with (
                store._write() as connection,
                pytest.raises(LiveSessionStoreError, match="operation refused"),
            ):
                store._check_reverse_paid_evidence(
                    connection, reserved.document, operation=second, evidence=evidence
                )
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("transaction", ["absent", "foreign connection"])
def test_owner_connection_and_explicit_transaction_are_required(
    reserved: ReservationCase,
    transaction: str,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            if transaction == "absent":
                with pytest.raises(LiveSessionStoreError, match="operation refused"):
                    store._check_reverse_paid_evidence(
                        store._connection, reserved.document, operation=operation, evidence=evidence
                    )
            else:
                with sqlite3.connect(":memory:") as foreign:
                    foreign.execute("BEGIN IMMEDIATE")
                    with pytest.raises(LiveSessionStoreError, match="operation refused"):
                        store._check_reverse_paid_evidence(
                            foreign, reserved.document, operation=operation, evidence=evidence
                        )
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("delay", [1.0, 30.0])
def test_same_operation_final_check_charges_elapsed_time_and_preserves_paid_state(
    reserved: ReservationCase,
    delay: float,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            before = store._connection.execute("SELECT * FROM swaps").fetchall()
            reserved.clock.advance(delay)
            with (
                pytest.raises(LiveSessionStoreError, match="preflight refused"),
                store._write() as connection,
            ):
                store._check_reverse_paid_evidence(
                    connection, reserved.document, operation=operation, evidence=evidence
                )
            assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
            assert not evidence.context.window.time_allowed()
        assert not store._cooperation_handles

    asyncio.run(exercise())


def test_final_native_validation_contract_needs_the_interval_check(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Test-only negative control disables interval checks, not the still-live
    # thirty-second cooperation deadline. The preserved contract must catch it.
    monkeypatch.setattr(
        ReverseCooperationWindow, "check_evidence_interval", lambda *_args, **_kwargs: None
    )
    with pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"):
        cases.test_bad_or_stale_paid_evidence_abandons_window_without_financial_or_custody_changes(
            reserved, monkeypatch, "validation delay"
        )


def test_diagnostic_transaction_commit_delay_never_returns_fresh_success(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        raw = store._connection

        class DelayedCommit:
            armed = False

            def __getattr__(self, name: str) -> object:
                return getattr(raw, name)

            def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
                if self.armed and sql == "COMMIT":
                    reserved.clock.advance(1)
                    self.armed = False
                return raw.execute(sql, parameters)

        proxy = DelayedCommit()
        store._connection = proxy
        checker = store._check_reverse_paid_evidence

        def check_then_delay(*args: object, **kwargs: object) -> object:
            context = checker(*args, **kwargs)
            proxy.armed = True
            return context

        monkeypatch.setattr(store, "_check_reverse_paid_evidence", check_then_delay)
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        before = raw.execute("SELECT * FROM swaps").fetchall()
        with pytest.raises(LiveSessionStoreError, match="preflight refused"):
            await engine._preflight_paid_proposal(reserved.document, configured_floor_sat=1)
        assert raw.execute("SELECT * FROM swaps").fetchall() == before
        window = store._reverse_proposals[reserved.origin.session_id].window
        assert window is not None
        assert not window.time_allowed()
        assert not store._cooperation_handles

    asyncio.run(exercise())


def test_context_wrapper_retains_sanitized_transaction_entry_failure(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EntryFailure:
        def __enter__(self) -> None:
            raise LiveSessionStoreError("live session store busy or unavailable")

        def __exit__(self, *_args: object) -> None:
            pass

    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:
            monkeypatch.setattr(reserved.store, "_write", EntryFailure)
            with pytest.raises(
                LiveSessionStoreError, match=r"^reverse proposal live context refused$"
            ):
                reserved.store._reverse_live_proposal_context(
                    reserved.document, operation=operation, purpose="paid-signing"
                )
        assert not reserved.store._cooperation_handles

    asyncio.run(exercise())
