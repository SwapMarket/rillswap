"""Reverse advancement reloads state inside the shared real-owner boundary."""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from test_live_session_store import Harness
from test_payment_reconciliation import Signer
from test_reverse_settlement_intent import _funded
from test_reverse_swap_store import PREIMAGE, _row

from rill_provider.core_tx_bytes import SpendScan
from rill_provider.live_session_store import LiveSessionStoreError, StaleSwapError
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def test_two_reverse_engines_share_refund_cancellation_and_reload_after_terminal_commit(
    harness: Harness,
) -> None:
    with harness.acquire() as store:
        session = _funded(store, harness, "REFUNDING")
        store._connection.execute(  # noqa: SLF001 - already scanned contiguous history
            "UPDATE reverse_spend_scans SET cursor_height=1099 WHERE session_id=?", (session,)
        )
        stale = store.settlement_work(session_id=session)[0]
        chain, hold = Mock(), Mock()
        chain.tip_height.return_value = 1102
        chain.block_hash.return_value = "ab" * 32
        chain.find_spender.return_value = SpendScan(None, 1102, "ab" * 32)
        chain.confirmations.return_value = 10
        entered, release = threading.Event(), threading.Event()

        def cancel(_payment_hash: str) -> None:
            entered.set()
            assert release.wait(3)

        hold.cancel.side_effect = cancel
        first = ReverseSettlement(store, chain, hold, Signer(harness))
        second = ReverseSettlement(store, chain, hold, Signer(harness))

        async def exercise() -> None:
            running = asyncio.create_task(first.advance(stale, 2001))
            queued = None
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                queued = asyncio.create_task(second.advance(stale, 2002))
                await asyncio.sleep(0.01)
                assert not queued.done()
                assert hold.cancel.call_count == 1
                assert _row(store, session)["state"] == "REFUNDING"
                release.set()
                assert await running == "REFUNDED"
                with pytest.raises(StaleSwapError, match="no longer available"):
                    await queued
                assert _row(store, session)["state"] == "REFUNDED"
                assert hold.cancel.call_count == 1
            finally:
                release.set()
                await asyncio.gather(
                    running, *(() if queued is None else (queued,)), return_exceptions=True
                )

        asyncio.run(exercise())


def test_queued_funded_snapshot_reloads_new_debt_before_any_core_or_refund_work(
    harness: Harness,
) -> None:
    with harness.acquire() as store:
        session = _funded(store, harness)
        stale = store.settlement_work(session_id=session)[0]
        assert stale.preimage is None
        chain, hold = Mock(), Mock()
        chain.tip_height.side_effect = AssertionError("new durable debt must settle before Core")
        engine = ReverseSettlement(store, chain, hold, Signer(harness))

        async def exercise() -> None:
            async with store.reverse_operations.operation() as operation:
                # Affirmative witnessed debt, not fresh cooperative admission.
                operation.check()
                store.record_reverse_settlement_preimage(
                    session,
                    from_state="FUNDED",
                    preimage=PREIMAGE,
                    now=2001,
                )
                queued = asyncio.create_task(engine.advance(stale, 2002))
                await asyncio.sleep(0)
                assert not queued.done()
                hold.settle.assert_not_called()
            assert await queued == "SETTLED"
            hold.settle.assert_called_once_with(PREIMAGE)
            hold.cancel.assert_not_called()
            chain.tip_height.assert_not_called()
            chain.broadcast.assert_not_called()
            assert _row(store, session)["state"] == "SETTLED"

        asyncio.run(exercise())


@pytest.mark.parametrize("rpc", ["cancel", "settle"])
def test_canceled_reverse_rpc_retains_owner_until_actual_completion_and_no_terminal_write(
    harness: Harness,
    rpc: str,
) -> None:
    with harness.acquire() as store:
        session = _funded(store, harness, "REFUNDING" if rpc == "cancel" else "FUNDED")
        store._connection.execute(  # noqa: SLF001 - already scanned contiguous history
            "UPDATE reverse_spend_scans SET cursor_height=1099 WHERE session_id=?", (session,)
        )
        if rpc == "settle":
            store.record_reverse_settlement_preimage(
                session,
                from_state="FUNDED",
                preimage=PREIMAGE,
                now=2000,
            )
        item = store.settlement_work(session_id=session)[0]
        chain, hold = Mock(), Mock()
        chain.tip_height.return_value = 1102
        chain.block_hash.return_value = "ab" * 32
        chain.find_spender.return_value = SpendScan(None, 1102, "ab" * 32)
        chain.confirmations.return_value = 10
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()

        def blocked(_value: str) -> None:
            entered.set()
            try:
                assert release.wait(3)
            finally:
                finished.set()

        getattr(hold, rpc).side_effect = blocked
        engine = ReverseSettlement(store, chain, hold, Signer(harness))

        async def exercise() -> None:
            running = asyncio.create_task(engine.advance(item, 2001))
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                store.close()  # Lifecycle or uncertain transaction can fence the owner.
                for _ in range(3):
                    running.cancel()
                    await asyncio.sleep(0)
                    assert not running.done()
                    assert not finished.is_set()
                    with pytest.raises(LiveSessionStoreError, match="owned by another"):
                        harness.acquire()
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await running
                assert finished.is_set()
                with harness.acquire() as fresh:
                    assert _row(fresh, session)["state"] == item.state
                    retained = fresh.settlement_work(session_id=session)[0]
                    assert retained.preimage == (PREIMAGE if rpc == "settle" else None)
            finally:
                release.set()
                await asyncio.gather(running, return_exceptions=True)

        asyncio.run(exercise())
