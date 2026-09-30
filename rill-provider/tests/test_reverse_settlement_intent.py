"""Reverse hold settlement is durably owed before any RPC or refund progression."""

from __future__ import annotations

import asyncio
from unittest.mock import Mock

import pytest
from test_payment_reconciliation import Signer
from test_reverse_swap_store import (
    FUNDING,
    HASH,
    PREIMAGE,
    REFUND,
    _advance,
    _ledger,
    _row,
    insert_reverse_swap,
)
from test_reverse_swap_store import harness as harness  # noqa: PLC0414 - reuse pytest fixture

from rill_provider.core_tx_bytes import SpendObservation, SpendScan
from rill_provider.live_session_store import LiveSessionStoreError
from rill_provider.lnd_hold_invoice import HoldInvoiceStatus
from rill_provider.lnd_payment_observation import LndProtocolError
from rill_provider.reverse_settlement import ReverseSettlement


def _funded(store: object, harness: object, state: str = "FUNDED") -> str:
    session = insert_reverse_swap(store, harness, "LN_HELD")
    _advance(
        store, harness, session, from_state="LN_HELD", to_state="FUNDING_SENT", funding=FUNDING
    )
    _advance(store, harness, session, from_state="FUNDING_SENT", to_state="FUNDED")
    if state == "REFUNDING":
        _advance(store, harness, session, from_state="FUNDED", to_state="REFUNDING", refund=REFUND)
    return session


@pytest.mark.parametrize("state", ["FUNDED", "REFUNDING"])
def test_intent_is_atomic_idempotent_and_does_not_release_or_publish(
    harness: object, state: str
) -> None:
    with harness.acquire() as store:
        session = _funded(store, harness, state)
        outbox = store.pending_outbox()
        store.record_reverse_settlement_preimage(
            session, from_state=state, preimage=PREIMAGE, now=2001
        )
        store.record_reverse_settlement_preimage(
            session, from_state=state, preimage=PREIMAGE, now=1999
        )
        row = _row(store, session)
        assert (row["state"], row["preimage"], row["updated_at"]) == (state, PREIMAGE, 2001)
        assert _ledger(store)[HASH][1] == "DISPATCHED"
        assert store.pending_outbox() == outbox
        target = "REFUNDING" if state == "FUNDED" else "REFUNDED"
        fields = {"refund": REFUND} if target == "REFUNDING" else {"refund_confirmations": 10}
        with pytest.raises(LiveSessionStoreError, match="obligation forbids refund"):
            _advance(store, harness, session, from_state=state, to_state=target, **fields)
        assert _row(store, session)["state"] == state


@pytest.mark.parametrize(
    "failure", ["wrong hash", "uppercase", "missing funding", "conflicting retained", "stale state"]
)
def test_invalid_intent_is_not_recorded(harness: object, failure: str) -> None:
    with harness.acquire() as store:
        session = _funded(store, harness)
        preimage = PREIMAGE
        state = "FUNDED"
        if failure == "wrong hash":
            preimage = "ab" * 32
        elif failure == "uppercase":
            preimage = "AB" * 32
        elif failure == "missing funding":
            store._connection.execute(  # noqa: SLF001 - corrupted storage cannot create an obligation
                "UPDATE swaps SET funding_tx=NULL,funding_txid=NULL,funding_vout=NULL "
                "WHERE session_id=?",
                (session,),
            )
        elif failure == "conflicting retained":
            store._connection.execute(  # noqa: SLF001 - retained intent cannot be replaced
                "UPDATE swaps SET preimage=? WHERE session_id=?", ("ab" * 32, session)
            )
        else:
            state = "REFUNDING"
        before = _row(store, session)
        with pytest.raises(LiveSessionStoreError):
            store.record_reverse_settlement_preimage(
                session, from_state=state, preimage=preimage, now=2001
            )
        assert _row(store, session) == before
        assert _ledger(store)[HASH][1] == "DISPATCHED"


@pytest.mark.parametrize(
    "failure", ["rpc fails", "rpc fails then succeeds", "commit after rpc fails"]
)
@pytest.mark.parametrize("state", ["FUNDED", "REFUNDING"])
def test_restart_settles_recorded_debt_without_core_or_a_retained_witness(
    harness: object,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    state: str,
) -> None:
    chain, hold = Mock(), Mock()
    chain.tip_height.return_value = 1020
    chain.find_spender.return_value = SpendScan(
        SpendObservation(
            "61" * 32, (b"\x77" * 64, bytes.fromhex(PREIMAGE), b"\x51", b"\xc0"), None
        ),
        1009,
    )
    with harness.acquire() as store:
        session = _funded(store, harness, state)
        engine = ReverseSettlement(store, chain, hold, Signer(harness))
        (item,) = store.settlement_work()
        recorded: list[str] = []
        record = store.record_reverse_settlement_preimage

        def checked_record(*args: object, **kwargs: object) -> None:
            record(*args, **kwargs)
            assert _row(store, session)["preimage"] == PREIMAGE
            assert _ledger(store)[HASH][1] == "DISPATCHED"
            recorded.append(PREIMAGE)

        def settle(preimage: str) -> None:
            assert recorded == [preimage] == [PREIMAGE]
            if failure.startswith("rpc fails"):
                raise LndProtocolError("temporary settle failure")

        hold.settle.side_effect = settle
        hold.lookup.return_value = HoldInvoiceStatus("ACCEPTED", ())
        with monkeypatch.context() as patch:
            patch.setattr(store, "record_reverse_settlement_preimage", checked_record)
            if failure == "commit after rpc fails":
                patch.setattr(
                    store,
                    "advance_reverse_swap",
                    Mock(side_effect=LiveSessionStoreError("crash before terminal commit")),
                )
            with pytest.raises((LndProtocolError, LiveSessionStoreError)):
                asyncio.run(engine.advance(item, 2001))
        assert _row(store, session)["state"] == state
        assert _row(store, session)["preimage"] == PREIMAGE
    # Reacquire a real store owner. The spender may disappear and Core may fail.
    with harness.acquire() as recovered:
        chain.reset_mock()
        chain.tip_height.side_effect = OSError("Core unavailable")
        chain.find_spender.side_effect = OSError("witness disappeared")
        hold.lookup.reset_mock()
        hold.settle.side_effect = (
            None if failure == "rpc fails then succeeds" else LndProtocolError("already settled")
        )
        hold.lookup.return_value = HoldInvoiceStatus("SETTLED", ())
        (item,) = recovered.settlement_work()
        assert item.preimage == PREIMAGE
        engine = ReverseSettlement(recovered, chain, hold, Signer(harness))
        assert asyncio.run(engine.advance(item, 2002)) == "SETTLED"
        chain.tip_height.assert_not_called()
        chain.find_spender.assert_not_called()
        chain.broadcast.assert_not_called()
        hold.cancel.assert_not_called()
        assert _ledger(recovered)[HASH][1] == "RELEASED"
        assert recovered.settlement_work() == ()
        if failure == "rpc fails then succeeds":
            hold.lookup.assert_not_called()


def test_intent_publication_failure_prevents_the_settlement_rpc(
    harness: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain, hold = Mock(), Mock()
    chain.tip_height.return_value = 1020
    chain.find_spender.return_value = SpendScan(
        SpendObservation("61" * 32, (bytes.fromhex(PREIMAGE),), None), 1009
    )
    with harness.acquire() as store:
        session = _funded(store, harness)
        (item,) = store.settlement_work()
        monkeypatch.setattr(
            store,
            "record_reverse_settlement_preimage",
            Mock(side_effect=LiveSessionStoreError("durability unknown")),
        )
        engine = ReverseSettlement(store, chain, hold, Signer(harness))
        with pytest.raises(LiveSessionStoreError, match="durability unknown"):
            asyncio.run(engine.advance(item, 2001))
        hold.settle.assert_not_called()
        hold.cancel.assert_not_called()
        assert _row(store, session)["preimage"] is None


def test_unexpected_state_with_a_preimage_is_quarantined_before_any_backend_effect(
    harness: object,
) -> None:
    chain, hold = Mock(), Mock()
    with harness.acquire() as store:
        session = _funded(store, harness)
        store.record_reverse_settlement_preimage(
            session, from_state="FUNDED", preimage=PREIMAGE, now=2001
        )
        store._connection.execute(  # noqa: SLF001 - unreachable repaired state has no authority
            "UPDATE swaps SET state='FUNDING_SENT' WHERE session_id=?", (session,)
        )
        (item,) = store.settlement_work()
        with pytest.raises(LiveSessionStoreError, match="unexpected state"):
            asyncio.run(ReverseSettlement(store, chain, hold, Signer(harness)).advance(item, 2002))
        assert chain.mock_calls == []
        assert hold.mock_calls == []


@pytest.mark.parametrize("state", ["FUNDED", "REFUNDING"])
def test_invalid_retained_preimage_never_reaches_a_backend(harness: object, state: str) -> None:
    chain, hold = Mock(), Mock()
    with harness.acquire() as store:
        session = _funded(store, harness, state)
        store._connection.execute(  # noqa: SLF001 - hash-mismatched repair is not an obligation
            "UPDATE swaps SET preimage=? WHERE session_id=?", ("ab" * 32, session)
        )
        (item,) = store.settlement_work()
        with pytest.raises(LiveSessionStoreError, match="evidence invalid"):
            asyncio.run(ReverseSettlement(store, chain, hold, Signer(harness)).advance(item, 2002))
        assert chain.mock_calls == []
        assert hold.mock_calls == []
        assert _ledger(store)[HASH][1] == "DISPATCHED"
