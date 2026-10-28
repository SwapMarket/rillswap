"""Real SQLite custody and HTTP Core scanning across branch changes and restarts."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import TYPE_CHECKING, Any

import pytest
from test_core_wallet_funding import _cookie, _server
from test_funding_input_cleanup import _engine
from test_live_session_store import Harness
from test_reverse_settlement import NOW, PREIMAGE
from test_reverse_swap_store import insert_reverse_swap

from rill_provider.core_tx_bytes import (
    CoreProtocolError,
    CoreTransactionReader,
    ReverseSpendCheckpoint,
)
from rill_provider.live_session_store import LiveSessionStore, LiveSessionStoreError

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def _funded(store: LiveSessionStore, harness: Harness, state: str = "FUNDED") -> str:
    """Insert a funded reverse swap; the caller seeds its scan checkpoint."""
    session = insert_reverse_swap(store, harness, state, reservation="DISPATCHED")
    store._connection.execute(  # noqa: SLF001 - funded record fixture
        "UPDATE swaps SET funding_txid=?,funding_vout=0,funding_tx=?,"
        "refund_txid=?,refund_tx=? WHERE session_id=?",
        (
            "51" * 32,
            b"funding",
            "71" * 32 if state == "REFUNDING" else None,
            b"refund" if state == "REFUNDING" else None,
            session,
        ),
    )
    return session


def _hash(branch: str, height: int) -> str:
    return hashlib.sha256(f"{branch if height > 100 else 'common'}:{height}".encode()).hexdigest()


class Chain:
    branch = "old"
    tip = 125
    reveal = False
    mixed = False
    tail_reorg = False
    claim_reorg = False
    valid_preimage = True
    unavailable_tail = False

    def respond(self, request: dict[str, Any]) -> tuple[int, bytes]:
        if (
            self.unavailable_tail
            and request["method"] == "getblockhash"
            and request["params"] == [114]
            and request["id"] == 5
        ):
            return 503, b"unavailable"
        return 200, json.dumps(
            {"jsonrpc": "2.0", "id": request["id"], "result": self.reply(request)}
        ).encode()

    def reply(self, request: dict[str, Any]) -> object:
        method, params = request["method"], request["params"]
        if method == "gettxspendingprevout":
            return [{}]
        if method == "getblockhash":
            if self.mixed and params[0] == 102:
                self.branch = "new"
            return _hash(self.branch, params[0])
        if method == "getblock":
            height = next(h for h in range(100, self.tip + 1) if _hash(self.branch, h) == params[0])
            transactions: list[object] = []
            if self.reveal and self.branch == "new" and height == 114:
                transactions.append(
                    {
                        "txid": "61" * 32,
                        "vin": [
                            {
                                "txid": "51" * 32,
                                "vout": 0,
                                "txinwitness": [PREIMAGE if self.valid_preimage else "00" * 32],
                            }
                        ],
                    }
                )
            result = {
                "hash": params[0],
                "height": height,
                "previousblockhash": _hash(self.branch, height - 1),
                "tx": transactions,
            }
            if self.tail_reorg and height == 112:
                self.branch = "new"
            if self.claim_reorg and height == 114:
                self.branch = "replacement"
            return result
        raise AssertionError(f"unexpected Core method {method}")


def _checkpoint(
    store: LiveSessionStore, session: str, value: ReverseSpendCheckpoint | None = None
) -> ReverseSpendCheckpoint | None:
    if value is not None:  # FUNDED normally commits this row atomically
        store._connection.execute(  # noqa: SLF001 - checkpoint fixture
            "INSERT INTO reverse_spend_scans VALUES (?,?,?,?,?)",
            (session, value.floor_height, value.floor_block, value.height, value.block),
        )

    async def work() -> ReverseSpendCheckpoint | None:
        async with store.reverse_operations.operation() as operation:
            return store.reverse_spend_checkpoint(session, operation=operation)

    return asyncio.run(work())


def test_same_height_reorg_rewinds_durably_then_finds_claim_in_later_batch(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    chain = Chain()
    requests: list[dict[str, Any]] = []
    with _server(chain.respond, requests) as port:
        reader = CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=harness.network
        )

        def step(store: LiveSessionStore) -> str:
            engine, backend = _engine(store, harness, monkeypatch)
            backend.tip_height.return_value = chain.tip
            backend.block_hash.side_effect = reader.block_hash
            backend.find_spender.side_effect = reader.find_spender
            return asyncio.run(engine.advance(store.settlement_work(session_id=session)[0], NOW))

        with harness.acquire() as store:
            session = _funded(store, harness)
            _checkpoint(
                store,
                session,
                ReverseSpendCheckpoint(100, _hash("old", 100), 100, _hash("old", 100)),
            )
            for _ in range(3):
                assert step(store) == "FUNDED"
            assert _checkpoint(store, session).height == 125
        chain.branch, chain.reveal = "new", True
        with harness.acquire() as store:
            assert step(store) == "FUNDED"  # Durable rewind, no block scan yet.
            assert _checkpoint(store, session).height == 100
        with harness.acquire() as store:
            assert step(store) == "FUNDED"
            assert _checkpoint(store, session).height == 112
        with harness.acquire() as store:
            assert step(store) == "SETTLED"
            assert store._connection.execute(  # noqa: SLF001 - exact retained debt
                "SELECT preimage FROM swaps WHERE session_id=?", (session,)
            ).fetchone() == (PREIMAGE,)
    assert not any(request["method"] == "sendrawtransaction" for request in requests)


@pytest.mark.parametrize("fault", ["mixed", "tail"])
def test_mixed_or_abandoned_branch_batch_never_commits_progress(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fault: str
) -> None:
    chain = Chain()
    chain.mixed, chain.tail_reorg = fault == "mixed", fault == "tail"
    with _server(chain.respond, []) as port, harness.acquire() as store:
        session = _funded(store, harness)
        initial = ReverseSpendCheckpoint(100, _hash("old", 100), 100, _hash("old", 100))
        _checkpoint(store, session, initial)
        reader = CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=harness.network
        )
        engine, backend = _engine(store, harness, monkeypatch)
        backend.tip_height.return_value = chain.tip
        backend.block_hash.side_effect = reader.block_hash
        backend.find_spender.side_effect = reader.find_spender
        with pytest.raises(CoreProtocolError, match=r"continuity|branch changed"):
            asyncio.run(engine.advance(store.settlement_work(session_id=session)[0], NOW))
        assert _checkpoint(store, session) == initial
        backend.broadcast.assert_not_called()


@pytest.mark.parametrize("state", ["FUNDED", "REFUNDING"])
def test_floor_crossing_reorg_blocks_refund_even_after_restart(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    with harness.acquire() as store:
        session = _funded(store, harness, state)
        _checkpoint(store, session, ReverseSpendCheckpoint(100, "ab" * 32, 100, "ab" * 32))
    with harness.acquire() as store:
        engine, chain = _engine(store, harness, monkeypatch)
        chain.tip_height.return_value = 1200
        chain.block_hash.return_value = "cd" * 32
        with pytest.raises(LiveSessionStoreError, match="floor reorganized"):
            asyncio.run(engine.advance(store.settlement_work(session_id=session)[0], NOW))
        chain.find_spender.assert_not_called()
        chain.broadcast.assert_not_called()
        engine._hold.cancel.assert_not_called()  # noqa: SLF001


def test_missing_checkpoint_requires_operator_recovery_without_scan_or_refund(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    with harness.acquire() as store:
        session = _funded(store, harness)
        engine, chain = _engine(store, harness, monkeypatch)
        chain.tip_height.return_value = 1200
        chain.block_hash.return_value = "ab" * 32
        with pytest.raises(LiveSessionStoreError, match="operator recovery required"):
            asyncio.run(engine.advance(store.settlement_work(session_id=session)[0], NOW))
        assert _checkpoint(store, session) is None  # no coverage is invented
        chain.find_spender.assert_not_called()
        chain.broadcast.assert_not_called()
        engine._hold.cancel.assert_not_called()  # noqa: SLF001


@pytest.mark.parametrize("state", ["FUNDED", "REFUNDING"])
def test_scan_backlog_blocks_refund_start_and_hold_cancellation(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    from rill_provider.core_tx_bytes import SpendScan  # noqa: PLC0415 - focused adapter fixture

    with harness.acquire() as store:
        session = _funded(store, harness, state)
        _checkpoint(store, session, ReverseSpendCheckpoint(100, "ab" * 32, 100, "ab" * 32))
        engine, chain = _engine(store, harness, monkeypatch)
        chain.tip_height.return_value = 1200
        chain.block_hash.return_value = "ab" * 32
        chain.find_spender.return_value = SpendScan(None, 112, "cd" * 32)
        assert (
            asyncio.run(engine.advance(store.settlement_work(session_id=session)[0], NOW)) == state
        )
        chain.broadcast.assert_not_called()
        engine._hold.cancel.assert_not_called()  # noqa: SLF001
        assert _checkpoint(store, session).height == 112


def test_retained_preimage_settles_even_with_noncanonical_floor_and_unavailable_rpc(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    with harness.acquire() as store:
        session = _funded(store, harness)
        _checkpoint(store, session, ReverseSpendCheckpoint(100, "ab" * 32, 100, "ab" * 32))
        store.record_reverse_settlement_preimage(
            session, from_state="FUNDED", preimage=PREIMAGE, now=NOW
        )
        engine, chain = _engine(store, harness, monkeypatch)
        chain.block_hash.side_effect = RuntimeError("RPC down")
        chain.tip_height.side_effect = RuntimeError("RPC down")
        assert (
            asyncio.run(engine.advance(store.settlement_work(session_id=session)[0], NOW))
            == "SETTLED"
        )
        chain.block_hash.assert_not_called()
        chain.tip_height.assert_not_called()


@pytest.mark.parametrize("fault", ["checkpoint-insert", "state-update"])
def test_atomic_funded_transition_rolls_back_both_checkpoint_and_state(
    harness: Harness,
    fault: str,
) -> None:
    from test_payment_reconciliation import Signer  # noqa: PLC0415 - custody signing fixture

    with harness.acquire() as store:
        session = _funded(store, harness, "FUNDING_SENT")
        initial = ReverseSpendCheckpoint(100, "ab" * 32, 100, "ab" * 32)
        with pytest.raises(LiveSessionStoreError, match="requires its initial"):
            store.advance_reverse_swap(
                session,
                from_state="FUNDING_SENT",
                to_state="FUNDED",
                signer=Signer(harness),
                now=NOW,
            )
        trigger = (
            "CREATE TRIGGER fail_scan BEFORE INSERT ON reverse_spend_scans BEGIN "
            if fault == "checkpoint-insert"
            else "CREATE TRIGGER fail_scan BEFORE UPDATE ON swaps WHEN NEW.state='FUNDED' BEGIN "
        )
        store._connection.execute(  # noqa: SLF001 - failure before or after the real checkpoint insert
            trigger + "SELECT RAISE(ABORT, 'checkpoint unavailable'); END"
        )
        with pytest.raises(LiveSessionStoreError, match="swap transition refused"):
            store.advance_reverse_swap(
                session,
                from_state="FUNDING_SENT",
                to_state="FUNDED",
                signer=Signer(harness),
                now=NOW,
                scan_checkpoint=initial,
            )
        assert store.settlement_work(session_id=session)[0].state == "FUNDING_SENT"
        assert _checkpoint(store, session) is None
        store._connection.execute("DROP TRIGGER fail_scan")  # noqa: SLF001
        store.advance_reverse_swap(
            session,
            from_state="FUNDING_SENT",
            to_state="FUNDED",
            signer=Signer(harness),
            now=NOW,
            scan_checkpoint=initial,
        )
        assert _checkpoint(store, session) == initial


def test_stale_cursor_update_cannot_overwrite_progress_or_change_the_floor(
    harness: Harness,
) -> None:
    with harness.acquire() as store:
        session = _funded(store, harness)
        initial = ReverseSpendCheckpoint(100, "ab" * 32, 100, "ab" * 32)
        _checkpoint(store, session, initial)

        async def check() -> None:
            async with store.reverse_operations.operation() as operation:
                progress = ReverseSpendCheckpoint(100, "ab" * 32, 112, "cd" * 32)
                store.update_reverse_spend_checkpoint(
                    session, expected=initial, checkpoint=progress, operation=operation
                )
                with pytest.raises(LiveSessionStoreError, match="cursor changed"):
                    store.update_reverse_spend_checkpoint(
                        session, expected=initial, checkpoint=progress, operation=operation
                    )
                with pytest.raises(LiveSessionStoreError, match="update unsupported"):
                    store.update_reverse_spend_checkpoint(
                        session,
                        expected=progress,
                        checkpoint=ReverseSpendCheckpoint(99, "ab" * 32, 112, "cd" * 32),
                        operation=operation,
                    )

        asyncio.run(check())


@pytest.mark.parametrize("fault", ["reorg", "unavailable"])
@pytest.mark.parametrize("valid", [False, True])
def test_decoded_spend_survives_lost_canonical_proof_but_never_grants_unproven_progress(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fault: str,
    *,
    valid: bool,
) -> None:
    chain = Chain()
    chain.branch, chain.reveal = "new", True
    chain.valid_preimage = valid
    chain.claim_reorg, chain.unavailable_tail = fault == "reorg", fault == "unavailable"
    with _server(chain.respond, []) as port, harness.acquire() as store:
        session = _funded(store, harness, "REFUNDING")
        initial = ReverseSpendCheckpoint(100, _hash("new", 100), 112, _hash("new", 112))
        _checkpoint(
            store, session, ReverseSpendCheckpoint(100, _hash("new", 100), 100, _hash("new", 100))
        )

        async def advance_cursor() -> None:
            async with store.reverse_operations.operation() as operation:
                old = store.reverse_spend_checkpoint(session, operation=operation)
                store.update_reverse_spend_checkpoint(
                    session, expected=old, checkpoint=initial, operation=operation
                )

        asyncio.run(advance_cursor())
        reader = CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=harness.network
        )
        engine, backend = _engine(store, harness, monkeypatch)
        backend.tip_height.return_value = chain.tip
        backend.block_hash.side_effect = reader.block_hash
        backend.find_spender.side_effect = reader.find_spender
        outcome = asyncio.run(engine.advance(store.settlement_work(session_id=session)[0], NOW))
        assert outcome == ("SETTLED" if valid else "REFUNDING")
        assert _checkpoint(store, session) == initial
        retained = store._connection.execute(  # noqa: SLF001 - debt survives vanished witness
            "SELECT preimage FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        assert retained == (PREIMAGE if valid else None,)
        backend.broadcast.assert_not_called()
        engine._hold.cancel.assert_not_called()  # noqa: SLF001
