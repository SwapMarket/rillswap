"""Wallet cleanup requires affirmative same-owner absence of a durable funding grant."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from dataclasses import replace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from test_live_session_store import Harness
from test_payment_reconciliation import Signer
from test_reverse_settlement import FUNDED, HELD, NOW, SCRIPT, TERMS
from test_reverse_swap_store import FUNDING, insert_reverse_swap

from rill_provider import reverse_settlement as reverse
from rill_provider.live_session_store import LiveSessionStore, LiveSessionStoreError

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def _certificate(store: LiveSessionStore, session: str) -> bool:
    async def check() -> bool:
        async with store.reverse_operations.operation() as operation:
            return store.reverse_funding_is_ungranted(session, operation=operation)

    return asyncio.run(check())


@pytest.mark.parametrize("state", ["UNSENT", "DISPATCHED", "RELEASED"])
def test_only_open_matching_reservation_authorizes_cleanup(harness: Harness, state: str) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(
            store, harness, "LN_HELD", reservation="UNSENT" if state == "RELEASED" else state
        )
        if state == "RELEASED":
            store._connection.execute(  # noqa: SLF001 - retained release evidence
                "UPDATE economic_reservations SET state='RELEASED',release_evidence=? "
                "WHERE session_id=?",
                (b"release", session),
            )
        assert _certificate(store, session) is (state == "UNSENT")


@pytest.mark.parametrize(
    "column", ["funding_binding", "funding_txid", "funding_vout", "funding_tx"]
)
def test_partial_funding_evidence_never_authorizes_cleanup(harness: Harness, column: str) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        store._connection.execute("PRAGMA ignore_check_constraints=ON")  # noqa: SLF001 - damaged state
        store._connection.execute(  # noqa: SLF001 - persisted-state fault injection
            f"UPDATE swaps SET {column}=? WHERE session_id=?",  # noqa: S608 - fixed parametric column
            (0 if column == "funding_vout" else b"partial", session),
        )
        assert not _certificate(store, session)


def test_committed_funding_cannot_be_certified_ungranted(harness: Harness) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        store.advance_reverse_swap(
            session,
            from_state="LN_HELD",
            to_state="FUNDING_SENT",
            signer=Signer(harness),
            now=2000,
            funding=FUNDING,
        )
        assert not _certificate(store, session)
        # An inconsistent swap row alone cannot erase the retained signed grant.
        store._connection.execute(  # noqa: SLF001 - evidence contradiction
            "UPDATE swaps SET state='LN_HELD',funding_binding=NULL,funding_txid=NULL,"
            "funding_vout=NULL,funding_tx=NULL WHERE session_id=?",
            (session,),
        )
        store._connection.execute(  # noqa: SLF001
            "UPDATE economic_reservations SET state='UNSENT' WHERE session_id=?", (session,)
        )
        assert not _certificate(store, session)


class FailingCommit:
    def __init__(self, connection: sqlite3.Connection, *, commit_first: bool) -> None:
        self.connection = connection
        self.commit_first = commit_first

    def execute(self, statement: str, *args: object) -> Any:  # noqa: ANN401 - sqlite fault boundary
        if statement == "COMMIT":
            if self.commit_first:
                self.connection.execute(statement, *args)
            raise sqlite3.OperationalError("commit response lost")
        return self.connection.execute(statement, *args)

    def close(self) -> None:
        self.connection.close()


@pytest.mark.parametrize("commit_first", [False, True])
def test_checking_transaction_uncertainty_never_returns_cleanup_authority(
    harness: Harness, *, commit_first: bool
) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        store._connection = FailingCommit(  # type: ignore[assignment]  # noqa: SLF001
            store._connection,  # noqa: SLF001
            commit_first=commit_first,
        )
        with pytest.raises(LiveSessionStoreError, match="commit outcome uncertain"):
            _certificate(store, session)
        assert not store.owner_is_open


def _engine(
    store: LiveSessionStore, harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> tuple[reverse.ReverseSettlement, Mock]:
    monkeypatch.setattr(reverse, "offered_terms", lambda _offer: TERMS)
    monkeypatch.setattr(
        reverse, "reconstruct_taproot_contract", lambda *_a, **_k: Mock(script_pubkey=SCRIPT)
    )
    chain = Mock()
    chain.tip_height.return_value = 1000
    chain.fund_output.return_value = replace(
        FUNDED, raw=b"\x01" * 8193, selected_inputs=((FUNDED.anchor_txid, FUNDED.anchor_vout),)
    )
    hold = Mock()
    hold.lookup.return_value = HELD
    return reverse.ReverseSettlement(store, chain, hold, Signer(harness)), chain


def test_real_serialization_rollback_releases_only_attempt_inputs_before_any_broadcast(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        engine, chain = _engine(store, harness, monkeypatch)
        item = store.settlement_work(session_id=session)[0]
        with pytest.raises(LiveSessionStoreError, match="swap transition refused"):
            asyncio.run(engine.advance(item, NOW))
        chain.release_funding_inputs.assert_called_once_with(
            ((FUNDED.anchor_txid, FUNDED.anchor_vout),)
        )
        chain.broadcast.assert_not_called()
        assert _certificate(store, session)


@pytest.mark.parametrize("commit_first", [False, True])
def test_uncertain_funding_commit_retains_inputs_even_when_physical_commit_failed(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, *, commit_first: bool
) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        engine, chain = _engine(store, harness, monkeypatch)
        chain.fund_output.return_value = replace(
            FUNDED, selected_inputs=((FUNDED.anchor_txid, FUNDED.anchor_vout),)
        )
        item = store.settlement_work(session_id=session)[0]
        advance = store.advance_reverse_swap

        def fail_at_grant(*args: Any, **kwargs: Any) -> str:  # noqa: ANN401 - fault boundary
            store._connection = FailingCommit(  # type: ignore[assignment]  # noqa: SLF001
                store._connection,  # noqa: SLF001
                commit_first=commit_first,
            )
            return advance(*args, **kwargs)

        monkeypatch.setattr(store, "advance_reverse_swap", fail_at_grant)
        with pytest.raises(LiveSessionStoreError, match="commit outcome uncertain"):
            asyncio.run(engine.advance(item, NOW))
        chain.fund_output.assert_called_once()
        chain.release_funding_inputs.assert_not_called()
        chain.broadcast.assert_not_called()
    with harness.acquire() as reopened:
        retained = reopened.settlement_work(session_id=session)[0]
        assert retained.state == ("FUNDING_SENT" if commit_first else "LN_HELD")
        assert retained.funding_tx == (FUNDED.raw if commit_first else None)
        assert _certificate(reopened, session) is not commit_first


@pytest.mark.parametrize("mode", ["negative", "query", "stale", "release", "legacy"])
def test_cleanup_refusal_preserves_original_error_and_conservative_locks(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        engine, chain = _engine(store, harness, monkeypatch)
        original = LiveSessionStoreError("grant refused")

        def refuse(*_args: object, **_kwargs: object) -> None:
            if mode == "stale":
                engine._check_operation().abandon()  # noqa: SLF001 - genuine stale token
            raise original

        monkeypatch.setattr(store, "advance_reverse_swap", refuse)
        certificate = Mock(return_value=mode != "negative")
        if mode == "query":
            certificate.side_effect = LiveSessionStoreError("checking authority unavailable")
        monkeypatch.setattr(store, "reverse_funding_is_ungranted", certificate)
        if mode == "release":
            chain.release_funding_inputs.side_effect = RuntimeError("RPC lost")
        if mode == "legacy":
            chain.fund_output.return_value = FUNDED
        item = store.settlement_work(session_id=session)[0]
        with pytest.raises(LiveSessionStoreError, match="grant refused") as error:
            asyncio.run(engine.advance(item, NOW))
        assert error.value is original
        if mode == "release":
            chain.release_funding_inputs.assert_called_once()
        else:
            chain.release_funding_inputs.assert_not_called()
        if mode in {"legacy", "stale"}:
            certificate.assert_not_called()
        if mode in {"query", "stale", "release"}:
            assert any("cleanup unconfirmed" in note for note in original.__notes__)
        chain.broadcast.assert_not_called()


def test_broadcast_error_after_committed_grant_never_releases_inputs(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        engine, chain = _engine(store, harness, monkeypatch)
        chain.fund_output.return_value = replace(FUNDED, selected_inputs=((FUNDED.anchor_txid, 0),))
        chain.broadcast.side_effect = RuntimeError("broadcast response lost")
        with pytest.raises(RuntimeError, match="broadcast response lost"):
            asyncio.run(engine.advance(store.settlement_work(session_id=session)[0], NOW))
        assert not _certificate(store, session)
        chain.release_funding_inputs.assert_not_called()


@pytest.mark.parametrize("phase", ["funding", "cleanup"])
def test_cancel_during_external_worker_drains_without_further_economic_action(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        engine, chain = _engine(store, harness, monkeypatch)
        entered, release = threading.Event(), threading.Event()

        def blocking() -> object:
            entered.set()
            assert release.wait(5)
            return chain.fund_output.return_value if phase == "funding" else None

        if phase == "funding":
            chain.fund_output.side_effect = lambda *_a, **_k: blocking()
        else:
            chain.release_funding_inputs.side_effect = lambda *_a: blocking()

        async def exercise() -> None:
            item = store.settlement_work(session_id=session)[0]
            task = asyncio.create_task(engine.advance(item, NOW))
            try:
                assert await asyncio.to_thread(entered.wait, 5)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()  # Gate remains owned until the real worker drains.
            finally:
                release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            async with store.reverse_operations.operation() as operation:
                operation.check()  # Cancellation did not strand the gate.

        asyncio.run(exercise())
        chain.broadcast.assert_not_called()
        if phase == "funding":
            chain.release_funding_inputs.assert_not_called()
