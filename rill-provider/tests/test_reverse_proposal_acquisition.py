"""Gate-owned acquisition using native crypto and simulated backend observations.

These cases do not activate production negotiation or establish live chain facts.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.settlement import reconstruct_taproot_contract
from test_reverse_proposal_debt import _facts
from test_reverse_proposal_debt import (
    pytestmark as pytestmark,  # noqa: PLC0414 - native test policy
)
from test_reverse_proposal_reservation import NativeSigner
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider.core_tx_bytes import ReverseSpendCheckpoint
from rill_provider.live_session_store import LiveSessionStoreError, StaleOwnerError
from rill_provider.lnd_payment_observation import LndProtocolError
from rill_provider.reverse_operations import ReverseOperation
from rill_provider.reverse_settlement import ReverseSettlement, _ReversePublicKeySnapshot

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.wire.messages import ContractTerms, FundingBinding, InvoiceBinding
    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - exact owner, clock, and reservation test seams


def _funded(reserved: ReservationCase) -> None:
    reserved.store.advance_reverse_swap(
        reserved.origin.session_id,
        from_state="FUNDING_SENT",
        to_state="FUNDED",
        scan_checkpoint=ReverseSpendCheckpoint(999, "ab" * 32, 999, "ab" * 32),
        signer=NativeSigner(reserved.origin),
        now=1_700_000_000,
    )


def _no_debt(reserved: ReservationCase) -> None:
    assert reserved.store._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)
    assert reserved.store._connection.execute(
        "SELECT state FROM economic_reservations"
    ).fetchone() == ("DISPATCHED",)


def test_fresh_acquisition_uses_original_clock_gate_and_public_worker_snapshot(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        _funded(reserved)
        terms, core, invoice = _facts(reserved)
        chain, hold = Mock(), Mock()
        owner_thread = threading.get_ident()
        native = reserved.origin.crypto.crypto
        calls = []
        guards = []

        class OwnerKeys:
            def musig_internal_key(self, user: bytes, provider: bytes) -> tuple[bytes, int]:
                assert threading.get_ident() == owner_thread
                return native.musig_internal_key(user, provider)

            def musig_output_key(
                self, user: bytes, provider: bytes, tweak: bytes
            ) -> tuple[bytes, int]:
                assert threading.get_ident() == owner_thread
                return native.musig_output_key(user, provider, tweak)

        def observe_core(
            binding: FundingBinding,
            retained: ContractTerms,
            *,
            keys: object,
            allow_unconfirmed: bool,
        ) -> object:
            assert threading.get_ident() != owner_thread
            assert allow_unconfirmed is True  # the client may claim before the signed depth
            assert retained == terms
            assert binding.funding_txid == core.funding_txid
            assert type(keys) is _ReversePublicKeySnapshot
            assert (
                reconstruct_taproot_contract(retained, keys=keys).script_pubkey
                == core.funding_script_pubkey
            )
            calls.append("Core")
            reserved.clock.advance(0.4)
            return core

        def observe_invoice(
            expected: InvoiceBinding, *, submission_allowed: Callable[[], bool]
        ) -> object:
            assert threading.get_ident() != owner_thread
            assert expected == terms.invoice_binding
            assert submission_allowed() is True
            guards.append(submission_allowed)
            calls.append("LND")
            reserved.clock.advance(0.3)
            assert submission_allowed() is True
            return invoice

        chain.observe_cooperative_claim_outpoint.side_effect = observe_core
        hold.observe_bound_invoice.side_effect = observe_invoice
        engine = ReverseSettlement(reserved.store, chain, hold, OwnerKeys())
        receipt = await engine._acquire_proposal_debt(
            reserved.document,
            1_700_000_001,
            wall_clock=reserved.clock.utc,
            monotonic_clock=reserved.clock.steady,
        )
        assert not receipt.replay
        assert calls == ["Core", "LND"]
        assert guards[0]() is False
        assert reserved.store._connection.execute(
            "SELECT state,preimage FROM swaps"
        ).fetchone() == (
            "FUNDED",
            "52" * 32,
        )
        assert (
            reserved.store._reverse_proposals[receipt.session_id].window.monotonic_deadline == 130
        )
        assert not reserved.store._cooperation_handles
        hold.settle_bound_invoice.assert_not_called()
        hold.settle.assert_not_called()
        hold.lookup.assert_not_called()
        hold.cancel.assert_not_called()

    asyncio.run(exercise())


@pytest.mark.parametrize("fault", ["absent", "partial", "lost memory", "lost negotiation"])
def test_incomplete_original_reservation_refuses_before_any_backend_acquisition(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    async def exercise() -> None:
        _funded(reserved)
        store = reserved.store
        original_admit = store._admit_reverse_cooperative_proposal

        def admit_then_corrupt(*args: object, **kwargs: object) -> object:
            receipt = original_admit(*args, **kwargs)
            if fault == "absent":
                store._connection.execute("DELETE FROM cooperation_attempts")
            elif fault == "partial":
                store._connection.execute("UPDATE cooperation_attempts SET binding=?", (b"{}",))
            elif fault == "lost memory":
                store._reverse_proposals.clear()
            else:
                store._reverse_negotiations.clear()
            return receipt

        monkeypatch.setattr(store, "_admit_reverse_cooperative_proposal", admit_then_corrupt)
        chain, hold = Mock(), Mock()
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        with pytest.raises(LiveSessionStoreError, match="acquisition refused"):
            await engine._acquire_proposal_debt(
                reserved.document,
                1_700_000_001,
                wall_clock=reserved.clock.utc,
                monotonic_clock=reserved.clock.steady,
            )
        _no_debt(reserved)
        assert chain.mock_calls == hold.mock_calls == []
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("backend", ["Core", "LND"])
@pytest.mark.parametrize("interrupt", ["cancel", "close"])
def test_interrupted_acquisition_retains_exclusion_through_physical_drain_without_debt(  # noqa: PLR0915 - one synchronized lifecycle
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    interrupt: str,
) -> None:
    async def exercise() -> None:  # noqa: PLR0915 - one synchronized lifecycle
        _funded(reserved)
        store = reserved.store
        _, core, invoice = _facts(reserved)
        entered, release = threading.Event(), threading.Event()
        draining = asyncio.Event()
        chain, hold = Mock(), Mock()
        original_drain = ReverseOperation._drain

        async def checked_drain(token: ReverseOperation) -> None:
            assert token.submission_allowed() is False
            window = store._reverse_proposals.get(reserved.origin.session_id)
            if window is not None and window.window is not None:
                assert window.window.time_allowed() is False
            draining.set()
            await original_drain(token)

        def blocked_core(*_args: object, **_kwargs: object) -> object:
            if backend == "Core":
                entered.set()
                assert release.wait(5)
            return core

        def blocked_invoice(*_args: object, submission_allowed: Callable[[], bool]) -> object:
            assert submission_allowed() is True
            entered.set()
            assert release.wait(5)
            assert submission_allowed() is False
            return invoice

        chain.observe_cooperative_claim_outpoint.side_effect = blocked_core
        hold.observe_bound_invoice.side_effect = blocked_invoice
        monkeypatch.setattr(ReverseOperation, "_drain", checked_drain)
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        running = asyncio.create_task(
            engine._acquire_proposal_debt(
                reserved.document,
                1_700_000_001,
                wall_clock=reserved.clock.utc,
                monotonic_clock=reserved.clock.steady,
            )
        )
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            if interrupt == "cancel":
                running.cancel()
                await asyncio.wait_for(draining.wait(), 2)
            else:
                store.close()
            assert not running.done()
            assert store.reverse_operations._active_operation is not None
            release.set()
            with pytest.raises(
                asyncio.CancelledError if interrupt == "cancel" else StaleOwnerError
            ):
                await running
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)
        hold.settle.assert_not_called()
        hold.settle_bound_invoice.assert_not_called()
        hold.cancel.assert_not_called()
        if backend == "Core":
            hold.observe_bound_invoice.assert_not_called()
        if interrupt == "cancel":
            _no_debt(reserved)
        else:
            with reserved.origin.acquire_at(
                reserved.origin.path,
                crypto=reserved.origin.crypto,
                public_keys=reserved.origin.crypto.crypto,
            ) as fresh:
                assert fresh._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)
                assert not fresh._reverse_proposals
                assert not fresh._reverse_negotiations

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "failure",
    [
        "Core error",
        "LND error",
        "Core expiry",
        "setup expiry",
        "dispatch expiry",
        "late response",
        "one second",
        "writer delay",
        "executor queue",
        "wrong reservation",
        "wrong tip",
    ],
)
def test_failed_acquisition_abandons_original_window_without_debt_or_secret_dispatch(  # noqa: PLR0915 - complete acquisition failure matrix
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    async def exercise() -> None:  # noqa: PLR0915 - complete failure lifecycle
        _funded(reserved)
        _, core, invoice = _facts(reserved)
        chain, hold = Mock(), Mock()

        def observe_core(*_args: object, **_kwargs: object) -> object:
            if failure == "Core error":
                raise OSError("unavailable")
            if failure == "Core expiry":
                reserved.clock.advance(30)
            if failure == "wrong reservation":
                return replace(core, funding_txid="ab" * 32)
            return core

        def observe_invoice(*_args: object, submission_allowed: Callable[[], bool]) -> object:
            if failure == "LND error":
                raise LndProtocolError("unavailable")
            if failure == "setup expiry":
                reserved.clock.advance(30)
                assert submission_allowed() is False
                raise LndProtocolError("setup expired")
            assert submission_allowed() is True
            if failure == "dispatch expiry":
                reserved.clock.advance(30)
                assert submission_allowed() is False
                raise LndProtocolError("next read dispatch expired")
            if failure == "late response":
                reserved.clock.advance(30)
            elif failure == "one second":
                reserved.clock.advance(1)
            if failure == "wrong tip":
                return replace(invoice, last_lnd_block_hash="ab" * 32)
            return invoice

        if failure == "writer delay":
            original = reserved.store._commit_reverse_proposal_debt

            def delayed(*args: object, **kwargs: object) -> None:
                reserved.clock.advance(1)
                original(*args, **kwargs)

            monkeypatch.setattr(reserved.store, "_commit_reverse_proposal_debt", delayed)
        if failure == "executor queue":
            original_worker = ReverseOperation.worker
            queued = False

            async def delayed_queue(
                token: ReverseOperation, function: Callable[[], object]
            ) -> object:
                nonlocal queued
                if not queued:
                    queued = True
                    reserved.clock.advance(1)
                return await original_worker(token, function)

            monkeypatch.setattr(ReverseOperation, "worker", delayed_queue)
        chain.observe_cooperative_claim_outpoint.side_effect = observe_core
        hold.observe_bound_invoice.side_effect = observe_invoice
        engine = ReverseSettlement(reserved.store, chain, hold, reserved.origin.crypto.crypto)
        with pytest.raises(LiveSessionStoreError, match="acquisition refused"):
            await engine._acquire_proposal_debt(
                reserved.document,
                1_700_000_001,
                wall_clock=reserved.clock.utc,
                monotonic_clock=reserved.clock.steady,
            )
        _no_debt(reserved)
        window = reserved.store._reverse_proposals[reserved.origin.session_id].window
        assert window is not None
        assert not window.time_allowed()
        assert (
            reserved.store._reverse_preimage_evidence(reserved.origin.session_id)
            == reserved.document
        )
        assert not reserved.store._cooperation_handles
        hold.settle.assert_not_called()
        hold.settle_bound_invoice.assert_not_called()
        hold.cancel.assert_not_called()
        if failure in ("Core error", "Core expiry"):
            hold.observe_bound_invoice.assert_not_called()

    asyncio.run(exercise())


@pytest.mark.parametrize("restart", [False, True])
@pytest.mark.parametrize("existing_debt", [False, True])
def test_replay_is_receipt_only_without_backend_clock_or_window_reconstruction(
    reserved: ReservationCase,
    *,
    restart: bool,
    existing_debt: bool,
) -> None:
    async def exercise() -> None:
        _funded(reserved)
        chain, hold = Mock(), Mock()
        if existing_debt:
            _, core, invoice = _facts(reserved)
            chain.observe_cooperative_claim_outpoint.return_value = core
            hold.observe_bound_invoice.return_value = invoice
            engine = ReverseSettlement(reserved.store, chain, hold, reserved.origin.crypto.crypto)
            receipt = await engine._acquire_proposal_debt(
                reserved.document,
                1_700_000_001,
                wall_clock=reserved.clock.utc,
                monotonic_clock=reserved.clock.steady,
            )
            assert not receipt.replay
            chain.reset_mock()
            hold.reset_mock()
        else:
            async with reserved.store.reverse_operations.operation() as operation:
                reserved.admit(operation)
        original_window = reserved.store._reverse_proposals[reserved.origin.session_id].window

        def forbidden_clock() -> float:
            raise AssertionError("replay sampled a replacement clock")

        async def replay(store: object) -> None:
            engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
            receipt = await engine._acquire_proposal_debt(
                reserved.document,
                1_700_000_001,
                wall_clock=forbidden_clock,
                monotonic_clock=forbidden_clock,
            )
            assert receipt.replay
            assert chain.mock_calls == hold.mock_calls == []
            assert store._connection.execute("SELECT preimage FROM swaps").fetchone() == (
                "52" * 32 if existing_debt else None,
            )

        if restart:
            reserved.store.close()
            with reserved.origin.acquire_at(
                reserved.origin.path,
                crypto=reserved.origin.crypto,
                public_keys=reserved.origin.crypto.crypto,
            ) as fresh:
                await replay(fresh)
                assert not fresh._reverse_proposals
                assert not fresh._reverse_negotiations
        else:
            await replay(reserved.store)
            assert (
                reserved.store._reverse_proposals[reserved.origin.session_id].window
                is original_window
            )

    asyncio.run(exercise())
