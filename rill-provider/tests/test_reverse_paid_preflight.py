"""Nonallocating paid preflight, native original context and simulated backend facts."""

from __future__ import annotations

import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core import networks
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from test_lnd_bound_invoice import _bound
from test_reverse_paid_context import _debt, _repay
from test_reverse_proposal_debt import _facts
from test_reverse_proposal_debt import (
    pytestmark as pytestmark,  # noqa: PLC0414 - native test policy
)
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider.core_tx_bytes import CooperativeFeePolicy
from rill_provider.live_session_store import LiveSessionStoreError, StaleOwnerError
from rill_provider.lnd_hold_invoice import HoldInvoiceStatus
from rill_provider.lnd_payment_observation import LndProtocolError
from rill_provider.reverse_operations import ReverseOperation
from rill_provider.reverse_settlement import ReverseSettlement, _ReversePublicKeySnapshot

if TYPE_CHECKING:
    from pathlib import Path

    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - exact original owner/window and nonallocating runtime seams


def _backends(reserved: ReservationCase) -> tuple[Mock, Mock]:
    terms, core, invoice = _facts(reserved)
    policy = CooperativeFeePolicy(
        terms.network_identity,
        core.tip_hash,
        core.tip_height,
        terms.timing_policy.claim_confirmation_blocks,
        1,
        1,
        1,
        1,
    )
    chain, hold = Mock(), Mock()
    chain.observe_cooperative_claim_outpoint.return_value = core
    chain.observe_cooperative_fee_policy.return_value = policy
    hold.observe_bound_settled_invoice.return_value = replace(
        invoice, status=HoldInvoiceStatus("SETTLED", ())
    )
    return chain, hold


def test_success_collects_stronger_paid_query_and_fees_without_creating_authority(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        chain, hold = _backends(reserved)
        assert (
            chain.observe_cooperative_claim_outpoint.return_value.tip_height
            == json.loads(reserved.document)["payload"]["deadline_height"]
        )  # Reverse signed height equality is allowed.
        rows = store._connection.execute("SELECT * FROM swaps").fetchall()
        attempts = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
        outbox = store.pending_outbox()
        window = store._reverse_proposals[reserved.origin.session_id].window
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        assert (
            await engine._preflight_paid_proposal(reserved.document, configured_floor_sat=1) is None
        )
        async with store.reverse_operations.operation() as operation:
            context = store._reverse_live_proposal_context(
                reserved.document, operation=operation, purpose="paid-signing"
            )
            assert (4 * len(context.plan.base_transaction) + 68 + 3) // 4 == 99
        core_args = chain.observe_cooperative_claim_outpoint.call_args
        assert type(core_args.kwargs["keys"]) is _ReversePublicKeySnapshot
        chain.observe_cooperative_fee_policy.assert_called_once_with(
            _facts(reserved)[0].timing_policy.claim_confirmation_blocks,
            allow_regtest_fixed_fee=False,
        )
        hold.observe_bound_settled_invoice.assert_called_once()
        assert hold.observe_bound_settled_invoice.call_args.kwargs["submission_allowed"]() is False
        hold.observe_bound_invoice.assert_not_called()
        hold.lookup.assert_not_called()
        hold.settle.assert_not_called()
        hold.settle_bound_invoice.assert_not_called()
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == rows
        assert (
            store._connection.execute("SELECT * FROM cooperation_attempts").fetchall() == attempts
        )
        assert store.pending_outbox() == outbox
        assert store._reverse_proposals[reserved.origin.session_id].window is window
        assert window is not None
        assert window.time_allowed()
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("flag", [None, 1, "true"])
def test_regtest_exemption_cannot_be_inferred_from_nonboolean_configuration(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    flag: object,
) -> None:
    async def exercise() -> None:
        getter = Mock(
            side_effect=AssertionError("configuration must fail before context acquisition")
        )
        monkeypatch.setattr(reserved.store, "_reverse_live_proposal_context", getter)
        chain, hold = Mock(), Mock()
        engine = ReverseSettlement(reserved.store, chain, hold, reserved.origin.crypto.crypto)
        with pytest.raises(LiveSessionStoreError, match="preflight refused"):
            await engine._preflight_paid_proposal(
                reserved.document, configured_floor_sat=1, allow_regtest_fixed_fee=flag
            )
        getter.assert_not_called()
        assert chain.mock_calls == hold.mock_calls == []

    asyncio.run(exercise())


@pytest.mark.parametrize("name", ["mainnet", "signet", "testnet4"])
def test_fixed_fee_exemption_is_forbidden_on_every_public_network_before_backend_reads(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    async def exercise() -> None:
        reserved.store._network = reserved.store.network_identity.model_copy(
            update={
                "name": name,
                "genesis_hash": networks._GENESIS[name],
                "consensus_profile": networks.PUBLIC_CONSENSUS_PROFILE,
                "deployment_namespace": None,
                "signet_challenge": networks.DEFAULT_SIGNET_CHALLENGE if name == "signet" else None,
            }
        )
        networks.require_supported_network(reserved.store.network_identity)
        getter = Mock(
            side_effect=AssertionError("public exemption must fail before context acquisition")
        )
        monkeypatch.setattr(reserved.store, "_reverse_live_proposal_context", getter)
        chain, hold = Mock(), Mock()
        engine = ReverseSettlement(reserved.store, chain, hold, reserved.origin.crypto.crypto)
        with pytest.raises(LiveSessionStoreError, match="preflight refused"):
            await engine._preflight_paid_proposal(
                reserved.document, configured_floor_sat=1, allow_regtest_fixed_fee=True
            )
        getter.assert_not_called()
        assert chain.mock_calls == hold.mock_calls == []

    asyncio.run(exercise())


@pytest.mark.parametrize("history", ["owed funded", "restart"])
def test_paid_preflight_never_uses_remote_payment_to_reconstruct_local_or_original_authority(
    reserved: ReservationCase,
    history: str,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        chain, hold = _backends(reserved)
        if history == "restart":
            await _repay(reserved)
            reserved.store.close()

        async def refuse(store: object) -> None:
            engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
            with pytest.raises(LiveSessionStoreError, match="preflight refused"):
                await engine._preflight_paid_proposal(reserved.document, configured_floor_sat=1)
            assert chain.mock_calls == hold.mock_calls == []
            assert not store._cooperation_handles

        if history == "restart":
            with reserved.origin.acquire_at(
                reserved.origin.path,
                crypto=reserved.origin.crypto,
                public_keys=reserved.origin.crypto.crypto,
            ) as fresh:
                await refuse(fresh)
                assert not fresh._reverse_proposals
        else:
            await refuse(reserved.store)
            await _repay(reserved)  # Early signing refusal must not strand debt.

    asyncio.run(exercise())


def test_invalid_native_proposal_plan_is_rejected_before_backend_acquisition(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        invalid = reserved.signed(transaction="00" * 60)
        outer = Envelope.model_validate_json(invalid, strict=True)
        attempt = store._reverse_proposals[reserved.origin.session_id]
        # Corrupted process-local correspondence still cannot skip native plan checks.
        store._reverse_proposals[reserved.origin.session_id] = replace(
            attempt, unsigned_digest=unsigned_envelope_hash(outer).hex()
        )
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        with pytest.raises(LiveSessionStoreError, match="preflight refused"):
            await engine._preflight_paid_proposal(invalid, configured_floor_sat=1)
        assert chain.mock_calls == hold.mock_calls == []
        assert attempt.window is not None
        assert not attempt.window.time_allowed()
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("backend", ["Core", "fees", "LND"])
@pytest.mark.parametrize("interrupt", ["cancel", "close"])
def test_interrupted_preflight_destroys_window_permission_and_drains_started_read(  # noqa: PLR0915 - synchronized physical drain lifecycle
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    interrupt: str,
) -> None:
    async def exercise() -> None:  # noqa: PLR0915 - one interrupt lifecycle
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        chain, hold = _backends(reserved)
        selected = {
            "Core": chain.observe_cooperative_claim_outpoint,
            "fees": chain.observe_cooperative_fee_policy,
            "LND": hold.observe_bound_settled_invoice,
        }[backend]
        entered, release = threading.Event(), threading.Event()
        draining = asyncio.Event()
        window = store._reverse_proposals[reserved.origin.session_id].window
        original_drain = ReverseOperation._drain

        async def checked_drain(token: ReverseOperation) -> None:
            assert not token.submission_allowed()
            assert window is not None
            assert not window.time_allowed()
            draining.set()
            await original_drain(token)

        def blocked(*_args: object, **kwargs: object) -> object:
            if backend == "LND":
                assert kwargs["submission_allowed"]() is True
            entered.set()
            assert release.wait(5)
            if backend == "LND":
                assert kwargs["submission_allowed"]() is False
            return selected.return_value

        selected.side_effect = blocked
        monkeypatch.setattr(ReverseOperation, "_drain", checked_drain)
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        running = asyncio.create_task(
            engine._preflight_paid_proposal(reserved.document, configured_floor_sat=1)
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
        hold.lookup.assert_not_called()
        hold.settle.assert_not_called()
        hold.settle_bound_invoice.assert_not_called()
        if interrupt == "cancel":
            assert store._connection.execute("SELECT state,preimage FROM swaps").fetchone() == (
                "SETTLED",
                "52" * 32,
            )
            assert not store._cooperation_handles
        else:
            with reserved.origin.acquire_at(
                reserved.origin.path,
                crypto=reserved.origin.crypto,
                public_keys=reserved.origin.crypto.crypto,
            ) as fresh:
                assert fresh._connection.execute("SELECT state,preimage FROM swaps").fetchone() == (
                    "SETTLED",
                    "52" * 32,
                )
                assert not fresh._reverse_proposals

    asyncio.run(exercise())


@pytest.mark.parametrize("paid", ["underpaid", "sufficient"])
def test_preflight_collects_actual_stronger_adapter_query_not_ordinary_observation(
    reserved: ReservationCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    paid: str,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        terms, core, _ = _facts(reserved)
        binding = terms.invoice_binding
        case = _bound(tmp_path, monkeypatch, terms.network_identity)
        for index in (0, 2):
            case.responses[index].identity_pubkey = binding.payee_compressed_pubkey
            case.responses[index].block_height = core.tip_height
            case.responses[index].block_hash = core.tip_hash
        invoice = case.responses[1]
        invoice.r_hash = bytes.fromhex(binding.payment_hash)
        invoice.payment_request = "lnbcrt1007u1hold"
        invoice.value_msat = int(binding.amount_msat)
        invoice.creation_date = binding.created_at
        invoice.expiry = binding.expires_at - binding.created_at
        invoice.cltv_expiry = binding.min_final_cltv_delta
        invoice.state = invoice.SETTLED
        invoice.amt_paid_msat = int(binding.amount_msat) - (1 if paid == "underpaid" else 0)
        chain, _ = _backends(reserved)
        engine = ReverseSettlement(
            reserved.store, chain, case.client, reserved.origin.crypto.crypto
        )
        if paid == "underpaid":
            with pytest.raises(LiveSessionStoreError, match="preflight refused"):
                await engine._preflight_paid_proposal(reserved.document, configured_floor_sat=1)
        else:
            await engine._preflight_paid_proposal(reserved.document, configured_floor_sat=1)
        assert len(case.channel.calls) == 3
        assert case.channel.closed
        assert not reserved.store._cooperation_handles
        assert reserved.store._connection.execute(
            "SELECT state,preimage FROM swaps"
        ).fetchone() == (
            "SETTLED",
            "52" * 32,
        )

    asyncio.run(exercise())


@pytest.mark.parametrize("floor", [0, -1, True, "1", 21_000_000 * 100_000_000 + 1])
def test_invalid_explicit_fee_configuration_cannot_acquire_backend_evidence(
    reserved: ReservationCase,
    floor: object,
) -> None:
    async def exercise() -> None:
        chain, hold = Mock(), Mock()
        engine = ReverseSettlement(reserved.store, chain, hold, reserved.origin.crypto.crypto)
        with pytest.raises(LiveSessionStoreError, match="preflight refused"):
            await engine._preflight_paid_proposal(reserved.document, configured_floor_sat=floor)
        assert chain.mock_calls == hold.mock_calls == []
        assert not reserved.store._reverse_proposals
        assert not reserved.store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "fault",
    [
        "underpaid",
        "ordinary lookup",
        "core tip",
        "fee tip",
        "invoice tip",
        "core outpoint",
        "static match",
        "depth",
        "bool depth",
        "estimate absent",
        "estimate horizon",
        "negative relay",
        "bool relay",
        "configured floor",
        "relay floor",
        "mempool floor",
        "estimate floor",
        "core delay",
        "fee delay",
        "invoice delay",
        "validation delay",
    ],
)
def test_bad_or_stale_paid_evidence_abandons_window_without_financial_or_custody_changes(  # noqa: PLR0915 - one evidence refusal matrix
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    async def exercise() -> None:  # noqa: PLR0912, PLR0915 - one evidence refusal matrix
        await _debt(reserved)
        await _repay(reserved)
        store = reserved.store
        chain, hold = _backends(reserved)
        core = chain.observe_cooperative_claim_outpoint.return_value
        policy = chain.observe_cooperative_fee_policy.return_value
        invoice = hold.observe_bound_settled_invoice.return_value
        floor = 1
        if fault in ("underpaid", "ordinary lookup"):
            hold.observe_bound_invoice.return_value = invoice
            hold.lookup.return_value = invoice.status
            hold.observe_bound_settled_invoice.side_effect = LndProtocolError(
                "not sufficiently settled"
            )
        elif fault == "core tip":
            chain.observe_cooperative_claim_outpoint.return_value = replace(
                core, tip_hash="ab" * 32
            )
        elif fault == "fee tip":
            chain.observe_cooperative_fee_policy.return_value = replace(policy, tip_hash="ab" * 32)
        elif fault == "invoice tip":
            hold.observe_bound_settled_invoice.return_value = replace(
                invoice, last_lnd_block_hash="ab" * 32
            )
        elif fault == "core outpoint":
            chain.observe_cooperative_claim_outpoint.return_value = replace(
                core, funding_txid="ab" * 32
            )
        elif fault == "static match":
            chain.observe_cooperative_claim_outpoint.return_value = replace(
                core, static_match=replace(core.static_match, lineage_anchor_txid="ab" * 32)
            )
        elif fault in ("depth", "bool depth"):
            chain.observe_cooperative_claim_outpoint.return_value = replace(
                core, confirmations=0 if fault == "depth" else True
            )
        elif fault == "estimate absent":
            chain.observe_cooperative_fee_policy.return_value = replace(
                policy, estimate_sat_kvb=None
            )
        elif fault == "estimate horizon":
            chain.observe_cooperative_fee_policy.return_value = replace(
                policy, estimate_blocks=policy.confirmation_blocks + 1
            )
        elif fault in ("negative relay", "bool relay"):
            chain.observe_cooperative_fee_policy.return_value = replace(
                policy, min_relay_sat_kvb=-1 if fault == "negative relay" else True
            )
        elif fault == "configured floor":
            floor = 1_000_000
        elif fault in ("relay floor", "mempool floor", "estimate floor"):
            field = {
                "relay floor": "min_relay_sat_kvb",
                "mempool floor": "mempool_min_sat_kvb",
                "estimate floor": "estimate_sat_kvb",
            }[fault]
            chain.observe_cooperative_fee_policy.return_value = replace(
                policy, **{field: 1_000_000}
            )
        elif fault in ("core delay", "fee delay", "invoice delay"):
            selected = {
                "core delay": chain.observe_cooperative_claim_outpoint,
                "fee delay": chain.observe_cooperative_fee_policy,
                "invoice delay": hold.observe_bound_settled_invoice,
            }[fault]

            def delayed(*_args: object, **_kwargs: object) -> object:
                reserved.clock.advance(1)
                return selected.return_value

            selected.side_effect = delayed
        else:
            getter = store._reverse_live_proposal_context
            count = 0

            def delayed_validation(*args: object, **kwargs: object) -> object:
                nonlocal count
                count += 1
                if count == 2:
                    reserved.clock.advance(1)
                return getter(*args, **kwargs)

            monkeypatch.setattr(store, "_reverse_live_proposal_context", delayed_validation)
        rows = store._connection.execute("SELECT * FROM swaps").fetchall()
        attempts = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        with pytest.raises(LiveSessionStoreError, match="preflight refused"):
            await engine._preflight_paid_proposal(reserved.document, configured_floor_sat=floor)
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == rows
        assert (
            store._connection.execute("SELECT * FROM cooperation_attempts").fetchall() == attempts
        )
        window = store._reverse_proposals[reserved.origin.session_id].window
        assert window is not None
        assert not window.time_allowed()
        assert not store._cooperation_handles
        hold.observe_bound_invoice.assert_not_called()
        hold.lookup.assert_not_called()
        hold.settle.assert_not_called()
        hold.settle_bound_invoice.assert_not_called()

    asyncio.run(exercise())


@pytest.mark.parametrize("exemption", [False, True])
def test_unavailable_estimate_needs_explicit_regtest_exemption(
    reserved: ReservationCase,
    *,
    exemption: bool,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        chain, hold = _backends(reserved)
        policy = chain.observe_cooperative_fee_policy.return_value
        chain.observe_cooperative_fee_policy.return_value = replace(
            policy, estimate_sat_kvb=None, estimate_blocks=0
        )
        engine = ReverseSettlement(reserved.store, chain, hold, reserved.origin.crypto.crypto)
        if exemption:
            await engine._preflight_paid_proposal(
                reserved.document, configured_floor_sat=1, allow_regtest_fixed_fee=True
            )
            assert not reserved.store._cooperation_handles
        else:
            with pytest.raises(LiveSessionStoreError, match="preflight refused"):
                await engine._preflight_paid_proposal(reserved.document, configured_floor_sat=1)

    asyncio.run(exercise())


def test_actual_executor_queue_delay_counts_against_original_complete_evidence_interval(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        chain, hold = _backends(reserved)
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        occupied, queued = asyncio.Event(), asyncio.Event()
        release = threading.Event()

        def occupy() -> None:
            loop.call_soon_threadsafe(occupied.set)
            assert release.wait(5)

        blocker = loop.run_in_executor(None, occupy)
        await asyncio.wait_for(occupied.wait(), 2)
        original_submit = loop.run_in_executor

        def submit(executor: object, function: object, *args: object) -> object:
            future = original_submit(executor, function, *args)
            queued.set()
            return future

        monkeypatch.setattr(loop, "run_in_executor", submit)
        engine = ReverseSettlement(reserved.store, chain, hold, reserved.origin.crypto.crypto)
        running = asyncio.create_task(
            engine._preflight_paid_proposal(reserved.document, configured_floor_sat=1)
        )
        try:
            await asyncio.wait_for(queued.wait(), 2)
            chain.observe_cooperative_claim_outpoint.assert_not_called()
            reserved.clock.advance(1)
            release.set()
            with pytest.raises(LiveSessionStoreError, match="preflight refused"):
                await running
            window = reserved.store._reverse_proposals[reserved.origin.session_id].window
            assert window is not None
            assert not window.time_allowed()
            assert not reserved.store._cooperation_handles
            hold.settle_bound_invoice.assert_not_called()
            assert reserved.store._connection.execute(
                "SELECT state,preimage FROM swaps"
            ).fetchone() == (
                "SETTLED",
                "52" * 32,
            )
        finally:
            release.set()
            await asyncio.gather(blocker, running, return_exceptions=True)

    asyncio.run(exercise())
