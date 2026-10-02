"""Native proposal debt boundary with simulated backend facts, not activation.

The fixture explicitly bypasses featured reverse acceptance. Native context and
transaction verification are real; supplied Core/LND observations are test data,
not live-chain or payment proof. Real adapter contracts are tested separately.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.settlement.funding import check_funding_binding_transaction
from rill_core.wire.canonical import canonicalize
from rill_core.wire.quotes import TermsOfferPayload
from rill_core.wire.settlement_messages import FundingBindingPayload
from test_handshake_reverse_gate import CommitThenFail
from test_reverse_proposal_reservation import NativeSigner
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - pytest fixture

from rill_provider import live_session_store as live
from rill_provider.core_tx_bytes import CooperativeClaimOutpoint
from rill_provider.lnd_hold_invoice import BoundHoldInvoiceObservation, HeldHtlc, HoldInvoiceStatus
from rill_provider.reverse_operations import ReverseOperations
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from rill_core.wire.messages import ContractTerms
    from test_reverse_proposal_reservation import ReservationCase

    from rill_provider.reverse_operations import ReverseOperation

pytestmark = [
    pytest.mark.native_crypto,
    pytest.mark.skipif(
        os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
        reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 for native reverse debt boundary",
    ),
]
# ruff: noqa: SLF001 - intentional real-store component/corruption seams


def _facts(
    reserved: ReservationCase,
) -> tuple[ContractTerms, CooperativeClaimOutpoint, BoundHoldInvoiceObservation]:
    connection = reserved.store._connection
    offered = json.loads(connection.execute("SELECT terms_offer FROM swaps").fetchone()[0])
    terms = TermsOfferPayload.model_validate_json(
        canonicalize(offered["payload"]), strict=True
    ).terms.contract_terms
    messages = [json.loads(entry.canonical_bytes) for entry in reserved.store.pending_outbox()]
    funded = next(item for item in messages if item["message_type"] == "funding_binding")
    selected = FundingBindingPayload.model_validate_json(
        canonicalize(funded["payload"]), strict=True
    )
    binding = selected.binding
    match = check_funding_binding_transaction(
        bytes.fromhex(selected.funding_transaction),
        binding,
        terms,
        keys=reserved.origin.crypto.crypto,
    )
    height = json.loads(reserved.document)["payload"]["deadline_height"]
    depth = max(terms.funding_confirmations, 2)
    core = CooperativeClaimOutpoint(
        terms.network_identity,
        match,
        binding.funding_txid,
        binding.contract_vout,
        int(binding.contract_value_sat),
        bytes.fromhex(binding.contract_script_pubkey),
        "61" * 32,
        height,
        depth,
        height - depth + 1,
        "62" * 32,
    )
    expiry = (
        terms.refund_lock_height
        + 2
        + int(terms.timing_policy.model_dump()["refund_and_ln_resolution_blocks"])
    )
    invoice = BoundHoldInvoiceObservation(
        terms.invoice_binding.payment_hash,
        terms.invoice_binding.bolt11_sha256,
        terms.invoice_binding.payee_compressed_pubkey,
        terms.network_identity,
        HoldInvoiceStatus("ACCEPTED", (HeldHtlc(int(terms.invoice_binding.amount_msat), expiry),)),
        height,
        core.tip_hash,
    )
    return terms, core, invoice


def _prepare(
    reserved: ReservationCase, operation: ReverseOperation, *, funded: bool = True
) -> None:
    store = reserved.store
    store._retain_reverse_preimage_evidence(
        reserved.document, operation=operation, now=1_700_000_000
    )
    reserved.admit(operation)
    if funded:
        store.advance_reverse_swap(
            reserved.origin.session_id,
            from_state="FUNDING_SENT",
            to_state="FUNDED",
            signer=NativeSigner(reserved.origin),
            now=1_700_000_000,
        )


def _commit(  # noqa: PLR0913 - explicit observations and their acquisition interval
    reserved: ReservationCase,
    operation: ReverseOperation,
    core: CooperativeClaimOutpoint,
    invoice: BoundHoldInvoiceObservation,
    *,
    started: float = 100.0,
    completed: float = 100.0,
) -> None:
    reserved.store._commit_reverse_proposal_debt(
        reserved.document,
        operation=operation,
        core=core,
        invoice=invoice,
        observations_started_at=started,
        observations_completed_at=completed,
        now=1_700_000_001,
    )


def test_native_debt_commit_changes_only_debt_and_audit_before_any_settlement(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
            sessions = store._connection.execute("SELECT * FROM sessions").fetchall()
            attempts = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
            outbox = store.pending_outbox()
            cursor = store._connection.execute("SELECT * FROM swaps")
            names = [column[0] for column in cursor.description]
            before = dict(zip(names, cursor.fetchone(), strict=True))
            _commit(reserved, operation, core, invoice)
            after = dict(
                zip(names, store._connection.execute("SELECT * FROM swaps").fetchone(), strict=True)
            )
            assert after == {**before, "preimage": "52" * 32, "updated_at": 1_700_000_001}
            assert store._connection.execute("SELECT * FROM sessions").fetchall() == sessions
            assert (
                store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
                == attempts
            )
            assert store.pending_outbox() == outbox
            assert store._reverse_preimage_evidence(reserved.origin.session_id) == reserved.document
            assert not store._cooperation_handles
            assert store._connection.execute(
                "SELECT state FROM economic_reservations"
            ).fetchone() == ("DISPATCHED",)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "fault",
    [
        "core network",
        "core match",
        "core txid",
        "core vout",
        "core amount",
        "core script",
        "depth",
        "inclusion",
        "tip hash",
        "inclusion hash",
        "maturity",
        "height cutoff",
        "lnd network",
        "lnd hash",
        "lnd bill",
        "lnd node",
        "lnd height",
        "lnd tip",
        "not accepted",
        "no parts",
        "held amount",
        "htlc margin",
        "bool amount",
        "origin",
        "blocked",
        "reservation",
        "generation",
        "binding",
        "inbox",
        "funding association",
        "existing debt",
        "not funded",
        "expiry",
        "evidence age",
    ],
)
def test_each_missing_or_mismatched_admission_fact_refuses_without_debt(  # noqa: PLR0915 - admission matrix
    reserved: ReservationCase, fault: str
) -> None:
    async def exercise() -> None:  # noqa: PLR0912, PLR0915 - one isolated fault per matrix case
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation, funded=fault != "not funded")
            terms, core, invoice = _facts(reserved)
            if fault == "core network":
                core = replace(
                    core,
                    network_identity=core.network_identity.model_copy(
                        update={"deployment_namespace": "other"}
                    ),
                )
            elif fault == "core match":
                core = replace(
                    core, static_match=replace(core.static_match, lineage_anchor_vout=99)
                )
            elif fault == "core txid":
                core = replace(core, funding_txid="ab" * 32)
            elif fault == "core vout":
                core = replace(core, funding_vout=True)
            elif fault == "core amount":
                core = replace(core, funding_value_sat=core.funding_value_sat + 1)
            elif fault == "core script":
                core = replace(core, funding_script_pubkey=b"\x51")
            elif fault == "depth":
                core = replace(core, confirmations=0)
            elif fault == "inclusion":
                core = replace(core, inclusion_height=0)
            elif fault == "tip hash":
                core = replace(core, tip_hash="not a hash")
            elif fault == "inclusion hash":
                core = replace(core, inclusion_block_hash="AA" * 32)
            elif fault == "maturity":
                core = replace(core, tip_height=terms.refund_lock_height)
            elif fault == "height cutoff":
                height = core.tip_height + 1
                core = replace(
                    core, tip_height=height, inclusion_height=height - core.confirmations + 1
                )
                invoice = replace(invoice, last_lnd_height=height)
            elif fault == "lnd network":
                invoice = replace(
                    invoice,
                    network=invoice.network.model_copy(update={"deployment_namespace": "other"}),
                )
            elif fault == "lnd hash":
                invoice = replace(invoice, payment_hash="ab" * 32)
            elif fault == "lnd bill":
                invoice = replace(invoice, bolt11_sha256="ab" * 32)
            elif fault == "lnd node":
                invoice = replace(invoice, node_pubkey="03" + "11" * 32)
            elif fault == "lnd height":
                invoice = replace(invoice, last_lnd_height=core.tip_height + 1)
            elif fault == "lnd tip":
                invoice = replace(invoice, last_lnd_block_hash="ab" * 32)
            elif fault == "not accepted":
                invoice = replace(invoice, status=replace(invoice.status, state="SETTLED"))
            elif fault == "no parts":
                invoice = replace(invoice, status=HoldInvoiceStatus("ACCEPTED", ()))
            elif fault in ("held amount", "htlc margin", "bool amount"):
                part = invoice.status.htlcs[0]
                if fault == "held amount":
                    part = replace(part, amount_msat=part.amount_msat + 1000)
                elif fault == "htlc margin":
                    part = replace(part, expiry_height=part.expiry_height - 1)
                else:
                    part = replace(part, amount_msat=True)
                invoice = replace(invoice, status=HoldInvoiceStatus("ACCEPTED", (part,)))
            elif fault == "origin":
                store._reverse_negotiations.clear()
            elif fault == "blocked":
                store._connection.execute("UPDATE sessions SET blocked=1")
            elif fault == "reservation":
                store._connection.execute("UPDATE cooperation_attempts SET state='ABANDONED'")
            elif fault == "generation":
                store._connection.execute(
                    "UPDATE cooperation_attempts SET owner_generation=owner_generation+1"
                )
            elif fault == "binding":
                store._connection.execute("UPDATE cooperation_attempts SET binding=?", (b"{}",))
            elif fault == "inbox":
                store._connection.execute("DELETE FROM inbox WHERE message_id=?", ("ee" * 32,))
            elif fault == "funding association":
                store._connection.execute("UPDATE swaps SET funding_tx=?", (b"changed",))
            elif fault == "existing debt":
                store.record_reverse_settlement_preimage(
                    reserved.origin.session_id,
                    from_state="FUNDED",
                    preimage="52" * 32,
                    now=1_700_000_000,
                )
            elif fault == "expiry":
                reserved.clock.advance(30)
            elif fault == "evidence age":
                reserved.clock.advance(1)
            before = store._connection.execute("SELECT * FROM swaps").fetchall()
            with pytest.raises(live.LiveSessionStoreError, match="reverse proposal debt refused"):
                _commit(reserved, operation, core, invoice)
            assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
            assert store._reverse_preimage_evidence(reserved.origin.session_id) == reserved.document
            assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "custody",
    ["local_nonce", "peer_nonce", "partial_signature", "nonce_response_id", "partial_response_id"],
)
def test_burned_reservation_with_any_custody_artifact_grants_no_debt(
    reserved: ReservationCase, custody: str
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
            artifact: object = (
                "response"
                if custody.endswith("response_id")
                else b"\x02" * (32 if custody == "partial_signature" else 66)
            )
            store._connection.execute("PRAGMA ignore_check_constraints=ON")
            store._connection.execute(f"UPDATE cooperation_attempts SET {custody}=?", (artifact,))  # noqa: S608
            store._connection.execute("PRAGMA ignore_check_constraints=OFF")
            before = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
            with pytest.raises(live.LiveSessionStoreError):
                _commit(reserved, operation, core, invoice)
            assert store._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)
            assert (
                store._connection.execute("SELECT * FROM cooperation_attempts").fetchall() == before
            )

    asyncio.run(exercise())


@pytest.mark.parametrize("unsafe_second_part", [False, True])
def test_every_multipart_htlc_must_cover_the_resolution_margin(
    reserved: ReservationCase, *, unsafe_second_part: bool
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
            part = invoice.status.htlcs[0]
            first = HeldHtlc(part.amount_msat // 2, part.expiry_height)
            second = HeldHtlc(
                part.amount_msat - first.amount_msat,
                part.expiry_height - int(unsafe_second_part),
            )
            invoice = replace(invoice, status=HoldInvoiceStatus("ACCEPTED", (first, second)))
            if unsafe_second_part:
                with pytest.raises(live.LiveSessionStoreError):
                    _commit(reserved, operation, core, invoice)
            else:
                _commit(reserved, operation, core, invoice)
            assert store._connection.execute("SELECT preimage FROM swaps").fetchone() == (
                None if unsafe_second_part else "52" * 32,
            )

    asyncio.run(exercise())


def test_positive_consistent_depth_below_signed_requirement_refuses(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            terms, core, invoice = _facts(reserved)
            assert terms.funding_confirmations > 1
            depth = terms.funding_confirmations - 1
            core = replace(
                core,
                confirmations=depth,
                inclusion_height=core.tip_height - depth + 1,
                inclusion_block_hash=core.tip_hash if depth == 1 else core.inclusion_block_hash,
            )
            with pytest.raises(live.LiveSessionStoreError):
                _commit(reserved, operation, core, invoice)
            assert store._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)

    asyncio.run(exercise())


@pytest.mark.parametrize("failure", ["delayed update", "write failure"])
def test_post_update_failure_rolls_back_debt_but_keeps_prior_knowledge(
    reserved: ReservationCase, failure: str
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
            original = store._connection

            class AfterUpdate:
                def __getattr__(self, name: str) -> object:
                    return getattr(original, name)

                def execute(self, statement: str, parameters: tuple[object, ...] = ()) -> object:
                    result = original.execute(statement, parameters)
                    if statement.startswith("UPDATE swaps SET preimage="):
                        if failure == "delayed update":
                            reserved.clock.advance(1)
                        else:
                            raise sqlite3.OperationalError("write reporting failure")
                    return result

            before = store._connection.execute("SELECT * FROM swaps").fetchall()
            store._connection = AfterUpdate()
            try:
                with pytest.raises(
                    live.LiveSessionStoreError, match="reverse proposal debt refused"
                ):
                    _commit(reserved, operation, core, invoice)
            finally:
                store._connection = original
            assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
            assert store._reverse_preimage_evidence(reserved.origin.session_id) == reserved.document
            assert not store._reverse_proposals[reserved.origin.session_id].window.time_allowed()

    asyncio.run(exercise())


@pytest.mark.parametrize("winner", ["debt", "refund"])
def test_shared_gate_serializes_refund_and_debt_with_first_committed_winner(
    reserved: ReservationCase, winner: str
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
        entered, release, queued = asyncio.Event(), asyncio.Event(), asyncio.Event()
        outcomes: dict[str, str] = {}

        async def act(kind: str) -> None:
            if kind != winner:
                queued.set()
            async with store.reverse_operations.operation() as operation:
                if kind == winner:
                    entered.set()
                    await release.wait()
                try:
                    if kind == "debt":
                        _commit(reserved, operation, core, invoice)
                    else:
                        store.advance_reverse_swap(
                            reserved.origin.session_id,
                            from_state="FUNDED",
                            to_state="REFUNDING",
                            signer=NativeSigner(reserved.origin),
                            now=1_700_000_001,
                            refund=("ab" * 32, b"signed-refund"),
                        )
                except live.LiveSessionStoreError:
                    outcomes[kind] = "refused"
                else:
                    outcomes[kind] = "committed"

        first = asyncio.create_task(act(winner))
        await entered.wait()
        loser = "refund" if winner == "debt" else "debt"
        second = asyncio.create_task(act(loser))
        await queued.wait()
        assert outcomes == {}
        release.set()
        await asyncio.gather(first, second)
        assert outcomes == {winner: "committed", loser: "refused"}
        assert store._connection.execute(
            "SELECT state,preimage,refund_txid FROM swaps"
        ).fetchone() == (
            ("FUNDED", "52" * 32, None) if winner == "debt" else ("REFUNDING", None, "ab" * 32)
        )

    asyncio.run(exercise())


@pytest.mark.parametrize("refund", ["both", "txid only", "raw only"])
def test_potentially_issued_or_partial_refund_refuses_even_with_unspent_evidence(
    reserved: ReservationCase, refund: str
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
            # Simulate an evicted signed refund, or an inconsistent stored artifact.
            store._connection.execute("PRAGMA ignore_check_constraints=ON")
            store._connection.execute(
                "UPDATE swaps SET refund_txid=?,refund_tx=?",
                (
                    None if refund == "raw only" else "ab" * 32,
                    None if refund == "txid only" else b"signed-refund",
                ),
            )
            store._connection.execute("PRAGMA ignore_check_constraints=OFF")
            with pytest.raises(live.LiveSessionStoreError):
                _commit(reserved, operation, core, invoice)
            assert store._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)

    asyncio.run(exercise())


def test_recorded_debt_survives_expiry_and_restart_and_repays_without_core(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
            _commit(reserved, operation, core, invoice)
            reserved.clock.advance(31)
            assert not store._reverse_proposals[reserved.origin.session_id].window.time_allowed()
        store.close()
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=reserved.origin.crypto.crypto,
        ) as fresh:
            assert fresh._connection.execute("SELECT preimage FROM swaps").fetchone() == (
                "52" * 32,
            )
            assert not fresh._reverse_proposals
            assert not fresh._reverse_negotiations
            chain, hold = Mock(), Mock()
            chain.tip_height.side_effect = OSError("Core unavailable")
            chain.find_spender.side_effect = OSError("witness unavailable")
            (item,) = fresh.settlement_work()
            engine = ReverseSettlement(fresh, chain, hold, NativeSigner(reserved.origin))
            assert await engine.advance(item, 1_700_000_032) == "SETTLED"
            hold.settle.assert_called_once_with("52" * 32)
            hold.cancel.assert_not_called()
            assert chain.mock_calls == []
            assert not fresh._cooperation_handles

    asyncio.run(exercise())


def test_uncertain_debt_commit_retains_obligation_but_restores_no_cooperation(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
            proxy = CommitThenFail(store._connection)
            proxy.armed = True
            store._connection = proxy
            with pytest.raises(live.StaleOwnerError, match="uncertain"):
                _commit(reserved, operation, core, invoice)
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=reserved.origin.crypto.crypto,
        ) as fresh:
            assert fresh._connection.execute("SELECT preimage FROM swaps").fetchone() == (
                "52" * 32,
            )
            assert not fresh._reverse_proposals
            assert not fresh._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("authority", ["restart", "foreign operation", "child task"])
def test_persisted_reservation_and_execution_tokens_do_not_restore_financial_authority(
    reserved: ReservationCase, authority: str
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            _prepare(reserved, operation)
            _, core, invoice = _facts(reserved)
            if authority == "child task":

                async def child() -> None:
                    _commit(reserved, operation, core, invoice)

                with pytest.raises(live.LiveSessionStoreError):
                    await asyncio.create_task(child())
        if authority == "restart":
            store.close()
            with reserved.origin.acquire_at(
                reserved.origin.path,
                crypto=reserved.origin.crypto,
                public_keys=reserved.origin.crypto.crypto,
            ) as fresh:
                async with fresh.reverse_operations.operation() as operation:
                    with pytest.raises(live.LiveSessionStoreError):
                        fresh._commit_reverse_proposal_debt(
                            reserved.document,
                            operation=operation,
                            core=core,
                            invoice=invoice,
                            observations_started_at=100.0,
                            observations_completed_at=100.0,
                            now=1_700_000_001,
                        )
                assert fresh._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)
        elif authority == "foreign operation":
            async with ReverseOperations(store).operation() as operation:
                with pytest.raises(live.LiveSessionStoreError):
                    _commit(reserved, operation, core, invoice)
        if authority != "restart":
            assert store._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)

    asyncio.run(exercise())
