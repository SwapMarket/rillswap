"""Private knowledge survives refusal without becoming debt."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from test_handshake_reverse_gate import CommitThenFail
from test_live_session_store import Harness
from test_payment_reconciliation import Signer
from test_reverse_proposal_reservation import (
    reserved as reserved,  # noqa: PLC0414 - pytest re-export
)
from test_reverse_settlement_intent import _funded
from test_reverse_swap_store import HASH, PREIMAGE, _ledger

from rill_provider import live_session_store as live
from rill_provider.reverse_operations import ReverseOperations
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from pathlib import Path

    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - intentional real-store component and corruption seams
NATIVE = pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 for authenticated preimage evidence",
)


@pytest.mark.parametrize(
    ("document", "received_at"),
    [
        (b"", 0),
        (b"x" * 65537, 0),
        ("{}", 0),
        (b"{}", -1),
        (b"{}", 0.5),
        (b"{}", "unknown"),
    ],
    ids=["empty", "oversized", "not-blob", "negative-time", "fractional-time", "text-time"],
)
def test_evidence_table_enforces_document_and_audit_storage_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    document: object,
    received_at: object,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                "INSERT INTO reverse_preimage_evidence VALUES (?,?,?)",
                ("unknown", document, received_at),
            )
        assert store._connection.execute(
            "SELECT count(*) FROM reverse_preimage_evidence"
        ).fetchone() == (0,)


@pytest.mark.parametrize("corruption", ["missing table", "older version", "metadata mismatch"])
def test_partial_schema_refuses_without_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    corruption: str,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with sqlite3.connect(harness.path) as connection:
        if corruption == "missing table":
            connection.execute("DROP TABLE reverse_preimage_evidence")
        elif corruption == "older version":
            connection.execute("PRAGMA user_version=13")
            connection.execute("UPDATE meta SET schema_version=13")
        else:
            connection.execute("UPDATE meta SET schema_version=13")
        before = connection.execute(
            "SELECT type,name,sql FROM sqlite_master ORDER BY name"
        ).fetchall()
    with pytest.raises(live.LiveSessionStoreError):
        harness.acquire()
    with sqlite3.connect(harness.path) as connection:
        assert (
            connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
            == before
        )


@pytest.mark.parametrize("state", ["FUNDED", "REFUNDING"])
def test_malformed_knowledge_does_not_block_actual_restarted_debt_repayment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session = _funded(store, harness, state)
        store.record_reverse_settlement_preimage(
            session, from_state=state, preimage=PREIMAGE, now=2001
        )
        financial = store._connection.execute("SELECT * FROM swaps").fetchall()
        store._connection.execute(
            "INSERT INTO reverse_preimage_evidence VALUES (?,?,?)", (session, b"{}", 1000)
        )
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == financial
    with harness.acquire() as recovered:
        chain, hold = Mock(), Mock()
        chain.tip_height.side_effect = OSError("Core unavailable")
        chain.find_spender.side_effect = OSError("witness disappeared")
        (item,) = recovered.settlement_work()
        engine = ReverseSettlement(recovered, chain, hold, Signer(harness))
        assert asyncio.run(engine.advance(item, 2002)) == "SETTLED"
        hold.settle.assert_called_once_with(PREIMAGE)
        hold.cancel.assert_not_called()
        assert chain.mock_calls == []
        assert _ledger(recovered)[HASH][1] == "RELEASED"
        assert recovered._connection.execute(
            "SELECT document FROM reverse_preimage_evidence"
        ).fetchone() == (b"{}",)


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("proposal", ["expired", "native-invalid", "valid"])
def test_native_knowledge_commit_is_independent_of_later_reservation_failure(
    reserved: ReservationCase,
    proposal: str,
) -> None:
    async def exercise() -> None:
        document = reserved.document
        if proposal == "expired":
            document = reserved.signed(deadline=1_699_999_999)
        elif proposal == "native-invalid":
            document = reserved.signed(transaction="00" * 60)
        store = reserved.store
        outbox = store.pending_outbox()
        before = store._connection.execute("SELECT * FROM swaps").fetchall()
        session = store._connection.execute(
            "SELECT revision,next_client_seq,next_provider_seq FROM sessions"
        ).fetchone()
        async with store.reverse_operations.operation() as operation:
            receipt = store._retain_reverse_preimage_evidence(
                document, operation=operation, now=1_700_000_000
            )
            assert not receipt.replay
            assert store._reverse_preimage_evidence(receipt.session_id) == document
            assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
            assert store.pending_outbox() == outbox
            assert (
                store._connection.execute(
                    "SELECT revision,next_client_seq,next_provider_seq FROM sessions"
                ).fetchone()
                == session
            )
            assert store._connection.execute(
                "SELECT count(*) FROM cooperation_attempts"
            ).fetchone() == (0,)
            assert not store._cooperation_handles
            if proposal != "valid":
                with pytest.raises(live.LiveSessionStoreError):
                    reserved.admit(operation, document)
                assert store._reverse_preimage_evidence(receipt.session_id) == document

    asyncio.run(exercise())


@pytest.mark.native_crypto
@NATIVE
def test_first_knowledge_is_immutable_and_restart_restores_no_cooperation(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            first = store._retain_reverse_preimage_evidence(
                reserved.document, operation=operation, now=1000
            )
            changed = reserved.signed(
                message="ab" * 32, cooperation="bc" * 32, deadline=1_700_001_000
            )
            receipt = store._retain_reverse_preimage_evidence(
                changed, operation=operation, now=2000
            )
            assert receipt.replay
            assert receipt.message_id == first.message_id
            assert receipt.received_at == 1000
            assert store._reverse_preimage_evidence(receipt.session_id) == reserved.document
        store.close()
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=reserved.origin.crypto.crypto,
        ) as fresh:
            assert fresh._reverse_preimage_evidence(first.session_id) == reserved.document
            assert not fresh._reverse_negotiations
            assert not fresh._reverse_proposals
            assert not fresh._cooperation_handles
            assert fresh._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)
            async with fresh.reverse_operations.operation() as operation:
                assert fresh._retain_reverse_preimage_evidence(
                    changed, operation=operation, now=3000
                ).replay

    asyncio.run(exercise())


@pytest.mark.native_crypto
@NATIVE
def test_wrong_preimage_cannot_replace_retained_knowledge(reserved: ReservationCase) -> None:
    async def exercise() -> None:
        store = reserved.store
        altered = json.loads(reserved.document)
        altered["payload"]["payment_preimage"] = "00" * 32
        reserved.origin.crypto.permit_confirm(altered)
        async with store.reverse_operations.operation() as operation:
            store._retain_reverse_preimage_evidence(
                reserved.document, operation=operation, now=1000
            )
            with pytest.raises(live.LiveSessionStoreError, match="evidence refused"):
                store._retain_reverse_preimage_evidence(
                    canonicalize(altered), operation=operation, now=2000
                )
        assert store._reverse_preimage_evidence(reserved.origin.session_id) == reserved.document

    asyncio.run(exercise())


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize(
    "fault", ["signer", "signature", "session", "contract", "network", "profile", "feature"]
)
def test_native_unauthenticated_or_cross_context_evidence_never_mutates_knowledge(
    reserved: ReservationCase, fault: str, *, retained: bool
) -> None:
    async def exercise() -> None:
        store = reserved.store
        altered = json.loads(reserved.document)
        if fault == "signer":
            altered["sender_session_key"] = reserved.origin.crypto.crypto.public_key(
                (9).to_bytes(32, "big")
            )[1:].hex()
        elif fault == "session":
            altered["session_id"] = "ab" * 32
        elif fault == "contract":
            altered["contract_hash"] = "ab" * 32
        elif fault == "network":
            altered["network_identity"]["deployment_namespace"] = "different-deployment"
        elif fault == "profile":
            altered["profile_id"] = "btc-to-ln/v1"
        elif fault == "feature":
            altered["required_features"] = []
        reserved.origin.crypto.permit_confirm(altered)
        if fault == "signer":
            envelope = Envelope.model_validate_json(canonicalize(altered), strict=True)
            altered["signature"] = reserved.origin.crypto.crypto.schnorr_sign(
                (9).to_bytes(32, "big"), unsigned_envelope_hash(envelope), b"\x55" * 32
            ).hex()
        elif fault == "signature":
            altered["signature"] = "01" * 64
        async with store.reverse_operations.operation() as operation:
            if retained:
                store._retain_reverse_preimage_evidence(
                    reserved.document, operation=operation, now=1000
                )
            before = store._connection.execute("SELECT * FROM reverse_preimage_evidence").fetchall()
            with pytest.raises(live.LiveSessionStoreError, match="evidence refused"):
                store._retain_reverse_preimage_evidence(
                    canonicalize(altered), operation=operation, now=2000
                )
            assert (
                store._connection.execute("SELECT * FROM reverse_preimage_evidence").fetchall()
                == before
            )
        assert store._reverse_preimage_evidence(reserved.origin.session_id) == (
            reserved.document if retained else None
        )
        assert store._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize(
    "fault", ["offer envelope", "accepted envelope", "provider terms", "client acceptance"]
)
def test_native_corrupt_archived_signatures_refuse_writer_and_retained_reader(
    reserved: ReservationCase, fault: str, *, retained: bool
) -> None:
    async def exercise() -> None:
        store = reserved.store
        column = "terms_offer" if fault in ("offer envelope", "provider terms") else "terms_accept"
        original = store._connection.execute(f"SELECT {column} FROM swaps").fetchone()[0]  # noqa: S608
        altered = json.loads(original)
        if fault in ("offer envelope", "accepted envelope"):
            altered["signature"] = "01" * 64
        else:
            field = (
                "provider_terms_signature"
                if fault == "provider terms"
                else "client_acceptance_signature"
            )
            altered["payload"][field] = "01" * 64
            envelope = Envelope.model_validate_json(canonicalize(altered), strict=True)
            altered["signature"] = reserved.origin.crypto.crypto.schnorr_sign(
                (9 if column == "terms_offer" else 8).to_bytes(32, "big"),
                unsigned_envelope_hash(envelope),
                b"\x55" * 32,
            ).hex()
        async with store.reverse_operations.operation() as operation:
            if retained:
                store._retain_reverse_preimage_evidence(
                    reserved.document, operation=operation, now=1000
                )
            before = store._connection.execute("SELECT * FROM reverse_preimage_evidence").fetchall()
            store._connection.execute(f"UPDATE swaps SET {column}=?", (canonicalize(altered),))  # noqa: S608
            with pytest.raises(live.LiveSessionStoreError, match="evidence refused"):
                store._retain_reverse_preimage_evidence(
                    reserved.document, operation=operation, now=2000
                )
            if retained:
                with pytest.raises(live.LiveSessionStoreError, match="evidence unavailable"):
                    store._reverse_preimage_evidence(reserved.origin.session_id)
            assert (
                store._connection.execute("SELECT * FROM reverse_preimage_evidence").fetchall()
                == before
            )
            store._connection.execute(f"UPDATE swaps SET {column}=?", (original,))  # noqa: S608
        assert store._reverse_preimage_evidence(reserved.origin.session_id) == (
            reserved.document if retained else None
        )

    asyncio.run(exercise())


@pytest.mark.native_crypto
@NATIVE
def test_historical_knowledge_ignores_blocked_state_and_advanced_sequence(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        store._connection.execute("UPDATE sessions SET blocked=1,next_client_seq=50")
        before = store._connection.execute("SELECT * FROM sessions").fetchall()
        async with store.reverse_operations.operation() as operation:
            store._retain_reverse_preimage_evidence(
                reserved.document, operation=operation, now=1000
            )
        assert store._connection.execute("SELECT * FROM sessions").fetchall() == before
        assert store._reverse_preimage_evidence(reserved.origin.session_id) == reserved.document
        assert store._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)
        assert store._connection.execute(
            "SELECT count(*) FROM cooperation_attempts"
        ).fetchone() == (0,)
        assert not store._reverse_proposals

    asyncio.run(exercise())


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("ownership", ["stale", "foreign"])
def test_stale_or_foreign_operation_cannot_write_knowledge(
    reserved: ReservationCase, ownership: str
) -> None:
    async def exercise() -> None:
        store = reserved.store
        gate = ReverseOperations(store) if ownership == "foreign" else store.reverse_operations
        async with gate.operation() as operation:
            if ownership == "foreign":
                with pytest.raises(live.LiveSessionStoreError):
                    store._retain_reverse_preimage_evidence(
                        reserved.document, operation=operation, now=1000
                    )
        if ownership == "stale":
            with pytest.raises(live.LiveSessionStoreError):
                store._retain_reverse_preimage_evidence(
                    reserved.document, operation=operation, now=1000
                )
        assert store._connection.execute("SELECT * FROM reverse_preimage_evidence").fetchall() == []

    asyncio.run(exercise())


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("malformed", [b"{}", b'{"wire_version":"2"}'])
def test_malformed_slot_refuses_without_deletion_or_financial_changes(
    reserved: ReservationCase, malformed: bytes
) -> None:
    async def exercise() -> None:
        store = reserved.store
        before = store._connection.execute("SELECT * FROM swaps").fetchall()
        store._connection.execute(
            "INSERT INTO reverse_preimage_evidence VALUES (?,?,?)",
            (reserved.origin.session_id, malformed, 1000),
        )
        with pytest.raises(live.LiveSessionStoreError, match="evidence unavailable"):
            store._reverse_preimage_evidence(reserved.origin.session_id)
        async with store.reverse_operations.operation() as operation:
            with pytest.raises(live.LiveSessionStoreError, match="evidence refused"):
                store._retain_reverse_preimage_evidence(
                    reserved.document, operation=operation, now=2000
                )
        assert store._connection.execute(
            "SELECT document FROM reverse_preimage_evidence"
        ).fetchone() == (malformed,)
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
        assert store.settlement_work(
            session_id=reserved.origin.session_id
        )  # No slot read is required.

    asyncio.run(exercise())


@pytest.mark.native_crypto
@NATIVE
def test_uncertain_evidence_commit_closes_owner_but_retains_knowledge_without_debt(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        async with store.reverse_operations.operation() as operation:
            proxy = CommitThenFail(store._connection)
            proxy.armed = True
            store._connection = proxy
            with pytest.raises(live.StaleOwnerError, match="uncertain"):
                store._retain_reverse_preimage_evidence(
                    reserved.document, operation=operation, now=1000
                )
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=reserved.origin.crypto.crypto,
        ) as fresh:
            assert fresh._reverse_preimage_evidence(reserved.origin.session_id) == reserved.document
            assert fresh._connection.execute("SELECT preimage FROM swaps").fetchone() == (None,)
            assert not fresh._reverse_proposals

    asyncio.run(exercise())
