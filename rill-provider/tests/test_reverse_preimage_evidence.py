"""Private knowledge survives refusal and upgrade without becoming debt."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from pyrage import x25519
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from test_handshake_reverse_gate import CommitThenFail
from test_live_session_store import Harness, without_v14_preimage_evidence
from test_payment_reconciliation import Signer
from test_reverse_proposal_reservation import (
    reserved as reserved,  # noqa: PLC0414 - pytest re-export
)
from test_reverse_settlement_intent import _funded
from test_reverse_swap_store import HASH, PREIMAGE, _ledger, insert_reverse_swap

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


def _historical(harness: Harness, version: int) -> None:
    """Construct an exact old empty capability, never discard private evidence."""
    schemas = {
        8: live.SCHEMA_V8,
        9: live.SCHEMA_V9,
        10: live.SCHEMA_V10,
        11: live.SCHEMA_V11,
        12: live.SCHEMA_V12,
        13: live.SCHEMA_V13,
    }
    wanted = {statement.split()[2]: statement for statement in schemas[version]}
    with sqlite3.connect(harness.path) as connection:
        definitions = dict(
            connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='table' "
                "AND name NOT GLOB 'sqlite_*'",
            )
        )
        for table, definition in definitions.items():
            if wanted.get(table) == definition:
                continue
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)  # noqa: S608
            connection.execute(f"DROP TABLE {table}")
            if table in wanted:
                connection.execute(wanted[table])
        connection.execute("UPDATE meta SET schema_version=?", (version,))
        connection.execute(f"PRAGMA user_version={version}")


@pytest.mark.parametrize("version", [8, 9, 10, 11, 12, 13])
def test_supported_upgrade_chains_add_empty_knowledge_without_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: int,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    _historical(harness, version)
    with harness.acquire() as store:
        assert store._connection.execute("PRAGMA user_version").fetchone() == (14,)
        assert store._connection.execute("SELECT schema_version FROM meta").fetchone() == (14,)
        assert store._connection.execute(
            "SELECT count(*) FROM reverse_preimage_evidence"
        ).fetchone() == (0,)
        assert store._reverse_preimage_evidence("unknown") is None
        assert not store._reverse_negotiations
        assert not store._reverse_proposals
        assert not store._cooperation_handles
        assert store._connection.execute("SELECT count(*) FROM swaps").fetchone() == (0,)


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


def test_v13_upgrade_preserves_retained_handshake_and_has_no_knowledge_backfill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        store.reserve(harness.init)
        store.commit_accept(harness.accept)
        store.admit_confirm(harness.confirm)
        before = store._connection.execute("SELECT * FROM sessions").fetchall()
        without_v14_preimage_evidence(store._connection)
        store._connection.execute("UPDATE meta SET schema_version=13")
        store._connection.execute("PRAGMA user_version=13")
    with harness.acquire() as upgraded:
        assert upgraded._connection.execute("SELECT * FROM sessions").fetchall() == before
        assert upgraded._connection.execute(
            "SELECT count(*) FROM reverse_preimage_evidence"
        ).fetchone() == (0,)
        assert not upgraded._reverse_negotiations


@pytest.mark.parametrize("corruption", ["missing table", "partial v13", "metadata mismatch"])
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
        elif corruption == "partial v13":
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


def test_failed_upgrade_rolls_back_empty_table_and_versions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    _historical(harness, 13)
    upgrade = live._upgrade_v13

    def fail(connection: sqlite3.Connection) -> None:
        upgrade(connection)
        raise RuntimeError("upgrade reporting failure")

    monkeypatch.setattr(live, "_upgrade_v13", fail)
    with pytest.raises(live.LiveSessionStoreError):
        harness.acquire()
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (13,)
        assert connection.execute("SELECT schema_version FROM meta").fetchone() == (13,)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='reverse_preimage_evidence'"
            ).fetchone()
            is None
        )


@pytest.mark.parametrize("debt", [False, True])
def test_populated_v13_preserves_finances_and_only_existing_restart_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, debt: bool
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    tables = ("sessions", "swaps", "payment_hashes", "economic_reservations", "inbox", "outbox")
    with harness.acquire() as store:
        session = (
            _funded(store, harness) if debt else insert_reverse_swap(store, harness, "ACCEPTED")
        )
        if debt:
            store.record_reverse_settlement_preimage(
                session, from_state="FUNDED", preimage=PREIMAGE, now=2001
            )
        for number, state in ((1, "COMPLETE"), (2, "BURNED")):
            complete = state == "COMPLETE"
            store._connection.execute(
                "INSERT INTO cooperation_attempts "
                "(cooperation_id,session_id,owner_generation,binding,created_at,deadline_at,"
                "state,local_nonce,peer_nonce,partial_signature,"
                "nonce_response_id,partial_response_id) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    bytes([number]) * 32,
                    session,
                    store.generation,
                    b"{}",
                    1000,
                    1020,
                    state,
                    b"\x02" * 66 if complete else None,
                    b"\x03" * 66 if complete else None,
                    b"\x04" * 32 if complete else None,
                    "nonce-response" if complete else None,
                    "partial-response" if complete else None,
                ),
            )
        before = {
            table: store._connection.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
            for table in tables
        }
        attempts = store._connection.execute(
            "SELECT * FROM cooperation_attempts ORDER BY cooperation_id"
        ).fetchall()
        without_v14_preimage_evidence(store._connection)
        store._connection.execute("UPDATE meta SET schema_version=13")
        store._connection.execute("PRAGMA user_version=13")
    # BURNED -> ABANDONED already occurs on every owner acquisition, independent of DDL.
    abandoned = list(attempts[1])
    abandoned[6] = "ABANDONED"
    for _ in range(2):
        with harness.acquire() as upgraded:
            assert upgraded._connection.execute("PRAGMA user_version").fetchone() == (14,)
            assert upgraded._connection.execute("SELECT schema_version FROM meta").fetchone() == (
                14,
            )
            for table in tables:
                assert (
                    upgraded._connection.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
                    == before[table]
                )
            assert upgraded._connection.execute(
                "SELECT * FROM cooperation_attempts ORDER BY cooperation_id"
            ).fetchall() == [attempts[0], tuple(abandoned)]
            assert (
                upgraded._connection.execute("SELECT * FROM reverse_preimage_evidence").fetchall()
                == []
            )
            assert not upgraded._reverse_negotiations
            assert not upgraded._reverse_proposals
            assert not upgraded._cooperation_handles


@pytest.mark.parametrize("refusal", ["namespace", "custody", "owner"])
def test_refused_valid_v13_acquisition_changes_neither_schema_nor_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    owner = harness.acquire()
    try:
        without_v14_preimage_evidence(owner._connection)
        owner._connection.execute("UPDATE meta SET schema_version=13")
        owner._connection.execute("PRAGMA user_version=13")
        if refusal != "owner":
            owner.close()
        with sqlite3.connect(harness.path) as connection:
            before = (
                connection.execute(
                    "SELECT type,name,sql FROM sqlite_master ORDER BY name"
                ).fetchall(),
                connection.execute("SELECT * FROM meta").fetchall(),
                connection.execute("PRAGMA user_version").fetchone(),
            )
        if refusal == "namespace":
            monkeypatch.setattr(harness, "identity", "02" * 32)
        if refusal == "custody":
            with pytest.raises(live.LiveSessionStoreError, match="custody identity does not match"):
                harness.acquire_at(harness.path, custody_identity=str(x25519.Identity.generate()))
        else:
            with pytest.raises(live.LiveSessionStoreError):
                harness.acquire()
        with sqlite3.connect(harness.path) as connection:
            after = (
                connection.execute(
                    "SELECT type,name,sql FROM sqlite_master ORDER BY name"
                ).fetchall(),
                connection.execute("SELECT * FROM meta").fetchall(),
                connection.execute("PRAGMA user_version").fetchone(),
            )
        assert after == before
        assert after[2] == (13,)
    finally:
        owner.close()


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
