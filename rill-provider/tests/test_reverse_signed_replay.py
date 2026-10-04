"""Archived reverse replies replay exact bytes, never native signing authority."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from test_reverse_paid_context import _debt, _repay
from test_reverse_paid_preflight import _backends
from test_reverse_proposal_debt import (
    pytestmark as pytestmark,  # noqa: PLC0414 - native test policy
)
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider.live_session_store import LiveSessionStoreError
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - immutable historical archive and native-call prohibition


async def _complete(reserved: ReservationCase) -> bytes:
    await _debt(reserved)
    await _repay(reserved)
    chain, hold = _backends(reserved)
    engine = ReverseSettlement(reserved.store, chain, hold, reserved.origin.crypto.crypto)
    async with reserved.store.reverse_operations.operation() as operation:
        evidence = await engine._collect_paid_proposal_evidence(
            reserved.document,
            operation=operation,
            configured_floor_sat=1,
            allow_regtest_fixed_fee=False,
        )
        return reserved.store._commit_reverse_signed_reply(
            reserved.document,
            operation=operation,
            evidence=evidence,
            crypto=reserved.origin.crypto.crypto,
            now=1_700_000_003,
        )


def _forbid_native(reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch) -> Mock:
    forbidden = Mock(side_effect=AssertionError("no native reconstruction/custody permitted"))
    for method in ("musig_begin", "musig_partial_verify", "musig_internal_key", "musig_output_key"):
        monkeypatch.setattr(reserved.origin.crypto.crypto, method, forbidden)
    return forbidden


@pytest.mark.parametrize("restart", [False, True])
def test_expired_or_restarted_complete_replay_is_exact_without_native_reconstruction(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    *,
    restart: bool,
) -> None:
    async def exercise() -> None:
        archived = await _complete(reserved)
        reserved.clock.advance(31)
        proposal = json.loads(reserved.document)
        envelope = Envelope.model_validate_json(reserved.document, strict=True)
        proposal["signature"] = reserved.origin.crypto.crypto.schnorr_sign(
            (8).to_bytes(32, "big"),
            unsigned_envelope_hash(envelope),
            b"\x66" * 32,
        ).hex()
        repeated = canonicalize(proposal)
        assert repeated != reserved.document
        forbidden = _forbid_native(reserved, monkeypatch)

        async def replay(store: object) -> None:
            before = store._connection.execute("SELECT * FROM swaps").fetchall()
            attempts = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
            outbox = store.pending_outbox()
            async with store.reverse_operations.operation() as operation:
                assert store._reverse_signed_reply_replay(repeated, operation=operation) == archived
            assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
            assert (
                store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
                == attempts
            )
            assert store.pending_outbox() == outbox
            assert not store._cooperation_handles

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
        forbidden.assert_not_called()

    asyncio.run(exercise())


@pytest.mark.parametrize("state", ["absent", "BURNED", "NONCE_READY", "SIGNING", "ABANDONED"])
def test_recognized_missing_or_incomplete_attempt_never_regenerates_a_contribution(
    reserved: ReservationCase,
    state: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        forbidden = _forbid_native(reserved, monkeypatch)
        store = reserved.store
        if state == "absent":
            store._connection.execute("DELETE FROM cooperation_attempts")
        elif state != "BURNED":
            store._connection.execute("PRAGMA ignore_check_constraints=ON")
            store._connection.execute("UPDATE cooperation_attempts SET state=?", (state,))
            store._connection.execute("PRAGMA ignore_check_constraints=OFF")
        before = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
        async with store.reverse_operations.operation() as operation:
            assert (
                store._reverse_signed_reply_replay(reserved.document, operation=operation) is None
            )
        assert store._connection.execute("SELECT * FROM cooperation_attempts").fetchall() == before
        assert not store._cooperation_handles
        forbidden.assert_not_called()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "fault",
    [
        "old binding",
        "malformed binding",
        "changed proposal digest",
        "bad derived format",
        "inbox digest",
        "missing nonce",
        "missing partial",
        "response IDs",
        "missing reply",
        "ambiguous reply",
        "invalid reply signature",
        "SQL sequence",
        "reply nonce",
    ],
)
def test_partial_or_ambiguous_completed_archive_refuses_without_repair_or_signing(  # noqa: PLR0915 - one archive fault matrix
    reserved: ReservationCase,
    fault: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:  # noqa: PLR0912 - one archive fault matrix
        archived = await _complete(reserved)
        forbidden = _forbid_native(reserved, monkeypatch)
        store = reserved.store
        proposal = Envelope.model_validate_json(reserved.document, strict=True)
        if fault in (
            "old binding",
            "malformed binding",
            "changed proposal digest",
            "bad derived format",
        ):
            bound = json.loads(
                store._connection.execute("SELECT binding FROM cooperation_attempts").fetchone()[0]
            )
            if fault == "old binding":
                bound["version"] = 1
            elif fault == "malformed binding":
                del bound["kind"]
            elif fault == "changed proposal digest":
                bound["proposal_unsigned_digest"] = "ab" * 32
            else:
                bound["tap_tweak"] = True
            store._connection.execute(
                "UPDATE cooperation_attempts SET binding=?", (canonicalize(bound),)
            )
        elif fault == "inbox digest":
            store._connection.execute(
                "UPDATE inbox SET unsigned_digest=? WHERE message_id=?",
                ("ab" * 32, proposal.message_id),
            )
        elif fault in ("missing nonce", "missing partial", "response IDs"):
            store._connection.execute("PRAGMA ignore_check_constraints=ON")
            if fault == "missing nonce":
                store._connection.execute("UPDATE cooperation_attempts SET local_nonce=NULL")
            elif fault == "missing partial":
                store._connection.execute("UPDATE cooperation_attempts SET partial_signature=NULL")
            else:
                store._connection.execute(
                    "UPDATE cooperation_attempts SET partial_response_id=?", ("ab" * 32,)
                )
            store._connection.execute("PRAGMA ignore_check_constraints=OFF")
        elif fault == "missing reply":
            store._connection.execute(
                "DELETE FROM outbox WHERE in_reply_to=?", (proposal.message_id,)
            )
        elif fault == "ambiguous reply":
            store._connection.execute(
                "INSERT INTO outbox SELECT ?,session_id,seq+100,in_reply_to,canonical_bytes,"
                "committed_revision,delivery_state FROM outbox WHERE in_reply_to=?",
                ("ab" * 32, proposal.message_id),
            )
        elif fault == "SQL sequence":
            store._connection.execute(
                "UPDATE outbox SET seq=seq+100 WHERE in_reply_to=?", (proposal.message_id,)
            )
        else:
            raw = json.loads(archived)
            if fault == "invalid reply signature":
                raw["signature"] = "01" * 64
            else:
                raw["payload"]["public_nonce"] = "02" + "01" * 32 + "02" + "02" * 32
                reply = Envelope.model_validate_json(canonicalize(raw), strict=True)
                raw["signature"] = reserved.origin.crypto.crypto.schnorr_sign(
                    (9).to_bytes(32, "big"),
                    unsigned_envelope_hash(reply),
                    b"\x55" * 32,
                ).hex()
            store._connection.execute(
                "UPDATE outbox SET canonical_bytes=? WHERE in_reply_to=?",
                (canonicalize(raw), proposal.message_id),
            )
        before = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
        outbox = store.pending_outbox()
        async with store.reverse_operations.operation() as operation:
            with pytest.raises(LiveSessionStoreError, match="archived contribution replay refused"):
                store._reverse_signed_reply_replay(reserved.document, operation=operation)
        assert store._connection.execute("SELECT * FROM cooperation_attempts").fetchall() == before
        assert store.pending_outbox() == outbox
        assert not store._cooperation_handles
        forbidden.assert_not_called()

    asyncio.run(exercise())


def test_completed_replay_needs_no_funding_archive_or_contract_secret_custody(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        archived = await _complete(reserved)
        store = reserved.store
        bound = json.loads(
            store._connection.execute("SELECT binding FROM cooperation_attempts").fetchone()[0]
        )
        store._connection.execute(
            "DELETE FROM outbox WHERE message_id=?", (bound["funding_message_id"],)
        )
        store._connection.execute("DELETE FROM contract_keys")
        store._connection.execute("PRAGMA ignore_check_constraints=ON")
        store._connection.execute(
            "UPDATE swaps SET funding_tx=NULL,funding_txid=NULL,funding_vout=NULL"
        )
        store._connection.execute("PRAGMA ignore_check_constraints=OFF")
        forbidden = _forbid_native(reserved, monkeypatch)
        async with store.reverse_operations.operation() as operation:
            assert (
                store._reverse_signed_reply_replay(reserved.document, operation=operation)
                == archived
            )
        forbidden.assert_not_called()
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("changed", ["cooperation", "deadline"])
def test_newly_signed_changed_request_cannot_retrieve_original_contribution(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    changed: str,
) -> None:
    async def exercise() -> None:
        await _complete(reserved)
        document = json.loads(reserved.document)
        if changed == "cooperation":
            document["payload"]["cooperation_id"] = "ab" * 32
        else:
            document["payload"]["deadline_at"] += 1
        reserved.origin.crypto.permit_confirm(document)
        repeated = canonicalize(document)
        forbidden = _forbid_native(reserved, monkeypatch)
        store = reserved.store
        before = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
        outbox = store.pending_outbox()
        async with store.reverse_operations.operation() as operation:
            with pytest.raises(LiveSessionStoreError, match="archived contribution replay refused"):
                store._reverse_signed_reply_replay(repeated, operation=operation)
        assert store._connection.execute("SELECT * FROM cooperation_attempts").fetchall() == before
        assert store.pending_outbox() == outbox
        forbidden.assert_not_called()

    asyncio.run(exercise())


def test_blocked_session_and_acknowledged_delivery_still_retrieve_historical_bytes(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        archived = await _complete(reserved)
        store = reserved.store
        response = Envelope.model_validate_json(archived, strict=True)
        store._connection.execute("UPDATE sessions SET blocked=1")
        store._connection.execute(
            "UPDATE outbox SET delivery_state='ACKED' WHERE message_id=?", (response.message_id,)
        )
        forbidden = _forbid_native(reserved, monkeypatch)
        async with store.reverse_operations.operation() as operation:
            assert (
                store._reverse_signed_reply_replay(reserved.document, operation=operation)
                == archived
            )
        forbidden.assert_not_called()
        assert not store._cooperation_handles

    asyncio.run(exercise())
