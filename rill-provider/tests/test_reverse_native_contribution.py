"""Native reverse cosigner consumption archives one contribution, never broadcasts."""

from __future__ import annotations

import asyncio
import sqlite3
from typing import TYPE_CHECKING

import pytest
from rill_core.settlement import reconstruct_taproot_contract
from rill_core.wire.canonical import canonicalize
from rill_core.wire.cooperative_messages import CooperativeClaimSigned
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from rill_crypto import binding as native_binding
from test_reverse_paid_context import _debt, _repay
from test_reverse_paid_preflight import _backends
from test_reverse_proposal_debt import (
    pytestmark as pytestmark,  # noqa: PLC0414 - native test policy
)
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider.live_session_store import LiveSessionStoreError, StaleOwnerError
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - exact store-owned custody/consumption regression seams


def test_one_native_provider_contribution_commits_exact_correlated_response_only(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store, crypto = reserved.store, reserved.origin.crypto.crypto
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, crypto)
        swap = store._connection.execute("SELECT * FROM swaps").fetchall()
        session = store._connection.execute(
            "SELECT revision,next_client_seq,next_provider_seq FROM sessions"
        ).fetchone()
        before_outbox = store.pending_outbox()
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            result = store._commit_reverse_signed_reply(
                reserved.document,
                operation=operation,
                evidence=evidence,
                crypto=crypto,
                now=1_700_000_003,
            )
            response = Envelope.model_validate_json(result, strict=True)
            payload = CooperativeClaimSigned.model_validate_json(
                canonicalize(response.payload), strict=True
            )
            proposal = Envelope.model_validate_json(reserved.document, strict=True)
            assert response.in_reply_to == proposal.message_id
            assert (
                response.sender_session_key
                == reserved.origin.source["verification_context"]["handshake_accept"][
                    "provider_session_xonly_key"
                ]
            )
            assert response.sequence == session[2]
            assert payload.status == "signed"
            assert payload.cooperation_id == proposal.payload["cooperation_id"]
            crypto.schnorr_verify(
                bytes.fromhex(response.sender_session_key),
                unsigned_envelope_hash(response),
                bytes.fromhex(response.signature),
            )
            taproot = reconstruct_taproot_contract(evidence.context.terms, keys=crypto)
            crypto.musig_partial_verify(
                user_public_key=bytes.fromhex(
                    evidence.context.terms.client_contract_compressed_key
                ),
                provider_public_key=bytes.fromhex(
                    evidence.context.terms.provider_contract_compressed_key
                ),
                tap_tweak=taproot.tap_tweak,
                message=evidence.context.plan.signature_hash,
                user_public_nonce=bytes.fromhex(proposal.payload["public_nonce"]),
                provider_public_nonce=bytes.fromhex(payload.public_nonce),
                signer_index=1,
                partial_signature=bytes.fromhex(payload.partial_signature),
            )
            assert store._connection.execute(
                "SELECT state,local_nonce,peer_nonce,partial_signature,nonce_response_id,"
                "partial_response_id FROM cooperation_attempts"
            ).fetchone() == (
                "COMPLETE",
                bytes.fromhex(payload.public_nonce),
                bytes.fromhex(proposal.payload["public_nonce"]),
                bytes.fromhex(payload.partial_signature),
                response.message_id,
                response.message_id,
            )
            assert store._connection.execute(
                "SELECT revision,next_client_seq,next_provider_seq FROM sessions"
            ).fetchone() == (session[0] + 1, session[1], session[2] + 1)
            assert store._connection.execute(
                "SELECT canonical_bytes FROM outbox WHERE in_reply_to=?", (proposal.message_id,)
            ).fetchone() == (result,)
            assert not store._cooperation_handles
            with pytest.raises(LiveSessionStoreError, match="signed contribution refused"):
                store._commit_reverse_signed_reply(
                    reserved.document,
                    operation=operation,
                    evidence=evidence,
                    crypto=crypto,
                    now=1_700_000_004,
                )
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == swap
        assert len(store.pending_outbox()) == len(before_outbox) + 1
        hold.settle.assert_not_called()
        hold.settle_bound_invoice.assert_not_called()
        assert not store._cooperation_handles

    asyncio.run(exercise())


def test_real_python_wrapper_failure_after_native_allocation_cannot_leave_private_custody(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store, crypto = reserved.store, reserved.origin.crypto.crypto
        initialize = native_binding.MusigAttempt.__init__
        references = []

        def fail_after_registration(self: native_binding.MusigAttempt, *args: object) -> None:
            initialize(self, *args)
            references.append(self)
            raise MemoryError("injected wrapper registration failure")

        monkeypatch.setattr(native_binding.MusigAttempt, "__init__", fail_after_registration)
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, crypto)
        before = store.pending_outbox()
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            with pytest.raises(LiveSessionStoreError, match="signed contribution refused"):
                store._commit_reverse_signed_reply(
                    reserved.document,
                    operation=operation,
                    evidence=evidence,
                    crypto=crypto,
                    now=1_700_000_003,
                )
        assert len(references) == 1
        assert references[0]._pointer == crypto._native.ffi.NULL
        assert crypto._active_attempts == 0
        assert store.pending_outbox() == before
        assert store._connection.execute("SELECT state FROM cooperation_attempts").fetchone() == (
            "ABANDONED",
        )
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "failure", ["session signing", "session signature expiry", "tentative update expiry"]
)
def test_response_signing_and_tentative_write_failures_preserve_all_committed_state(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store, crypto = reserved.store, reserved.origin.crypto.crypto
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, crypto)
        signed = crypto.schnorr_sign
        before_outbox = store.pending_outbox()
        before_swap = store._connection.execute("SELECT * FROM swaps").fetchall()
        before_sessions = store._connection.execute("SELECT * FROM sessions").fetchall()
        if failure != "tentative update expiry":

            def sign(*args: object) -> bytes:
                if failure == "session signing":
                    raise RuntimeError("private signature failure")
                result = signed(*args)
                reserved.clock.advance(1)
                return result

            monkeypatch.setattr(crypto, "schnorr_sign", sign)
        else:
            raw = store._connection

            class LateUpdate:
                def __getattr__(self, name: str) -> object:
                    return getattr(raw, name)

                def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
                    result = raw.execute(sql, parameters)
                    if sql.startswith("UPDATE cooperation_attempts SET state='COMPLETE'"):
                        reserved.clock.advance(1)
                    return result

            store._connection = LateUpdate()
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            with pytest.raises(LiveSessionStoreError, match="signed contribution refused"):
                store._commit_reverse_signed_reply(
                    reserved.document,
                    operation=operation,
                    evidence=evidence,
                    crypto=crypto,
                    now=1_700_000_003,
                )
        assert store.pending_outbox() == before_outbox
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == before_swap
        assert store._connection.execute("SELECT * FROM sessions").fetchall() == before_sessions
        assert store._connection.execute("SELECT state FROM cooperation_attempts").fetchone() == (
            "ABANDONED",
        )
        assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize("delay", [1, 31])
def test_slow_successful_commit_returns_archived_contribution_not_renewed_authority(
    reserved: ReservationCase,
    delay: int,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store, crypto = reserved.store, reserved.origin.crypto.crypto
        raw = store._connection

        class SlowCommit:
            armed = False

            def __getattr__(self, name: str) -> object:
                return getattr(raw, name)

            def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
                if sql.startswith("UPDATE cooperation_attempts SET state='COMPLETE'"):
                    self.armed = True
                if sql == "COMMIT" and self.armed:
                    self.armed = False
                    reserved.clock.advance(delay)
                return raw.execute(sql, parameters)

        store._connection = SlowCommit()
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, crypto)
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            result = store._commit_reverse_signed_reply(
                reserved.document,
                operation=operation,
                evidence=evidence,
                crypto=crypto,
                now=1_700_000_003,
            )
            assert raw.execute("SELECT state FROM cooperation_attempts").fetchone() == ("COMPLETE",)
            response = Envelope.model_validate_json(result, strict=True)
            assert raw.execute(
                "SELECT canonical_bytes FROM outbox WHERE message_id=?", (response.message_id,)
            ).fetchone() == (result,)
            assert evidence.context.window.monotonic_deadline == 130
            if delay == 31:
                assert not evidence.context.window.time_allowed()
            assert not store._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "failure",
    [
        "before begin",
        "after begin",
        "before partial",
        "after partial",
        "late begin",
        "late partial",
        "malformed peer",
    ],
)
def test_native_failures_never_reallocate_or_expose_a_response(  # noqa: PLR0915 - one native fault matrix
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store, crypto = reserved.store, reserved.origin.crypto.crypto
        begin = crypto.musig_begin
        begins = []
        handles = []

        def guarded_begin(**kwargs: object) -> object:
            begins.append(kwargs["cooperation_id"])
            assert kwargs["cooperation_id"] in store._allocated_cooperation_ids
            if failure == "before begin":
                raise RuntimeError("private native failure")
            attempt, nonce = begin(**kwargs)
            handles.append(attempt)
            original_partial = attempt.partial_sign_once

            def partial(peer: bytes) -> bytes:
                if failure == "malformed peer":
                    return original_partial(b"\0" * 66)
                if failure == "before partial":
                    raise RuntimeError("private native failure")
                signed = original_partial(peer)
                if failure == "after partial":
                    raise RuntimeError("private native failure")
                if failure == "late partial":
                    reserved.clock.advance(1)
                return signed

            monkeypatch.setattr(attempt, "partial_sign_once", partial)
            if failure == "after begin":
                attempt.close()  # Adapter failure cannot leak its created handle.
                raise RuntimeError("private native failure")
            if failure == "late begin":
                reserved.clock.advance(1)
            return attempt, nonce

        monkeypatch.setattr(crypto, "musig_begin", guarded_begin)
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, crypto)
        before = store.pending_outbox()
        swap = store._connection.execute("SELECT * FROM swaps").fetchall()
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            with pytest.raises(
                LiveSessionStoreError, match=r"^reverse signed contribution refused$"
            ) as error:
                store._commit_reverse_signed_reply(
                    reserved.document,
                    operation=operation,
                    evidence=evidence,
                    crypto=crypto,
                    now=1_700_000_003,
                )
            assert "private native failure" not in str(error.value)
            assert error.value.__context__ is None
            with pytest.raises(LiveSessionStoreError):
                store._commit_reverse_signed_reply(
                    reserved.document,
                    operation=operation,
                    evidence=evidence,
                    crypto=crypto,
                    now=1_700_000_004,
                )
        assert len(begins) == 1
        assert begins[0] in store._allocated_cooperation_ids
        assert store.pending_outbox() == before
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == swap
        assert store._connection.execute("SELECT state FROM cooperation_attempts").fetchone() == (
            "ABANDONED",
        )
        assert not store._cooperation_handles
        for handle in handles:
            assert handle._pointer == crypto._native.ffi.NULL

    asyncio.run(exercise())


@pytest.mark.parametrize("failure", ["outbox insert", "before commit", "after commit"])
def test_consumed_native_contribution_never_regenerates_after_failed_or_uncertain_persistence(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store, crypto = reserved.store, reserved.origin.crypto.crypto
        raw = store._connection

        class FailingConnection:
            armed = False

            def __getattr__(self, name: str) -> object:
                return getattr(raw, name)

            def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
                if (
                    self.armed
                    and failure == "outbox insert"
                    and sql.startswith("INSERT INTO outbox")
                ):
                    self.armed = False
                    raise sqlite3.OperationalError("injected persistence failure")
                if self.armed and failure.endswith("commit") and sql == "COMMIT":
                    self.armed = False
                    if failure == "after commit":
                        raw.execute(sql, parameters)
                    raise sqlite3.OperationalError("injected uncertain commit")
                return raw.execute(sql, parameters)

        proxy = FailingConnection()
        store._connection = proxy
        original_begin = crypto.musig_begin
        calls = []

        def begin(**kwargs: object) -> object:
            calls.append(kwargs["cooperation_id"])
            attempt, nonce = original_begin(**kwargs)
            original_partial = attempt.partial_sign_once

            def partial(peer: bytes) -> bytes:
                signed = original_partial(peer)
                proxy.armed = True
                return signed

            monkeypatch.setattr(attempt, "partial_sign_once", partial)
            return attempt, nonce

        monkeypatch.setattr(crypto, "musig_begin", begin)
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, crypto)
        proposal = Envelope.model_validate_json(reserved.document, strict=True)
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            expected = LiveSessionStoreError if failure == "outbox insert" else StaleOwnerError
            with pytest.raises(expected):
                store._commit_reverse_signed_reply(
                    reserved.document,
                    operation=operation,
                    evidence=evidence,
                    crypto=crypto,
                    now=1_700_000_003,
                )
            assert not store._cooperation_handles
            if failure == "outbox insert":
                assert store.owner_is_open
                with pytest.raises(LiveSessionStoreError):
                    store._commit_reverse_signed_reply(
                        reserved.document,
                        operation=operation,
                        evidence=evidence,
                        crypto=crypto,
                        now=1_700_000_004,
                    )
            else:
                assert not store.owner_is_open
        assert len(calls) == 1
        store.close()
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=crypto,
        ) as fresh:
            completed = failure == "after commit"
            assert fresh._connection.execute(
                "SELECT state FROM cooperation_attempts"
            ).fetchone() == ("COMPLETE" if completed else "ABANDONED",)
            replies = fresh._connection.execute(
                "SELECT canonical_bytes FROM outbox WHERE in_reply_to=?", (proposal.message_id,)
            ).fetchall()
            assert len(replies) == (1 if completed else 0)
            assert fresh._connection.execute("SELECT state,preimage FROM swaps").fetchone() == (
                "SETTLED",
                "52" * 32,
            )
            assert not fresh._reverse_proposals
            assert not fresh._cooperation_handles
        assert len(calls) == 1

    asyncio.run(exercise())


@pytest.mark.parametrize("interruption", ["cancel", "close"])
def test_cancellation_or_owner_loss_after_native_begin_closes_custody_without_reply(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
    interruption: str,
) -> None:
    async def exercise() -> None:
        await _debt(reserved)
        await _repay(reserved)
        store, crypto = reserved.store, reserved.origin.crypto.crypto
        original_begin = crypto.musig_begin
        handles = []

        def begin(**kwargs: object) -> object:
            attempt, nonce = original_begin(**kwargs)
            handles.append(attempt)

            def interrupted(_peer: bytes) -> bytes:
                if interruption == "close":
                    store.close()
                    raise StaleOwnerError("owner lost during native effect")
                raise asyncio.CancelledError

            monkeypatch.setattr(attempt, "partial_sign_once", interrupted)
            return attempt, nonce

        monkeypatch.setattr(crypto, "musig_begin", begin)
        chain, hold = _backends(reserved)
        engine = ReverseSettlement(store, chain, hold, crypto)
        proposal = Envelope.model_validate_json(reserved.document, strict=True)
        async with store.reverse_operations.operation() as operation:
            evidence = await engine._collect_paid_proposal_evidence(
                reserved.document,
                operation=operation,
                configured_floor_sat=1,
                allow_regtest_fixed_fee=False,
            )
            with pytest.raises(
                asyncio.CancelledError if interruption == "cancel" else StaleOwnerError
            ):
                store._commit_reverse_signed_reply(
                    reserved.document,
                    operation=operation,
                    evidence=evidence,
                    crypto=crypto,
                    now=1_700_000_003,
                )
        assert len(handles) == 1
        assert handles[0]._pointer == crypto._native.ffi.NULL
        store.close()
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=crypto,
        ) as fresh:
            assert fresh._connection.execute(
                "SELECT state FROM cooperation_attempts"
            ).fetchone() == ("ABANDONED",)
            assert (
                fresh._connection.execute(
                    "SELECT 1 FROM outbox WHERE in_reply_to=?", (proposal.message_id,)
                ).fetchone()
                is None
            )
            assert not fresh._cooperation_handles

    asyncio.run(exercise())
