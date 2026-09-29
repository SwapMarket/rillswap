"""Native completion selects one spend before exposing a provider partial."""

from __future__ import annotations

import asyncio
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import replace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from rill_core.settlement import validate_cooperative_claim
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from rill_core.wire.messages import Envelope
from rill_core.wire.settlement_messages import FundingBindingPayload
from test_cooperation_burn import _featured_paid_swap
from test_live_session_store import Harness

from rill_provider import live_session_store as live
from rill_provider.core_tx_bytes import CoreTransactionUnknownError
from rill_provider.live_session_store import LiveSessionStoreError, SettlementItem
from rill_provider.settlement_engine import SettlementEngine
from rill_provider.settlement_policy import offered_terms

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize(
    "winner",
    [
        "cooperative",
        "prior_paid",
        "fallback",
        "uncertain_written",
        "uncertain_rolledback",
        "burn_after_close",
        "begin_after_close",
        "nonce_race",
        "expired_without_selection",
        "late_result",
        "burn_lock_expiry",
        "begin_lock_expiry",
        "before_native_expiry",
        "after_native_expiry",
        "commit_lock_expiry",
        "proposal_sign_expiry",
        "clock_unavailable",
        "noncallable_clock",
        "after_native_clock_failure",
        "proposal_sign_clock_failure",
    ],
)
def test_checked_completion_selects_before_exposing_partial(  # noqa: PLR0911, PLR0912, PLR0915 - native custody lifecycle
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, winner: str
) -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, plan, funding = _featured_paid_swap(harness, store)
        store._public_keys = crypto  # noqa: SLF001 - actual native custody fixture
        store._crypto = crypto  # noqa: SLF001
        store._connection.execute(  # noqa: SLF001 - synthetic confirmed client sequence
            "UPDATE sessions SET next_client_seq=2 WHERE session_id=?", (session,)
        )
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001 - native provider contract key
            store._contract_key(connection, session)  # noqa: SLF001
        offer, funded, preimage, digest = store._connection.execute(  # noqa: SLF001
            "SELECT terms_offer,funding_binding,preimage,contract_hash "
            "FROM swaps WHERE session_id=?",
            (session,),
        ).fetchone()
        terms = offered_terms(Envelope.model_validate_json(offer, strict=True))
        binding = parse_model_json(
            FundingBindingPayload,
            canonicalize(Envelope.model_validate_json(funded, strict=True).payload),
        ).binding
        item = SettlementItem(
            session_id=session,
            state="PAID",
            blocked=False,
            terms_offer=offer,
            funding_binding=funded,
            invoice="",
            preimage=preimage,
            claim_tx=None,
            claim_txid=None,
        )
        fallback = SettlementEngine(store, Mock(), Mock(), crypto)._claim(  # noqa: SLF001
            item, terms, binding, 300
        )
        with store._connection as connection:  # noqa: SLF001 - synthetic admission fixture
            connection.execute(
                "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
                "VALUES (?, ?, 1, 'ADMITTED')",
                (session, digest),
            )
        store.prepare_claim_window(
            session,
            fallback_raw=fallback.raw_transaction,
            fallback_txid=fallback.txid,
            fallback_fee_sat=fallback.fee_sat,
            started_at=1000,
            now=1000,
            deadline_at=1020,
            deadline_height=1094,
        )
        cooperation_id = b"\xe1" * 32
        clock_now = 1000
        clock_failed = False

        def clock() -> int:
            if clock_failed:
                raise OSError("test-only clock failure")
            return clock_now

        with pytest.raises(LiveSessionStoreError, match="window height unavailable"):
            store.burn_selected_cooperative_claim(
                session,
                cooperation_id,
                plan,
                now=clock,
                tip_height=None,  # type: ignore[arg-type] - runtime boundary rejects untyped caller
                deadline_at=1020,
                deadline_height=1094,
            )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM cooperation_attempts WHERE session_id=?", (session,)
        ).fetchone() == (0,)
        if winner == "noncallable_clock":
            for invalid_clock in (None, 1000, True):
                with pytest.raises(LiveSessionStoreError, match="clock unavailable"):
                    store.burn_selected_cooperative_claim(
                        session,
                        cooperation_id,
                        plan,
                        now=invalid_clock,  # type: ignore[arg-type] - fail-closed runtime input
                        tip_height=1090,
                        deadline_at=1020,
                        deadline_height=1094,
                    )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM cooperation_attempts WHERE session_id=?", (session,)
            ).fetchone() == (0,)
        if winner == "burn_after_close":
            (candidate,) = store.prepared_fallbacks()
            store.select_prepared_fallback(candidate, signer=crypto, now=1000, height=1094)
        if winner == "burn_after_close":
            with pytest.raises(LiveSessionStoreError, match="cooperative window unavailable"):
                store.burn_selected_cooperative_claim(
                    session,
                    cooperation_id,
                    plan,
                    now=clock,
                    tip_height=1090,
                    deadline_at=1020,
                    deadline_height=1094,
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM cooperation_attempts WHERE session_id=?", (session,)
            ).fetchone() == (0,)
            return
        if winner == "burn_lock_expiry":
            original_write = store._write  # noqa: SLF001 - model elapsed SQLite acquisition

            @contextmanager
            def delayed_burn_write() -> Iterator[sqlite3.Connection]:
                nonlocal clock_now
                with original_write() as connection:
                    clock_now = 1020
                    yield connection

            monkeypatch.setattr(store, "_write", delayed_burn_write)
            with pytest.raises(LiveSessionStoreError, match="cooperative window unavailable"):
                store.burn_selected_cooperative_claim(
                    session,
                    cooperation_id,
                    plan,
                    now=clock,
                    tip_height=1090,
                    deadline_at=1020,
                    deadline_height=1094,
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM cooperation_attempts WHERE session_id=?", (session,)
            ).fetchone() == (0,)
            assert store.pending_outbox() == ()
            assert store._allocated_cooperation_ids == set()  # noqa: SLF001
            return
        store.burn_selected_cooperative_claim(
            session,
            cooperation_id,
            plan,
            now=clock,
            tip_height=1090,
            deadline_at=1020,
            deadline_height=1094,
        )
        clock_now = 1001
        with pytest.raises(LiveSessionStoreError, match="window height unavailable"):
            store.begin_selected_cooperative_proposal(
                session,
                cooperation_id,
                now=clock,
                tip_height=None,  # type: ignore[arg-type] - runtime boundary rejects untyped caller
            )
        assert cooperation_id not in store._allocated_cooperation_ids  # noqa: SLF001
        assert store.pending_outbox() == ()
        if winner == "noncallable_clock":
            for invalid_clock in (None, 1001, True):
                with pytest.raises(LiveSessionStoreError, match="clock unavailable"):
                    store.begin_selected_cooperative_proposal(
                        session,
                        cooperation_id,
                        now=invalid_clock,  # type: ignore[arg-type] - fail-closed runtime input
                        tip_height=1090,
                    )
            assert cooperation_id not in store._allocated_cooperation_ids  # noqa: SLF001
            assert store._cooperation_handles == {}  # noqa: SLF001
            assert store.pending_outbox() == ()
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM cooperation_attempts WHERE session_id=?", (session,)
            ).fetchone() == ("BURNED",)
            return
        if winner in ("begin_after_close", "nonce_race"):
            (candidate,) = store.prepared_fallbacks()
            if winner == "begin_after_close":
                store.select_prepared_fallback(candidate, signer=crypto, now=1001, height=1094)
            else:
                original = store._commit_cooperative_proposal_nonce_impl  # noqa: SLF001

                def close_before_nonce(*args: object, **kwargs: object) -> str:
                    store.select_prepared_fallback(candidate, signer=crypto, now=1001, height=1094)
                    return original(*args, **kwargs)  # type: ignore[arg-type]

                monkeypatch.setattr(
                    store, "_commit_cooperative_proposal_nonce_impl", close_before_nonce
                )
            with pytest.raises(LiveSessionStoreError, match="cooperative window unavailable"):
                store.begin_selected_cooperative_proposal(
                    session, cooperation_id, now=clock, tip_height=1090
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM cooperation_attempts WHERE session_id=?", (session,)
            ).fetchone() == ("BURNED",)
            assert store._cooperation_handles == {}  # noqa: SLF001 - no leaked native handle
            return
        if winner in {
            "begin_lock_expiry",
            "before_native_expiry",
            "after_native_expiry",
            "commit_lock_expiry",
            "proposal_sign_expiry",
            "clock_unavailable",
            "after_native_clock_failure",
            "proposal_sign_clock_failure",
        }:
            original_write = store._write  # noqa: SLF001
            write_count = 0

            @contextmanager
            def delayed_begin_write() -> Iterator[sqlite3.Connection]:
                nonlocal clock_now, write_count
                with original_write() as connection:
                    write_count += 1
                    if (winner == "begin_lock_expiry" and write_count == 1) or (
                        winner == "commit_lock_expiry" and write_count == 2
                    ):
                        clock_now = 1020
                    yield connection

            monkeypatch.setattr(store, "_write", delayed_begin_write)
            original_public_key = crypto.public_key
            original_begin = crypto.musig_begin
            original_sign = crypto.schnorr_sign
            native_calls = 0

            def delayed_public_key(secret: bytes) -> bytes:
                nonlocal clock_now
                result = original_public_key(secret)
                if winner == "before_native_expiry":
                    clock_now = 1020
                return result

            def delayed_native_begin(**kwargs: Any) -> Any:  # noqa: ANN401 - native keyword boundary
                nonlocal clock_now, native_calls, clock_failed
                native_calls += 1
                result = original_begin(**kwargs)
                if winner == "after_native_expiry":
                    clock_now = 1020
                if winner == "after_native_clock_failure":
                    clock_failed = True
                return result

            def delayed_sign(secret: bytes, message: bytes, aux: bytes) -> bytes:
                nonlocal clock_now, clock_failed
                result = original_sign(secret, message, aux)
                if winner == "proposal_sign_expiry":
                    clock_now = 1020
                if winner == "proposal_sign_clock_failure":
                    clock_failed = True
                return result

            monkeypatch.setattr(crypto, "public_key", delayed_public_key)
            monkeypatch.setattr(crypto, "musig_begin", delayed_native_begin)
            monkeypatch.setattr(crypto, "schnorr_sign", delayed_sign)

            def unavailable_clock() -> int:
                raise OSError("test-only clock failure")

            with pytest.raises(
                LiveSessionStoreError,
                match=(
                    r"cooperative (nonce (allocation )?unavailable|"
                    r"deadline elapsed|clock unavailable)"
                ),
            ):
                store.begin_selected_cooperative_proposal(
                    session,
                    cooperation_id,
                    now=unavailable_clock if winner == "clock_unavailable" else clock,
                    tip_height=1090,
                )
            assert native_calls == int(
                winner
                in {
                    "after_native_expiry",
                    "commit_lock_expiry",
                    "proposal_sign_expiry",
                    "after_native_clock_failure",
                    "proposal_sign_clock_failure",
                }
            )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM cooperation_attempts WHERE session_id=?", (session,)
            ).fetchone() == ("BURNED",)
            assert store.pending_outbox() == ()
            assert store._cooperation_handles == {}  # noqa: SLF001
            assert (cooperation_id in store._allocated_cooperation_ids) == bool(native_calls)  # noqa: SLF001
            return
        proposal_id = store.begin_selected_cooperative_proposal(
            session, cooperation_id, now=clock, tip_height=1090
        )
        assert not store.pending_sendable(proposal_id, now=1001)
        assert store.pending_sendable(proposal_id, now=1001, tip_height=1090)
        assert not store.pending_sendable(proposal_id, now=1001, tip_height=1094)
        assert not store.pending_sendable(proposal_id, now=1020, tip_height=1090)
        if winner == "expired_without_selection":
            assert store.reconcile_expired_cooperative_proposals(1019) == 0
            assert store.reconcile_expired_cooperative_proposals(1020) == 1
            assert store._connection.execute(  # noqa: SLF001
                "SELECT delivery_state FROM outbox WHERE message_id=?", (proposal_id,)
            ).fetchone() == ("RECONCILED",)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
            ).fetchone() == ("WAITING",)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM swaps WHERE session_id=?", (session,)
            ).fetchone() == ("PAID",)
            return
        proposal = Envelope.model_validate_json(store.pending_outbox()[0].canonical_bytes)
        provider_nonce = bytes.fromhex(str(proposal.payload["public_nonce"]))
        user_attempt, user_nonce = crypto.musig_begin(
            secret_key=(4).to_bytes(32, "big"),
            user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
            provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
            tap_tweak=bytes.fromhex(harness.source["taproot_contract"]["tap_tweak"]),
            message=plan.signature_hash,
            cooperation_id=cooperation_id,
        )
        with user_attempt:
            user_partial = user_attempt.partial_sign_once(provider_nonce)
        unsigned = proposal.model_copy(
            update={
                "message_id": "e2" * 32,
                "sender_session_key": harness.source["verification_context"]["handshake_init"][
                    "client_session_xonly_key"
                ],
                "sequence": 2,
                "in_reply_to": proposal_id,
                "message_type": "action_result",
                "payload": {
                    "action": "cooperative_claim_propose",
                    "cooperation_id": cooperation_id.hex(),
                    "status": "signed",
                    "public_nonce": user_nonce.hex(),
                    "partial_signature": user_partial.hex(),
                },
                "signature": None,
            }
        )
        signed = unsigned.model_copy(
            update={
                "signature": crypto.schnorr_sign(
                    (2).to_bytes(32, "big"), live.unsigned_envelope_hash(unsigned), b"\x19" * 32
                ).hex()
            }
        )
        if winner == "late_result":
            (candidate,) = store.prepared_fallbacks()
            store.select_prepared_fallback(candidate, signer=crypto, now=1003, height=1094)
            with pytest.raises(LiveSessionStoreError, match="no longer current"):
                store._admit_cooperative_result(  # noqa: SLF001 - stale signed client reply
                    canonicalize(signed.model_dump(mode="json")), now=1004
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM cooperation_attempts WHERE session_id=?", (session,)
            ).fetchone() == ("NONCE_READY",)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM inbox WHERE session_id=?", (session,)
            ).fetchone() == (0,)
            return
        assert (
            store._admit_cooperative_result(  # noqa: SLF001
                canonicalize(signed.model_dump(mode="json")), now=1002
            ).status
            == "signed"
        )
        observation = live.CooperativeClaimObservation(
            network=harness.network,
            funding_txid=funding.txid.hex(),
            funding_vout=funding.output_index,
            funding_value_sat=funding.value_sat,
            funding_script_pubkey=funding.script_pubkey,
            tip_height=1090,
            tip_hash="19" * 32,
            confirmations=terms.funding_confirmations,
            sampled_at=1003,
            mempool_unspent=True,
            fee_floor_sat=0,
        )
        if winner == "fallback":
            (candidate,) = store.prepared_fallbacks()
            store.select_prepared_fallback(candidate, signer=crypto, now=1003, height=1094)
            with pytest.raises(LiveSessionStoreError, match="arbitration unavailable"):
                store.commit_selected_cooperative_claim(
                    session, cooperation_id, observation, now=1004
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT cooperative_raw FROM claim_arbitration WHERE session_id=?", (session,)
            ).fetchone() == (None,)
        elif winner in ("cooperative", "prior_paid"):
            completion_id = store.commit_selected_cooperative_claim(
                session, cooperation_id, observation, now=1004
            )
            raw, txid, state = store._connection.execute(  # noqa: SLF001
                "SELECT cooperative_raw,cooperative_txid,state FROM claim_arbitration "
                "WHERE session_id=?",
                (session,),
            ).fetchone()
            assert state == "CLOSED"
            assert validate_cooperative_claim(raw, plan.authorization, verifier=crypto).txid == txid
            assert store._connection.execute(  # noqa: SLF001
                "SELECT partial_response_id FROM cooperation_attempts WHERE session_id=?",
                (session,),
            ).fetchone() == (completion_id,)
            assert any(entry.message_id == completion_id for entry in store.pending_outbox())
            assert store.pending_sendable(completion_id, now=1025)  # selected winner is still owed
            assert store.recorded_fallbacks() == ()
            assert store.selected_cooperative_claim(session).raw == raw
            with pytest.raises(LiveSessionStoreError, match="replacement refused"):
                store.record_claim_attempt(
                    session,
                    attempt=1,
                    txid="ff" * 32,
                    raw=b"forbidden",
                    fee_sat=400,
                    height=1091,
                )
            if winner == "prior_paid":
                # Characterize the earlier v13 implementation: winner selected
                # and completion durable, but the swap still said PAID.
                with store._connection as connection:  # noqa: SLF001
                    connection.execute("DELETE FROM claim_attempts WHERE session_id=?", (session,))
                    connection.execute(
                        "UPDATE swaps SET state='PAID',claim_tx=NULL,claim_txid=NULL "
                        "WHERE session_id=?",
                        (session,),
                    )
        else:

            class UncertainCompletion:
                def __init__(self, delegate: sqlite3.Connection) -> None:
                    self.delegate, self.fired = delegate, False

                def __getattr__(self, name: str) -> Any:  # noqa: ANN401 - connection proxy
                    return getattr(self.delegate, name)

                def execute(self, statement: str, *values: object) -> sqlite3.Cursor:
                    if (
                        statement == "COMMIT"
                        and not self.fired
                        and self.delegate.execute(
                            "SELECT state FROM cooperation_attempts WHERE cooperation_id=?",
                            (cooperation_id,),
                        ).fetchone()
                        == ("COMPLETE",)
                    ):
                        self.fired = True
                        if winner == "uncertain_written":
                            self.delegate.execute(statement)
                        raise sqlite3.OperationalError("unknown completion commit outcome")
                    return self.delegate.execute(statement, *values)

            proxy = UncertainCompletion(store._connection)  # noqa: SLF001
            store._connection = proxy  # type: ignore[assignment]  # noqa: SLF001
            with pytest.raises(live.StaleOwnerError, match="commit outcome uncertain"):
                store.commit_selected_cooperative_claim(
                    session, cooperation_id, observation, now=1004
                )
            assert proxy.fired
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as verifier,
        harness.acquire() as resumed,
    ):
        assert resumed._connection.execute(  # noqa: SLF001
            "SELECT delivery_state FROM outbox WHERE message_id=?", (proposal_id,)
        ).fetchone() == ("RECONCILED",)
        if winner == "prior_paid":
            resumed._public_keys = verifier  # noqa: SLF001 - native custody on reacquisition
            resumed._crypto = verifier  # noqa: SLF001
            assert resumed._connection.execute(  # noqa: SLF001
                "SELECT state FROM swaps WHERE session_id=?", (session,)
            ).fetchone() == ("PAID",)
            assert (
                len(
                    SettlementEngine(resumed, Mock(), Mock(), verifier).recover_cooperative_winners(
                        1005
                    )
                )
                == 1
            )
        if winner != "uncertain_rolledback":
            assert resumed.prepared_fallbacks(closed_only=True) == ()
        assert len(resumed.recorded_fallbacks()) == (1 if winner == "fallback" else 0)
        row = resumed._connection.execute(  # noqa: SLF001
            "SELECT state,cooperative_raw,cooperative_txid FROM claim_arbitration "
            "WHERE session_id=?",
            (session,),
        ).fetchone()
        if winner in ("cooperative", "prior_paid", "uncertain_written"):
            assert row[0] == "CLOSED"
            assert (
                validate_cooperative_claim(row[1], plan.authorization, verifier=verifier).txid
                == row[2]
            )
            selected = resumed.selected_cooperative_claim(session)
            assert selected is not None
            assert (selected.raw, selected.txid) == row[1:]
            assert resumed._connection.execute(  # noqa: SLF001
                "SELECT state FROM cooperation_attempts WHERE cooperation_id=?", (cooperation_id,)
            ).fetchone() == ("COMPLETE",)
            if winner == "cooperative":
                chain = Mock()
                chain.confirmations.return_value = terms.settlement_confirmations
                engine = SettlementEngine(resumed, chain, Mock(), verifier)
                claiming = replace(item, state="CLAIMING", claim_tx=row[1], claim_txid=row[2])
                assert asyncio.run(engine._claiming(claiming, terms, binding, 1005)) == "CLAIMED"  # noqa: SLF001
                chain.broadcast.assert_called_once_with(row[1], row[2])
                assert resumed._connection.execute(  # noqa: SLF001
                    "SELECT state FROM swaps WHERE session_id=?", (session,)
                ).fetchone() == ("CLAIMED",)
            elif winner == "uncertain_written":
                chain = Mock()
                chain.broadcast.side_effect = OSError("Core unavailable")
                chain.confirmations.side_effect = CoreTransactionUnknownError(-5)
                chain.tip_height.return_value = 1090
                chain.outpoint_unspent.return_value = True
                engine = SettlementEngine(resumed, chain, Mock(), verifier)
                claiming = replace(item, state="CLAIMING", claim_tx=row[1], claim_txid=row[2])
                assert asyncio.run(engine._claiming(claiming, terms, binding, 1005)) == "CLAIMING"  # noqa: SLF001
                assert resumed._connection.execute(  # noqa: SLF001
                    "SELECT count(*) FROM claim_attempts WHERE session_id=?", (session,)
                ).fetchone() == (1,)
                (recorded,) = engine.recorded_cooperative_winners()
                assert chain.broadcast.call_count == 1
                with resumed._connection as connection:  # noqa: SLF001 - malformed persisted history
                    connection.execute(
                        "UPDATE claim_attempts SET fee_sat=fee_sat+1 WHERE session_id=?",
                        (session,),
                    )
                asyncio.run(engine.broadcast_cooperative_winner(recorded))
                assert asyncio.run(engine._claiming(claiming, terms, binding, 1006)) == "CLAIMING"  # noqa: SLF001
                assert chain.broadcast.call_count == 1  # both lanes quarantine the bad fee
        else:
            assert row == ("CLOSED", None, None)
            if winner == "uncertain_rolledback":
                assert resumed._connection.execute(  # noqa: SLF001
                    "SELECT state FROM cooperation_attempts WHERE cooperation_id=?",
                    (cooperation_id,),
                ).fetchone() == ("ABANDONED",)
                assert len(resumed.prepared_fallbacks(closed_only=True)) == 1
