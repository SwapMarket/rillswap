"""Native completion selects one spend before exposing a provider partial."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from rill_core.settlement import FundingBindingTransactionMatch, validate_cooperative_claim
from rill_core.settlement.unilateral import build_cooperative_claim
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from rill_core.wire.messages import Envelope
from rill_core.wire.settlement_messages import FundingBindingPayload
from test_cooperation_burn import _featured_paid_swap
from test_live_session_store import Harness

from rill_provider import live_session_store as live
from rill_provider.core_tx_bytes import (
    CooperativeClaimOutpoint,
    CooperativeFeePolicy,
    CoreTransactionUnknownError,
)
from rill_provider.live_session_store import LiveSessionStoreError, SettlementItem
from rill_provider.settlement_engine import EngineSettings, SettlementEngine
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
        "completion_lock_deadline",
        "completion_lock_age",
        "completion_before_partial_deadline",
        "completion_after_partial_deadline",
        "completion_persistence_deadline",
        "completion_persistence_age",
        "completion_clock_failure",
        "completion_noncallable_clock",
        "completion_age_exactly_five",
        "candidate_snapshot",
        "candidate_distinct_fee",
        "candidate_no_handle",
        "candidate_other_owner",
        "candidate_unilateral_winner",
        "candidate_blocked",
        "candidate_malformed_json",
        "runtime_completion",
        "runtime_distinct_fee",
        "runtime_tip_mismatch",
        "runtime_fee_high",
        "runtime_target_expanded",
        "runtime_revoked",
        "runtime_hung_outpoint",
        "runtime_hung_fee",
        "runtime_acquisition_expired",
        "runtime_shutdown_after_sample",
        "runtime_canceled_sampling",
        "runtime_clock_delay",
        "runtime_clock_revokes",
        "runtime_fallback_wins",
        "runtime_commit_uncertain",
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
        if winner in {"candidate_distinct_fee", "runtime_distinct_fee"}:
            plan = build_cooperative_claim(plan.authorization, fee_sat=350)
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
        if winner.startswith("candidate_"):
            assert store.cooperative_completion_candidate(session, cooperation_id) is None
        assert (
            store._admit_cooperative_result(  # noqa: SLF001
                canonicalize(signed.model_dump(mode="json")), now=1002
            ).status
            == "signed"
        )
        if winner.startswith("candidate_"):
            if winner == "candidate_no_handle":
                store._cooperation_handles.pop(cooperation_id).close()  # noqa: SLF001 - custody lost, never reconstructed
            elif winner == "candidate_other_owner":
                store._connection.execute(  # noqa: SLF001 - another generation is not live authority
                    "UPDATE cooperation_attempts SET owner_generation=owner_generation+1"
                )
            elif winner == "candidate_blocked":
                store._connection.execute("UPDATE sessions SET blocked=1")  # noqa: SLF001
            elif winner == "candidate_unilateral_winner":
                (fallback_candidate,) = store.prepared_fallbacks()
                store.select_prepared_fallback(
                    fallback_candidate, signer=crypto, now=1003, height=1094
                )
            elif winner == "candidate_malformed_json":
                store._connection.execute(  # noqa: SLF001 - corrupt storage is an error, not absence
                    "UPDATE cooperation_attempts SET binding=?", (b"{",)
                )
            before = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()  # noqa: SLF001
            handles = dict(store._cooperation_handles)  # noqa: SLF001
            if winner == "candidate_malformed_json":
                with pytest.raises(LiveSessionStoreError, match="candidate unavailable"):
                    store.cooperative_completion_candidate(session, cooperation_id)
                candidate = None
            else:
                candidate = store.cooperative_completion_candidate(session, cooperation_id)
            assert (
                store._connection.execute("SELECT * FROM cooperation_attempts").fetchall() == before  # noqa: SLF001 - getter never consumes custody
            )
            assert store._cooperation_handles == handles  # noqa: SLF001
            if winner in {"candidate_snapshot", "candidate_distinct_fee"}:
                assert candidate is not None
                assert candidate.fallback.raw == fallback.raw_transaction
                assert candidate.fallback.fee_sat == 300
                burned = parse_json_strict(candidate.burned_binding)
                assert burned["fee_sat"] == (350 if winner == "candidate_distinct_fee" else 300)
                assert burned["unsigned_transaction"] == plan.base_transaction.hex()
                assert burned["signature_hash"] == plan.signature_hash.hex()
                assert "peer_nonce" not in burned
                assert "local_nonce" not in burned
                assert preimage not in repr(candidate)
            else:
                assert candidate is None
            assert store.cooperative_completion_candidate(session, b"\x99" * 32) is None
            return
        if winner.startswith("runtime_"):
            chain = Mock()
            output = CooperativeClaimOutpoint(
                harness.network,
                FundingBindingTransactionMatch(
                    binding.funding_txid,
                    binding.contract_vout,
                    binding.lineage_anchor_txid,
                    binding.lineage_anchor_vout,
                ),
                binding.funding_txid,
                binding.contract_vout,
                int(binding.contract_value_sat),
                bytes.fromhex(binding.contract_script_pubkey),
                "19" * 32,
                1090,
                terms.funding_confirmations,
                1091 - terms.funding_confirmations,
                "18" * 32,
            )
            policy = CooperativeFeePolicy(
                harness.network,
                "19" * 32,
                1090,
                terms.timing_policy.claim_confirmation_blocks,
                100,
                1000,
                1000,
                terms.timing_policy.claim_confirmation_blocks,
            )
            if winner == "runtime_tip_mismatch":
                policy = replace(policy, tip_hash="20" * 32)
            elif winner == "runtime_fee_high":
                policy = replace(policy, estimate_sat_kvb=100000)
            elif winner == "runtime_target_expanded":
                policy = replace(
                    policy, estimate_blocks=terms.timing_policy.claim_confirmation_blocks + 1
                )
            chain.observe_cooperative_claim_outpoint.return_value = output
            chain.observe_cooperative_fee_policy.return_value = policy
            engine = SettlementEngine(
                store, chain, Mock(), crypto, EngineSettings(claim_fee_sat=300)
            )
            if winner in {"runtime_clock_delay", "runtime_clock_revokes"}:
                monotonic_value = 0.0
                armed = False
                verify = crypto.musig_partial_verify

                def arm_clock(**kwargs: object) -> None:
                    nonlocal armed
                    verify(**kwargs)
                    if kwargs["signer_index"] == 0:
                        armed = True

                def delayed_clock() -> int:
                    nonlocal monotonic_value
                    if armed:
                        if winner == "runtime_clock_delay":
                            monotonic_value = 1.0
                        else:
                            engine.disable_new_exposure()
                    return 1003

                monkeypatch.setattr(
                    "rill_provider.settlement_engine.time", Mock(monotonic=lambda: monotonic_value)
                )
                monkeypatch.setattr(crypto, "musig_partial_verify", arm_clock)
                with pytest.raises(LiveSessionStoreError, match="cooperative clock unavailable"):
                    asyncio.run(
                        engine.complete_cooperative_claim(
                            session, cooperation_id, now=delayed_clock
                        )
                    )
                assert cooperation_id in store._cooperation_handles  # noqa: SLF001 - callback fenced before native consumption
                assert store._connection.execute(  # noqa: SLF001
                    "SELECT state FROM cooperation_attempts WHERE session_id=?", (session,)
                ).fetchone() == ("SIGNING",)
                return
            if winner == "runtime_fallback_wins":
                original_sample = engine._sample_cooperative  # noqa: SLF001 - deterministic concurrent arbitration

                async def sampled_after_fallback(operation: object, *, budget: float) -> object:
                    observed = await original_sample(operation, budget=budget)
                    assert len(engine.select_due_fallbacks(1003, height=1094)) == 1
                    return observed

                monkeypatch.setattr(engine, "_sample_cooperative", sampled_after_fallback)
                with pytest.raises(LiveSessionStoreError, match="arbitration unavailable"):
                    asyncio.run(
                        engine.complete_cooperative_claim(session, cooperation_id, now=lambda: 1003)
                    )
                assert store.selected_cooperative_claim(session) is None
                assert store.cooperative_completion_candidate(session, cooperation_id) is None
                return
            if winner == "runtime_commit_uncertain":
                commit = store.commit_selected_cooperative_claim

                def uncertain_commit(*args: object, **kwargs: object) -> str:
                    commit(*args, **kwargs)
                    raise LiveSessionStoreError("completion outcome unknown")

                monkeypatch.setattr(store, "commit_selected_cooperative_claim", uncertain_commit)
                with pytest.raises(LiveSessionStoreError, match="outcome unknown"):
                    asyncio.run(
                        engine.complete_cooperative_claim(session, cooperation_id, now=lambda: 1003)
                    )
                assert store.selected_cooperative_claim(session) is not None
                assert cooperation_id not in store._cooperation_handles  # noqa: SLF001 - durable consumption cannot be retried
                return
            if winner == "runtime_revoked":
                engine.disable_new_exposure()
            elif winner == "runtime_shutdown_after_sample":

                def revoked_policy(*_args: object, **_kwargs: object) -> CooperativeFeePolicy:
                    engine.disable_new_exposure()
                    return policy

                chain.observe_cooperative_fee_policy.side_effect = revoked_policy
            elif winner == "runtime_acquisition_expired":
                getter = store.cooperative_completion_candidate

                def slow_getter(*args: object) -> live.CooperativeCompletionCandidate | None:
                    result = getter(*args)
                    time.sleep(0.02)
                    return result

                monkeypatch.setattr(
                    "rill_provider.settlement_engine.COOPERATIVE_SAMPLE_SECONDS", 0.01
                )
                monkeypatch.setattr(store, "cooperative_completion_candidate", slow_getter)
            elif winner in {
                "runtime_hung_outpoint",
                "runtime_hung_fee",
                "runtime_canceled_sampling",
            }:
                entered, release = threading.Event(), threading.Event()

                def hung(*_args: object, **_kwargs: object) -> object:
                    entered.set()
                    assert release.wait(timeout=3)
                    return output if winner == "runtime_hung_outpoint" else policy

                if winner == "runtime_hung_outpoint":
                    chain.observe_cooperative_claim_outpoint.side_effect = hung
                else:
                    chain.observe_cooperative_fee_policy.side_effect = hung

                async def exercise_busy_sampler() -> None:
                    running = asyncio.create_task(
                        engine.complete_cooperative_claim(session, cooperation_id, now=lambda: 1003)
                    )
                    try:
                        assert await asyncio.to_thread(entered.wait, 1)
                        # Proposal and completion cannot start two Core workers.
                        assert (
                            await engine.initiate_cooperative_proposal(session, now=lambda: 1003)
                            is None
                        )
                        if winner == "runtime_canceled_sampling":
                            running.cancel()
                            with pytest.raises(asyncio.CancelledError):
                                await running
                        else:
                            assert (
                                await asyncio.wait_for(asyncio.shield(running), timeout=1.5) is None
                            )
                        assert engine._cooperative_sample_task is not None  # noqa: SLF001 - canceled waiter retains worker slot
                        chain.observe_cooperative_claim_outpoint.assert_called_once()
                        release.set()
                        await asyncio.shield(engine._cooperative_sample_task)  # noqa: SLF001 - drain actual worker before crypto close
                        assert engine._cooperative_sample_task is None  # noqa: SLF001
                        assert store.selected_cooperative_claim(session) is None
                    finally:
                        release.set()
                        await asyncio.gather(running, return_exceptions=True)
                        if engine._cooperative_sample_task is not None:  # noqa: SLF001
                            await asyncio.shield(engine._cooperative_sample_task)  # noqa: SLF001

                asyncio.run(exercise_busy_sampler())
                return
            result = asyncio.run(
                engine.complete_cooperative_claim(session, cooperation_id, now=lambda: 1003)
            )
            if winner in {"runtime_completion", "runtime_distinct_fee"}:
                assert result is not None
                (selected,) = store.cooperative_winners()
                assert (
                    validate_cooperative_claim(
                        selected.raw, plan.authorization, verifier=crypto
                    ).fee_sat
                    == plan.fee_sat
                )
                assert store.cooperative_completion_candidate(session, cooperation_id) is None
            else:
                assert result is None
                assert store._connection.execute(  # noqa: SLF001 - preconsumption refusal retains custody
                    "SELECT state FROM cooperation_attempts WHERE session_id=?", (session,)
                ).fetchone() == ("SIGNING",)
                assert cooperation_id in store._cooperation_handles  # noqa: SLF001
                if winner == "runtime_acquisition_expired":
                    chain.observe_cooperative_claim_outpoint.assert_not_called()
                    chain.observe_cooperative_fee_policy.assert_not_called()
            return
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
        clock_now = 1004
        if winner.startswith("completion_"):
            prior_outbox = store._connection.execute(  # noqa: SLF001 - compare all durable rows
                "SELECT * FROM outbox ORDER BY message_id"
            ).fetchall()
            if winner == "completion_noncallable_clock":
                for invalid_clock in (None, 1004, True):
                    with pytest.raises(LiveSessionStoreError, match="clock unavailable"):
                        store.commit_selected_cooperative_claim(
                            session,
                            cooperation_id,
                            observation,
                            now=invalid_clock,  # type: ignore[arg-type] - runtime guard
                        )
                assert cooperation_id in store._cooperation_handles  # noqa: SLF001
                assert store._connection.execute(  # noqa: SLF001
                    "SELECT state FROM cooperation_attempts WHERE session_id=?",
                    (session,),
                ).fetchone() == ("SIGNING",)
                return
            if winner == "completion_age_exactly_five":
                clock_now = 1008
                completion_id = store.commit_selected_cooperative_claim(
                    session,
                    cooperation_id,
                    observation,
                    now=clock,
                )
                assert store.pending_sendable(completion_id, now=1025)
                assert cooperation_id not in store._cooperation_handles  # noqa: SLF001
                return
            if winner.endswith("deadline"):
                clock_now = 1019
                observation = replace(observation, sampled_at=1019)
            expired_at = 1020 if winner.endswith("deadline") else 1009
            original_write = store._write  # noqa: SLF001 - acquisition delay injection

            @contextmanager
            def delayed_completion_write() -> Iterator[sqlite3.Connection]:
                nonlocal clock_now
                with original_write() as connection:
                    if winner.startswith("completion_lock_"):
                        clock_now = expired_at
                    yield connection

            monkeypatch.setattr(store, "_write", delayed_completion_write)
            original_verify = crypto.musig_partial_verify
            original_sign = crypto.schnorr_sign
            signs = 0

            def verify_and_expire(**kwargs: Any) -> None:  # noqa: ANN401 - exact native boundary
                nonlocal clock_now, clock_failed
                original_verify(**kwargs)
                if winner == "completion_before_partial_deadline" and kwargs["signer_index"] == 0:
                    clock_now = expired_at
                if winner == "completion_after_partial_deadline" and kwargs["signer_index"] == 1:
                    clock_now = expired_at
                if winner == "completion_clock_failure" and kwargs["signer_index"] == 1:
                    clock_failed = True

            def completion_sign_and_expire(secret: bytes, message: bytes, aux: bytes) -> bytes:
                nonlocal signs, clock_now
                signed = original_sign(secret, message, aux)
                signs += 1
                if winner.startswith("completion_persistence_") and signs == 2:
                    clock_now = expired_at
                return signed

            monkeypatch.setattr(crypto, "musig_partial_verify", verify_and_expire)
            monkeypatch.setattr(crypto, "schnorr_sign", completion_sign_and_expire)
            with pytest.raises(
                LiveSessionStoreError,
                match=(
                    r"cooperative (signing (observation expired|custody unavailable)|"
                    r"deadline elapsed|clock unavailable)"
                ),
            ):
                store.commit_selected_cooperative_claim(
                    session,
                    cooperation_id,
                    observation,
                    now=clock,
                )
            consumed = winner not in {
                "completion_lock_deadline",
                "completion_lock_age",
                "completion_before_partial_deadline",
            }
            assert (cooperation_id in store._cooperation_handles) == (not consumed)  # noqa: SLF001
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state,partial_signature,partial_response_id "
                "FROM cooperation_attempts WHERE session_id=?",
                (session,),
            ).fetchone() == (("ABANDONED", None, None) if consumed else ("SIGNING", None, None))
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state,cooperative_raw,cooperative_txid "
                "FROM claim_arbitration WHERE session_id=?",
                (session,),
            ).fetchone() == ("WAITING", None, None)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state,claim_tx,claim_txid FROM swaps WHERE session_id=?",
                (session,),
            ).fetchone() == ("PAID", None, None)
            assert store.claim_attempts(session) == ()
            assert [entry.message_id for entry in store.pending_outbox()] == [proposal_id]
            assert (
                store._connection.execute(  # noqa: SLF001
                    "SELECT * FROM outbox ORDER BY message_id"
                ).fetchall()
                == prior_outbox
            )
            return
        if winner == "fallback":
            (candidate,) = store.prepared_fallbacks()
            store.select_prepared_fallback(candidate, signer=crypto, now=1003, height=1094)
            with pytest.raises(LiveSessionStoreError, match="arbitration unavailable"):
                store.commit_selected_cooperative_claim(
                    session, cooperation_id, observation, now=clock
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT cooperative_raw FROM claim_arbitration WHERE session_id=?", (session,)
            ).fetchone() == (None,)
        elif winner in ("cooperative", "prior_paid"):
            completion_id = store.commit_selected_cooperative_claim(
                session, cooperation_id, observation, now=clock
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
            assert store.pending_requires_live_cooperation(completion_id) is False
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
                    session, cooperation_id, observation, now=clock
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
