"""A fresh echo cannot permit nonce effects before a durable verified fallback."""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE, unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from test_cooperation_burn import _featured_paid_swap
from test_cooperative_probe_gate import _insert_first_request
from test_live_session_store import Harness

from rill_provider import live_session_store as live
from rill_provider._nip59_send import _wrap_envelope
from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import LiveSessionStoreError, ReadinessChallenge
from rill_provider.lnd_payment_send import PaymentOutcome
from rill_provider.settlement_engine import SettlementEngine
from rill_provider.settlement_policy import offered_terms

if TYPE_CHECKING:
    from pathlib import Path


CLIENT_SECRET = (2).to_bytes(32, "big")  # Fixture session key, not production custody.


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize("outcome", ["waiting", "selected_during_tip"])
def test_signed_echo_enters_waiting_only_via_original_live_service(  # noqa: PLR0915 - one integrated signed lifecycle
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, _, _ = _featured_paid_swap(harness, store)
        store._crypto = crypto  # noqa: SLF001 - native signature boundary
        store._public_keys = crypto  # noqa: SLF001
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001 - native contract custody
            store._contract_key(connection, session)  # noqa: SLF001
            connection.execute(
                "UPDATE sessions SET next_client_seq=3 WHERE session_id=?", (session,)
            )
            (digest,) = connection.execute(
                "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
            ).fetchone()
            connection.execute(
                "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
                "VALUES (?, ?, 1, 'ADMITTED')",
                (session, digest),
            )
            _insert_first_request(harness, store, session)
            connection.execute(
                "UPDATE swaps SET state='PAYING',preimage=NULL WHERE session_id=?", (session,)
            )
        chain = Mock()
        lightning = Mock(track=Mock(return_value=PaymentOutcome("SUCCEEDED", "42" * 32)))
        engine = SettlementEngine(store, chain, lightning, crypto)
        assert engine.register_new_featured_session(session, digest)
        assert asyncio.run(engine._advance(store.settlement_work(session_id=session)[0], 1002)) == (  # noqa: SLF001
            "PAID"
        )
        window = engine.probe_window(session)
        assert window is not None
        service = HandshakeService(
            store,
            Mock(),
            crypto,
            Mock(relay_urls=()),
            clock=lambda: window.started_at + 1,
            chain_tip=lambda: 1090,
            settlement=engine,
        )
        request_id = asyncio.run(service.start_cooperative_readiness(session, window=window))
        assert request_id is not None
        request = next(
            Envelope.model_validate_json(row.canonical_bytes, strict=True)
            for row in store.pending_outbox()
            if row.message_id == request_id
        )
        challenge = service._readiness_probes[session]  # noqa: SLF001 - original token fixture
        assert request.message_id == challenge.request_id
        client_key = crypto.public_key(CLIENT_SECRET)[1:].hex()
        bare = request.model_copy(
            update={
                "message_type": "action_result",
                "message_id": "d1" * 32,
                "sender_session_key": client_key,
                "sequence": 3,
                "in_reply_to": challenge.request_id,
                "payload": {
                    "action": "cooperative_claim_ready",
                    "challenge": challenge.challenge,
                    "status": "ready",
                },
                "signature": None,
            }
        )
        signed = bare.model_copy(
            update={
                "signature": crypto.schnorr_sign(
                    CLIENT_SECRET, unsigned_envelope_hash(bare), b"\x37" * 32
                ).hex()
            }
        )
        event = _wrap_envelope(
            canonicalize(signed.model_dump(mode="json")),
            sender_session_secret=CLIENT_SECRET,
            recipient_xonly_key=request.sender_session_key,
            crypto=crypto,
        )
        if outcome == "selected_during_tip":

            async def race_selection() -> str:
                started, release = asyncio.Event(), asyncio.Event()
                tip_calls = [0]

                async def paused_tip() -> int:
                    tip_calls[0] += 1
                    if tip_calls[0] == 2:
                        started.set()
                        await release.wait()
                    return 1090

                monkeypatch.setattr(service, "_fresh_probe_tip", paused_tip)
                echo = asyncio.create_task(service.handle(event, []))
                await asyncio.wait_for(started.wait(), timeout=2)
                engine.abandon_probe(session)
                (due,) = engine.expired_probe_windows()
                await engine.recover_expired_probe(due, window.started_at + 2)
                release.set()
                return await asyncio.wait_for(echo, timeout=2)

            assert asyncio.run(race_selection()) == "readiness-abandoned"
            assert store.prepared_fallbacks() == ()
            assert store.claim_attempts(session)[0].attempt == 0
            assert store._connection.execute(  # noqa: SLF001 - selected winner cannot be overwritten
                "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
            ).fetchone() == ("ADMITTED",)
        else:
            assert asyncio.run(service.handle(event, [])) == "readiness-prepared"
            (fallback,) = store.prepared_fallbacks()
            assert fallback.state == "WAITING"
            assert fallback.deadline_at == window.deadline_at
            assert fallback.deadline_height == 1094
            assert store.claim_attempts(session) == ()
        assert engine.probe_window(session) is None
        assert service.take_cooperative_readiness(session) is None
        assert asyncio.run(service.handle(event, [])) == "duplicate"
        chain.tip_height.assert_not_called()
        chain.fee_rate_sat_vb.assert_not_called()
        chain.broadcast.assert_not_called()


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize(
    "outcome", ["committed", "zero_height_wall", "height_expired", "abandoned"]
)
def test_echo_prepares_exact_fallback_with_original_deadlines_or_refuses(  # noqa: PLR0915 - one real paid owner fixture
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    from rill_crypto import Context  # noqa: PLC0415 - native signing opt-in

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, _, _ = _featured_paid_swap(harness, store)
        store._crypto = crypto  # noqa: SLF001 - native contract custody
        store._public_keys = crypto  # noqa: SLF001
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001 - new owner contract key fixture
            store._contract_key(connection, session)  # noqa: SLF001
        (digest, offer) = store._connection.execute(  # noqa: SLF001
            "SELECT contract_hash,terms_offer FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        with store._connection as connection:  # noqa: SLF001 - signed admission fixture
            connection.execute(
                "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
                "VALUES (?, ?, 1, 'ADMITTED')",
                (session, digest),
            )
            _insert_first_request(harness, store, session)
            connection.execute(
                "UPDATE swaps SET state='PAYING',preimage=NULL WHERE session_id=?", (session,)
            )
        chain = Mock()
        chain.tip_height.side_effect = RuntimeError("Core tip unavailable")
        chain.fee_rate_sat_vb.side_effect = RuntimeError("fee estimate unavailable")
        chain.broadcast.side_effect = RuntimeError("network unavailable")
        payment = Mock(track=Mock(return_value=PaymentOutcome("SUCCEEDED", "42" * 32)))
        engine = SettlementEngine(store, chain, payment, crypto)
        assert engine.register_new_featured_session(session, digest)
        assert asyncio.run(engine._advance(store.settlement_work(session_id=session)[0], 1002)) == (  # noqa: SLF001
            "PAID"
        )
        window = engine.probe_window(session)
        assert window is not None
        terms = offered_terms(Envelope.model_validate_json(offer, strict=True))
        height = terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks
        challenge = ReadinessChallenge(
            session,
            "bb" * 32,
            "cc" * 32,
            digest,
            store.generation,
            window.started_at,
            window.deadline_at,
            height,
        )

        async def fresh_tip() -> int:
            if outcome == "abandoned":
                engine.abandon_probe(session)
            return height if outcome == "height_expired" else height - 1

        if outcome in ("committed", "zero_height_wall"):
            asyncio.run(
                engine.prepare_cooperative_window(
                    challenge, sample_tip=fresh_tip, now=lambda: window.started_at + 1
                )
            )
            assert engine.probe_window(session) is None
            (fallback,) = store.prepared_fallbacks()
            assert fallback.session_id == session
            assert fallback.state == "WAITING"
            assert (fallback.deadline_at, fallback.deadline_height) == (window.deadline_at, height)
            assert fallback.fee_sat > 0
            assert store.claim_attempts(session) == ()
            assert not store.immediate_claim_allowed(session)
            assert engine.select_due_fallbacks(window.deadline_at - 1) == ()
            if outcome == "zero_height_wall":
                (selected,) = engine.select_due_fallbacks(window.deadline_at, height=0)
            else:
                assert engine.select_due_fallbacks(window.deadline_at - 1, height=height - 1) == ()
                (selected,) = engine.select_due_fallbacks(window.deadline_at - 1, height=height)
            assert selected.txid == fallback.txid
            assert store.recorded_fallbacks()[0].txid == fallback.txid
            assert engine.select_due_fallbacks(window.deadline_at - 1, height=height) == ()
        else:
            with pytest.raises(LiveSessionStoreError, match="deadline unavailable"):
                asyncio.run(
                    engine.prepare_cooperative_window(
                        challenge, sample_tip=fresh_tip, now=lambda: window.started_at + 1
                    )
                )
            assert store.prepared_fallbacks() == ()
            assert store.immediate_claim_allowed(session)
            assert store._connection.execute(  # noqa: SLF001 - no WAITING on failure
                "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
            ).fetchone() == ("ADMITTED",)
        chain.tip_height.assert_not_called()
        chain.fee_rate_sat_vb.assert_not_called()
        chain.broadcast.assert_not_called()
