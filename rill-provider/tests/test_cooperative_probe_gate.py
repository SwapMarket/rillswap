"""Only a newly accepted original-process session may defer a PAID claim."""

from __future__ import annotations

import asyncio
import copy
import os
import time
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from test_cooperation_burn import FixtureEnvelopeSigner, _featured_paid_swap
from test_live_session_store import Harness

from rill_provider import live_session_store as live
from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import (
    FIRST_REQUEST_SEQUENCE,
    Answer,
    LiveSessionStore,
    RequestAnswer,
)
from rill_provider.lnd_payment_send import PaymentOutcome
from rill_provider.quote_policy import QuoteSchedule
from rill_provider.settlement_engine import (
    COOPERATIVE_PROBE_SECONDS,
    ClaimProbeWindow,
    SettlementEngine,
)

if TYPE_CHECKING:
    from pathlib import Path


def _insert_first_request(harness: Harness, store: LiveSessionStore, session: str) -> None:
    """Populate the synthetic fixture's funded-work inbox join."""
    (client_key,) = store._connection.execute(  # noqa: SLF001
        "SELECT client_key FROM sessions WHERE session_id=?", (session,)
    ).fetchone()
    first_request = copy.deepcopy(harness.envelopes[2])
    first_request.update(
        message_type="quote_request",
        message_id="fe" * 32,
        sequence=FIRST_REQUEST_SEQUENCE,
        in_reply_to=None,
        contract_hash=None,
        payload={"invoice": "fixture"},
    )
    store._connection.execute(  # noqa: SLF001 - synthetic authenticated inbox only
        "INSERT INTO inbox VALUES (?,?,?,?,?,?,?)",
        (
            session,
            client_key,
            "fe" * 32,
            FIRST_REQUEST_SEQUENCE,
            b"\x00" * 32,
            canonicalize(first_request),
            100,
        ),
    )


def test_approved_new_session_gate_does_not_reinterpret_historical_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(
        harness.policy, features=harness.policy.features | {COOPERATIVE_CLAIM_FEATURE}
    )
    harness.provision()
    with harness.acquire() as store:
        session, _, _ = _featured_paid_swap(harness, store)
        (digest,) = store._connection.execute(  # noqa: SLF001
            "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        assert not store.admitted_featured_claim(session, digest)
        with store._connection as connection:  # noqa: SLF001 - synthetic signed feature admission
            connection.execute(
                "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
                "VALUES (?, ?, 1, 'ADMITTED')",
                (session, digest),
            )
            _insert_first_request(harness, store, session)
        assert store.admitted_featured_claim(session, digest)
        assert not store.admitted_featured_claim(session, "ff" * 32)
        chain = Mock(tip_height=Mock(return_value=1090))
        signer = FixtureEnvelopeSigner(harness, store._public_keys)  # noqa: SLF001
        engine = SettlementEngine(store, chain, Mock(), signer)
        assert engine.probe_window(session) is None
        assert engine.expired_probe_windows() == ()
        engine._initial_claim = AsyncMock(side_effect=RuntimeError("legacy immediate"))  # type: ignore[method-assign]  # noqa: SLF001
        with pytest.raises(RuntimeError, match="legacy immediate"):
            asyncio.run(engine._advance(store.settlement_work(session_id=session)[0], 1002))  # noqa: SLF001
        engine._initial_claim.assert_awaited_once()  # noqa: SLF001

        with store._connection as connection:  # noqa: SLF001 - fresh successful payment fixture
            connection.execute(
                "UPDATE swaps SET state='PAYING',preimage=NULL WHERE session_id=?", (session,)
            )
        payment = Mock(track=Mock(return_value=PaymentOutcome("SUCCEEDED", "42" * 32)))
        engine = SettlementEngine(store, chain, payment, signer)
        assert engine.register_new_featured_session(session, digest)
        assert not engine.register_new_featured_session(session, digest)
        paying = store.settlement_work(session_id=session)[0]
        assert paying.state == "PAYING"
        assert asyncio.run(engine._advance(paying, 1003)) == "PAID"  # noqa: SLF001
        assert chain.tip_height.call_count == 1  # previous legacy path, no gate claim
        window = engine.probe_window(session)
        assert window is not None
        assert window.contract_hash == digest
        assert window.owner_generation == store.generation
        assert window.deadline_at - window.started_at == COOPERATIVE_PROBE_SECONDS
        assert asyncio.run(engine._advance(store.settlement_work(session_id=session)[0], 1004)) == (  # noqa: SLF001
            "PAID"
        )
        assert chain.tip_height.call_count == 1
        assert engine.expired_probe_windows() == ()
        # A wall-clock correction cannot prolong the process-local probe.
        engine._claim_probes[session] = replace(  # noqa: SLF001 - simulated monotonic expiry
            window, started_monotonic=time.monotonic() - COOPERATIVE_PROBE_SECONDS - 1
        )
        expired = engine.expired_probe_windows()
        assert len(expired) == 1
        engine._initial_claim = AsyncMock(side_effect=RuntimeError("due unilateral"))  # type: ignore[method-assign]  # noqa: SLF001
        with pytest.raises(RuntimeError, match="due unilateral"):
            asyncio.run(engine.recover_expired_probe(expired[0], 1005))
        engine._initial_claim.assert_awaited_once()  # noqa: SLF001
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state FROM swaps WHERE session_id=?", (session,)
        ).fetchone() == ("PAID",)


def test_probe_is_not_inferred_from_an_older_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(
        harness.policy, features=harness.policy.features | {COOPERATIVE_CLAIM_FEATURE}
    )
    harness.provision()
    with harness.acquire() as store:
        session, _, _ = _featured_paid_swap(harness, store)
        (digest,) = store._connection.execute(  # noqa: SLF001
            "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        store._connection.execute(  # noqa: SLF001 - synthetic prior admission
            "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
            "VALUES (?, ?, 1, 'ADMITTED')",
            (session, digest),
        )
        engine = SettlementEngine(store, Mock(), Mock(), Mock())
        assert engine.register_new_featured_session(session, digest)
    with harness.acquire() as restarted:
        engine = SettlementEngine(restarted, Mock(), Mock(), Mock())
        assert restarted.admitted_featured_claim(session, digest)
        assert engine.probe_window(session) is None
        assert engine.expired_probe_windows() == ()


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_due_probe_records_real_unilateral_before_any_core_rpc(  # noqa: PLR0915 - one interrupted-owner lifecycle
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native signing

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(
        harness.policy, features=harness.policy.features | {COOPERATIVE_CLAIM_FEATURE}
    )
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, _, _ = _featured_paid_swap(harness, store)
        store._crypto = crypto  # noqa: SLF001 - real native signature and verification
        store._public_keys = crypto  # noqa: SLF001
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001 - native contract key custody
            store._contract_key(connection, session)  # noqa: SLF001
        (digest,) = store._connection.execute(  # noqa: SLF001
            "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        with store._connection as connection:  # noqa: SLF001 - synthetic signed feature admission
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
        chain.tip_height.side_effect = RuntimeError("Core tip hung")
        chain.fee_rate_sat_vb.side_effect = RuntimeError("Core fee hung")
        chain.broadcast.side_effect = RuntimeError("Core broadcast hung")
        lightning = Mock(track=Mock(return_value=PaymentOutcome("SUCCEEDED", "42" * 32)))
        engine = SettlementEngine(store, chain, lightning, crypto)
        assert engine.register_new_featured_session(session, digest)
        assert asyncio.run(engine._advance(store.settlement_work(session_id=session)[0], 1002)) == (  # noqa: SLF001
            "PAID"
        )
        window = engine.probe_window(session)
        assert window is not None
        engine.abandon_probe(session)
        (due,) = engine.expired_probe_windows()
        asyncio.run(engine.recover_expired_probe(due, 1003))
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state FROM swaps WHERE session_id=?", (session,)
        ).fetchone() == ("CLAIMING",)
        (attempt,) = store.claim_attempts(session)
        assert attempt.attempt == 0
        assert attempt.first_seen_height is None
        assert attempt.fee_sat is not None
        assert store._connection.execute(  # noqa: SLF001
            "SELECT claim_tx,claim_txid FROM swaps WHERE session_id=?", (session,)
        ).fetchone() == (attempt.raw, attempt.txid)
        assert engine.probe_window(session) is None
        assert engine.expired_probe_windows() == ()
        chain.tip_height.assert_not_called()
        chain.fee_rate_sat_vb.assert_not_called()
        chain.broadcast.assert_not_called()
        selected = engine.recorded_unilateral_claims()
        assert len(selected) == 1
        assert (selected[0].raw, selected[0].txid, selected[0].fee_sat) == (
            attempt.raw,
            attempt.txid,
            attempt.fee_sat,
        )
        asyncio.run(
            engine.broadcast_recorded_unilateral(replace(selected[0], raw=b"unverified claim"))
        )
        chain.broadcast.assert_not_called()

    # An interrupted owner loses its in-memory gate, but an affirmative,
    # selected attempt remains available to the independent submission lane.
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as restarted,
    ):
        restarted._crypto = crypto  # noqa: SLF001 - native verifier on recovered owner
        restarted._public_keys = crypto  # noqa: SLF001
        chain = Mock()
        engine = SettlementEngine(restarted, chain, Mock(), crypto)
        assert engine.probe_window(session) is None
        assert engine.expired_probe_windows() == ()
        (recorded,) = engine.recorded_unilateral_claims()
        assert recorded.raw == attempt.raw
        assert recorded.txid == attempt.txid
        asyncio.run(engine.broadcast_recorded_unilateral(recorded))
        chain.broadcast.assert_called_once_with(attempt.raw, attempt.txid)
        chain.broadcast.reset_mock()

        async def dispatch_while_tick_hangs() -> None:
            loop = asyncio.get_running_loop()
            stop, tick_entered, broadcasted, release_tick = (asyncio.Event() for _ in range(4))

            def broadcast(raw: bytes, txid: str) -> str:
                assert (raw, txid) == (attempt.raw, attempt.txid)
                loop.call_soon_threadsafe(broadcasted.set)
                return txid

            chain.broadcast.side_effect = broadcast
            service = HandshakeService(
                restarted,
                Mock(),
                crypto,
                Mock(relay_urls=()),
                clock=lambda: 1003,
                settlement=engine,
            )

            async def hung_tick(_relays: object) -> None:
                tick_entered.set()
                await release_tick.wait()

            monkeypatch.setattr(service, "tick", hung_tick)
            running = asyncio.create_task(service.run(stop, tick_seconds=10))
            try:
                await asyncio.wait_for(tick_entered.wait(), timeout=2)
                await asyncio.wait_for(broadcasted.wait(), timeout=2)
            finally:
                stop.set()
                release_tick.set()
                await asyncio.wait_for(running, timeout=2)

        asyncio.run(dispatch_while_tick_hangs())
        chain.broadcast.assert_called_once_with(attempt.raw, attempt.txid)
        # Older selected attempts may have NULL fee metadata. The native spend
        # proves its actual fee without trusting that migration-era column.
        chain.broadcast.reset_mock()
        with restarted._connection as connection:  # noqa: SLF001 - old-format fee fixture
            connection.execute(
                "UPDATE claim_attempts SET fee_sat=NULL WHERE session_id=? AND attempt=0",
                (session,),
            )
        (legacy,) = engine.recorded_unilateral_claims()
        assert legacy.fee_sat is None
        asyncio.run(engine.broadcast_recorded_unilateral(legacy))
        chain.broadcast.assert_called_once_with(attempt.raw, attempt.txid)
        with restarted._connection as connection:  # noqa: SLF001 - corrupt selected attempt fixture
            connection.execute(
                "UPDATE claim_attempts SET raw=? WHERE session_id=? AND attempt=0",
                (b"not the selected transaction", session),
            )
        assert engine.recorded_unilateral_claims() == ()
        asyncio.run(engine.broadcast_recorded_unilateral(recorded))
        chain.broadcast.assert_called_once()
        with restarted._connection as connection:  # noqa: SLF001 - matching corrupt custody
            connection.execute(
                "UPDATE swaps SET claim_tx=? WHERE session_id=?",
                (b"not the selected transaction", session),
            )
        (corrupt,) = engine.recorded_unilateral_claims()
        asyncio.run(engine.broadcast_recorded_unilateral(corrupt))
        chain.broadcast.assert_called_once()  # matching rows alone do not authorize a spend


def test_supervisor_recovers_due_probe_while_settlement_tick_is_hung(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        session = "aa" * 32
        stop, reached, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        window = ClaimProbeWindow(session, "bb" * 32, 1, 1000, 1030, time.monotonic() - 31)
        settlement = Mock()
        settlement.expired_probe_windows.return_value = (window,)
        settlement.select_due_fallbacks.return_value = ()
        settlement.recorded_fallbacks.return_value = ()
        settlement.recover_cooperative_winners.return_value = ()
        settlement.recorded_cooperative_winners.return_value = ()

        async def recover(selected: ClaimProbeWindow, now: int) -> None:
            assert selected == window
            assert now >= 1000
            assert not release.is_set()  # never wait for normal settlement
            reached.set()
            release.set()
            stop.set()

        settlement.recover_expired_probe = AsyncMock(side_effect=recover)
        service = HandshakeService(
            Mock(),
            Mock(),
            Mock(),
            Mock(relay_urls=()),
            clock=lambda: 1030,
            settlement=settlement,
        )
        service._probe_supervision_needed = True  # noqa: SLF001 - first-time signed client input

        async def hung_tick(_relays: object) -> None:
            await release.wait()

        monkeypatch.setattr(service, "tick", hung_tick)
        await asyncio.wait_for(service.run(stop, tick_seconds=10), timeout=2)
        assert reached.is_set()
        settlement.recover_expired_probe.assert_awaited_once()

    asyncio.run(scenario())


class _FeaturedService:
    """A forward-profile service whose store answers every request with an ack."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rill_provider.handshake_service as service_module  # noqa: PLC0415 - request policy mock

        self.session, self.digest = "aa" * 32, "bb" * 32
        self.store, self.settlement = Mock(), Mock()
        self.store.admitted_featured_claim.return_value = True
        self.settlement.register_new_featured_session.return_value = True
        policy = Mock(
            relay_urls=(),
            amount_bands=(),
            base_fee_sat=0,
            proportional_millionths=0,
            quote=QuoteSchedule(),
            profile="btc-to-ln/v1",
            handshake_timeout=600,
        )
        self.service = HandshakeService(
            self.store, Mock(), Mock(), policy, settlement=self.settlement
        )
        monkeypatch.setattr(self.service, "_decode_invoice", AsyncMock(return_value=None))
        monkeypatch.setattr(self.service, "_route_ready", AsyncMock(side_effect=lambda _d, t: t))
        monkeypatch.setattr(self.service, "_open_hold", AsyncMock(return_value=None))
        monkeypatch.setattr(self.service, "_send_pending", AsyncMock(return_value=None))
        monkeypatch.setattr(
            service_module, "answer_client_request", lambda *_args: Answer("ack", {})
        )
        self.context = Mock()
        self.replay = [False]

        def respond(document: bytes, *, responder: object, **_kwargs: object) -> RequestAnswer:
            from rill_core.wire.messages import Envelope  # noqa: PLC0415 - fixture parse

            request = Envelope.model_validate_json(document, strict=True)
            if not self.replay[0]:
                responder(request, (), self.context)  # type: ignore[operator]
            return RequestAnswer(self.session, request.message_id, "cc" * 32, self.replay[0])

        self.store.answer_request.side_effect = respond
        from test_live_session_store import _envelopes  # noqa: PLC0415 - signed structural fixture

        _, envelopes = _envelopes()
        self._template = envelopes[2]

    def request(self, kind: str, *, contract: str | None = None) -> bytes:
        message = self._template | {
            "message_type": kind,
            "session_id": self.session,
            "contract_hash": self.digest if contract is None else contract,
            "message_id": ("dd" if kind == "terms_accept" else "ee") * 32,
            "payload": {},
        }
        return canonicalize(message)


def test_service_requires_first_accept_and_first_binding_under_same_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _FeaturedService(monkeypatch)
        service, settlement, request = fixture.service, fixture.settlement, fixture.request
        session, digest, replay = fixture.session, fixture.digest, fixture.replay
        replay[0] = True
        assert await service._answer(request("terms_accept"), [], 1000) == "request-replay"  # noqa: SLF001
        replay[0] = False
        assert await service._answer(request("funding_binding"), [], 1000) == "request-answered"  # noqa: SLF001
        settlement.register_new_featured_session.assert_not_called()
        assert await service._answer(request("terms_accept"), [], 1000) == "request-answered"  # noqa: SLF001
        assert (
            await service._answer(  # noqa: SLF001 - authenticated request handler
                request("funding_binding", contract="ff" * 32), [], 1000
            )
            == "request-answered"
        )
        settlement.register_new_featured_session.assert_not_called()
        assert await service._answer(request("terms_accept"), [], 1000) == "request-answered"  # noqa: SLF001
        assert await service._answer(request("funding_binding"), [], 1000) == "request-answered"  # noqa: SLF001
        settlement.register_new_featured_session.assert_called_once_with(session, digest)
        assert service._probe_supervision_needed  # noqa: SLF001 - deadline supervisor gate

    asyncio.run(scenario())


class _AnHourLater:
    """The handshake module's clock, an hour (six handshake timeouts) ahead."""

    def __getattr__(self, name: str) -> object:
        return getattr(time, name)

    @staticmethod
    def monotonic() -> float:
        return time.monotonic() + 3600


def test_a_binding_after_a_slow_deposit_confirmation_keeps_cooperation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A browser binds only once its deposit confirms, often past the handshake timeout."""

    async def scenario() -> None:
        import rill_provider.handshake_service as service_module  # noqa: PLC0415 - module clock

        fixture = _FeaturedService(monkeypatch)
        service, store, settlement = fixture.service, fixture.store, fixture.settlement
        session, digest, request = fixture.session, fixture.digest, fixture.request
        store.unfunded_swaps.return_value = [(session, b"offer")]
        assert await service._answer(request("terms_accept"), [], 1000) == "request-answered"  # noqa: SLF001
        monkeypatch.setattr(service_module, "time", _AnHourLater())
        service._expire_fresh_accepts()  # noqa: SLF001 - the tick's duty: still awaiting funding
        assert await service._answer(request("funding_binding"), [], 1000) == "request-answered"  # noqa: SLF001
        settlement.register_new_featured_session.assert_called_once_with(session, digest)

        # The acceptance lives exactly as long as the swap awaits its first binding.
        settlement.register_new_featured_session.reset_mock()
        assert await service._answer(request("terms_accept"), [], 1000) == "request-answered"  # noqa: SLF001
        store.unfunded_swaps.side_effect = live.LiveSessionStoreError("swap listing refused")
        service._expire_fresh_accepts()  # noqa: SLF001 - unknown store state forgets nothing
        assert service._fresh_featured_accepts == {session: digest}  # noqa: SLF001
        store.unfunded_swaps.side_effect = live.StaleOwnerError("ownership lost")
        with pytest.raises(live.StaleOwnerError):  # lost ownership is fatal, never swallowed
            service._expire_fresh_accepts()  # noqa: SLF001
        store.unfunded_swaps.side_effect = None
        store.unfunded_swaps.return_value = []  # closed unfunded (or aborted)
        service._expire_fresh_accepts()  # noqa: SLF001
        assert service._fresh_featured_accepts == {}  # noqa: SLF001
        assert await service._answer(request("funding_binding"), [], 1000) == "request-answered"  # noqa: SLF001
        settlement.register_new_featured_session.assert_not_called()

    asyncio.run(scenario())
