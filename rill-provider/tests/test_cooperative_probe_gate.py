"""Only a newly accepted original-process session may defer a PAID claim."""

from __future__ import annotations

import asyncio
import copy
import time
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from test_cooperation_burn import FixtureEnvelopeSigner, _featured_paid_swap
from test_live_session_store import Harness

from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import (
    FIRST_REQUEST_SEQUENCE,
    Answer,
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


def test_approved_new_session_gate_does_not_reinterpret_historical_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
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
            (client_key,) = connection.execute(
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
            connection.execute(
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
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
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


def test_service_requires_first_accept_and_first_binding_under_same_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        import rill_provider.handshake_service as service_module  # noqa: PLC0415 - request policy mock

        session, digest = "aa" * 32, "bb" * 32
        store, settlement = Mock(), Mock()
        store.admitted_featured_claim.return_value = True
        settlement.register_new_featured_session.return_value = True
        policy = Mock(
            relay_urls=(),
            amount_bands=(),
            base_fee_sat=0,
            proportional_millionths=0,
            quote=QuoteSchedule(),
            profile="btc-to-ln/v1",
            handshake_timeout=600,
        )
        service = HandshakeService(store, Mock(), Mock(), policy, settlement=settlement)
        monkeypatch.setattr(service, "_decode_invoice", AsyncMock(return_value=None))
        monkeypatch.setattr(service, "_route_ready", AsyncMock(side_effect=lambda _d, t: t))
        monkeypatch.setattr(service, "_open_hold", AsyncMock(return_value=None))
        monkeypatch.setattr(service, "_send_pending", AsyncMock(return_value=None))
        monkeypatch.setattr(
            service_module, "answer_client_request", lambda *_args: Answer("ack", {})
        )
        context = Mock()
        replay = [False]

        def respond(document: bytes, *, responder: object, **_kwargs: object) -> RequestAnswer:
            from rill_core.wire.messages import Envelope  # noqa: PLC0415 - fixture parse

            request = Envelope.model_validate_json(document, strict=True)
            if not replay[0]:
                responder(request, (), context)  # type: ignore[operator]
            return RequestAnswer(session, request.message_id, "cc" * 32, replay[0])

        store.answer_request.side_effect = respond
        from test_live_session_store import _envelopes  # noqa: PLC0415 - signed structural fixture

        _, envelopes = _envelopes()
        template = envelopes[2]

        def request(kind: str, *, contract: str = digest) -> bytes:
            message = template | {
                "message_type": kind,
                "session_id": session,
                "contract_hash": contract,
                "message_id": ("dd" if kind == "terms_accept" else "ee") * 32,
                "payload": {},
            }
            return canonicalize(message)

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
