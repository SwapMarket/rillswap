"""Only the issuing service process can turn a signed echo into eligibility."""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, Mock

import pytest

from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import (
    CooperativeResultAdmission,
    LiveSessionStoreError,
    ReadinessChallenge,
)
from rill_provider.settlement_engine import ClaimProbeWindow


def _service(store: Mock, clock: list[int]) -> HandshakeService:
    return HandshakeService(
        store,
        Mock(),
        Mock(),
        Mock(relay_urls=()),
        clock=lambda: clock[0],
        chain_tip=lambda: 1090,
    )


def test_original_session_echo_is_consumed_once_and_never_reconstructed() -> None:
    async def scenario() -> None:
        clock = [1000]
        session = "aa" * 32
        probe = ReadinessChallenge(session, "bb" * 32, "cc" * 32, "dd" * 32, 1, 1000, 1030, 1100)
        store = Mock(generation=1)
        store.issue_cooperative_readiness.return_value = probe
        store.admit_cooperative_readiness.return_value = CooperativeResultAdmission(
            session, "ee" * 32, "ready", replay=False
        )
        service = _service(store, clock)
        assert (
            await service.start_cooperative_readiness(session, deadline_height=1100)
            == probe.request_id
        )
        assert await service.start_cooperative_readiness(session, deadline_height=1100) is None
        store.issue_cooperative_readiness.assert_called_once()
        assert store.issue_cooperative_readiness.call_args.kwargs["started_at"] == 1000
        assert store.issue_cooperative_readiness.call_args.kwargs["deadline_at"] == 1030
        result = {
            "message_type": "action_result",
            "session_id": session,
            "payload": {"action": "cooperative_claim_ready", "status": "ready"},
        }
        store.open_mailbox_frame.return_value = json.dumps(result).encode()
        event = json.dumps({"id": "01" * 32}).encode()
        assert await service.handle(event, []) == "readiness-admitted"
        store.admit_cooperative_readiness.assert_called_once()
        assert store.admit_cooperative_readiness.call_args.args[1] is probe
        assert await service.handle(event, []) == "duplicate"
        assert await service.handle(json.dumps({"id": "02" * 32}).encode(), []) == "refused"
        assert service.take_cooperative_readiness(session) is probe
        assert service.take_cooperative_readiness(session) is None
        restarted = _service(store, clock)
        assert await restarted.handle(json.dumps({"id": "03" * 32}).encode(), []) == "refused"
        assert restarted.take_cooperative_readiness(session) is None

    asyncio.run(scenario())


def test_expired_probe_is_retired_without_renewing_budget() -> None:
    async def scenario() -> None:
        clock = [1000]
        session = "aa" * 32
        probe = ReadinessChallenge(session, "bb" * 32, "cc" * 32, "dd" * 32, 1, 1000, 1030, 1100)
        store = Mock(generation=1)
        store.issue_cooperative_readiness.return_value = probe
        service = _service(store, clock)
        assert await service.start_cooperative_readiness(session, deadline_height=1100)
        clock[0] = 1030
        service._expire_readiness()  # noqa: SLF001 - independent deadline task calls this
        store.retire_cooperative_readiness.assert_called_once_with(probe)
        assert service.take_cooperative_readiness(session) is None
        clock[0] = 1000  # correcting the wall clock cannot renew the original budget
        assert await service.start_cooperative_readiness(session, deadline_height=1100) is None
        store.issue_cooperative_readiness.assert_called_once()

    asyncio.run(scenario())


def test_probe_delivery_needs_process_token_and_fresh_tip() -> None:
    async def scenario() -> None:
        session = "aa" * 32
        probe = ReadinessChallenge(session, "bb" * 32, "cc" * 32, "dd" * 32, 1, 1000, 1030, 1100)
        store = Mock(generation=1)
        store.issue_cooperative_readiness.return_value = probe

        def authorized(
            request_id: str,
            *,
            now: int,
            tip_height: int | None = None,
            readiness: ReadinessChallenge | None = None,
        ) -> bool:
            return (
                request_id == probe.request_id
                and now < probe.deadline_at
                and tip_height == 1090
                and readiness is probe
            )

        store.pending_sendable.side_effect = authorized
        store.wrap_pending.return_value = b"wrapped challenge"
        relay = Mock(publish=AsyncMock(return_value=True))
        service = _service(store, [1000])
        assert await service.start_cooperative_readiness(session, deadline_height=1100)
        await service._send_pending(probe.request_id, [relay])  # noqa: SLF001
        relay.publish.assert_awaited_once_with(b"wrapped challenge")
        restarted = _service(store, [1000])
        await restarted._send_pending(probe.request_id, [relay])  # noqa: SLF001
        relay.publish.assert_awaited_once()
        store.wrap_pending.assert_called_once()

    asyncio.run(scenario())


def test_shutdown_during_tip_lookup_cannot_recreate_a_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        started, release, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()
        store = Mock(generation=1)
        service = _service(store, [1000])

        async def delayed_tip() -> int:
            started.set()
            await release.wait()
            return 1090

        async def stop_tick(_relays: object) -> None:
            stop.set()

        monkeypatch.setattr(service, "_sample_tip", delayed_tip)
        monkeypatch.setattr(service, "tick", stop_tick)
        pending = asyncio.create_task(
            service.start_cooperative_readiness("aa" * 32, deadline_height=1100)
        )
        await started.wait()
        await service.run(stop)
        release.set()
        assert await pending is None
        store.issue_cooperative_readiness.assert_not_called()
        assert service.take_cooperative_readiness("aa" * 32) is None
        assert await service.start_cooperative_readiness("aa" * 32, deadline_height=1100) is None

    asyncio.run(scenario())


def test_shutdown_during_echo_tip_lookup_cannot_admit_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        started, release, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()
        session = "aa" * 32
        store = Mock(generation=1)
        service = _service(store, [1000])
        service._readiness_probes[session] = ReadinessChallenge(  # noqa: SLF001 - live token fixture
            session, "bb" * 32, "cc" * 32, "dd" * 32, 1, 1000, 1030, 1100
        )
        store.open_mailbox_frame.return_value = json.dumps(
            {
                "message_type": "action_result",
                "session_id": session,
                "payload": {"action": "cooperative_claim_ready", "status": "ready"},
            }
        ).encode()

        async def delayed_tip() -> int:
            started.set()
            await release.wait()
            return 1090

        async def stop_tick(_relays: object) -> None:
            stop.set()

        monkeypatch.setattr(service, "_sample_tip", delayed_tip)
        monkeypatch.setattr(service, "tick", stop_tick)
        pending = asyncio.create_task(service.handle(json.dumps({"id": "01" * 32}).encode(), []))
        await started.wait()
        await service.run(stop)
        release.set()
        assert await pending == "refused"
        store.admit_cooperative_readiness.assert_not_called()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "failure", ["none", "height", "old_lookup", "late_time", "cutoff_unavailable"]
)
def test_live_probe_reuses_paid_window_and_requires_fresh_evidence(
    failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        clock = [1012]
        session, contract = "aa" * 32, "dd" * 32
        window = ClaimProbeWindow(session, contract, 1, 1000, 1030, time.monotonic() - 1)
        challenge = ReadinessChallenge(session, "bb" * 32, "cc" * 32, contract, 1, 1000, 1030, 1094)
        store = Mock(generation=1)
        store.cooperative_height_cutoff.return_value = 1094
        if failure == "cutoff_unavailable":
            store.cooperative_height_cutoff.side_effect = LiveSessionStoreError("locked")
        store.issue_cooperative_readiness.return_value = challenge
        service = _service(store, clock)
        settlement = Mock(probe_window=Mock(return_value=window))
        service._settlement = settlement  # noqa: SLF001 - original PAID transition
        if failure == "height":
            service._chain_tip = lambda: 1094  # noqa: SLF001 - fresh tip reaches cutoff
        if failure == "late_time":

            async def advanced_clock() -> int:
                clock[0] = 1030
                return 1090

            monkeypatch.setattr(service, "_fresh_probe_tip", advanced_clock)
        pending: asyncio.Task[object] | None = None
        if failure == "old_lookup":
            pending = asyncio.create_task(asyncio.Event().wait())
            service._tip_lookup = pending  # type: ignore[assignment]  # noqa: SLF001
            service._tip_lookup_started = time.monotonic() - 3  # noqa: SLF001
        try:
            result = await service.start_cooperative_readiness(session, window=window)
        finally:
            if pending is not None:
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
        if failure != "none":
            assert result is None
            settlement.abandon_probe.assert_called_once_with(session)
            store.issue_cooperative_readiness.assert_not_called()
            return
        assert result == challenge.request_id
        assert store.issue_cooperative_readiness.call_args.kwargs == {
            "signer": service._transport,  # noqa: SLF001 - expected exact signer custody
            "started_at": 1000,
            "now": 1012,
            "deadline_at": 1030,
            "deadline_height": 1094,
        }
        store.issue_cooperative_readiness.assert_called_once()
        settlement.abandon_probe.assert_not_called()

    asyncio.run(scenario())


def test_only_newly_registered_paid_transition_starts_a_live_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        session, contract = "aa" * 32, "dd" * 32
        window = ClaimProbeWindow(session, contract, 1, 1000, 1030, time.monotonic())
        store = Mock(generation=1)
        settlement = Mock(probe_window=Mock(return_value=window))
        service = _service(store, [1000])
        service._settlement = settlement  # noqa: SLF001 - fresh registered transition fixture
        start = AsyncMock(return_value="bb" * 32)
        monkeypatch.setattr(service, "start_cooperative_readiness", start)
        await service._begin_paid_probe(session, "PAID", [])  # noqa: SLF001 - historical PAID
        start.assert_not_awaited()
        service._probe_supervision_needed = True  # noqa: SLF001 - fresh accepted + binding
        await service._begin_paid_probe(session, "PAYING", [])  # noqa: SLF001
        start.assert_not_awaited()
        await service._begin_paid_probe(session, "PAID", [])  # noqa: SLF001
        start.assert_awaited_once_with(session, relays=[], window=window)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "outcome",
    [
        "prepared",
        "failure",
        "proposal_refused",
        "proposal_failure",
        "shutdown",
        "unhealthy",
        "shutdown_after_sample",
        "unhealthy_after_sample",
        "deadline_after_sample",
    ],
)
def test_live_echo_is_consumed_before_fallback_preparation(  # noqa: PLR0915 - one-shot authorization lifecycle
    outcome: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:  # noqa: PLR0915 - original token consumption and effect ordering
        session, contract = "aa" * 32, "dd" * 32
        challenge = ReadinessChallenge(session, "bb" * 32, "cc" * 32, contract, 1, 1000, 1030, 1094)
        window = ClaimProbeWindow(session, contract, 1, 1000, 1030, time.monotonic())
        store = Mock(generation=1)
        store.pending_outbox.return_value = ()  # nothing queued for the immediate flush
        store.admit_cooperative_readiness.return_value = CooperativeResultAdmission(
            session, "ee" * 32, "ready", replay=False
        )
        settlement = Mock(probe_window=Mock(return_value=window))
        trace: list[str] = []
        clock = [1001]
        service = _service(store, clock)
        service._settlement = settlement  # noqa: SLF001 - newly paid original session
        service._readiness_probes[session] = challenge  # noqa: SLF001 - freshly issued token
        monkeypatch.setattr(service, "_fresh_probe_tip", AsyncMock(return_value=1090))

        async def prepare(token: ReadinessChallenge, *, sample_tip: object, now: object) -> None:
            assert token is challenge
            assert callable(sample_tip)
            assert callable(now)
            assert service.take_cooperative_readiness(session) is None
            trace.append("prepared")
            if outcome == "failure":
                raise LiveSessionStoreError("fallback not durable")
            if outcome == "shutdown":
                service._readiness_closed = True  # noqa: SLF001
            if outcome == "unhealthy":
                service._deadline_healthy = False  # noqa: SLF001

        store.retire_cooperative_readiness.side_effect = lambda _token: trace.append("retired")

        async def initiate(session_id: str, *, now: object) -> str | None:
            assert session_id == session
            assert callable(now)
            assert now() == 1001
            assert trace == ["prepared", "retired"]
            trace.append("initiated")
            if outcome == "proposal_failure":
                raise LiveSessionStoreError("burn may be durable")
            if outcome.endswith("after_sample"):
                await asyncio.sleep(0)
                if outcome == "shutdown_after_sample":
                    service._readiness_closed = True  # noqa: SLF001
                elif outcome == "unhealthy_after_sample":
                    service._deadline_healthy = False  # noqa: SLF001
                else:
                    clock[0] = 1030
                now()  # late eligibility must be refused by the supplied clock
                raise AssertionError("late service authority must never survive sampling")
            return None if outcome == "proposal_refused" else "ff" * 32

        settlement.prepare_cooperative_window = AsyncMock(side_effect=prepare)
        settlement.initiate_cooperative_proposal = AsyncMock(side_effect=initiate)
        store.open_mailbox_frame.return_value = json.dumps(
            {
                "message_type": "action_result",
                "session_id": session,
                "payload": {"action": "cooperative_claim_ready", "status": "ready"},
            }
        ).encode()
        event = json.dumps({"id": "01" * 32}).encode()
        assert await service.handle(event, []) == (
            "readiness-abandoned" if outcome == "failure" else "readiness-prepared"
        )
        store.admit_cooperative_readiness.assert_called_once()
        settlement.prepare_cooperative_window.assert_awaited_once()
        store.retire_cooperative_readiness.assert_called_once_with(challenge)
        assert service.take_cooperative_readiness(session) is None
        assert await service.handle(json.dumps({"id": "02" * 32}).encode(), []) == (
            "unavailable" if outcome.startswith(("shutdown", "unhealthy")) else "refused"
        )
        settlement.prepare_cooperative_window.assert_awaited_once()
        if outcome == "failure":
            settlement.abandon_probe.assert_called_once_with(session)
        else:
            settlement.abandon_probe.assert_not_called()
        if outcome in ("failure", "shutdown", "unhealthy"):
            settlement.initiate_cooperative_proposal.assert_not_called()
        else:
            settlement.initiate_cooperative_proposal.assert_awaited_once()

    asyncio.run(scenario())
