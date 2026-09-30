"""Fresh admitted partials trigger signing preflight, never replays or receipts."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, Mock

import pytest
from test_handshake_service import _Relay

from rill_provider.handshake_service import HandshakeService, ServicePolicy
from rill_provider.live_session_store import (
    CooperativeResultAdmission,
    LiveSessionStoreError,
    StaleOwnerError,
)

COOPERATION = "11" * 32
SESSION = "22" * 32


def _service(*, status: str = "signed", replay: bool = False) -> tuple:
    document = json.dumps(
        {
            "message_type": "action_result",
            "session_id": "untrusted routing hint",
            "payload": {
                "action": "cooperative_claim_propose",
                "status": "signed",
                "cooperation_id": COOPERATION,
            },
        }
    ).encode()
    store = Mock()
    store.open_mailbox_frame.return_value = document
    store._admit_cooperative_result.return_value = CooperativeResultAdmission(  # noqa: SLF001 - authenticated admission stub
        SESSION, "33" * 32, status, replay
    )
    settlement = Mock(complete_cooperative_claim=AsyncMock(return_value="44" * 32))
    policy = ServicePolicy(
        network=None,
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 2000),),  # type: ignore[arg-type]
        base_fee_sat=1,
        proportional_millionths=1,
        slot="s",
        relay_urls=("ws://r/",),
    )
    service = HandshakeService(
        store, Mock(), Mock(), policy, clock=lambda: 123, settlement=settlement
    )
    return service, store, settlement, document


def _event() -> bytes:
    return json.dumps({"id": "aa" * 32}).encode()


@pytest.mark.parametrize(
    ("status", "replay"),
    [("signed", False), ("signed", True), ("declined", False), ("verified", False)],
)
def test_only_fresh_signed_admission_triggers_independent_completion(
    status: str, *, replay: bool
) -> None:
    async def exercise() -> None:
        service, store, settlement, document = _service(status=status, replay=replay)
        relay = _Relay(accept=True)
        assert await service.handle(_event(), [relay]) == (
            "result-replay" if replay else "result-admitted"
        )
        store._admit_cooperative_result.assert_called_once_with(document, now=123)  # noqa: SLF001
        if status == "signed" and not replay:
            settlement.complete_cooperative_claim.assert_awaited_once()
            call = settlement.complete_cooperative_claim.await_args
            assert call.args == (SESSION, bytes.fromhex(COOPERATION))
            assert callable(call.kwargs["now"])
            assert call.kwargs["now"]() == 123
        else:
            settlement.complete_cooperative_claim.assert_not_called()
        store.answer_request.assert_not_called()
        assert relay.published == []

    asyncio.run(exercise())


@pytest.mark.parametrize("outcome", ["none", "id", "failure", "stale", "cancellation"])
def test_completion_outcome_does_not_reclassify_durable_admission(
    outcome: str, caplog: pytest.LogCaptureFixture
) -> None:
    async def exercise() -> None:
        service, _, settlement, _ = _service()
        if outcome == "none":
            settlement.complete_cooperative_claim.return_value = None
        elif outcome == "failure":
            settlement.complete_cooperative_claim.side_effect = LiveSessionStoreError(
                "sensitive completion details"
            )
        elif outcome == "stale":
            settlement.complete_cooperative_claim.side_effect = StaleOwnerError("ownership lost")
        elif outcome == "cancellation":
            settlement.complete_cooperative_claim.side_effect = asyncio.CancelledError()
        if outcome == "stale":
            with pytest.raises(StaleOwnerError):
                await service.handle(_event(), [])
        elif outcome == "cancellation":
            with pytest.raises(asyncio.CancelledError):
                await service.handle(_event(), [])
        else:
            assert await service.handle(_event(), []) == "result-admitted"
        settlement.complete_cooperative_claim.assert_awaited_once()

    asyncio.run(exercise())
    assert "sensitive completion details" not in caplog.text


def test_failed_admission_cannot_trigger_completion() -> None:
    service, store, settlement, _ = _service()
    store._admit_cooperative_result.side_effect = LiveSessionStoreError("invalid partial")  # noqa: SLF001
    assert asyncio.run(service.handle(_event(), [])) == "refused"
    settlement.complete_cooperative_claim.assert_not_called()


@pytest.mark.parametrize("flag", ["closed", "unhealthy"])
@pytest.mark.parametrize("boundary", ["before entry", "inside clock", "during sampling"])
def test_original_service_health_cannot_be_restored_by_a_clock_return(
    flag: str,
    boundary: str,
) -> None:
    async def exercise() -> None:
        service, _, settlement, _ = _service()

        def revoke() -> None:
            if flag == "closed":
                service._readiness_closed = True  # noqa: SLF001 - revocation fault injection
            else:
                service._deadline_healthy = False  # noqa: SLF001

        if boundary == "before entry":
            revoke()
        elif boundary == "inside clock":

            def revoked_clock() -> int:
                revoke()
                return 123

            service._deadline_now = revoked_clock  # noqa: SLF001 - external clock boundary
        else:

            async def sampling(_session: str, _cooperation: bytes, *, now: object) -> None:
                assert now() == 123
                revoke()
                with pytest.raises(LiveSessionStoreError, match="service unavailable"):
                    now()

            settlement.complete_cooperative_claim.side_effect = sampling
        expected = "unavailable" if boundary == "before entry" else "result-admitted"
        assert await service.handle(_event(), []) == expected
        if boundary == "during sampling":
            settlement.complete_cooperative_claim.assert_awaited_once()
        else:
            settlement.complete_cooperative_claim.assert_not_called()

    asyncio.run(exercise())


def test_committed_completion_delivery_does_not_require_live_signing_health() -> None:
    service, store, _, _ = _service()
    service._readiness_closed = True  # noqa: SLF001 - suppress only new exposure
    service._deadline_healthy = False  # noqa: SLF001
    service._chain_tip = Mock(side_effect=OSError("Core unavailable"))  # noqa: SLF001
    store.pending_requires_live_cooperation.return_value = False
    store.pending_sendable.return_value = True
    store.wrap_pending.return_value = b"owed sealed completion"
    relay = _Relay(accept=True)
    asyncio.run(service._send_pending("completion", [relay]))  # noqa: SLF001 - normal owed outbox path
    assert relay.published == [b"owed sealed completion"]
    service._chain_tip.assert_not_called()  # noqa: SLF001
