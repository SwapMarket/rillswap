"""Runtime orchestration of one LN to BTC claim proposal under its original window."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.cooperative_messages import CooperativeClaimSigned
from rill_core.wire.messages import Envelope
from test_handshake_service import _Relay
from test_reverse_paid_preflight import _backends
from test_reverse_proposal_debt import _facts
from test_reverse_proposal_debt import (
    pytestmark as native_marks,
)
from test_reverse_proposal_reservation import NativeSigner
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider import reverse_settlement
from rill_provider.core_tx_bytes import ReverseSpendCheckpoint, SpendScan
from rill_provider.handshake_service import HandshakeService, ServicePolicy
from rill_provider.live_session_store import LiveSessionStoreError, StaleOwnerError
from rill_provider.lnd_hold_invoice import HoldInvoiceStatus
from rill_provider.lnd_payment_observation import LndNotSyncedError
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - real store/engine seams and deterministic fixture clocks


def _funded_engine(reserved: ReservationCase) -> tuple[ReverseSettlement, Mock, Mock]:
    store = reserved.store
    store.advance_reverse_swap(
        reserved.origin.session_id,
        from_state="FUNDING_SENT",
        to_state="FUNDED",
        scan_checkpoint=ReverseSpendCheckpoint(999, "ab" * 32, 999, "ab" * 32),
        signer=NativeSigner(reserved.origin),
        now=1_700_000_000,
    )
    _, _, invoice = _facts(reserved)
    chain, hold = _backends(reserved)
    hold.observe_bound_invoice.return_value = invoice
    engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
    return engine, chain, hold


async def _cosign(engine: ReverseSettlement, reserved: ReservationCase) -> bytes | None:
    return await engine.cosign_cooperative_proposal(
        reserved.document,
        1_700_000_001,
        wall_clock=reserved.clock.utc,
        monotonic_clock=reserved.clock.steady,
    )


@pytest.mark.native_crypto
@native_marks[1]
@pytest.mark.parametrize("depth", ["signed", "below", "mempool"])
def test_proposal_first_runs_the_providers_own_funding_depth_step(
    reserved: ReservationCase,
    caplog: pytest.LogCaptureFixture,
    depth: str,
) -> None:
    """A client whose node saw its chosen depth first must not race the periodic pass.

    The client may claim before the signed depth, even from the mempool: it
    alone risks a provider double-spend, so the provider cooperates and
    settles straight from FUNDING_SENT.
    """

    async def exercise() -> None:
        terms, core, invoice = _facts(reserved)
        chain, hold = _backends(reserved)
        hold.observe_bound_invoice.return_value = invoice
        observed = {
            "signed": terms.funding_confirmations,
            "below": terms.funding_confirmations - 1,
            "mempool": 0,
        }[depth]
        if depth == "mempool":
            chain.observe_cooperative_claim_outpoint.return_value = replace(
                core, confirmations=0, inclusion_height=None, inclusion_block_hash=None
            )
        chain.confirmations.return_value = observed
        chain.funding_scan_boundary.return_value = (core.inclusion_height - 1, "ab" * 32)
        chain.tip_height.return_value = core.tip_height
        chain.find_spender.return_value = SpendScan(None, core.tip_height)
        store = reserved.store
        engine = ReverseSettlement(store, chain, hold, reserved.origin.crypto.crypto)
        assert await _cosign(engine, reserved) is not None
        ((state,),) = store._connection.execute(
            "SELECT state FROM swaps WHERE session_id=?", (reserved.origin.session_id,)
        ).fetchall()
        assert state == "SETTLED"
        chain.confirmations.assert_called()

    with caplog.at_level("INFO", logger="rill_provider.reverse_settlement"):
        asyncio.run(exercise())
    prefix = f"swap {reserved.origin.session_id[:16]} moved to"
    assert (f"{prefix} FUNDED" in caplog.messages) is (depth == "signed")
    assert f"{prefix} SETTLED" in caplog.messages


@pytest.mark.native_crypto
@native_marks[1]
@pytest.mark.parametrize("lag", ["unsynced", "behind"])
def test_lnd_lagging_core_by_a_block_is_resampled_not_refused(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch, lag: str
) -> None:
    async def exercise() -> None:
        monkeypatch.setattr(reverse_settlement, "TIP_AGREEMENT_PAUSE_SECONDS", 0)
        engine, _, hold = _funded_engine(reserved)
        invoice = hold.observe_bound_invoice.return_value
        stale = (
            LndNotSyncedError("LND invoice observation requires a synchronized tip")
            if lag == "unsynced"
            else replace(invoice, last_lnd_height=invoice.last_lnd_height - 1)
        )
        hold.observe_bound_invoice.side_effect = [stale, invoice]
        assert await _cosign(engine, reserved) is not None
        assert hold.observe_bound_invoice.call_count == 2

    asyncio.run(exercise())


@pytest.mark.native_crypto
@native_marks[1]
def test_persistent_tip_disagreement_refuses_without_a_nonce(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise() -> None:
        monkeypatch.setattr(reverse_settlement, "TIP_AGREEMENT_PAUSE_SECONDS", 0)
        engine, _, hold = _funded_engine(reserved)
        invoice = hold.observe_bound_invoice.return_value
        hold.observe_bound_invoice.return_value = replace(invoice, last_lnd_block_hash="00" * 32)
        monkeypatch.setattr(
            reserved.origin.crypto.crypto,
            "musig_begin",
            Mock(side_effect=AssertionError("no nonce without agreeing tips")),
        )
        with pytest.raises(LiveSessionStoreError):
            await _cosign(engine, reserved)
        assert hold.observe_bound_invoice.call_count == reverse_settlement.TIP_AGREEMENT_ATTEMPTS

    asyncio.run(exercise())


@pytest.mark.native_crypto
@native_marks[1]
def test_proposal_is_repaid_then_cosigned_once_and_replayed_exactly(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def exercise() -> None:
        engine, _, hold = _funded_engine(reserved)
        crypto = reserved.origin.crypto.crypto
        begin = crypto.musig_begin
        begins: list[object] = []

        def counted(**kwargs: object) -> object:
            begins.append(kwargs["cooperation_id"])
            return begin(**kwargs)

        monkeypatch.setattr(crypto, "musig_begin", counted)
        reply = await _cosign(engine, reserved)
        assert reply is not None
        response = Envelope.model_validate_json(reply, strict=True)
        proposal = Envelope.model_validate_json(reserved.document, strict=True)
        payload = CooperativeClaimSigned.model_validate_json(
            canonicalize(response.payload), strict=True
        )
        assert response.in_reply_to == proposal.message_id
        assert payload.status == "signed"
        hold.settle_bound_invoice.assert_called_once()
        store = reserved.store
        assert store._connection.execute("SELECT state,preimage FROM swaps").fetchone() == (
            "SETTLED",
            "52" * 32,
        )
        assert store._connection.execute("SELECT state FROM cooperation_attempts").fetchone() == (
            "COMPLETE",
        )
        assert any(entry.message_id == response.message_id for entry in store.pending_outbox())
        # A relayed duplicate gets the exact archive, never a second nonce.
        assert await _cosign(engine, reserved) == reply
        assert len(begins) == 1
        hold.settle_bound_invoice.assert_called_once()

    with caplog.at_level("INFO", logger="rill_provider.reverse_settlement"):
        asyncio.run(exercise())
    # The operator sees the settlement the proposal caused, once, not only at the next pass.
    moved = f"swap {reserved.origin.session_id[:16]} moved to SETTLED"
    assert caplog.messages.count(moved) == 1


@pytest.mark.native_crypto
@native_marks[1]
@pytest.mark.parametrize("failure", ["unpaid", "fee", "expired"])
def test_refused_proposal_never_signs_and_replay_stays_empty(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    async def exercise() -> None:
        engine, chain, hold = _funded_engine(reserved)
        crypto = reserved.origin.crypto.crypto
        begin = Mock(side_effect=AssertionError("no nonce for a refused proposal"))
        if failure == "unpaid":
            hold.observe_bound_settled_invoice.return_value = replace(
                hold.observe_bound_settled_invoice.return_value,
                status=HoldInvoiceStatus("ACCEPTED", ()),
            )
        elif failure == "fee":
            policy = chain.observe_cooperative_fee_policy.return_value
            chain.observe_cooperative_fee_policy.return_value = replace(
                policy, estimate_sat_kvb=10_000_000
            )
        else:

            def slow_settle(*_args: object, **_kwargs: object) -> None:
                reserved.clock.advance(31)  # Repayment outlives the original window.

            hold.settle_bound_invoice.side_effect = slow_settle
        monkeypatch.setattr(crypto, "musig_begin", begin)
        with pytest.raises(LiveSessionStoreError):
            await _cosign(engine, reserved)
        store = reserved.store
        proposal = Envelope.model_validate_json(reserved.document, strict=True)
        assert (
            store._connection.execute(
                "SELECT 1 FROM outbox WHERE in_reply_to=?", (proposal.message_id,)
            ).fetchone()
            is None
        )
        assert await _cosign(engine, reserved) is None
        begin.assert_not_called()

    asyncio.run(exercise())


def _service(settlement: Mock, *, profile: str = "ln-to-btc/v1") -> tuple:
    document = json.dumps(
        {
            "message_type": "action_request",
            "session_id": "untrusted routing hint",
            "payload": {"action": "cooperative_claim_propose"},
        }
    ).encode()
    store = Mock()
    store.open_mailbox_frame.return_value = document
    policy = ServicePolicy(
        network=None,
        profiles=(profile,),
        amount_bands=((1000, 2000),),  # type: ignore[arg-type]
        base_fee_sat=1,
        proportional_millionths=1,
        slot="s",
        relay_urls=("ws://r/",),
        profile=profile,  # type: ignore[arg-type]
    )
    service = HandshakeService(
        store, Mock(), Mock(), policy, clock=lambda: 123, settlement=settlement
    )
    return service, store, document


def _event() -> bytes:
    return json.dumps({"id": "aa" * 32}).encode()


@pytest.mark.parametrize("outcome", ["signed", "replay", "refused", "stale"])
def test_service_routes_reverse_proposals_to_the_cosigner_only(
    outcome: str, caplog: pytest.LogCaptureFixture
) -> None:
    async def exercise() -> None:
        reply = json.dumps({"message_id": "44" * 32}).encode()
        settlement = Mock(cosign_reverse_proposal=AsyncMock(return_value=reply))
        if outcome == "replay":
            settlement.cosign_reverse_proposal.return_value = None
        elif outcome == "refused":
            settlement.cosign_reverse_proposal.side_effect = LiveSessionStoreError(
                "sensitive preimage detail"
            )
        elif outcome == "stale":
            settlement.cosign_reverse_proposal.side_effect = StaleOwnerError("owner lost")
        service, store, document = _service(settlement)
        sent = AsyncMock()
        envelope = Mock(message_id="44" * 32)
        service._send_pending = sent  # type: ignore[method-assign]
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                "rill_provider.handshake_service.Envelope.model_validate_json",
                Mock(return_value=envelope),
            )
            if outcome == "stale":
                with pytest.raises(StaleOwnerError):
                    await service.handle(_event(), [])
                return
            result = await service.handle(_event(), [])
        assert (
            result
            == {
                "signed": "proposal-signed",
                "replay": "proposal-replay",
                "refused": "refused",
            }[outcome]
        )
        settlement.cosign_reverse_proposal.assert_awaited_once_with(document, now=123)
        store.answer_request.assert_not_called()
        if outcome == "signed":
            sent.assert_awaited_once_with("44" * 32, [])
        else:
            sent.assert_not_called()

    asyncio.run(exercise())
    assert "sensitive preimage detail" not in caplog.text
    if outcome == "refused":  # the operator learns the class, never the detail
        assert "reverse cooperative proposal refused (LiveSessionStoreError)" in caplog.messages


def test_forward_profile_never_routes_proposal_requests_to_reverse_cosigner() -> None:
    settlement = Mock(cosign_reverse_proposal=AsyncMock())
    service, store, _ = _service(settlement, profile="btc-to-ln/v1")
    store.answer_request.side_effect = LiveSessionStoreError("not a client request")
    assert asyncio.run(service.handle(_event(), [_Relay(accept=True)])) == "refused"
    settlement.cosign_reverse_proposal.assert_not_called()


@pytest.mark.parametrize("outcome", ["verified", "replay", "refused", "stale"])
def test_service_routes_reverse_completion_to_public_verification(
    outcome: str, caplog: pytest.LogCaptureFixture
) -> None:
    async def exercise() -> None:
        settlement = Mock(verify_reverse_completion=AsyncMock())
        settlement.verify_reverse_completion.return_value = Mock(
            response_message_id="44" * 32, replay=outcome == "replay"
        )
        if outcome == "refused":
            settlement.verify_reverse_completion.side_effect = LiveSessionStoreError(
                "private transcript detail"
            )
        elif outcome == "stale":
            settlement.verify_reverse_completion.side_effect = StaleOwnerError("owner lost")
        service, store, proposal = _service(settlement)
        routed = json.loads(proposal)
        routed["payload"]["action"] = "cooperative_claim_complete"
        document = json.dumps(routed).encode()
        store.open_mailbox_frame.return_value = document
        sent = AsyncMock()
        service._send_pending = sent  # type: ignore[method-assign]
        if outcome == "stale":
            with pytest.raises(StaleOwnerError):
                await service.handle(_event(), [])
            return
        assert (
            await service.handle(_event(), [])
            == {
                "verified": "completion-verified",
                "replay": "completion-replay",
                "refused": "refused",
            }[outcome]
        )
        settlement.verify_reverse_completion.assert_awaited_once_with(document, now=123)
        store.answer_request.assert_not_called()
        if outcome == "refused":
            sent.assert_not_called()
        else:
            sent.assert_awaited_once_with("44" * 32, [])

    asyncio.run(exercise())
    assert "private transcript detail" not in caplog.text


def test_closed_readiness_refuses_new_reverse_signing_exposure() -> None:
    settlement = Mock(cosign_reverse_proposal=AsyncMock())
    service, _, _ = _service(settlement)
    service._readiness_closed = True
    assert asyncio.run(service.handle(_event(), [])) == "unavailable"
    settlement.cosign_reverse_proposal.assert_not_called()
