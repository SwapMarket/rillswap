"""Reverse hold effects require committed refusal and continuous owner exclusion."""

# Deliberately exercise private admission and transaction lifecycle boundaries.
# ruff: noqa: SLF001

from __future__ import annotations

import asyncio
import copy
import hashlib
import sqlite3
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
import test_live_session_store as fixtures
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import canonical_model, provider_terms_hash
from test_handshake_hold_invoice import POLICY, _document, _hold, _refusal, _service
from test_payment_reconciliation import Signer
from test_reverse_quote_policy import HASH, HOLD, REVERSE_FIRM

from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import (
    Answer,
    LiveSessionStoreError,
    OutboxEntry,
    RequestAnswer,
    SettlementItem,
    StaleOwnerError,
    StaleSwapError,
)
from rill_provider.quote_policy import FirmSigner
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rill_core.wire.messages import InvoiceBinding

    from rill_provider.live_session_store import LiveSessionStore


@dataclass
class ReverseCase:
    store: LiveSessionStore
    service: HandshakeService
    hold: Mock
    request: bytes
    fixture: fixtures.Harness
    clock: dict[str, int]


@pytest.fixture
def reverse_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReverseCase]:
    monkeypatch.setattr(
        fixtures,
        "FIXTURE",
        Path(fixtures.__file__).parent / "fixtures/initial-ln-to-btc-no-prepayment-v1.json",
    )
    fixture = fixtures.Harness(tmp_path, monkeypatch)
    fixture.policy = replace(fixture.policy, profile="ln-to-btc/v1")
    fixture.scalar = (9).to_bytes(32, "big")
    fixture.provision()
    with fixture.acquire() as store:
        store.reserve(fixture.init)
        store.commit_accept(fixture.accept)
        store.admit_confirm(fixture.confirm)
        request = copy.deepcopy(fixture.envelopes[2])
        request.update(
            message_type="quote_request",
            sequence=2,
            message_id="66" * 32,
            in_reply_to=None,
            payload=REVERSE_FIRM | {"extensions": {}},
            signature="55" * 64,
        )
        fixture.crypto.permit_confirm(request)
        signer, hold = Signer(fixture), Mock()
        invoice = "lnbcrt1007u1hold"
        binding = HOLD.model_copy(
            update={
                "bolt11_sha256": hashlib.sha256(invoice.encode()).hexdigest(),
                "expires_at": 1_700_003_600,
            }
        )
        hold.add.return_value = invoice
        clock = {"now": 1_700_000_000}
        service = HandshakeService(
            store,
            Mock(),
            signer,
            replace(POLICY, network=fixture.network),
            clock=lambda: clock["now"],
            invoice_decoder=lambda _invoice: binding,
            hold_invoices=hold,
        )
        firm = FirmSigner(
            network=fixture.network,
            provider_identity_key=fixture.identity,
            provider_destination_script=POLICY.provider_destination_script,
            sign=lambda terms: signer.schnorr_sign(
                (1).to_bytes(32, "big"), provider_terms_hash(terms), b"\0" * 32
            ).hex(),
        )
        monkeypatch.setattr(service, "_firm_signer", lambda: firm)
        monkeypatch.setattr(service, "_send_pending", AsyncMock(return_value=None))
        service._state.tip = 850
        yield ReverseCase(store, service, hold, canonicalize(request), fixture, clock)


def test_real_reverse_terms_commit_then_replay_never_cancels_invoice(
    reverse_case: ReverseCase,
) -> None:
    case = reverse_case
    assert (
        asyncio.run(case.service._answer(case.request, (), case.clock["now"])) == "request-answered"
    )
    case.hold.add.assert_called_once()
    case.hold.cancel.assert_not_called()
    pending = case.store.pending_outbox()
    assert any(b'"message_type":"terms_offer"' in entry.canonical_bytes for entry in pending)
    assert (
        asyncio.run(case.service._answer(case.request, (), case.clock["now"])) == "request-replay"
    )
    assert case.hold.add.call_count == 1
    case.hold.cancel.assert_not_called()


class CommitThenFail:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.armed = False

    def execute(self, statement: str, *args: object) -> sqlite3.Cursor:
        result = self.connection.execute(statement, *args)
        if statement == "COMMIT" and self.armed:
            raise sqlite3.OperationalError("successful commit reported as failed")
        return result

    def close(self) -> None:
        self.connection.close()


def test_actual_commit_followed_by_error_preserves_payable_terms_without_cleanup(
    reverse_case: ReverseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = reverse_case
    proxy = CommitThenFail(case.store._connection)
    case.store._connection = proxy  # type: ignore[assignment]
    original = case.store.answer_request

    def admit(*args: object, **kwargs: object) -> RequestAnswer:
        proxy.armed = True
        return original(*args, **kwargs)

    monkeypatch.setattr(case.store, "answer_request", admit)
    with pytest.raises(StaleOwnerError, match="uncertain"):
        asyncio.run(case.service._answer(case.request, (), case.clock["now"]))
    case.hold.add.assert_called_once()
    case.hold.cancel.assert_not_called()
    with case.fixture.acquire() as fresh:
        assert any(
            b'"message_type":"terms_offer"' in entry.canonical_bytes
            for entry in fresh.pending_outbox()
        )
        # Durable replay does not call a responder or manufacture a new invoice.
        replay = fresh.answer_request(
            case.request,
            responder=Mock(side_effect=AssertionError("no renewed offer")),
            signer=Signer(case.fixture),
            now=case.clock["now"],
        )
        assert replay.replay


def test_successful_rollback_preserves_original_error_without_guessing_cleanup_authority(
    reverse_case: ReverseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = reverse_case
    error = RuntimeError("admission failed before any payable offer")

    def rolled_back(*_args: object, **_kwargs: object) -> RequestAnswer:
        with case.store._write():
            raise error

    monkeypatch.setattr(case.store, "answer_request", rolled_back)
    with pytest.raises(RuntimeError) as observed:
        asyncio.run(case.service._answer(case.request, (), case.clock["now"]))
    assert observed.value is error
    assert case.store.owner_is_open
    case.hold.add.assert_called_once()
    case.hold.cancel.assert_not_called()
    assert not any(
        b'"message_type":"terms_offer"' in entry.canonical_bytes
        for entry in case.store.pending_outbox()
    )


def test_relay_failure_after_payable_commit_does_not_cancel_bound_invoice(
    reverse_case: ReverseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = reverse_case
    monkeypatch.setattr(
        case.service, "_send_pending", AsyncMock(side_effect=RuntimeError("relay unavailable"))
    )
    with pytest.raises(RuntimeError, match="relay unavailable"):
        asyncio.run(case.service._answer(case.request, (), case.clock["now"]))
    case.hold.cancel.assert_not_called()
    assert any(
        b'"message_type":"terms_offer"' in entry.canonical_bytes
        for entry in case.store.pending_outbox()
    )


@pytest.mark.parametrize("phase", ["add", "decode"])
def test_canceled_creation_or_decoding_drains_without_admission_or_cleanup(
    reverse_case: ReverseCase,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    case = reverse_case
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original_decode = case.service._invoice_decoder
    admission = Mock(wraps=case.store.answer_request)
    monkeypatch.setattr(case.store, "answer_request", admission)

    def block(*args: object, **_kwargs: object) -> object:
        entered.set()
        try:
            assert release.wait(3)
            return "lnbcrt1007u1hold" if phase == "add" else original_decode(args[0])
        finally:
            finished.set()

    if phase == "add":
        case.hold.add.side_effect = block
    else:
        monkeypatch.setattr(case.service, "_invoice_decoder", block)

    async def exercise() -> None:
        running = asyncio.create_task(case.service._answer(case.request, (), case.clock["now"]))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            case.store.close()
            for _ in range(3):
                running.cancel()
                await asyncio.sleep(0)
                assert not running.done()
                with pytest.raises(LiveSessionStoreError, match="owned by another"):
                    case.fixture.acquire()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await running
            assert finished.is_set()
            admission.assert_not_called()
            case.hold.cancel.assert_not_called()
            with case.fixture.acquire() as fresh:
                assert not any(
                    b'"message_type":"terms_offer"' in row.canonical_bytes
                    for row in fresh.pending_outbox()
                )
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    asyncio.run(exercise())


def _refuse(*_args: object) -> Answer:
    return Answer("error", {"code": "capacity_unavailable", "message": "firm quote unavailable"})


def test_cleanup_failure_does_not_erase_committed_refusal(
    reverse_case: ReverseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = reverse_case
    monkeypatch.setattr("rill_provider.handshake_service.answer_client_request", _refuse)
    case.hold.cancel.side_effect = RuntimeError("private cleanup RPC details")
    assert (
        asyncio.run(case.service._answer(case.request, (), case.clock["now"])) == "request-answered"
    )
    case.hold.cancel.assert_called_once_with(HASH)
    assert any(
        b'"message_type":"error"' in entry.canonical_bytes for entry in case.store.pending_outbox()
    )


def test_cleanup_rpc_holds_shared_gate_against_reverse_advancement_until_actual_finish(
    reverse_case: ReverseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = reverse_case
    monkeypatch.setattr("rill_provider.handshake_service.answer_client_request", _refuse)
    entered, release = threading.Event(), threading.Event()

    def cancel(_hash: str) -> None:
        entered.set()
        assert release.wait(3)

    case.hold.cancel.side_effect = cancel
    engine = ReverseSettlement(case.store, Mock(), case.hold, Signer(case.fixture))
    selector = SettlementItem(
        session_id=case.fixture.envelopes[2]["session_id"],
        state="FUNDED",
        blocked=False,
        terms_offer=b"stale selector",
        funding_binding=None,
        invoice="",
        preimage=None,
        claim_tx=None,
        claim_txid=None,
    )

    async def exercise() -> None:
        running = asyncio.create_task(case.service._answer(case.request, (), case.clock["now"]))
        queued = None
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            queued = asyncio.create_task(engine.advance(selector, case.clock["now"]))
            await asyncio.sleep(0.01)
            assert not queued.done()
            release.set()
            assert await running == "request-answered"
            with pytest.raises(StaleSwapError):
                await queued  # Fresh refusal state, not the stale FUNDED selector.
            case.hold.cancel.assert_called_once_with(HASH)
        finally:
            release.set()
            await asyncio.gather(
                running, *(() if queued is None else (queued,)), return_exceptions=True
            )

    asyncio.run(exercise())


def test_quote_resamples_injected_clock_after_gate_wait_and_async_hold_preparation(
    reverse_case: ReverseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = reverse_case
    admission = Mock(wraps=case.store.answer_request)
    monkeypatch.setattr(case.store, "answer_request", admission)
    original_decode = case.service._invoice_decoder

    def decode(invoice: str) -> InvoiceBinding:
        case.clock["now"] += 3
        return original_decode(invoice)

    monkeypatch.setattr(case.service, "_invoice_decoder", decode)

    async def exercise() -> None:
        old = case.clock["now"]
        async with case.store.reverse_operations.operation():
            running = asyncio.create_task(case.service._answer(case.request, (), old))
            await asyncio.sleep(0)
            assert not running.done()
            case.clock["now"] += 7
        assert await running == "request-answered"
        assert admission.call_args.kwargs["now"] == old + 10
        case.hold.cancel.assert_not_called()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "evidence",
    [
        "terms",
        "missing",
        "malformed",
        "noncanonical",
        "entry id",
        "session",
        "reply",
        "profile",
        "network",
        "unsigned",
        "payload",
        "contract",
        "original session",
        "original id",
        "invoice hash",
    ],
)
def test_inconsistent_or_possibly_payable_owned_evidence_cannot_cancel(evidence: str) -> None:
    hold = _hold()
    service, store = _service(hold)
    response = _refusal()
    if evidence == "terms":
        response = response.model_copy(update={"message_type": "terms_offer"})
    elif evidence == "session":
        response = response.model_copy(update={"session_id": "aa" * 32})
    elif evidence == "reply":
        response = response.model_copy(update={"in_reply_to": "aa" * 32})
    elif evidence == "profile":
        response = response.model_copy(update={"profile_id": "btc-to-ln/v1"})
    elif evidence == "network":
        response = response.model_copy(
            update={
                "network_identity": response.network_identity.model_copy(
                    update={"deployment_namespace": "other"}
                )
            }
        )
    elif evidence == "unsigned":
        response = response.model_copy(update={"signature": None})
    elif evidence == "payload":
        response = response.model_copy(
            update={"payload": {"code": "not-a-refusal-code", "message": "invalid"}}
        )
    elif evidence == "contract":
        response = response.model_copy(update={"contract_hash": "aa" * 32})
    raw = canonical_model(response)
    if evidence == "malformed":
        raw = b"{}"
    elif evidence == "noncanonical":
        raw += b"\n"
    store.pending_outbox.return_value = (
        ()
        if evidence == "missing"
        else (OutboxEntry("aa" * 32 if evidence == "entry id" else "00" * 32, "11" * 32, raw),)
    )
    original = _document(REVERSE_FIRM)
    if evidence in {"original session", "original id"}:
        from rill_core.wire.canonical import parse_model_json  # noqa: PLC0415 - proof fixture
        from rill_core.wire.messages import Envelope  # noqa: PLC0415 - proof fixture

        original_request = parse_model_json(Envelope, original)
        original = canonical_model(
            original_request.model_copy(
                update={
                    "session_id" if evidence == "original session" else "message_id": "aa" * 32,
                }
            )
        )
    elif evidence == "invoice hash":
        original = _document(REVERSE_FIRM | {"payment_hash": "aa" * 32})

    async def exercise() -> None:
        async with store.reverse_operations.operation() as operation:
            assert not service._matching_unused_hold(
                original,
                RequestAnswer("11" * 32, "22" * 32, "00" * 32, replay=True),
                (hold.add.return_value, HOLD),
                operation=operation,
            )
        hold.cancel.assert_not_called()

    asyncio.run(exercise())
