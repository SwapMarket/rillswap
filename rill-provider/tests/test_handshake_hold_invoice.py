"""LN to BTC firm requests: the service opens a hold invoice before answering.

The store is mocked: these tests pin when a hold invoice is opened, what it is
opened with, and that an invoice no offer bound is canceled again.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from rill_core.wire.messages import InvoiceBinding
from test_quote_policy import CONTRACT, FIRM, SIGNER
from test_reverse_quote_policy import HASH, HOLD, REVERSE_FIRM, SCHEDULE

from rill_provider.handshake_service import HandshakeService, ServicePolicy
from rill_provider.live_session_store import Answer
from rill_provider.quote_policy import QuoteTerms

if TYPE_CHECKING:
    from collections.abc import Callable

POLICY = ServicePolicy(
    network=SIGNER.network,
    profiles=("ln-to-btc/v1",),
    amount_bands=((1_000, 100_000),),
    base_fee_sat=50,
    proportional_millionths=1_500,
    slot="s",
    relay_urls=("ws://r/",),
    provider_destination_script=CONTRACT["provider_destination_script"],
    quote=SCHEDULE,
    profile="ln-to-btc/v1",
)


def _document(payload: dict[str, Any], sequence: int = 2) -> bytes:
    return json.dumps({"sequence": sequence, "payload": payload | {"extensions": {}}}).encode()


def _terms(**changes: Any) -> QuoteTerms:  # noqa: ANN401
    base: dict[str, Any] = {
        "amount_bands": POLICY.amount_bands,
        "base_fee_sat": 50,
        "proportional_millionths": 1_500,
        "schedule": SCHEDULE,
        "tip_height": 850,
        "now": 1_700_000_000,
        "firm": SIGNER,
        "profile": "ln-to-btc/v1",
    }
    return QuoteTerms(**base | changes)


def _service(hold: Mock | None, store: Mock | None = None) -> tuple[HandshakeService, Mock]:
    store = store or Mock()
    store.classify_request.return_value = "new"
    store.payment_hash_reserved.return_value = False
    store.firm_capacity_available.return_value = True
    service = HandshakeService(
        store,
        Mock(),
        Mock(),
        POLICY,
        invoice_decoder=lambda _bolt11: HOLD,
        hold_invoices=hold,
    )
    return service, store


def _hold() -> Mock:
    hold = Mock()
    hold.add.return_value = "lnbcrt1007u1hold"
    return hold


def test_hold_is_opened_for_exactly_h_with_the_schedule_cltv() -> None:
    service, _ = _service(_hold())
    outcome = asyncio.run(service._open_hold(_document(REVERSE_FIRM), _terms()))  # noqa: SLF001
    assert outcome == ("lnbcrt1007u1hold", HOLD)
    service._hold_invoices.add.assert_called_once_with(  # type: ignore[union-attr] # noqa: SLF001
        HASH, value_msat=100_700_000, expiry_seconds=1_800, cltv_expiry_delta=185
    )


@pytest.mark.parametrize(
    ("document", "terms_changes", "store_changes"),
    [
        (_document(REVERSE_FIRM), {"profile": "btc-to-ln/v1"}, {}),  # served profile differs
        (_document(REVERSE_FIRM), {"firm": None}, {}),
        (_document(REVERSE_FIRM, sequence=3), {}, {}),  # not the first request
        (_document(REVERSE_FIRM | {"mode": "indicative"}), {}, {}),
        (_document(FIRM), {}, {}),  # a BTC to LN request: no hold invoice
        (_document(REVERSE_FIRM | {"nominal_payout_sat": "1"}), {}, {}),  # outside bands
        (_document(REVERSE_FIRM), {}, {"classify_request.return_value": "replay"}),
        (_document(REVERSE_FIRM), {}, {"payment_hash_reserved.return_value": True}),
        (_document(REVERSE_FIRM), {}, {"firm_capacity_available.return_value": False}),
    ],
)
def test_no_hold_is_opened_when_the_offer_could_not_bind_it(
    document: bytes, terms_changes: dict[str, Any], store_changes: dict[str, Any]
) -> None:
    hold = _hold()
    service, store = _service(hold)
    store.configure_mock(**store_changes)
    assert asyncio.run(service._open_hold(document, _terms(**terms_changes))) is None  # noqa: SLF001
    hold.add.assert_not_called()


def test_backend_failure_only_defers_the_firm_quote() -> None:
    hold = _hold()
    hold.add.side_effect = RuntimeError("boom")
    service, _ = _service(hold)
    assert asyncio.run(service._open_hold(_document(REVERSE_FIRM), _terms())) == "unavailable"  # noqa: SLF001
    service, _ = _service(None)  # no adapter configured: never a hold, never an error
    assert asyncio.run(service._open_hold(_document(REVERSE_FIRM), _terms())) is None  # noqa: SLF001


@pytest.mark.parametrize(
    ("answers", "canceled"),
    [
        (["terms_offer"], False),
        (["error"], True),
        ([], True),  # replay: the recorded answer is re-sent, this invoice binds nothing
    ],
)
def test_unbound_hold_invoices_are_canceled_after_the_answer(
    monkeypatch: pytest.MonkeyPatch,
    answers: list[str],
    canceled: bool,  # noqa: FBT001
) -> None:
    hold = _hold()
    service, store = _service(hold)

    def answer_request(
        _document: bytes, *, responder: Callable[..., Answer], **_kwargs: object
    ) -> Mock:
        for _ in answers:
            responder(Mock(), (), Mock())
        return Mock(response_message_id="00" * 32, replay=not answers)

    store.answer_request.side_effect = answer_request
    monkeypatch.setattr(
        "rill_provider.handshake_service.answer_client_request",
        lambda *_a, **_k: Answer(answers[0], {}),
    )

    async def none(*_a: object, **_k: object) -> None:
        return None

    monkeypatch.setattr(service, "_send_pending", none)
    monkeypatch.setattr(service, "_route_ready", lambda _d, terms: _same(terms))
    service._state.tip = 850  # noqa: SLF001
    asyncio.run(service._answer(_document(REVERSE_FIRM), [], now=1_700_000_000))  # noqa: SLF001
    hold.add.assert_called_once()
    assert hold.cancel.call_count == (1 if canceled else 0)
    if canceled:
        hold.cancel.assert_called_once_with(HASH)


async def _same(terms: QuoteTerms) -> QuoteTerms:
    return terms


def test_hold_binding_is_an_invoice_binding() -> None:
    assert isinstance(HOLD, InvoiceBinding)
