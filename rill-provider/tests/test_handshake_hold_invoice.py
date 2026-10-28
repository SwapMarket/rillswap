"""LN to BTC firm requests: the service opens a hold invoice before answering.

The store is mocked: these tests pin when a hold invoice is opened, what it is
opened with, and that an invoice no offer bound is canceled again.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import nullcontext
from dataclasses import replace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from rill_core.wire.hashes import canonical_model
from rill_core.wire.messages import Envelope, InvoiceBinding
from test_quote_policy import CONTRACT, FIRM, SIGNER
from test_reverse_quote_policy import HASH, HOLD, REVERSE_FIRM, SCHEDULE

from rill_provider.handshake_service import HandshakeService, ServicePolicy
from rill_provider.live_session_store import Answer, OutboxEntry, RequestAnswer
from rill_provider.quote_policy import ClaimFeeRate, QuoteTerms
from rill_provider.reverse_operations import ReverseOperations

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
    return canonical_model(
        Envelope(
            protocol="rillswap",
            wire_version="1",
            profile_id="ln-to-btc/v1",
            network_identity=SIGNER.network,
            session_id="11" * 32,
            message_id="22" * 32,
            sender_session_key="33" * 32,
            sequence=sequence,
            in_reply_to=None,
            contract_hash=None,
            message_type="quote_request",
            payload=payload | {"extensions": {}},
            required_features=(),
            extensions={},
            signature="66" * 64,
        )
    )


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


def _service(
    hold: Mock | None,
    store: Mock | None = None,
    *,
    policy: ServicePolicy = POLICY,
    claim_fee: Callable[[], ClaimFeeRate] | None = None,
    liquidity: Callable[[], int] | None = None,
) -> tuple[HandshakeService, Mock]:
    store = store or Mock()
    store.classify_request.return_value = "new"
    store.payment_hash_reserved.return_value = False
    store.firm_capacity_available.return_value = True
    store.owner_is_open = True
    store.retain_owner.side_effect = nullcontext
    store.reverse_operations = ReverseOperations(store)
    store.pending_outbox.return_value = ()
    service = HandshakeService(
        store,
        Mock(),
        Mock(),
        policy,
        invoice_decoder=lambda _bolt11: HOLD,
        hold_invoices=hold,
        clock=lambda: 1_700_000_000,
        claim_fee=claim_fee,
        liquidity=liquidity,
    )
    return service, store


def _hold() -> Mock:
    hold = Mock()
    hold.add.return_value = "lnbcrt1007u1hold"
    return hold


async def _open(service: HandshakeService, document: bytes, terms: QuoteTerms) -> object:
    async with service._store.reverse_operations.operation() as operation:  # noqa: SLF001 - component scope
        return await service._open_hold(document, terms, operation=operation)  # noqa: SLF001


def _refusal() -> Envelope:
    return Envelope(
        protocol="rillswap",
        wire_version="1",
        profile_id="ln-to-btc/v1",
        network_identity=SIGNER.network,
        session_id="11" * 32,
        message_id="00" * 32,
        sender_session_key="33" * 32,
        sequence=3,
        in_reply_to="22" * 32,
        contract_hash=None,
        message_type="error",
        payload={"code": "capacity_unavailable", "message": "firm quote unavailable"},
        required_features=(),
        extensions={},
        signature="44" * 64,
    )


def test_hold_is_opened_for_exactly_h_with_the_schedule_cltv() -> None:
    service, _ = _service(_hold())
    outcome = asyncio.run(_open(service, _document(REVERSE_FIRM), _terms()))
    assert outcome == ("lnbcrt1007u1hold", HOLD)
    service._hold_invoices.add.assert_called_once_with(  # type: ignore[union-attr] # noqa: SLF001
        HASH, value_msat=100_700_000, expiry_seconds=3_600, cltv_expiry_delta=185
    )


@pytest.mark.parametrize("message_type", ["error", "terms_accept", "funding_binding"])
def test_non_quote_requests_never_invoke_invoice_or_hold_rpc(message_type: str) -> None:
    hold = _hold()
    service, store = _service(hold)
    decoder = Mock()
    service._invoice_decoder = decoder  # noqa: SLF001 - assert the external effect boundary
    document = json.loads(_document(REVERSE_FIRM | {"invoice": "untrusted"}))
    document["message_type"] = message_type
    encoded = json.dumps(document).encode()
    assert asyncio.run(service._decode_invoice(encoded)) is None  # noqa: SLF001
    assert asyncio.run(_open(service, encoded, _terms())) is None
    decoder.assert_not_called()
    hold.add.assert_not_called()
    store.classify_request.assert_not_called()


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
    assert asyncio.run(_open(service, document, _terms(**terms_changes))) is None
    hold.add.assert_not_called()


def test_backend_failure_only_defers_the_firm_quote() -> None:
    hold = _hold()
    hold.add.side_effect = RuntimeError("boom")
    service, _ = _service(hold)
    assert asyncio.run(_open(service, _document(REVERSE_FIRM), _terms())) == "unavailable"
    service, _ = _service(None)  # no adapter configured: never a hold, never an error
    assert asyncio.run(_open(service, _document(REVERSE_FIRM), _terms())) is None


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
    # Make this test's unbound replay premise explicit: its owned prior reply
    # is a committed refusal, not unspecified or possibly payable terms.
    refusal = _refusal()
    store.pending_outbox.return_value = (
        OutboxEntry(refusal.message_id, refusal.session_id, canonical_model(refusal)),
    )

    def answer_request(
        _document: bytes, *, responder: Callable[..., Answer], **_kwargs: object
    ) -> RequestAnswer:
        for _ in answers:
            responder(Mock(), (), Mock())
        return RequestAnswer("11" * 32, "22" * 32, "00" * 32, replay=not answers)

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


def _answer_automatic(
    monkeypatch: pytest.MonkeyPatch, claim_fee: Callable[[], ClaimFeeRate]
) -> tuple[Mock, list[QuoteTerms]]:
    """Run one tick's fee sample, then answer a firm request with an automatic reserve."""
    hold = _hold()
    automatic = replace(SCHEDULE, claim_fee_reserve_sat=None, max_claim_fee_sat=1_000)
    policy = replace(POLICY, quote=automatic)
    service, store = _service(hold, policy=policy, claim_fee=claim_fee)
    seen: list[QuoteTerms] = []

    def answer_request(
        _document: bytes, *, responder: Callable[..., Answer], **_kwargs: object
    ) -> RequestAnswer:
        responder(Mock(), (), Mock())
        return RequestAnswer("11" * 32, "22" * 32, "00" * 32, replay=False)

    def answer(
        _request: object, _prior: object, _context: object, terms: QuoteTerms, _t: object
    ) -> Answer:
        seen.append(terms)
        return Answer("terms_offer", {})

    store.answer_request.side_effect = answer_request
    monkeypatch.setattr("rill_provider.handshake_service.answer_client_request", answer)

    async def none(*_a: object, **_k: object) -> None:
        return None

    monkeypatch.setattr(service, "_send_pending", none)
    monkeypatch.setattr(service, "_route_ready", lambda _d, terms: _same(terms))
    service._state.tip = 850  # noqa: SLF001
    asyncio.run(service._refresh_claim_fee())  # noqa: SLF001 - the per-tick step alone
    asyncio.run(service._answer(_document(REVERSE_FIRM), [], now=1_700_000_000))  # noqa: SLF001
    return hold, seen


def test_automatic_reserve_prices_the_hold_from_this_ticks_fee_sample(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    samples: list[None] = []

    def claim_fee() -> ClaimFeeRate:
        samples.append(None)
        return ClaimFeeRate(rate_sat_kvb=6_000, floor_sat_kvb=100)

    hold, seen = _answer_automatic(monkeypatch, claim_fee)
    # P2WPKH destination: the 143 vB script path at 6 sat/vB is 858, over the client's 500.
    hold.add.assert_called_once_with(
        HASH, value_msat=(100_000 + 858 + 200) * 1000, expiry_seconds=3_600, cltv_expiry_delta=185
    )
    assert [terms.claim_fee for terms in seen] == [ClaimFeeRate(6_000, 100)]
    assert len(samples) == 1  # requests never trigger fee RPC


def test_failed_fee_sample_opens_no_hold(monkeypatch: pytest.MonkeyPatch) -> None:
    def claim_fee() -> ClaimFeeRate:
        raise RuntimeError("Core next-block fee estimate unavailable")

    hold, seen = _answer_automatic(monkeypatch, claim_fee)
    hold.add.assert_not_called()
    assert [terms.claim_fee for terms in seen] == [None]


def test_hold_binding_is_an_invoice_binding() -> None:
    assert isinstance(HOLD, InvoiceBinding)


# The fixed schedule's contract: payout 100,000 plus a 500 claim reserve (H less
# the 200 success fee), funded with at most max_funding_fee_sat on chain.
FUNDING_NEED = 100_500 + SCHEDULE.max_funding_fee_sat


@pytest.mark.parametrize(("balance", "opened"), [(FUNDING_NEED, True), (FUNDING_NEED - 1, False)])
def test_no_hold_is_opened_when_the_wallet_cannot_fund_the_contract(
    balance: int,
    opened: bool,  # noqa: FBT001
) -> None:
    hold = _hold()
    service, _ = _service(hold, liquidity=lambda: balance)
    outcome = asyncio.run(_open(service, _document(REVERSE_FIRM), _terms()))
    assert (outcome == ("lnbcrt1007u1hold", HOLD)) is opened
    assert (outcome is None) is not opened  # answered capacity_unavailable, nothing to cancel
    assert hold.add.called is opened


def test_an_unreadable_balance_admits_the_quote_as_before(
    caplog: pytest.LogCaptureFixture,
) -> None:
    readings: list[int | Exception] = [PermissionError("getbalances not whitelisted")] * 2

    def balance() -> int:
        reading = readings.pop(0)
        if isinstance(reading, Exception):
            raise reading
        return reading

    hold = _hold()
    service, _ = _service(hold, liquidity=balance)
    for _ in range(2):  # an upgraded node's old whitelist must not stop LN to BTC
        assert asyncio.run(_open(service, _document(REVERSE_FIRM), _terms())) is not None
    assert hold.add.call_count == 2
    warnings = [r for r in caplog.records if "funding balance unavailable" in r.message]
    assert len(warnings) == 1  # once per failure streak
    readings.append(FUNDING_NEED - 1)  # readable again: a known shortfall refuses
    assert asyncio.run(_open(service, _document(REVERSE_FIRM), _terms())) is None
    assert hold.add.call_count == 2


def test_the_funding_check_applies_without_following_liquidity() -> None:
    hold = _hold()
    policy = replace(POLICY, follow_liquidity=False)
    service, _ = _service(hold, policy=policy, liquidity=lambda: FUNDING_NEED - 1)
    assert service._liquidity_cap is None  # noqa: SLF001 - announced bands stay configured
    assert asyncio.run(_open(service, _document(REVERSE_FIRM), _terms())) is None
    hold.add.assert_not_called()
