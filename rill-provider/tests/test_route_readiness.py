"""Firm offers need current payment readiness: a route within the payment's own bounds."""

from __future__ import annotations

import asyncio
import json
from itertools import pairwise
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from test_quote_policy import BINDING, FIRM, FIRM_TERMS, _with

from rill_provider import settlement_engine
from rill_provider.handshake_service import HandshakeService
from rill_provider.lnd_invoice_decode import InvoiceRejectedError
from rill_provider.lnd_payment_observation import LndProtocolError, LndUnavailableError
from rill_provider.settlement_engine import EngineSettings, SettlementEngine

if TYPE_CHECKING:
    from rill_provider.quote_policy import QuoteTerms

DOCUMENT = json.dumps({"sequence": 1, "payload": FIRM}).encode()
PRINCIPAL = int(BINDING.amount_msat) // 1000


class _Lightning:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def prepare(self, invoice: str, **bounds: Any) -> object:  # noqa: ANN401
        self.calls.append({"invoice": invoice, **bounds})
        if self.error is not None:
            raise self.error
        return object()  # discarded: preflight never dispatches


def _ready(
    lightning: _Lightning | None,
    terms: QuoteTerms = FIRM_TERMS,
    cap: int = 1_000,
    *,
    capacity: bool = True,
) -> Any:  # noqa: ANN401
    settlement = (
        None
        if lightning is None
        else SettlementEngine(
            None,  # type: ignore[arg-type]
            None,  # type: ignore[arg-type]
            lightning,  # type: ignore[arg-type]
            None,  # type: ignore[arg-type]
            EngineSettings(max_routing_fee_sat=cap),
        )
    )
    service: Any = SimpleNamespace(
        _settlement=settlement,
        _evm_settlement=None,
        _store=SimpleNamespace(firm_capacity_available=lambda: capacity),
    )
    return asyncio.run(HandshakeService._route_ready(service, DOCUMENT, terms))  # noqa: SLF001


@pytest.mark.parametrize("cap", [1, 1_000_000])
def test_route_query_uses_the_payments_exact_bounds(cap: int) -> None:
    lightning = _Lightning()
    assert _ready(lightning, cap=cap) is FIRM_TERMS
    fee = FIRM_TERMS.base_fee_sat + -(-PRINCIPAL * FIRM_TERMS.proportional_millionths // 10**6)
    (call,) = lightning.calls
    assert 0 < call.pop("deadline_seconds") <= settlement_engine.READINESS_BUDGET_SECONDS
    assert call == {
        "invoice": FIRM["invoice"],
        "invoice_binding": BINDING,
        "fee_limit_sat": min(cap, fee),
        "max_expiry_height": 850 + FIRM_TERMS.schedule.outgoing_cltv_budget_blocks,
    }


@pytest.mark.parametrize(
    "error", [LndProtocolError("no route"), LndUnavailableError("down"), ValueError("bounds")]
)
def test_no_route_liquidity_or_sync_defers_the_offer(error: BaseException) -> None:
    assert _ready(_Lightning(error)).invoice == "unavailable"


def test_unsupported_routing_features_refuse_the_invoice() -> None:
    assert _ready(_Lightning(InvoiceRejectedError("features"))).invoice == "rejected"


@pytest.mark.parametrize(
    "terms",
    [
        _with(FIRM_TERMS, firm=None),
        _with(FIRM_TERMS, tip_height=None),
        _with(FIRM_TERMS, invoice="unavailable"),
        _with(FIRM_TERMS, amount_bands=((1, PRINCIPAL - 1),)),
    ],
)
def test_no_route_query_when_the_quote_rules_refuse_anyway(terms: Any) -> None:  # noqa: ANN401
    lightning = _Lightning()
    assert _ready(lightning, terms) is terms
    assert lightning.calls == []


def test_without_settlement_there_is_no_preflight() -> None:
    assert _ready(None) is FIRM_TERMS


def test_a_briefly_unsynced_node_is_retried_then_deferred(monkeypatch: pytest.MonkeyPatch) -> None:
    from rill_provider.lnd_payment_observation import LndNotSyncedError  # noqa: PLC0415

    clock = [0.0]
    monkeypatch.setattr(
        settlement_engine.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + s)
    )
    monkeypatch.setattr(settlement_engine.time, "monotonic", lambda: clock[0])

    class Catching(_Lightning):
        def prepare(self, invoice: str, **bounds: Any) -> object:  # noqa: ANN401
            self.calls.append({"invoice": invoice, **bounds})
            if len(self.calls) < 3:
                raise LndNotSyncedError("syncing")
            return object()

    catching = Catching()
    assert _ready(catching) is FIRM_TERMS
    assert len(catching.calls) == 3
    stuck = _Lightning(LndNotSyncedError("syncing"))
    assert _ready(stuck).invoice == "unavailable"
    budget = settlement_engine.READINESS_BUDGET_SECONDS
    assert len(stuck.calls) == int(budget / settlement_engine.READINESS_SYNC_DELAY)
    # Every query shares the one budget: the backend enforces the remainder.
    remaining = [call["deadline_seconds"] for call in stuck.calls]
    assert remaining[0] == budget
    assert all(b < a for a, b in pairwise(remaining))


def test_a_full_provider_skips_the_route_query() -> None:
    lightning = _Lightning()
    assert _ready(lightning, capacity=False) is FIRM_TERMS
    assert lightning.calls == []
