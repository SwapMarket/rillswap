"""Store schema v18: durable per-swap accounting written with each swap event."""

from __future__ import annotations

import copy
import json
import os
import sqlite3
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from evm_fixtures import PREIMAGE as EVM_PREIMAGE
from evm_fixtures import evm_terms
from rill_core.wire.messages import ContractTerms, Envelope
from test_economic_reservations import CONFLICT
from test_evm_swap_store import LOCKUP, TX, _accept_evm_swap, _advancer
from test_live_session_store import Harness
from test_payment_dispatch_store import _insert_funded_swap
from test_reverse_swap_store import FUNDING, PREIMAGE, REFUND, _advance, insert_reverse_swap

from rill_provider import live_session_store as live
from rill_provider.swap_accounting import SwapEconomics, ledger_amount, swap_economics

FIXTURES = Path(__file__).parent / "fixtures"
FORWARD = FIXTURES / "initial-btc-to-ln-v1.json"
REVERSE = FIXTURES / "initial-ln-to-btc-no-prepayment-v1.json"


def _contract(fixture: Path) -> ContractTerms:
    return ContractTerms.model_validate_json(
        json.dumps(json.loads(fixture.read_text())["contract_terms"])
    )


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    ready = Harness(tmp_path, monkeypatch)
    ready.provision()
    return ready


def _snapshot(path: Path) -> tuple[str, ...]:
    with sqlite3.connect(path) as connection:
        (version,) = connection.execute("PRAGMA user_version").fetchone()
        return (f"PRAGMA user_version={version}", *connection.iterdump())


def test_previous_release_refuses_a_newer_store_without_writing(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rollback to an older binary refuses the store and leaves it untouched."""
    before = _snapshot(harness.path)
    with monkeypatch.context() as patch:
        patch.setattr(live, "SCHEMA_VERSION", live.SCHEMA_VERSION - 1)
        with pytest.raises(live.LiveSessionStoreError, match="version unsupported"):
            harness.acquire()
    assert _snapshot(harness.path) == before


def _rows(
    store: live.LiveSessionStore, session: str
) -> list[tuple[int, str, int | None, str | None]]:
    return [
        (entry.recorded_at, entry.kind, entry.amount, entry.unit)
        for entry in store.ledger_session(session)
    ]


def _state(store: live.LiveSessionStore, session: str) -> str:
    return str(
        store._connection.execute(  # noqa: SLF001 - committed state evidence
            "SELECT state FROM swaps WHERE session_id=?", (session,)
        ).fetchone()[0]
    )


def _forward(
    store: live.LiveSessionStore,
    session: str,
    from_state: str,
    to_state: str,
    now: int,
    **kw: object,
) -> None:
    store.advance_swap(
        session,
        from_state=from_state,
        to_state=to_state,
        signer=None,  # type: ignore[arg-type]
        now=now,
        **kw,  # type: ignore[arg-type]
    )


def _claimed_swap(store: live.LiveSessionStore, harness: Harness) -> str:
    """PAYING with a routing fee at 1001, claimed at 1500 by a 300 sat claim."""
    session = _insert_funded_swap(store, harness, "PAYING")
    _forward(store, session, "PAYING", "PAID", 1001, routing_fee_msat=1234)
    _forward(
        store,
        session,
        "PAID",
        "CLAIMING",
        1002,
        claim_tx=b"c0",
        claim_txid="a0" * 32,
        claim_fee_sat=300,
        claim_height=990,
    )
    _forward(store, session, "CLAIMING", "CLAIMED", 1500, claim_tx=b"c0", claim_txid="a0" * 32)
    return session


def test_forward_swap_records_routing_fee_revenue_and_confirmed_claim_fee(
    harness: Harness,
) -> None:
    with harness.acquire() as store:
        session = _claimed_swap(store, harness)
        assert _rows(store, session) == [
            (1001, "routing_fee", 1234, "msat"),
            (1500, "completed", 1000, "sat"),  # the signed success fee
            (1500, "claim_fee", 300, "sat"),
        ]


def test_claim_fee_comes_from_the_attempt_that_confirmed(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "PAID")
        _forward(
            store,
            session,
            "PAID",
            "CLAIMING",
            1002,
            claim_tx=b"c0",
            claim_txid="a0" * 32,
            claim_fee_sat=None,  # a legacy attempt whose fee was never observed
            claim_height=990,
        )
        store.record_claim_attempt(
            session, attempt=1, txid="a1" * 32, raw=b"c1", fee_sat=600, height=991
        )
        _forward(store, session, "CLAIMING", "CLAIMED", 1500, claim_tx=b"c0", claim_txid="a0" * 32)
        assert _rows(store, session) == [
            (1500, "completed", 1000, "sat"),
            (1500, "claim_fee", None, None),  # unmeasured, never the other attempt's 600
        ]


def test_failure_records_no_cost_and_non_terminal_moves_record_nothing(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "FUNDING_SEEN")
        _forward(store, session, "FUNDING_SEEN", "PAYING", 1001)
        assert _rows(store, session) == []
        _forward(store, session, "PAYING", "FAILED", 1002)
        assert _rows(store, session) == [(1002, "failed", None, None)]


def test_lost_swap_records_the_paid_principal(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "CLAIMING")
        _forward(store, session, "CLAIMING", "LOST", 1500, loss_evidence=CONFLICT)
        assert _rows(store, session) == [(1500, "lost", 100000, "sat")]


@pytest.mark.parametrize("fee", [-1, True, 2**70, 1.5, "12"])
def test_unmeasurable_cost_is_recorded_unknown_and_the_transition_commits(
    harness: Harness, fee: object
) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "PAYING")
        _forward(store, session, "PAYING", "PAID", 1001, routing_fee_msat=fee)
        assert _rows(store, session) == [(1001, "routing_fee", None, None)]
        assert _state(store, session) == "PAID"


def test_a_refused_ledger_row_rolls_back_its_transition(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row shares the transition's transaction: one never commits without the other."""
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "PAYING")
        with monkeypatch.context() as patch:
            patch.setattr(live, "ledger_amount", lambda _value: -1)  # violates the CHECK
            with pytest.raises(live.LiveSessionStoreError, match="swap transition refused"):
                _forward(store, session, "PAYING", "PAID", 1001, routing_fee_msat=5)
        assert _state(store, session) == "PAYING"
        assert _rows(store, session) == []
        _forward(store, session, "PAYING", "PAID", 1001, routing_fee_msat=5)  # the retry
        assert _rows(store, session) == [(1001, "routing_fee", 5, "msat")]


def test_window_includes_earlier_costs_of_swaps_closed_in_it(harness: Harness) -> None:
    with harness.acquire() as store:
        closed = _claimed_swap(store, harness)
        kinds = [(entry.session_id, entry.kind) for entry in store.ledger_window(1400, 1600)]
        assert kinds == [(closed, "routing_fee"), (closed, "completed"), (closed, "claim_fee")]
        assert store.ledger_window(1000, 1100)[0].kind == "routing_fee"  # recorded in it
        assert store.ledger_window(1600, 2000) == ()


def test_cursor_reads_are_bounded_and_ordered(harness: Harness) -> None:
    with harness.acquire() as store:
        assert store.ledger_head() == 0
        session = _claimed_swap(store, harness)
        head = store.ledger_head()
        assert [entry.entry_id for entry in store.ledger_after(0)] == [head - 2, head - 1, head]
        assert [entry.kind for entry in store.ledger_after(0, limit=1)] == ["routing_fee"]
        assert store.ledger_after(head) == ()
        assert store.ledger_session(session) == store.ledger_after(0)
        for bad in ({"entry_id": "0"}, {"entry_id": 0, "limit": 0}, {"entry_id": 0, "limit": 5000}):
            with pytest.raises(live.LiveSessionStoreError, match="bounds unsupported"):
                store.ledger_after(**bad)  # type: ignore[arg-type]


def test_reverse_refund_records_funding_and_refund_fees(harness: Harness) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        advance = partial(_advance, store, harness, session)
        advance(from_state="LN_HELD", to_state="FUNDING_SENT", funding=FUNDING, funding_fee_sat=210)
        advance(from_state="FUNDING_SENT", to_state="FUNDED")
        advance(from_state="FUNDED", to_state="REFUNDING", refund=REFUND, refund_fee_sat=180)
        advance(from_state="REFUNDING", to_state="REFUNDED", refund_confirmations=6)
        assert _rows(store, session) == [
            (2000, "funding_fee", 210, "sat"),
            (2000, "refund_fee", 180, "sat"),
            (2000, "refunded", None, None),
        ]


def test_reverse_settlement_records_the_kept_hold_amount(harness: Harness) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "FUNDED", reservation="DISPATCHED")
        _advance(
            store, harness, session, from_state="FUNDED", to_state="SETTLED", preimage=PREIMAGE
        )
        # hold invoice 102000 minus contract output 100500 (fee plus claim reserve)
        assert _rows(store, session) == [(2000, "completed", 1500, "sat")]


def test_evm_forward_records_routing_fee_gas_and_quoted_rate_revenue(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, evm_terms("erc20-to-ln/v1"))
        advance = _advancer(store, session)
        advance("ACCEPTED", "FUNDING_SEEN", lockup=LOCKUP)
        advance("FUNDING_SEEN", "PAYING")
        advance("PAYING", "PAID", preimage=EVM_PREIMAGE, routing_fee_msat=2000)
        advance("PAID", "CLAIMING", sent=(TX, b"raw"))
        advance("CLAIMING", "CLAIMED", gas_wei=21000 * 10**9)
        assert _rows(store, session) == [
            (2000, "routing_fee", 2000, "msat"),
            (2000, "gas", 21000 * 10**9, "wei"),
            (2000, "completed", 5, "sat"),  # 5000 token base at 1e11 per BTC
        ]


def test_acceptance_records_the_swapped_volume(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "ACCEPTED")
        connection = store._connection  # noqa: SLF001 - admission's own effect
        (offer,) = connection.execute("SELECT terms_offer FROM swaps").fetchone()
        connection.execute("DELETE FROM swaps")
        request = copy.deepcopy(harness.envelopes[2])
        request.update(message_type="terms_accept", contract_hash=harness.source["contract_hash"])
        envelope = Envelope.model_validate_json(json.dumps(request))
        effect = live.AcceptSwap(harness.source["contract_hash"])
        live._apply_effect(connection, envelope, effect, (offer,), 1000)  # noqa: SLF001
        assert _rows(store, session) == [(1000, "accepted", 100000, "sat")]


@pytest.mark.parametrize(
    ("terms", "expected"),
    [
        (lambda: _contract(FORWARD), SwapEconomics(100000, 1000, 100000)),
        (lambda: _contract(REVERSE), SwapEconomics(100000, 1500, None)),
        (lambda: evm_terms("erc20-to-ln/v1"), SwapEconomics(1000, 5, 1000)),
        (lambda: evm_terms("ln-to-erc20/v1"), SwapEconomics(1000, 100, None)),
    ],
)
def test_economics_of_every_profile(terms: Any, expected: SwapEconomics) -> None:  # noqa: ANN401
    assert swap_economics(terms()) == expected


@pytest.mark.parametrize(
    ("value", "stored"),
    [(0, 0), (7, 7), (2**63 - 1, 2**63 - 1), (2**63, None), (-1, None), (True, None), (None, None)],
)
def test_ledger_amount_keeps_only_storable_integers(value: object, stored: int | None) -> None:
    assert ledger_amount(value) == stored


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize("firm", [True, False])
def test_only_a_firm_terms_offer_records_an_offer(harness: Harness, firm: bool) -> None:  # noqa: FBT001
    from rill_crypto import Context  # noqa: PLC0415
    from test_live_session_store import _signed_request  # noqa: PLC0415

    source = harness.source

    def responder(_request: Any, _prior: Any, _context: live.RequestContext) -> live.Answer:  # noqa: ANN401
        if not firm:  # a refusal that still reserved a hash is not an offer
            payload = {"code": "capacity_unavailable", "message": "fixture"}
            return live.Answer("error", payload, payment_hash="a1" * 32)
        payload = {
            "terms": {
                "contract_hash": source["contract_hash"],
                "contract_terms": source["contract_terms"],
                "handshake_hash": source["verification_context"]["handshake_hash"],
            },
            "provider_terms_signature": source["verification_context"]["provider_terms_signature"],
        }
        return live.Answer(
            "terms_offer",
            payload,
            payment_hash=source["contract_terms"]["invoice_binding"]["payment_hash"],
            contract_hash=source["contract_hash"],
        )

    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
        session = store.reserve(harness.init, now=1000).session_id
        store.commit_accept(harness.accept)
        store.admit_confirm(harness.confirm)
        request = _signed_request(harness, crypto, 2, "21" * 32)
        store.answer_request(request, responder=responder, signer=crypto, now=1000)
        expected = [(1000, "offered", 100000, "sat")] if firm else []
        assert _rows(store, session) == expected
