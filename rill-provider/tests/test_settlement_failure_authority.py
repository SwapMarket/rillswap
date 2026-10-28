"""A different configured payer's failed record cannot close retained work."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import ContractTerms
from test_live_session_store import Harness
from test_payment_reconciliation import PREIMAGE, Signer, _financial_rows, _paying
from test_settlement_engine import BINDING, DOCUMENT, ITEM, TERMS, _backends

from rill_provider.lnd_payment_send import PaymentOutcome
from rill_provider.settlement_engine import SettlementEngine

if TYPE_CHECKING:
    from pathlib import Path

    from rill_provider.live_session_store import LiveSessionStore


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def _binding(store: LiveSessionStore, harness: Harness, contract: str | None = None) -> None:
    contract = contract or harness.source["contract_hash"]
    envelope = copy.deepcopy(harness.envelopes[2])
    envelope.update(
        message_type="funding_binding",
        contract_hash=contract,
        payload={
            "binding": BINDING.model_dump(mode="json") | {"contract_hash": contract},
            "funding_binding_signature": "00" * 64,
            "funding_transaction": "00" * 100,
        },
    )
    # Database-boundary fixture only; these tests never re-admit funding or build claims.
    store._connection.execute(  # noqa: SLF001
        "UPDATE swaps SET funding_binding=?", (canonicalize(envelope),)
    )


@pytest.mark.parametrize("dispatch", [None, "UNSENT", "SUBMITTED"])
@pytest.mark.parametrize("blocked", [False, True])
def test_tick_preserves_tracked_failure_then_recovers_witness_after_restart(
    harness: Harness, dispatch: str | None, monkeypatch: pytest.MonkeyPatch, *, blocked: bool
) -> None:
    lightning = Mock(spec=["track", "prepare", "send"])
    lightning.track.return_value = PaymentOutcome("FAILED")
    chain = Mock()
    with harness.acquire() as store:
        session = _paying(store, harness, dispatch)
        _binding(store, harness)
        store._connection.execute("UPDATE sessions SET blocked=?", (int(blocked),))  # noqa: SLF001
        before = _financial_rows(store)
        engine = SettlementEngine(store, chain, lightning, Signer(harness))
        assert asyncio.run(engine.tick(now=1002)) == {}
        assert _financial_rows(store) == before
        assert not chain.mock_calls
        lightning.prepare.assert_not_called()
        lightning.send.assert_not_called()
    with harness.acquire() as store:
        assert _financial_rows(store) == before
        lightning.track.return_value = PaymentOutcome("SUCCEEDED", PREIMAGE, fee_msat=640)
        engine = SettlementEngine(store, chain, lightning, Signer(harness))
        # Deliberately stop at the persisted PAID boundary; claim tests own construction.
        monkeypatch.setattr(engine, "_claim", Mock(side_effect=ValueError("claim paused")))
        asyncio.run(engine.tick(now=1003))
        assert store.settlement_work(session_id=session)[0].state == "PAID"
        assert store.settlement_work(session_id=session)[0].preimage == PREIMAGE
        assert [(e.kind, e.amount) for e in store.ledger_session(session)] == [
            ("routing_fee", 640)  # the tracked payment's fee, recorded with PAID
        ]
        assert len(store.pending_outbox()) == 1
        assert store._connection.execute("SELECT * FROM payment_dispatch").fetchall() == before[2]  # noqa: SLF001
        lightning.prepare.assert_not_called()
        lightning.send.assert_not_called()


def test_newly_submitted_failed_attempt_retains_the_existing_outcome_contract() -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    lightning.send.return_value = PaymentOutcome("FAILED")
    assert asyncio.run(
        engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"])  # noqa: SLF001
    ) == PaymentOutcome("FAILED")
    chain.observe_candidate_outpoint.assert_called_once()
    lightning.send.assert_called_once_with(lightning.prepare.return_value)


def test_tick_can_terminalize_the_failure_of_its_own_newly_authorized_attempt(
    harness: Harness,
) -> None:
    _, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    lightning.send.return_value = PaymentOutcome("FAILED")
    with harness.acquire() as store:
        session = _paying(store, harness, "UNSENT")
        _binding(store, harness)
        item = store.settlement_work(session_id=session)[0]
        offer = json.loads(item.terms_offer)
        invoice_binding = offer["payload"]["terms"]["contract_terms"]["invoice_binding"]
        invoice_binding["bolt11_sha256"] = hashlib.sha256(item.invoice.encode()).hexdigest()
        updated_hash = contract_hash(
            ContractTerms.model_validate_json(
                canonicalize(offer["payload"]["terms"]["contract_terms"])
            )
        ).hex()
        offer["contract_hash"] = offer["payload"]["terms"]["contract_hash"] = updated_hash
        _binding(store, harness, updated_hash)
        store._connection.execute(  # noqa: SLF001 - align database fixture with retained invoice
            "UPDATE swaps SET terms_offer=?, contract_hash=?", (canonicalize(offer), updated_hash)
        )
        engine = SettlementEngine(store, chain, lightning, Signer(harness))
        assert asyncio.run(engine.tick(now=1002)) == {session: "FAILED"}
        assert store._connection.execute("SELECT state FROM payment_dispatch").fetchone() == (  # noqa: SLF001
            "SUBMITTED",
        )
        assert len(store.pending_outbox()) == 1
        lightning.track.assert_called_once()
        lightning.send.assert_called_once_with(lightning.prepare.return_value)
