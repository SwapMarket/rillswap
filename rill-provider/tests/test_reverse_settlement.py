"""LN to BTC provider lifecycle (RS-004): hold checks, funding grant, settle, refund."""

from __future__ import annotations

import asyncio
import json
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from rill_core.wire.messages import ContractTerms

from rill_provider import reverse_settlement as reverse
from rill_provider.core_tx_bytes import FundedOutput, SpendObservation, SpendScan
from rill_provider.live_session_store import SettlementItem
from rill_provider.lnd_hold_invoice import HeldHtlc, HoldInvoiceStatus
from rill_provider.lnd_payment_observation import LndProtocolError
from rill_provider.reverse_operations import ReverseOperations

DOCUMENT = json.loads(
    (Path(__file__).parent / "fixtures/initial-ln-to-btc-no-prepayment-v1.json").read_text()
)
TERMS = ContractTerms.model_validate_json(json.dumps(DOCUMENT["contract_terms"]))
HASH = TERMS.invoice_binding.payment_hash
PREIMAGE = DOCUMENT["monotonic_knowledge"]["preimage"]
SCRIPT = bytes.fromhex(DOCUMENT["taproot_contract"]["script_pubkey"])
# refund_lock_height 1100, funding 2, response 6, claim 6 -> fund while tip + 14 < 1100
# H = 102000 sat; first refund block 1101 + 20 resolution < E_in -> E_in >= 1122
HELD = HoldInvoiceStatus("ACCEPTED", (HeldHtlc(60_000_000, 1180), HeldHtlc(42_000_000, 1130)))
FUNDED = FundedOutput("51" * 32, 0, b"funding-raw", 250, "a1" * 32, 7)
NOW = DOCUMENT["created_at"] + 60


def _item(state: str, **changes: Any) -> SettlementItem:  # noqa: ANN401
    base = SettlementItem(
        session_id="11" * 32,
        state=state,
        blocked=False,
        terms_offer=b"offer",
        funding_binding=None,
        invoice="",
        preimage=None,
        claim_tx=None,
        claim_txid=None,
    )
    return replace(base, **changes)


@pytest.fixture
def backends(monkeypatch: pytest.MonkeyPatch) -> tuple[reverse.ReverseSettlement, Mock, Mock, Mock]:
    monkeypatch.setattr(reverse, "Envelope", Mock())
    monkeypatch.setattr(reverse, "offered_terms", lambda _envelope: TERMS)
    monkeypatch.setattr(
        reverse, "reconstruct_taproot_contract", lambda *_a, **_k: Mock(script_pubkey=SCRIPT)
    )
    store, chain, hold = Mock(), Mock(), Mock()
    # These lifecycle cases exercise explicitly unfeatured historical terms.
    store._reverse_repayment_binding.return_value = None  # noqa: SLF001 - archive boundary mock
    store.owner_is_open = True
    store.retain_owner.side_effect = nullcontext
    store.reverse_operations = ReverseOperations(store)
    chain.tip_height.return_value = 1000
    chain.fund_output.return_value = FUNDED
    chain.find_spender.return_value = SpendScan(None, 1000)
    hold.lookup.return_value = HELD
    engine = reverse.ReverseSettlement(store, chain, hold, Mock())
    return engine, store, chain, hold


def _run(engine: reverse.ReverseSettlement, item: SettlementItem) -> str:
    # This fixture supplies the authoritative row under the real execution
    # gate, rather than treating a queued caller snapshot as current state.
    engine._store.settlement_work.return_value = (item,)  # type: ignore[attr-defined]  # noqa: SLF001
    return asyncio.run(engine.advance(item, NOW))


def _moved(store: Mock, to_state: str) -> dict[str, Any]:
    call = store.advance_reverse_swap.call_args
    assert call.kwargs["to_state"] == to_state
    return dict(call.kwargs)


def test_accepted_waits_for_an_open_hold_until_it_expires(backends: Any) -> None:  # noqa: ANN401
    engine, store, _chain, hold = backends
    hold.lookup.return_value = HoldInvoiceStatus("OPEN", ())
    assert _run(engine, _item("ACCEPTED")) == "ACCEPTED"
    store.advance_reverse_swap.assert_not_called()
    hold.cancel.assert_not_called()
    assert (
        asyncio.run(engine.advance(_item("ACCEPTED"), TERMS.invoice_binding.expires_at))
        == "ABORTED"
    )
    hold.cancel.assert_called_once_with(HASH)
    assert _moved(store, "ABORTED")["observation"]["reason"] == "hold invoice expired unpaid"


def test_reverse_entry_refuses_misdirected_terms_before_any_hold_or_chain_effect(
    backends: Any,  # noqa: ANN401
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, store, chain, hold = backends
    monkeypatch.setattr(reverse, "offered_terms", lambda _envelope: Mock(profile_id="btc-to-ln/v1"))
    with pytest.raises(reverse.LiveSessionStoreError, match="requires LN to BTC terms"):
        _run(engine, _item("ACCEPTED"))
    hold.lookup.assert_not_called()
    hold.cancel.assert_not_called()
    chain.tip_height.assert_not_called()
    store.advance_reverse_swap.assert_not_called()


@pytest.mark.parametrize(
    ("status", "tip", "reason"),
    [
        (HoldInvoiceStatus("CANCELED", ()), 1000, "hold canceled"),
        (replace(HELD, htlcs=(HeldHtlc(101_999_000, 1180),)), 1000, "held amount differs from H"),
        (  # 1101 + 20 >= 1121: the earliest part leaves no LN resolution margin
            replace(HELD, htlcs=(HeldHtlc(60_000_000, 1180), HeldHtlc(42_000_000, 1121))),
            1000,
            "incoming HTLC expires too soon",
        ),
        (HELD, 1086, "funding window closed"),  # 1086 + 14 == 1100
    ],
)
def test_accepted_aborts_unless_every_part_and_the_window_check_out(
    backends: Any,  # noqa: ANN401
    status: HoldInvoiceStatus,
    tip: int,
    reason: str,
) -> None:
    engine, store, chain, hold = backends
    hold.lookup.return_value = status
    chain.tip_height.return_value = tip
    assert _run(engine, _item("ACCEPTED")) == "ABORTED"
    assert _moved(store, "ABORTED")["observation"] == {"kind": "swap_aborted", "reason": reason}
    assert hold.cancel.call_count == (0 if status.state == "CANCELED" else 1)
    chain.fund_output.assert_not_called()


def test_accepted_becomes_held_at_exactly_h_with_margin(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, _hold = backends
    chain.tip_height.return_value = 1085  # 1085 + 14 < 1100
    assert _run(engine, _item("ACCEPTED")) == "LN_HELD"
    assert _moved(store, "LN_HELD")["observation"] == {"kind": "hold_accepted"}
    chain.fund_output.assert_not_called()  # funding is the next step, after a fresh check


def test_held_funds_exactly_v_records_the_grant_then_broadcasts(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, _hold = backends
    order: list[str] = []
    store.advance_reverse_swap.side_effect = lambda *_a, **_k: order.append("record")
    chain.broadcast.side_effect = lambda *_a: order.append("broadcast")
    assert _run(engine, _item("LN_HELD")) == "FUNDING_SENT"
    chain.fund_output.assert_called_once_with(SCRIPT, 100_500, max_fee_sat=500)
    moved = _moved(store, "FUNDING_SENT")
    binding, raw = moved["funding"]
    assert raw == b"funding-raw"
    assert binding.model_dump(mode="json") == {
        "contract_hash": DOCUMENT["contract_hash"],
        "funding_attempt_id": binding.funding_attempt_id,
        "binding_revision": 0,
        "funder_role": "provider",
        "lineage_anchor_txid": "a1" * 32,
        "lineage_anchor_vout": 7,
        "funding_txid": "51" * 32,
        "contract_vout": 0,
        "contract_value_sat": "100500",
        "contract_script_pubkey": SCRIPT.hex(),
        "replaces_txid": None,
        "created_at": NOW,
    }
    assert "observation" not in moved
    assert order == ["record", "broadcast"]
    chain.broadcast.assert_called_once_with(b"funding-raw", "51" * 32)


def test_held_re_checks_the_hold_before_signing_anything(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, hold = backends
    hold.lookup.return_value = HoldInvoiceStatus("CANCELED", ())
    assert _run(engine, _item("LN_HELD")) == "ABORTED"
    chain.fund_output.assert_not_called()
    assert _moved(store, "ABORTED")["from_state"] == "LN_HELD"


def test_funding_sent_rebroadcasts_and_confirms_at_depth(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, _hold = backends
    item = _item("FUNDING_SENT", funding_txid="51" * 32, funding_vout=0, funding_tx=b"funding-raw")
    chain.confirmations.return_value = 1
    assert _run(engine, item) == "FUNDING_SENT"
    chain.broadcast.assert_called_once_with(b"funding-raw", "51" * 32)
    store.advance_reverse_swap.assert_not_called()
    chain.confirmations.return_value = 2
    chain.tip_height.return_value = 1011
    assert _run(engine, item) == "FUNDED"
    store.record_spend_scan.assert_called_once_with("11" * 32, 1009)  # inclusion block 1010


def _funded_item(state: str = "FUNDED", **changes: Any) -> SettlementItem:  # noqa: ANN401
    return _item(
        state,
        funding_txid="51" * 32,
        funding_vout=0,
        funding_tx=b"funding-raw",
        spend_scan_height=1009,
        **changes,
    )


def test_funded_settles_the_hold_with_the_claim_witness_preimage(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, hold = backends
    chain.tip_height.return_value = 1020
    witness = (b"\x77" * 64, bytes.fromhex(PREIMAGE), b"\x51", b"\xc0" + b"\x00" * 32)
    chain.find_spender.return_value = SpendScan(SpendObservation("61" * 32, witness, None), 1009)
    assert _run(engine, _funded_item()) == "SETTLED"
    chain.find_spender.assert_called_once_with("51" * 32, 0, from_height=1010, to_height=1020)
    hold.settle.assert_called_once_with(PREIMAGE)
    moved = _moved(store, "SETTLED")
    assert (moved["preimage"], moved["observation"]) == (PREIMAGE, {"kind": "hold_settled"})
    chain.fee_rate_sat_vb.assert_not_called()


def test_funded_tolerates_an_already_settled_hold_but_not_other_failures(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, hold = backends
    chain.tip_height.return_value = 1020
    witness = (b"\x77" * 64, bytes.fromhex(PREIMAGE), b"\x51", b"\xc0")
    chain.find_spender.return_value = SpendScan(SpendObservation("61" * 32, witness, 1015), 1015)
    hold.settle.side_effect = LndProtocolError("already settled")
    hold.lookup.return_value = HoldInvoiceStatus("SETTLED", ())
    assert _run(engine, _funded_item()) == "SETTLED"
    hold.lookup.return_value = HoldInvoiceStatus("ACCEPTED", ())
    with pytest.raises(LndProtocolError):
        _run(engine, _funded_item())
    assert store.advance_reverse_swap.call_count == 1


def test_funded_advances_the_scan_cursor_and_waits_for_the_lock(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, _hold = backends
    chain.tip_height.return_value = 1099
    chain.find_spender.return_value = SpendScan(None, 1021)
    assert _run(engine, _funded_item()) == "FUNDED"
    store.record_spend_scan.assert_called_once_with("11" * 32, 1021)
    store.advance_reverse_swap.assert_not_called()
    chain.find_spender.return_value = SpendScan(None, 1005)  # a stale, shorter scan
    store.record_spend_scan.reset_mock()
    assert _run(engine, _funded_item()) == "FUNDED"
    store.record_spend_scan.assert_not_called()


def test_funded_refunds_once_the_lock_is_reached_recording_before_broadcast(
    backends: Any,  # noqa: ANN401
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, store, chain, _hold = backends
    chain.tip_height.return_value = 1100
    spend = Mock(txid="71" * 32, raw_transaction=b"refund-raw")

    async def refund(_item: SettlementItem, _terms: ContractTerms) -> Mock:
        return spend

    monkeypatch.setattr(engine, "_refund", refund)
    order: list[str] = []
    store.advance_reverse_swap.side_effect = lambda *_a, **_k: order.append("record")
    chain.broadcast.side_effect = lambda *_a: order.append("broadcast")
    assert _run(engine, _funded_item()) == "REFUNDING"
    moved = _moved(store, "REFUNDING")
    assert moved["refund"] == ("71" * 32, b"refund-raw")
    assert moved["observation"] == {"kind": "refund_broadcast", "refund_txid": "71" * 32}
    assert order == ["record", "broadcast"]


def test_refunding_cancels_the_hold_only_at_the_signed_depth(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, hold = backends
    chain.tip_height.return_value = 1105
    item = _funded_item("REFUNDING", refund_txid="71" * 32, refund_tx=b"refund-raw")
    chain.confirmations.return_value = 3
    assert _run(engine, item) == "REFUNDING"
    chain.broadcast.assert_called_once_with(b"refund-raw", "71" * 32)
    hold.cancel.assert_not_called()
    chain.confirmations.return_value = 4
    assert _run(engine, item) == "REFUNDED"
    hold.cancel.assert_called_once_with(HASH)
    moved = _moved(store, "REFUNDED")
    assert moved["refund_confirmations"] == 4
    assert moved["observation"] == {"kind": "refund_confirmed", "refund_txid": "71" * 32}


def test_refunding_still_settles_when_the_claim_wins_the_race(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, hold = backends
    chain.tip_height.return_value = 1105
    witness = (b"\x77" * 64, bytes.fromhex(PREIMAGE), b"\x51", b"\xc0")
    chain.find_spender.return_value = SpendScan(SpendObservation("61" * 32, witness, 1101), 1101)
    item = _funded_item("REFUNDING", refund_txid="71" * 32, refund_tx=b"refund-raw")
    assert _run(engine, item) == "SETTLED"
    hold.settle.assert_called_once_with(PREIMAGE)
    hold.cancel.assert_not_called()
    assert _moved(store, "SETTLED")["from_state"] == "REFUNDING"


def test_our_own_refund_spend_is_not_mistaken_for_a_claim(backends: Any) -> None:  # noqa: ANN401
    engine, store, chain, hold = backends
    chain.tip_height.return_value = 1105
    chain.find_spender.return_value = SpendScan(
        SpendObservation("71" * 32, (b"\x77" * 64, b"\x51", b"\xc0"), 1101), 1101
    )
    chain.confirmations.return_value = 1
    item = _funded_item("REFUNDING", refund_txid="71" * 32, refund_tx=b"refund-raw")
    assert _run(engine, item) == "REFUNDING"
    hold.settle.assert_not_called()
    store.advance_reverse_swap.assert_not_called()
    # An unknown spender without the preimage: never settle, never refund on top of it.
    chain.find_spender.return_value = SpendScan(
        SpendObservation("99" * 32, (b"\x77" * 64, b"\x51", b"\xc0"), 1101), 1101
    )
    assert _run(engine, _funded_item()) == "FUNDED"
    chain.fee_rate_sat_vb.assert_not_called()
