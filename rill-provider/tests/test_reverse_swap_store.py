"""LN to BTC swap lifecycle in the store (RS-004): grants, evidence, releases."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from rill_core.wire.canonical import canonicalize
from test_economic_reservations import _ledger
from test_live_session_store import Harness
from test_payment_reconciliation import Signer

from rill_provider import live_session_store as live


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


REVERSE = json.loads(
    (Path(__file__).parent / "fixtures/initial-ln-to-btc-no-prepayment-v1.json").read_text()
)
HASH = REVERSE["contract_terms"]["invoice_binding"]["payment_hash"]
PREIMAGE = REVERSE["monotonic_knowledge"]["preimage"]
assert hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest() == HASH
FUNDING = ("aa" * 32, 1, b"funding-raw")
REFUND = ("bb" * 32, b"refund-raw")


def _preimage() -> str:
    return str(PREIMAGE)


def insert_reverse_swap(
    store: live.LiveSessionStore, harness: Harness, state: str, *, reservation: str = "UNSENT"
) -> str:
    """Insert an accepted LN to BTC swap with its hash and reservation rows."""
    session = store.reserve(harness.init, now=1000).session_id
    offer = copy.deepcopy(harness.envelopes[1])
    offer.update(
        message_type="terms_offer",
        contract_hash=REVERSE["contract_hash"],
        payload={
            "terms": {
                "contract_hash": REVERSE["contract_hash"],
                "contract_terms": REVERSE["contract_terms"],
                "handshake_hash": REVERSE["verification_context"]["handshake_hash"],
            },
            "provider_terms_signature": REVERSE["verification_context"]["provider_terms_signature"],
            "hold_invoice": "lnbcrt1020u1hold",
        },
    )
    connection = store._connection  # noqa: SLF001
    connection.execute(
        "INSERT INTO swaps VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, 1000, NULL, NULL, "
        "NULL, NULL, NULL, NULL, NULL, NULL)",
        (session, REVERSE["contract_hash"], canonicalize(offer), b"accepted", state),
    )
    connection.execute("UPDATE sessions SET phase='ACCEPTED' WHERE session_id=?", (session,))
    connection.execute("INSERT INTO payment_hashes VALUES (?, ?, 1000)", (HASH, session))
    request = copy.deepcopy(harness.envelopes[2])
    request.update(
        message_type="quote_request",
        sequence=2,
        payload={"kind": "ln-to-btc", "mode": "firm", "payment_hash": HASH, "extensions": {}},
    )
    connection.execute(
        "INSERT INTO inbox VALUES (?, ?, ?, 2, ?, ?, 0)",
        (
            session,
            request["sender_session_key"],
            request["message_id"],
            "00" * 32,
            canonicalize(request),
        ),
    )
    connection.execute(
        "INSERT INTO economic_reservations VALUES (?, ?, ?, NULL)", (HASH, session, reservation)
    )
    return session


def _row(store: live.LiveSessionStore, session: str) -> dict[str, Any]:
    cursor = store._connection.execute("SELECT * FROM swaps WHERE session_id=?", (session,))  # noqa: SLF001
    names = [column[0] for column in cursor.description]
    return dict(zip(names, cursor.fetchone(), strict=True))


def _advance(store: live.LiveSessionStore, harness: Harness, session: str, **kw: Any) -> None:  # noqa: ANN401
    store.advance_reverse_swap(session, signer=Signer(harness), now=2000, **kw)


def test_funding_is_a_one_shot_grant_marking_the_reservation(harness: Harness) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        _advance(
            store, harness, session, from_state="LN_HELD", to_state="FUNDING_SENT", funding=FUNDING
        )
        row = _row(store, session)
        assert (row["state"], row["funding_txid"], row["funding_vout"], row["funding_tx"]) == (
            "FUNDING_SENT",
            *FUNDING,
        )
        assert _ledger(store)[HASH][1] == "DISPATCHED"
        with pytest.raises(live.StaleSwapError):
            _advance(
                store,
                harness,
                session,
                from_state="LN_HELD",
                to_state="FUNDING_SENT",
                funding=FUNDING,
            )


def test_settlement_needs_the_preimage_of_the_payment_hash(harness: Harness) -> None:
    preimage = _preimage()
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "FUNDED", reservation="DISPATCHED")
        with pytest.raises(live.LiveSessionStoreError, match="preimage does not match"):
            _advance(
                store, harness, session, from_state="FUNDED", to_state="SETTLED", preimage="ab" * 32
            )
        with pytest.raises(live.LiveSessionStoreError, match="needs the preimage"):
            _advance(store, harness, session, from_state="FUNDED", to_state="SETTLED")
        _advance(
            store,
            harness,
            session,
            from_state="FUNDED",
            to_state="SETTLED",
            preimage=preimage,
            observation={"kind": "hold_settled", "preimage": preimage},
        )
        assert _row(store, session)["preimage"] == preimage
        _session, state, evidence = _ledger(store)[HASH]
        assert state == "RELEASED"
        assert evidence == b'{"reason":"hold-settled","settled_at":2000,"version":1}'
        assert store.pending_outbox()[-1].canonical_bytes.count(b'"hold_settled"') == 1


def test_refund_records_the_transaction_and_releases_only_at_depth(harness: Harness) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "FUNDED", reservation="DISPATCHED")
        with pytest.raises(live.LiveSessionStoreError, match="exact refund"):
            _advance(store, harness, session, from_state="FUNDED", to_state="REFUNDING")
        _advance(store, harness, session, from_state="FUNDED", to_state="REFUNDING", refund=REFUND)
        row = _row(store, session)
        assert (row["refund_txid"], row["refund_tx"]) == REFUND
        assert _ledger(store)[HASH][1] == "DISPATCHED"
        with pytest.raises(live.LiveSessionStoreError, match="observed confirmations"):
            _advance(store, harness, session, from_state="REFUNDING", to_state="REFUNDED")
        _advance(
            store,
            harness,
            session,
            from_state="REFUNDING",
            to_state="REFUNDED",
            refund_confirmations=6,
        )
        _session, state, evidence = _ledger(store)[HASH]
        assert state == "RELEASED"
        assert evidence == (
            b'{"observed_confirmations":6,"reason":"refund-confirmed","refund_txid":"'
            + REFUND[0].encode()
            + b'","required_confirmations":4,"version":1}'
        )


@pytest.mark.parametrize(
    ("from_state", "reservation", "released"),
    [("ACCEPTED", "UNSENT", True), ("LN_HELD", "UNKNOWN", True), ("LN_HELD", "DISPATCHED", False)],
)
def test_abort_releases_only_an_undispatched_reservation(
    harness: Harness,
    from_state: str,
    reservation: str,
    released: bool,  # noqa: FBT001
) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, from_state, reservation=reservation)
        _advance(store, harness, session, from_state=from_state, to_state="ABORTED")
        assert _row(store, session)["state"] == "ABORTED"
        assert _ledger(store)[HASH][1] == ("RELEASED" if released else reservation)


def test_unsupported_transitions_are_refused(harness: Harness) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "FUNDED")
        with pytest.raises(live.LiveSessionStoreError, match="unsupported"):
            _advance(store, harness, session, from_state="FUNDED", to_state="CLAIMED")
        with pytest.raises(live.StaleSwapError):
            _advance(store, harness, session, from_state="LN_HELD", to_state="ABORTED")


def test_a_btc_to_ln_swap_never_takes_a_reverse_transition(harness: Harness) -> None:
    from test_payment_dispatch_store import _insert_funded_swap  # noqa: PLC0415

    with harness.acquire() as store:
        forward = _insert_funded_swap(store, harness, "ACCEPTED")
        with pytest.raises(live.LiveSessionStoreError, match="not an LN to BTC swap"):
            _advance(store, harness, forward, from_state="ACCEPTED", to_state="ABORTED")


def test_settlement_work_lists_reverse_states_with_provider_transactions(harness: Harness) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD")
        _advance(
            store, harness, session, from_state="LN_HELD", to_state="FUNDING_SENT", funding=FUNDING
        )
        store.record_spend_scan(session, 1234)
        store.record_spend_scan(session, 1200)  # never moves backwards
        (item,) = store.settlement_work()
        assert (item.state, item.invoice) == ("FUNDING_SENT", "")
        assert (item.funding_txid, item.funding_vout, item.funding_tx) == FUNDING
        assert (item.refund_txid, item.refund_tx, item.spend_scan_height) == (None, None, 1234)
        assert store.unfunded_swaps() == []  # LN_HELD is not an unfunded BTC to LN swap
        _advance(store, harness, session, from_state="FUNDING_SENT", to_state="FUNDED")
        assert store.settlement_work()[0].state == "FUNDED"


def test_funding_is_refused_without_an_open_reservation(harness: Harness) -> None:
    with harness.acquire() as store:
        session = insert_reverse_swap(store, harness, "LN_HELD", reservation="DISPATCHED")
        with pytest.raises(live.LiveSessionStoreError, match="funding grant refused"):
            _advance(
                store,
                harness,
                session,
                from_state="LN_HELD",
                to_state="FUNDING_SENT",
                funding=FUNDING,
            )
        assert _row(store, session)["state"] == "LN_HELD"  # the whole transition rolled back
