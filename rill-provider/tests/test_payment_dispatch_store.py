"""One-shot payment permission and explicit upgrade of authoritative v5 state."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from test_live_session_store import Harness

from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def _insert_funded_swap(store: live.LiveSessionStore, harness: Harness, state: str) -> str:
    # Historical (pre-mandatory) admission: the fixture rewrites the transcript.
    policy = store._policy  # noqa: SLF001
    store._policy = replace(policy, features=policy.features - {COOPERATIVE_CLAIM_FEATURE})  # noqa: SLF001
    try:
        reservation = store.reserve(harness.init, now=1000)
    finally:
        store._policy = policy  # noqa: SLF001
    source = harness.source
    offer = copy.deepcopy(harness.envelopes[1])
    offer.update(
        message_type="terms_offer",
        contract_hash=source["contract_hash"],
        payload={
            "terms": {
                "contract_hash": source["contract_hash"],
                "contract_terms": source["contract_terms"],
                "handshake_hash": source["verification_context"]["handshake_hash"],
            },
            "provider_terms_signature": source["verification_context"]["provider_terms_signature"],
        },
    )
    # Database fixture for the durable transition boundary, not wire admission.
    store._connection.execute(  # noqa: SLF001
        "INSERT INTO swaps VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, NULL, NULL, "
        "NULL, NULL, NULL, NULL, NULL)",
        (
            reservation.session_id,
            source["contract_hash"],
            canonicalize(offer),
            b"accepted",
            state,
            b"bound",
            1000,
        ),
    )
    store._connection.execute(  # noqa: SLF001
        "UPDATE sessions SET phase='ACCEPTED' WHERE session_id=?", (reservation.session_id,)
    )
    # Admission always reserves the offered hash with its economic reservation.
    store._connection.execute(  # noqa: SLF001
        "INSERT INTO payment_hashes VALUES (?, ?, 1000)", (_hash(harness), reservation.session_id)
    )
    store._connection.execute(  # noqa: SLF001
        "INSERT INTO economic_reservations VALUES (?, ?, 'UNSENT', NULL)",
        (_hash(harness), reservation.session_id),
    )
    return reservation.session_id


def _hash(harness: Harness) -> str:
    return str(harness.source["contract_terms"]["invoice_binding"]["payment_hash"])


def test_only_new_paying_transition_creates_a_one_shot_grant(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "FUNDING_SEEN")
        assert not store.commit_payment_dispatch(session, _hash(harness), b"request")
        store.advance_swap(
            session, from_state="FUNDING_SEEN", to_state="PAYING", signer=Mock(), now=1001
        )
        assert not store.commit_payment_dispatch(session, "00" * 32, b"request")
        assert store.commit_payment_dispatch(session, _hash(harness), b"first")
        assert not store.commit_payment_dispatch(session, _hash(harness), b"second")
    with harness.acquire() as store:
        assert not store.commit_payment_dispatch(session, _hash(harness), b"after restart")
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state, request FROM payment_dispatch"
        ).fetchall() == [("SUBMITTED", b"first")]


def test_conflict_and_dispatch_share_the_store_transaction_boundary(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "FUNDING_SEEN")
        store.advance_swap(
            session, from_state="FUNDING_SEEN", to_state="PAYING", signer=Mock(), now=1001
        )
        conflict = copy.deepcopy(harness.envelopes[0])
        conflict["message_id"] = "99" * 32
        with pytest.raises(live.SessionBlockedError):
            store.reserve(canonicalize(conflict), now=1002)
        assert not store.commit_payment_dispatch(session, _hash(harness), b"request")
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state, request FROM payment_dispatch"
        ).fetchall() == [("UNSENT", None)]


def test_interruption_after_dispatch_commit_does_not_restore_permission(harness: Harness) -> None:
    # Simulate process loss at the boundary before any external payment RPC.
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "FUNDING_SEEN")
        store.advance_swap(
            session, from_state="FUNDING_SEEN", to_state="PAYING", signer=Mock(), now=1001
        )
        assert store.commit_payment_dispatch(session, _hash(harness), b"never delivered")
    with harness.acquire() as store:
        assert not store.commit_payment_dispatch(session, _hash(harness), b"retry")
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state FROM swaps WHERE session_id=?", (session,)
        ).fetchone() == ("PAYING",)
