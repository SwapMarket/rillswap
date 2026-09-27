"""One-shot payment permission and explicit upgrade of authoritative v5 state."""

from __future__ import annotations

import copy
import sqlite3
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from test_live_session_store import Harness, swaps_as_v9, without_v12_cooperation

from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def _insert_funded_swap(store: live.LiveSessionStore, harness: Harness, state: str) -> str:
    reservation = store.reserve(harness.init, now=1000)
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
        "NULL, NULL, NULL, NULL, NULL, NULL)",
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


def _as_v5(path: Path) -> None:
    _as_v6(path)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE payment_dispatch")
        connection.execute("UPDATE meta SET schema_version=5")
        connection.execute("PRAGMA user_version=5")


def _as_v6(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        without_v12_cooperation(connection)
        swaps_as_v9(connection)
        connection.execute("DROP TABLE claim_attempts")
        connection.execute("DROP TABLE economic_reservations")
        connection.execute("DROP TABLE epoch_admissions")
        connection.execute("DROP TABLE epoch_retirement")
        connection.execute("DROP TABLE epoch_key_history")
        connection.execute("UPDATE meta SET schema_version=6")
        connection.execute("PRAGMA user_version=6")


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


def test_upgraded_funded_swap_gets_permission_only_on_new_paying_transition(
    harness: Harness,
) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "FUNDING_SEEN")
    _as_v5(harness.path)
    with harness.acquire_at(harness.path, upgrade_from_v5=True) as store:
        assert not store.commit_payment_dispatch(session, _hash(harness), b"premature")
        store.advance_swap(
            session, from_state="FUNDING_SEEN", to_state="PAYING", signer=Mock(), now=1001
        )
        assert store.commit_payment_dispatch(session, _hash(harness), b"new payment")


def test_partial_current_schema_is_not_repaired_by_migration(harness: Harness) -> None:
    with sqlite3.connect(harness.path) as connection:
        connection.execute("DROP TABLE payment_dispatch")
    with pytest.raises(live.LiveSessionStoreError, match="schema incompatible"):
        harness.acquire_at(harness.path, upgrade_from_v5=True)
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (live.SCHEMA_VERSION,)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='payment_dispatch'"
            ).fetchall()
            == []
        )


@pytest.mark.parametrize(
    "state", ["ACCEPTED", "FUNDING_SEEN", "PAYING", "PAID", "CLAIMING", "CLAIMED", "FAILED"]
)
def test_upgrade_is_explicit_and_never_backfills_send_permission(
    harness: Harness, state: str
) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, state)
        before = store._connection.execute("SELECT * FROM swaps").fetchall()  # noqa: SLF001
    _as_v5(harness.path)
    with pytest.raises(live.LiveSessionStoreError, match="version unsupported"):
        harness.acquire()
    with harness.acquire_at(harness.path, upgrade_from_v5=True) as store:
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == before  # noqa: SLF001
        assert store._connection.execute("SELECT * FROM payment_dispatch").fetchall() == []  # noqa: SLF001
        assert not store.commit_payment_dispatch(session, _hash(harness), b"request")
    with harness.acquire() as store:
        assert store._connection.execute("PRAGMA user_version").fetchone() == (12,)  # noqa: SLF001
        assert not store.commit_payment_dispatch(session, _hash(harness), b"request")


def test_interrupted_upgrade_rolls_back_all_schema_and_version_changes(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    _as_v5(harness.path)
    upgrade = live._upgrade_v5  # noqa: SLF001

    def interrupted(connection: sqlite3.Connection) -> None:
        upgrade(connection)
        raise OSError("simulated interruption before commit")

    with monkeypatch.context() as patch:
        patch.setattr(live, "_upgrade_v5", interrupted)
        with pytest.raises(live.LiveSessionStoreError, match="unavailable"):
            harness.acquire_at(harness.path, upgrade_from_v5=True)
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
        assert connection.execute("SELECT schema_version FROM meta").fetchone() == (5,)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='payment_dispatch'"
            ).fetchall()
            == []
        )
    with harness.acquire_at(harness.path, upgrade_from_v5=True):
        pass


def test_explicit_upgrade_still_refuses_missing_or_foreign_state(harness: Harness) -> None:
    absent = harness.path.parent / "missing.sqlite"
    with pytest.raises(live.LiveSessionStoreError):
        harness.acquire_at(absent, upgrade_from_v5=True)
    assert not absent.exists()
    with sqlite3.connect(harness.path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(live.LiveSessionStoreError, match="version unsupported"):
        harness.acquire_at(harness.path, upgrade_from_v5=True)
