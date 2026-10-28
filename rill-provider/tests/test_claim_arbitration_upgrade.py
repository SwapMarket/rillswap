"""V12 to v13 stores arbitration shape, not cooperation eligibility."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

import pytest
from test_live_session_store import Harness, without_v13_arbitration
from test_payment_dispatch_store import _insert_funded_swap

from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    ready = Harness(tmp_path, monkeypatch)
    ready.provision()
    return ready


def _as_v12(path: Path) -> None:
    """Recreate exact previous-release schema, never discard arbitration evidence."""
    with sqlite3.connect(path) as connection:
        without_v13_arbitration(connection)
        connection.execute("UPDATE meta SET schema_version=12")
        connection.execute("PRAGMA user_version=12")


def test_v12_upgrade_preserves_existing_sessions_and_grants_no_waiting_window(
    harness: Harness,
) -> None:
    with harness.acquire() as store:
        session = store.reserve(harness.init, now=1000).session_id
        original = store._connection.execute(  # noqa: SLF001 - migration evidence
            "SELECT * FROM sessions WHERE session_id=?", (session,)
        ).fetchone()
    _as_v12(harness.path)
    with harness.acquire() as store:
        connection = store._connection  # noqa: SLF001 - exact upgrade evidence
        assert connection.execute("PRAGMA user_version").fetchone() == (18,)
        assert connection.execute("SELECT schema_version FROM meta").fetchone() == (18,)
        assert connection.execute("SELECT * FROM claim_arbitration").fetchall() == []
        assert connection.execute("SELECT * FROM cooperation_attempts").fetchall() == []
        assert (
            connection.execute("SELECT * FROM sessions WHERE session_id=?", (session,)).fetchone()
            == original
        )
    with harness.acquire() as store:
        assert (
            store._connection.execute(  # noqa: SLF001
                "SELECT * FROM claim_arbitration"
            ).fetchall()
            == []
        )


def test_populated_v12_preserves_paid_swap_and_completed_cooperation_evidence(
    harness: Harness,
) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "PAID")
        connection = store._connection  # noqa: SLF001 - exact v12 retained evidence
        connection.execute(
            "INSERT INTO cooperation_attempts (cooperation_id,session_id,owner_generation,"
            "binding,created_at,deadline_at,state,local_nonce,peer_nonce,"
            "partial_signature,nonce_response_id,partial_response_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                b"\x71" * 32,
                session,
                store.generation,
                b"{}",
                1000,
                1020,
                "COMPLETE",
                b"\x02" * 66,
                b"\x03" * 66,
                b"\x04" * 32,
                "nonce-response",
                "partial-response",
            ),
        )
        swap_before = connection.execute(
            "SELECT * FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        cooperation_before = connection.execute(
            "SELECT * FROM cooperation_attempts WHERE session_id=?", (session,)
        ).fetchone()
    _as_v12(harness.path)
    with harness.acquire() as store:
        connection = store._connection  # noqa: SLF001 - upgrade must not mutate evidence
        assert (
            connection.execute("SELECT * FROM swaps WHERE session_id=?", (session,)).fetchone()
            == swap_before
        )
        assert (
            connection.execute(
                "SELECT * FROM cooperation_attempts WHERE session_id=?", (session,)
            ).fetchone()
            == cooperation_before
        )
        assert connection.execute("SELECT * FROM claim_arbitration").fetchall() == []


def test_interrupted_v12_upgrade_retains_exact_previous_schema(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    _as_v12(harness.path)
    upgrade = live._upgrade_v12  # noqa: SLF001 - fault before commit

    def interrupt(connection: sqlite3.Connection) -> None:
        upgrade(connection)
        raise OSError("interrupted before durable commit")

    with monkeypatch.context() as patch:
        patch.setattr(live, "_upgrade_v12", interrupt)
        with pytest.raises(live.LiveSessionStoreError, match="store unavailable"):
            harness.acquire()
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (12,)
        assert connection.execute("SELECT schema_version FROM meta").fetchone() == (12,)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='claim_arbitration'"
            ).fetchall()
            == []
        )
    with harness.acquire() as store:
        assert (
            store._connection.execute(  # noqa: SLF001
                "SELECT * FROM claim_arbitration"
            ).fetchall()
            == []
        )


def test_failure_after_both_version_markers_rolls_back_v13_ddl(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    _as_v12(harness.path)

    def interrupt(connection: sqlite3.Connection) -> int:
        assert connection.execute("PRAGMA user_version").fetchone() == (18,)
        assert connection.execute("SELECT schema_version FROM meta").fetchone() == (18,)
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name='claim_arbitration'"
        ).fetchone() == ("claim_arbitration",)
        raise OSError("interrupted after version markers")

    with monkeypatch.context() as patch:
        patch.setattr(live, "_epoch_watermark", interrupt)
        with pytest.raises(live.LiveSessionStoreError, match="store unavailable"):
            harness.acquire()
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (12,)
        assert connection.execute("SELECT schema_version FROM meta").fetchone() == (12,)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='claim_arbitration'"
            ).fetchall()
            == []
        )
    with harness.acquire() as store:
        assert (
            store._connection.execute(  # noqa: SLF001
                "SELECT * FROM claim_arbitration"
            ).fetchall()
            == []
        )


def test_mismatched_or_partial_v12_schema_cannot_auto_repair(harness: Harness) -> None:
    _as_v12(harness.path)
    with sqlite3.connect(harness.path) as connection:
        connection.execute(live.CLAIM_ARBITRATION_SCHEMA)
    with pytest.raises(live.LiveSessionStoreError, match="schema incompatible"):
        harness.acquire()
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (12,)
        connection.execute("DROP TABLE claim_arbitration")
        connection.execute("UPDATE meta SET schema_version=13")
    with pytest.raises(live.LiveSessionStoreError, match="namespace or policy mismatch"):
        harness.acquire()


def _insert_arbitration(connection: sqlite3.Connection, **changes: object) -> None:
    row: dict[str, object] = {
        "session_id": "one",
        "contract_hash": "aa" * 32,
        "version": 1,
        "state": "ADMITTED",
        "owner_generation": None,
        "prepared_at": None,
        "deadline_at": None,
        "deadline_height": None,
        "fallback_raw": None,
        "fallback_txid": None,
        "fallback_fee_sat": None,
        "cooperative_raw": None,
        "cooperative_txid": None,
    }
    row.update(changes)
    columns = ",".join(row)
    parameters = ",".join("?" for _ in row)
    connection.execute(
        f"INSERT INTO claim_arbitration ({columns}) VALUES ({parameters})",  # noqa: S608 - fixed fixture keys
        tuple(row.values()),
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"state": "WAITING"},
        {"state": "ADMITTED", "owner_generation": 1},
        {"contract_hash": "short"},
        {"version": 2},
        {"state": "CLOSED", "cooperative_raw": b"claim", "cooperative_txid": "bb" * 32},
        {"state": "CLOSED", "cooperative_raw": b"claim"},
        {"state": "WAITING", "owner_generation": "not-an-integer"},
        {"state": "WAITING", "owner_generation": 1, "prepared_at": 10},
        {
            "state": "WAITING",
            "owner_generation": 1,
            "prepared_at": 10,
            "deadline_at": 10,
            "deadline_height": 100,
            "fallback_raw": b"signed",
            "fallback_txid": "bb" * 32,
            "fallback_fee_sat": 1,
        },
    ],
)
def test_arbitration_table_rejects_incomplete_or_false_authority(
    harness: Harness, changes: dict[str, object]
) -> None:
    with sqlite3.connect(harness.path) as connection, pytest.raises(sqlite3.IntegrityError):
        _insert_arbitration(connection, **changes)


def test_new_owner_closes_prepared_window_without_losing_fallback(harness: Harness) -> None:
    bundle = {
        "state": "WAITING",
        "owner_generation": 1,
        "prepared_at": 10,
        "deadline_at": 20,
        "deadline_height": 100,
        "fallback_raw": b"presigned unilateral",
        "fallback_txid": "bb" * 32,
        "fallback_fee_sat": 200,
    }
    with sqlite3.connect(harness.path) as connection:
        _insert_arbitration(connection, **bundle)
    for _ in range(2):
        with harness.acquire() as store:
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state,deadline_at,fallback_raw,cooperative_raw "
                "FROM claim_arbitration WHERE session_id='one'"
            ).fetchone() == ("CLOSED", 20, b"presigned unilateral", None)
            assert (
                store._connection.execute(  # noqa: SLF001
                    "SELECT * FROM cooperation_attempts"
                ).fetchall()
                == []
            )


def test_reacquisition_preserves_closed_and_admitted_rows_unchanged(harness: Harness) -> None:
    prepared = {
        "state": "CLOSED",
        "owner_generation": 1,
        "prepared_at": 10,
        "deadline_at": 20,
        "deadline_height": 100,
        "fallback_raw": b"presigned unilateral",
        "fallback_txid": "bb" * 32,
        "fallback_fee_sat": 200,
    }
    with sqlite3.connect(harness.path) as connection:
        _insert_arbitration(connection, session_id="closed-without-cooperation", **prepared)
        _insert_arbitration(
            connection,
            session_id="closed-with-cooperation",
            cooperative_raw=b"signed cooperative spend",
            cooperative_txid="cc" * 32,
            **prepared,
        )
        _insert_arbitration(connection, session_id="only-admitted")
        original = connection.execute(
            "SELECT * FROM claim_arbitration ORDER BY session_id"
        ).fetchall()
    for _ in range(2):
        with harness.acquire() as store:
            assert (
                store._connection.execute(  # noqa: SLF001
                    "SELECT * FROM claim_arbitration ORDER BY session_id"
                ).fetchall()
                == original
            )
