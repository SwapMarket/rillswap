"""Arbitration rows store shape, not cooperation eligibility."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

import pytest
from test_live_session_store import Harness

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    ready = Harness(tmp_path, monkeypatch)
    ready.provision()
    return ready


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
