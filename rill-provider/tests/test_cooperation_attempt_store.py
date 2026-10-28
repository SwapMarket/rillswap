"""Cooperation burns: table constraints and new-owner reconciliation."""

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


def test_cooperation_table_rejects_malformed_burns(harness: Harness) -> None:
    with sqlite3.connect(harness.path) as connection:
        for cooperation_id, binding, generation, created_at, deadline_at, state in (
            (b"short", b"{}", 1, 1, 2, "BURNED"),
            (b"\x01" * 32, b"", 1, 1, 2, "BURNED"),
            (b"\x02" * 32, b"{}", 1, 1, 2, "COMPLETE"),
            (b"\x03" * 32, b"{}", "not-an-integer", 1, 2, "BURNED"),
            (b"\x04" * 32, b"{}", 1, "not-a-time", 2, "BURNED"),
            (b"\x05" * 32, b"{}", 1, 1, "not-a-time", "BURNED"),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO cooperation_attempts "
                    "(cooperation_id,session_id,owner_generation,binding,created_at,"
                    "deadline_at,state) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (
                        cooperation_id,
                        "session",
                        generation,
                        binding,
                        created_at,
                        deadline_at,
                        state,
                    ),
                )


def test_burned_id_is_permanent_and_one_active_attempt_per_session(harness: Harness) -> None:
    with sqlite3.connect(harness.path) as connection:
        statement = (
            "INSERT INTO cooperation_attempts "
            "(cooperation_id,session_id,owner_generation,binding,created_at,deadline_at,state) "
            "VALUES (?,?,?,?,?,?,?)"
        )
        first = (b"\x01" * 32, "session", 1, b"{}", 1, 2, "BURNED")
        connection.execute(statement, first)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement, (b"\x02" * 32, "session", 1, b"{}", 1, 2, "BURNED"))
        connection.execute(
            "UPDATE cooperation_attempts SET state='ABANDONED' WHERE cooperation_id=?",
            (first[0],),
        )
        connection.execute(statement, (b"\x02" * 32, "session", 1, b"{}", 1, 2, "BURNED"))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement, first)
        assert connection.execute(
            "SELECT cooperation_id,state FROM cooperation_attempts ORDER BY cooperation_id"
        ).fetchall() == [(first[0], "ABANDONED"), (b"\x02" * 32, "BURNED")]


@pytest.mark.parametrize("state", ["BURNED", "NONCE_READY", "SIGNING", "COMPLETE"])
def test_new_owner_abandons_every_unfinished_nonce_without_recreating_it(
    harness: Harness, state: str
) -> None:
    """Public bytes survive if recorded, but no secret handle crosses ownership."""
    public_nonce = b"\x02" * 66 if state != "BURNED" else None
    peer_nonce = b"\x03" * 66 if state in ("SIGNING", "COMPLETE") else None
    partial = b"\x04" * 32 if state == "COMPLETE" else None
    with sqlite3.connect(harness.path) as connection:
        connection.execute(
            "INSERT INTO cooperation_attempts "
            "(cooperation_id,session_id,owner_generation,binding,created_at,deadline_at,"
            "state,local_nonce,peer_nonce,partial_signature,nonce_response_id,partial_response_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                b"\x11" * 32,
                "session",
                1,
                b"{}",
                1000,
                1020,
                state,
                public_nonce,
                peer_nonce,
                partial,
                "nonce-response" if public_nonce else None,
                "partial-response" if partial else None,
            ),
        )
    with harness.acquire() as store:
        assert store._connection.execute(  # noqa: SLF001 - startup transition evidence
            "SELECT state,local_nonce,peer_nonce,partial_signature "
            "FROM cooperation_attempts WHERE cooperation_id=?",
            (b"\x11" * 32,),
        ).fetchone() == (
            "COMPLETE" if state == "COMPLETE" else "ABANDONED",
            public_nonce,
            peer_nonce,
            partial,
        )
