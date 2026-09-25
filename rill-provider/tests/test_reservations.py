from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import get_context
from typing import TYPE_CHECKING

import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider.reservations import (
    LedgerError,
    ReservationConflictError,
    ReservationLedger,
    ReservedInput,
)

if TYPE_CHECKING:
    from multiprocessing.queues import Queue
    from multiprocessing.synchronize import Barrier as ProcessBarrier
    from pathlib import Path


def _network(namespace: str = "site-a") -> NetworkIdentity:
    return NetworkIdentity.model_validate(
        {
            "family": "bitcoin",
            "name": "regtest",
            "genesis_hash": "11" * 32,
            "signet_challenge": None,
            "consensus_profile": "bitcoin-core-v30.0-regtest-default",
            "deployment_namespace": namespace,
        }
    )


def _inputs() -> tuple[ReservedInput, ReservedInput]:
    return (
        ReservedInput("aa" * 32, 1, 60_000, "client-1"),
        ReservedInput("bb" * 32, 2, 70_000, "client-1"),
    )


def _reserve_process(path: str, barrier: ProcessBarrier, queue: Queue[str], swap: str) -> None:
    ledger = ReservationLedger.open_existing(path, _network())
    barrier.wait(timeout=10)
    try:
        ledger.record_reservation(swap, swap, "22" * 32, (_inputs()[0],))
    except ReservationConflictError:
        queue.put("conflict")
    else:
        queue.put("recorded")


def test_explicit_creation_reopen_and_unknown_storage_are_conservative(tmp_path: Path) -> None:
    path = tmp_path / "reservations.sqlite3"
    with pytest.raises(LedgerError, match="existing regular file"):
        ReservationLedger.open_existing(path, _network())
    ledger = ReservationLedger.create(path, _network())
    assert ledger.list_reservations() == ()
    assert ledger.get("aa" * 32) is None
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        ReservationLedger.create(path, _network())
    with pytest.raises(LedgerError, match="network identity mismatch"):
        ReservationLedger.open_existing(path, _network("site-b"))
    assert ReservationLedger.open_existing(path, _network()).list_reservations() == ()


def test_full_input_set_is_committed_and_survives_reopen(tmp_path: Path) -> None:
    path = tmp_path / "reservations.sqlite3"
    ledger = ReservationLedger.create(path, _network())
    inputs = _inputs()
    result = ledger.record_reservation("10" * 32, "11" * 32, "12" * 32, inputs[::-1])
    assert result.inputs == inputs
    assert ledger.get("10" * 32) == result
    reopened = ReservationLedger.open_existing(path, _network())
    assert reopened.list_reservations() == (result,)
    assert reopened.record_reservation("10" * 32, "11" * 32, "12" * 32, inputs) == result
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        assert connection.execute("PRAGMA application_id").fetchone() == (0x52494C4C,)
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)


def test_idempotency_and_attempt_identity_require_exact_immutable_content(tmp_path: Path) -> None:
    ledger = ReservationLedger.create(tmp_path / "reservations.sqlite3", _network())
    original = ledger.record_reservation("10" * 32, "11" * 32, "12" * 32, _inputs())
    variants = (
        ("10" * 32, "13" * 32, "12" * 32, _inputs()),
        ("10" * 32, "11" * 32, "13" * 32, _inputs()),
        ("10" * 32, "11" * 32, "12" * 32, _inputs()[:1]),
        (
            "10" * 32,
            "11" * 32,
            "12" * 32,
            (ReservedInput("aa" * 32, 1, 60_001, "client-1"), _inputs()[1]),
        ),
        (
            "10" * 32,
            "11" * 32,
            "12" * 32,
            (
                ReservedInput("aa" * 32, 1, 60_000, "client-2"),
                ReservedInput("bb" * 32, 2, 70_000, "client-2"),
            ),
        ),
        ("20" * 32, "11" * 32, "12" * 32, (ReservedInput("cc" * 32, 0, 60_000, "client-1"),)),
        ("20" * 32, "21" * 32, "22" * 32, (_inputs()[1],)),
    )
    for key, swap, attempt, inputs in variants:
        with pytest.raises(ReservationConflictError):
            ledger.record_reservation(key, swap, attempt, inputs)
        assert ledger.list_reservations() == (original,)
    second = ledger.record_reservation(
        "30" * 32,
        "11" * 32,
        "14" * 32,
        (ReservedInput("cc" * 32, 0, 60_000, "client-1"),),
    )
    assert ledger.list_reservations() == (original, second)


def test_partial_input_set_conflict_rolls_back_every_new_row(tmp_path: Path) -> None:
    ledger = ReservationLedger.create(tmp_path / "reservations.sqlite3", _network())
    existing = ledger.record_reservation("10" * 32, "11" * 32, "12" * 32, (_inputs()[1],))
    with pytest.raises(ReservationConflictError):
        ledger.record_reservation("20" * 32, "21" * 32, "22" * 32, _inputs())
    assert ledger.list_reservations() == (existing,)
    assert ledger.get("20" * 32) is None
    ledger.record_reservation("30" * 32, "31" * 32, "32" * 32, (_inputs()[0],))
    assert len(ledger.list_reservations()) == 2


def test_independent_connection_threads_admit_only_one_overlapping_set(tmp_path: Path) -> None:
    path = tmp_path / "reservations.sqlite3"
    ReservationLedger.create(path, _network())

    def compete(key: str) -> bool:
        try:
            ReservationLedger.open_existing(path, _network()).record_reservation(
                key, key, "22" * 32, (_inputs()[0],)
            )
        except ReservationConflictError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sum(executor.map(compete, ("10" * 32, "11" * 32))) == 1
    assert len(ReservationLedger.open_existing(path, _network()).list_reservations()) == 1


def test_separate_processes_compete_on_one_input(tmp_path: Path) -> None:
    path = tmp_path / "reservations.sqlite3"
    ReservationLedger.create(path, _network())
    ctx = get_context("spawn")
    barrier = ctx.Barrier(2)
    queue: Queue[str] = ctx.Queue()
    processes = [
        ctx.Process(target=_reserve_process, args=(str(path), barrier, queue, swap))
        for swap in ("10" * 32, "11" * 32)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=15)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0
    assert sorted((queue.get(timeout=2), queue.get(timeout=2))) == ["conflict", "recorded"]
    assert len(ReservationLedger.open_existing(path, _network()).list_reservations()) == 1


def test_invalid_inputs_and_partial_or_newer_databases_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "reservations.sqlite3"
    ledger = ReservationLedger.create(path, _network())
    for item in (
        ("GG" * 32, 0, 100, "a"),
        ("11" * 32, -1, 100, "a"),
        ("11" * 32, 2**32, 100, "a"),
        ("11" * 32, 0, 0, "a"),
        ("11" * 32, 0, True, "a"),
        ("11" * 32, 0, 100, "bad cluster"),
    ):
        with pytest.raises(LedgerError):
            ReservedInput(*item)
    with pytest.raises(LedgerError, match="repeats"):
        ledger.record_reservation("10" * 32, "11" * 32, "12" * 32, (_inputs()[0],) * 2)
    with pytest.raises(LedgerError, match="privacy clusters"):
        ledger.record_reservation(
            "10" * 32,
            "11" * 32,
            "12" * 32,
            (_inputs()[0], ReservedInput("bb" * 32, 2, 100, "different")),
        )
    with pytest.raises(LedgerError, match="nonempty"):
        ledger.record_reservation("10" * 32, "11" * 32, "12" * 32, ())
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=2")
    with pytest.raises(LedgerError, match="unsupported reservation database version"):
        ReservationLedger.open_existing(path, _network())
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=1")
        connection.execute("DELETE FROM metadata")
    with pytest.raises(LedgerError, match="missing or duplicate metadata"):
        ReservationLedger.open_existing(path, _network())
    foreign_path = tmp_path / "other.sqlite3"
    foreign_path.write_bytes(b"not sqlite")
    with pytest.raises(LedgerError):
        ReservationLedger.open_existing(foreign_path, _network())


@pytest.mark.parametrize(
    ("table", "replacement"),
    [
        (
            "reservations",
            (
                "CREATE TABLE reservations (idempotency_key TEXT PRIMARY KEY, "
                "swap_id TEXT NOT NULL, funding_attempt_id TEXT NOT NULL)"
            ),
        ),
        (
            "reserved_inputs",
            (
                "CREATE TABLE reserved_inputs (txid TEXT NOT NULL, vout INTEGER NOT NULL, "
                "idempotency_key TEXT NOT NULL REFERENCES reservations(idempotency_key), "
                "value_sat INTEGER NOT NULL, cluster_id TEXT NOT NULL)"
            ),
        ),
        (
            "reserved_inputs",
            (
                "CREATE TABLE reserved_inputs (vout INTEGER NOT NULL, txid TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL REFERENCES reservations(idempotency_key), "
                "value_sat INTEGER NOT NULL, cluster_id TEXT NOT NULL, PRIMARY KEY (txid, vout))"
            ),
        ),
    ],
)
def test_matching_version_and_metadata_cannot_hide_broken_constraints(
    tmp_path: Path, table: str, replacement: str
) -> None:
    path = tmp_path / "reservations.sqlite3"
    ReservationLedger.create(path, _network())
    with sqlite3.connect(path) as connection:
        connection.execute(f"DROP TABLE {table}")
        connection.execute(replacement)
        before = connection.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
    with pytest.raises(LedgerError, match="incompatible schema"):
        ReservationLedger.open_existing(path, _network())
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
            == before
        )


def test_many_declared_inputs_are_rejected_before_consuming_an_unbounded_stream(
    tmp_path: Path,
) -> None:
    ledger = ReservationLedger.create(tmp_path / "reservations.sqlite3", _network())
    seen = 0

    def inputs() -> object:
        nonlocal seen
        while True:
            seen += 1
            yield ReservedInput(f"{seen:064x}", 0, 1, "client-1")

    with pytest.raises(LedgerError, match="local size limit"):
        ledger.record_reservation("10" * 32, "11" * 32, "12" * 32, inputs())
    assert seen == 101
    assert ledger.list_reservations() == ()


def test_reserved_prefix_lookalike_trigger_is_not_hidden_by_schema_check(tmp_path: Path) -> None:
    path = tmp_path / "reservations.sqlite3"
    ReservationLedger.create(path, _network())
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TRIGGER sqliteXerase AFTER INSERT ON reserved_inputs "
            "BEGIN DELETE FROM reserved_inputs; END"
        )
        before = connection.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
    with pytest.raises(LedgerError, match="incompatible schema"):
        ReservationLedger.open_existing(path, _network())
    with sqlite3.connect(path) as connection:
        after = connection.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
        assert after == before
