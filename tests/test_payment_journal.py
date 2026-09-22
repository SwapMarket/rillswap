from __future__ import annotations

import hashlib
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from multiprocessing import get_context
from typing import TYPE_CHECKING

import pytest
from rill_core.domain.amounts import MAX_MILLISATS
from rill_core.wire.types import NetworkIdentity

from rill_provider import payment_journal
from rill_provider.payment_journal import (
    OutgoingPaymentIntent,
    OutgoingPaymentJournal,
    PaymentJournalConflictError,
    PaymentJournalError,
    PaymentObservation,
)

if TYPE_CHECKING:
    from multiprocessing.queues import Queue
    from multiprocessing.synchronize import Barrier as ProcessBarrier
    from pathlib import Path


def _network(namespace: str = "journal-a") -> NetworkIdentity:
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


def _intent(key: str = "10" * 32, **changes: object) -> OutgoingPaymentIntent:
    values: dict[str, object] = {
        "idempotency_key": key,
        "swap_id": "11" * 32,
        "attempt_id": "12" * 32,
        "terms_digest": "13" * 32,
        "payment_hash": "14" * 32,
        "destination_amount_msat": 100_000_000,
        "fee_cap_msat": 1_000_000,
        "absolute_cltv_height": 1050,
        "max_absolute_cltv_height": 1070,
        "route_format": "lnd-route-bytes/v1",
        "route": b"\x00\xfffixture route",
    }
    values.update(changes)
    return OutgoingPaymentIntent(**values)  # type: ignore[arg-type]


def _observation(key: str = "10" * 32, **changes: object) -> PaymentObservation:
    values: dict[str, object] = {
        "observation_id": "20" * 32,
        "idempotency_key": key,
        "backend_identity": "node-alpha",
        "backend_attempt_id": "try-one",
        "reported_status": "IN_FLIGHT",
        "evidence_sha256": hashlib.sha256(b"opaque\x00\xff").hexdigest(),
    }
    values.update(changes)
    return PaymentObservation(**values)  # type: ignore[arg-type]


def _compete(path: str, barrier: ProcessBarrier, results: Queue[str], key: str) -> None:
    journal = OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    barrier.wait(timeout=10)
    try:
        journal.record_intent(_intent(key, attempt_id=key))
    except PaymentJournalConflictError:
        results.put("conflict")
    else:
        results.put("recorded")


def _exit_at_transaction_boundary(path: str, phase: str) -> None:
    original_connect = sqlite3.connect

    class ExitBeforeCommit(sqlite3.Connection):
        def commit(self) -> None:
            assert self.in_transaction
            count_query = {
                "before-create-commit": "SELECT COUNT(*) FROM metadata",
                "before-intent-commit": "SELECT COUNT(*) FROM intents",
                "before-observation-commit": "SELECT COUNT(*) FROM observations",
            }[phase]
            assert self.execute(count_query).fetchone() == (1,)
            os._exit(0)

    def crash_on_commit(*args: object, **kwargs: object) -> sqlite3.Connection:
        return original_connect(*args, factory=ExitBeforeCommit, **kwargs)

    if phase == "before-create-commit":
        payment_journal.sqlite3.connect = crash_on_commit
        OutgoingPaymentJournal.create(path, _network(), "node-alpha")
        os._exit(9)
    journal = OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    if phase == "before-intent-commit":
        payment_journal.sqlite3.connect = crash_on_commit
        journal.record_intent(_intent())
        os._exit(9)
    if phase == "after-intent-commit":
        journal.record_intent(_intent())
        os._exit(0)
    if phase == "before-observation-commit":
        payment_journal.sqlite3.connect = crash_on_commit
        journal.record_observation(_observation())
        os._exit(9)
    if phase == "after-observation-commit":
        journal.record_observation(_observation())
        os._exit(0)
    os._exit(9)


def _run_exit(path: Path, phase: str) -> None:
    process = get_context("spawn").Process(
        target=_exit_at_transaction_boundary, args=(str(path), phase)
    )
    process.start()
    process.join(timeout=15)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
    assert process.exitcode == 0


def test_explicit_creation_network_backend_binding_and_reopen(tmp_path: Path) -> None:
    path = tmp_path / "payments.sqlite3"
    with pytest.raises(PaymentJournalError, match="existing regular file"):
        OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    journal = OutgoingPaymentJournal.create(path, _network(), "node-alpha")
    assert journal.list_intents() == ()
    assert journal.get_intent("10" * 32) is None
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        OutgoingPaymentJournal.create(path, _network(), "node-alpha")
    for network, backend in ((_network("other"), "node-alpha"), (_network(), "node-beta")):
        with pytest.raises(PaymentJournalError, match="identity mismatch"):
            OutgoingPaymentJournal.open_existing(path, network, backend)
    assert OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha").list_intents() == ()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        assert connection.execute("PRAGMA application_id").fetchone() == (0x52494C50,)
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)


def test_intent_replay_is_exact_and_committed_route_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "payments.sqlite3"
    journal = OutgoingPaymentJournal.create(path, _network(), "node-alpha")
    intent = _intent()
    assert journal.record_intent(intent) == intent
    reopened = OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    assert reopened.get_intent(intent.idempotency_key) == intent
    assert reopened.record_intent(intent) == intent
    assert reopened.list_intents() == (intent,)
    for changed in (
        replace(intent, swap_id="19" * 32),
        replace(intent, attempt_id="19" * 32),
        replace(intent, terms_digest="19" * 32),
        replace(intent, payment_hash="19" * 32),
        replace(intent, destination_amount_msat=intent.destination_amount_msat + 1),
        replace(intent, fee_cap_msat=intent.fee_cap_msat + 1),
        replace(intent, absolute_cltv_height=intent.absolute_cltv_height + 1),
        replace(intent, max_absolute_cltv_height=intent.max_absolute_cltv_height + 1),
        replace(intent, route_format="other-route/v1"),
        replace(intent, route=b"changed"),
    ):
        with pytest.raises(PaymentJournalConflictError):
            reopened.record_intent(changed)
        assert reopened.list_intents() == (intent,)


def test_second_key_cannot_bypass_attempt_swap_or_payment_hash(tmp_path: Path) -> None:
    journal = OutgoingPaymentJournal.create(tmp_path / "payments.sqlite3", _network(), "node-alpha")
    original = journal.record_intent(_intent())
    for collision in (
        _intent("20" * 32, attempt_id="22" * 32, payment_hash="24" * 32),
        _intent("20" * 32, swap_id="21" * 32, payment_hash="24" * 32),
        _intent("20" * 32, swap_id="21" * 32, attempt_id="22" * 32),
    ):
        with pytest.raises(PaymentJournalConflictError):
            journal.record_intent(collision)
        assert journal.list_intents() == (original,)
    different = _intent("20" * 32, swap_id="21" * 32, attempt_id="22" * 32, payment_hash="24" * 32)
    assert journal.record_intent(different) == different
    assert journal.list_intents() == (original, different)


def test_observations_are_append_only_even_when_backend_reports_disagree(tmp_path: Path) -> None:
    path = tmp_path / "payments.sqlite3"
    journal = OutgoingPaymentJournal.create(path, _network(), "node-alpha")
    intent = journal.record_intent(_intent())
    initial = _observation()
    with pytest.raises(PaymentJournalError, match="absent payment intent"):
        journal.record_observation(_observation("ff" * 32))
    with pytest.raises(PaymentJournalError, match="identity differs"):
        journal.record_observation(replace(initial, backend_identity="node-beta"))
    with pytest.raises(TypeError):
        _observation(evidence=b"raw backend response")
    assert journal.record_observation(initial) == initial
    assert journal.record_observation(initial) == initial
    with pytest.raises(PaymentJournalConflictError):
        journal.record_observation(replace(initial, evidence_sha256="ff" * 32))
    success = replace(initial, observation_id="21" * 32, reported_status="SUCCEEDED")
    failure = replace(initial, observation_id="22" * 32, reported_status="FAILED")
    unknown = replace(
        initial,
        observation_id="23" * 32,
        reported_status="UNKNOWN",
        backend_attempt_id=None,
        evidence_sha256=hashlib.sha256(b"not found").hexdigest(),
    )
    for item in (success, failure, unknown):
        journal.record_observation(item)
    reopened = OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    assert reopened.list_observations(intent.idempotency_key) == (
        initial,
        success,
        failure,
        unknown,
    )
    assert reopened.list_intents() == (intent,)


def test_threads_and_processes_admit_only_one_competing_intent(tmp_path: Path) -> None:
    path = tmp_path / "payments.sqlite3"
    OutgoingPaymentJournal.create(path, _network(), "node-alpha")

    def compete(key: str) -> bool:
        journal = OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
        try:
            journal.record_intent(_intent(key, attempt_id=key))
        except PaymentJournalConflictError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert sum(workers.map(compete, ("30" * 32, "31" * 32))) == 1
    assert (
        len(OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha").list_intents())
        == 1
    )

    other = tmp_path / "other-payments.sqlite3"
    OutgoingPaymentJournal.create(other, _network(), "node-alpha")
    context = get_context("spawn")
    barrier = context.Barrier(2)
    results: Queue[str] = context.Queue()
    processes = [
        context.Process(target=_compete, args=(str(other), barrier, results, key))
        for key in ("30" * 32, "31" * 32)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=15)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0
    assert sorted((results.get(timeout=2), results.get(timeout=2))) == ["conflict", "recorded"]
    assert (
        len(OutgoingPaymentJournal.open_existing(other, _network(), "node-alpha").list_intents())
        == 1
    )


def test_invalid_amounts_heights_routes_and_observations_fail_before_sqlite(tmp_path: Path) -> None:
    journal = OutgoingPaymentJournal.create(tmp_path / "payments.sqlite3", _network(), "node-alpha")
    for changes in (
        {"idempotency_key": "not-hex"},
        {"destination_amount_msat": 0},
        {"destination_amount_msat": True},
        {"destination_amount_msat": MAX_MILLISATS, "fee_cap_msat": 1},
        {"fee_cap_msat": -1},
        {"absolute_cltv_height": 1071},
        {"absolute_cltv_height": True},
        {"route_format": "BAD FORMAT"},
        {"route": b""},
        {"route": b"a" * (16 * 1024 + 1)},
    ):
        with pytest.raises(PaymentJournalError):
            _intent(**changes)
    for changes in (
        {"observation_id": "missing"},
        {"reported_status": "RETRY_SAFE"},
        {"backend_attempt_id": "bad ID"},
        {"evidence_sha256": b"secret response"},
        {"evidence_sha256": "zz" * 32},
    ):
        with pytest.raises(PaymentJournalError):
            _observation(**changes)
    assert journal.list_intents() == ()


def test_partial_unknown_newer_and_modified_schema_fail_without_repair(tmp_path: Path) -> None:
    path = tmp_path / "payments.sqlite3"
    OutgoingPaymentJournal.create(path, _network(), "node-alpha")
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=2")
    with pytest.raises(PaymentJournalError, match="unsupported payment journal version"):
        OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=1")
        connection.execute("DELETE FROM metadata")
    with pytest.raises(PaymentJournalError, match="metadata"):
        OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")

    changed_schema = tmp_path / "changed.sqlite3"
    OutgoingPaymentJournal.create(changed_schema, _network(), "node-alpha")
    with sqlite3.connect(changed_schema) as connection:
        connection.execute("DROP TABLE observations")
        connection.execute(
            "CREATE TABLE observations (observation_id TEXT PRIMARY KEY, "
            "idempotency_key TEXT NOT NULL, backend_identity TEXT NOT NULL, "
            "backend_attempt_id TEXT, reported_status TEXT NOT NULL, "
            "evidence_sha256 TEXT NOT NULL)"
        )
        before = connection.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
    with pytest.raises(PaymentJournalError, match="schema is incompatible"):
        OutgoingPaymentJournal.open_existing(changed_schema, _network(), "node-alpha")
    with sqlite3.connect(changed_schema) as connection:
        assert (
            connection.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
            == before
        )


def test_restored_older_snapshot_is_not_evidence_of_absent_backend_effect(tmp_path: Path) -> None:
    path = tmp_path / "payments.sqlite3"
    journal = OutgoingPaymentJournal.create(path, _network(), "node-alpha")
    original = journal.record_intent(_intent())
    snapshot = tmp_path / "snapshot.sqlite3"
    with sqlite3.connect(path) as live, sqlite3.connect(snapshot) as backup:
        live.backup(backup)
    observation = _observation()
    journal.record_observation(observation)
    assert journal.list_observations(original.idempotency_key) == (observation,)
    restored = OutgoingPaymentJournal.open_existing(snapshot, _network(), "node-alpha")
    assert restored.list_intents() == (original,)
    assert restored.list_observations(original.idempotency_key) == ()


def test_interrupted_transactions_preserve_only_committed_facts(tmp_path: Path) -> None:
    path = tmp_path / "payments.sqlite3"
    OutgoingPaymentJournal.create(path, _network(), "node-alpha")
    _run_exit(path, "before-intent-commit")
    journal = OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    assert journal.list_intents() == ()
    _run_exit(path, "after-intent-commit")
    journal = OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    assert journal.list_intents() == (_intent(),)
    assert journal.list_observations(_intent().idempotency_key) == ()
    _run_exit(path, "before-observation-commit")
    journal = OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    assert journal.list_intents() == (_intent(),)
    assert journal.list_observations(_intent().idempotency_key) == ()
    _run_exit(path, "after-observation-commit")
    journal = OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    assert journal.list_intents() == (_intent(),)
    assert journal.list_observations(_intent().idempotency_key) == (_observation(),)


def test_interrupted_initialization_preserves_partial_file_for_diagnosis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "payments.sqlite3"
    monkeypatch.setitem(payment_journal.SCHEMA_SQL, "observations", "INVALID SQL")
    with pytest.raises(PaymentJournalError):
        OutgoingPaymentJournal.create(path, _network(), "node-alpha")
    assert path.exists()
    with pytest.raises(PaymentJournalError):
        OutgoingPaymentJournal.open_existing(path, _network(), "node-alpha")
    with pytest.raises(FileExistsError):
        OutgoingPaymentJournal.create(path, _network(), "node-alpha")

    killed_path = tmp_path / "killed-create.sqlite3"
    _run_exit(killed_path, "before-create-commit")
    assert killed_path.exists()
    with pytest.raises(PaymentJournalError):
        OutgoingPaymentJournal.open_existing(killed_path, _network(), "node-alpha")
    with pytest.raises(FileExistsError):
        OutgoingPaymentJournal.create(killed_path, _network(), "node-alpha")
