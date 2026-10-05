"""Authoritative inventory allocations, not assertions of production custody."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError
from rill_core.wire.types import NetworkIdentity

from rill_cli import conversion_journal as module
from rill_cli.conversion_journal import (
    Allocation,
    CapacityQuery,
    ConversionJournal,
    ConversionJournalError,
    ConversionReceipt,
    ConversionRequest,
    ConversionReservation,
    PreparedConversion,
    SourceAuthority,
    SourceCredit,
    WalletAvailability,
)
from rill_cli.publication import RecoveryPublicationError, RecoveryPublicationUncertainError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

NODE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
NETWORK = NetworkIdentity(
    family="bitcoin",
    name="regtest",
    genesis_hash="a" * 64,
    signet_challenge=None,
    consensus_profile="bitcoin-regtest/1",
    deployment_namespace="conversion-test",
)
AUTHORITY = SourceAuthority(
    source_node=NODE,
    network=NETWORK,
    source_epoch="b" * 64,
    exclusive_wallet=True,
    commitments_known=True,
    fixed_reserve_msat=1_000_000,
    treasury_script="5120" + NODE[2:],
    provider_identity=NODE[2:],
)
CREDIT = SourceCredit(payment_hash="c" * 64, invoice_sha256="d" * 64, amount_msat=50_000_000)
PREPARED = PreparedConversion(
    contract_hash="e" * 64,
    payment_hash="f" * 64,
    invoice_sha256="1" * 64,
    invoice_amount_msat=40_000_000,
    routing_fee_ceiling_msat=1_000_000,
    minimum_net_output_sat=35_000,
)
CIPHERTEXT = b"opaque encrypted recovery fixture, not a live export"


def request(operation_id: str = "conversion_op_01", /, **updates: object) -> ConversionRequest:
    values = {
        "operation_id": operation_id,
        "allocations": (Allocation(payment_hash=CREDIT.payment_hash, amount_msat=45_000_000),),
        "requested_payout_sat": 35_000,
        "minimum_output_sat": 35_000,
        "max_source_debit_msat": 45_000_000,
        "max_fee_msat": 10_000_000,
        "max_routing_fee_msat": 1_000_000,
        "confirmation_blocks": 6,
        "expires_at": int(time.time()) + 3600,
    }
    return ConversionRequest.model_validate(values | updates)


def availability(journal: ConversionJournal | None = None, **updates: object) -> WalletAvailability:
    return WalletAvailability.model_validate(
        {
            "source_node": NODE,
            "network": NETWORK,
            "query": journal.begin_capacity_query()
            if journal
            else CapacityQuery(journal_id="b" * 64, generation=0, started_at=int(time.time())),
            "observed_at": int(time.time()),
            "spendable_msat": 100_000_000,
            "commitments_known": True,
        }
        | updates
    )


def receipt(**updates: object) -> ConversionReceipt:
    return ConversionReceipt.model_validate(
        {
            "source_node": NODE,
            "network": NETWORK,
            "payment_hash": PREPARED.payment_hash,
            "invoice_sha256": PREPARED.invoice_sha256,
            "amount_msat": PREPARED.invoice_amount_msat,
            "routing_fee_msat": 1000,
            "destination_txid": "2" * 64,
            "destination_vout": 0,
            "destination_script": AUTHORITY.treasury_script,
            "destination_value_sat": 35_000,
            "confirmation_blocks": 6,
        }
        | updates
    )


@pytest.fixture
def journal(tmp_path: Path) -> ConversionJournal:
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    return ConversionJournal.provision(directory, tmp_path / "source-owner.json", AUTHORITY)


def reopen(journal: ConversionJournal) -> ConversionJournal:
    return ConversionJournal.open(journal.directory, journal.source_fence, AUTHORITY)


def reserve(
    journal: ConversionJournal, approved: ConversionRequest | None = None
) -> ConversionReservation:
    return journal.reserve(
        approved or request(), credits=(CREDIT,), availability=availability(journal)
    )


def verify(stored: bytes) -> None:
    assert stored == CIPHERTEXT


def dispatched(journal: ConversionJournal) -> module._LiveRight:
    reservation = reserve(journal)
    right = journal.invoke(reservation)
    path = journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)
    assert path.stat().st_mode & 0o777 == 0o600
    journal.dispatch(right, PREPARED.payment_hash)
    return right


def test_explicit_private_provision_open_and_no_reprovision(journal: ConversionJournal) -> None:
    assert reopen(journal).directory == journal.directory
    assert journal.source_fence.stat().st_mode & 0o777 == 0o600
    assert (journal.directory / "inventory.sqlite").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ConversionJournalError):
        ConversionJournal.provision(journal.directory, journal.source_fence, AUTHORITY)
    assert sorted(path.name for path in journal.directory.iterdir()) == [
        "inventory.sqlite",
        "recovery",
    ]


def test_missing_journal_never_creates_or_reconstructs(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    with pytest.raises(FileNotFoundError):
        ConversionJournal.open(directory, tmp_path / "source-owner.json", AUTHORITY)
    assert not list(directory.iterdir())
    journal = ConversionJournal.provision(directory, tmp_path / "source-owner.json", AUTHORITY)
    reserve(journal)
    (directory / "inventory.sqlite").unlink()
    with pytest.raises(FileNotFoundError):
        reopen(journal)
    (directory / "recovery").rmdir()
    with pytest.raises(FileExistsError):
        ConversionJournal.provision(directory, journal.source_fence, AUTHORITY)
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize("kind", ["file_fsync", "directory_fsync"])
def test_failed_provision_retains_external_fence_never_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    fence = tmp_path / "source-owner.json"
    original = os.fsync

    def fail(fd: int) -> None:
        is_directory = os.fstat(fd).st_mode & 0o170000 == 0o040000
        if is_directory == (kind == "directory_fsync"):
            raise OSError("injected provision durability failure")
        original(fd)

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError, match="durability failure"):
        ConversionJournal.provision(directory, fence, AUTHORITY)
    assert fence.exists()
    assert not list(directory.iterdir())
    monkeypatch.setattr(os, "fsync", original)
    with pytest.raises(FileExistsError):
        ConversionJournal.provision(directory, fence, AUTHORITY)
    with pytest.raises(FileNotFoundError):
        ConversionJournal.open(directory, fence, AUTHORITY)


@pytest.mark.parametrize(
    "kind",
    [
        "missing_fence",
        "partial_fence",
        "old_fence",
        "duplicate_fence_key",
        "public_fence",
        "symlink_fence",
        "hardlink_store",
        "public_store",
        "partial_schema",
        "extra_schema",
        "partial_job",
        "missing_holds",
        "invalid_hold",
        "overconsumption",
        "missing_recovery_directory",
    ],
)
def test_unknown_or_modified_state_refuses_ordinary_open(
    journal: ConversionJournal, kind: str
) -> None:
    reserve(journal)
    store, fence = journal.directory / "inventory.sqlite", journal.source_fence
    if kind == "missing_fence":
        fence.unlink()
    elif kind == "partial_fence":
        fence.write_text("{")
    elif kind == "old_fence":
        data = json.loads(fence.read_text())
        data["version"] = "old/0"
        fence.write_text(json.dumps(data))
    elif kind == "duplicate_fence_key":
        fence.write_text(fence.read_text().replace("{", '{"version":"old/0",', 1))
    elif kind == "public_fence":
        fence.chmod(0o644)
    elif kind == "symlink_fence":
        target = fence.with_suffix(".original")
        fence.rename(target)
        fence.symlink_to(target)
    elif kind == "hardlink_store":
        os.link(store, store.with_suffix(".alias"))
    elif kind == "public_store":
        store.chmod(0o644)
    elif kind == "missing_recovery_directory":
        (journal.directory / "recovery").rmdir()
    else:
        statements = {
            "partial_schema": "DROP TABLE holds",
            "extra_schema": "CREATE TABLE surprise(id INTEGER)",
            "partial_job": "UPDATE jobs SET job='{}'",
            "missing_holds": "DELETE FROM holds",
            "invalid_hold": "UPDATE holds SET kind='unknown'",
            "overconsumption": "UPDATE credits SET consumed_msat=50000000",
        }
        with sqlite3.connect(store) as db:
            db.execute(statements[kind])
    with pytest.raises((ConversionJournalError, OSError, ValueError, sqlite3.Error)):
        reopen(journal)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_epoch", "8" * 64),
        ("provider_identity", "8" * 64),
        ("fixed_reserve_msat", 0),
        ("treasury_script", "5120" + "8" * 64),
        ("network", NETWORK.model_copy(update={"deployment_namespace": "another"})),
    ],
)
def test_pinned_authority_cannot_change(
    journal: ConversionJournal, field: str, value: object
) -> None:
    changed = SourceAuthority.model_validate(AUTHORITY.model_dump() | {field: value})
    with pytest.raises(ConversionJournalError, match="ownership changed"):
        ConversionJournal.open(journal.directory, journal.source_fence, changed)


@pytest.mark.parametrize("value", [False, 0, 1, "true", None])
def test_unknown_or_coerced_commitments_are_not_authority(value: object) -> None:
    for field in ("exclusive_wallet", "commitments_known"):
        with pytest.raises(ValidationError):
            SourceAuthority.model_validate(AUTHORITY.model_dump() | {field: value})
    with pytest.raises(ValidationError):
        availability(commitments_known=value)


def test_atomic_reservation_replay_conflict_and_process_local_right(
    journal: ConversionJournal,
) -> None:
    approved = request()
    original = reserve(journal, approved)
    replay = reserve(reopen(journal), approved)
    assert replay.job == original.job
    with pytest.raises(ConversionJournalError, match="no invocation owner"):
        journal.invoke(replay)
    with pytest.raises(ConversionJournalError, match="owner"):
        reopen(journal).invoke(original)
    with pytest.raises(ConversionJournalError, match="authorization changed"):
        reserve(journal, request(expires_at=approved.expires_at + 1))
    journal.invoke(original)
    assert reopen(journal).status(approved.operation_id).state == "invoked"
    with pytest.raises(ConversionJournalError, match="already consumed"):
        journal.invoke(original)


@pytest.mark.parametrize(
    "updates",
    [
        {"observed_at": 1},
        {"observed_at": 9_999_999_999},
        {"network": NETWORK.model_copy(update={"deployment_namespace": "other"})},
        {"source_node": "03" + NODE[2:]},
        {"spendable_msat": 45_999_999},
    ],
)
def test_unknown_capacity_rolls_back_credit_and_job(
    journal: ConversionJournal, updates: dict[str, object]
) -> None:
    with pytest.raises(ConversionJournalError):
        journal.reserve(request(), credits=(CREDIT,), availability=availability(journal, **updates))
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        for table in ("credits", "holds", "jobs"):
            assert db.execute(f"SELECT * FROM {table}").fetchall() == []  # noqa: S608 - fixed test-only table names


def test_canonical_receipt_conflict_and_no_capacity_from_alias(journal: ConversionJournal) -> None:
    reserve(journal)
    alias = CREDIT.model_copy(update={"invoice_sha256": "3" * 64})
    with pytest.raises(ConversionJournalError, match="credit conflict"):
        journal.reserve(
            request("conversion_op_02"), credits=(alias,), availability=availability(journal)
        )
    with pytest.raises(ConversionJournalError, match="reserved"):
        journal.reserve(
            request("conversion_op_02"), credits=(CREDIT,), availability=availability(journal)
        )
    assert reopen(journal).status("conversion_op_01").state == "reserved"


def test_concurrent_origins_share_one_source_credit_domain(journal: ConversionJournal) -> None:
    barrier = Barrier(2)
    instances = [reopen(journal), reopen(journal)]

    def attempt(index: int) -> bool:
        barrier.wait()
        try:
            reserve(instances[index], request(f"conversion_op_0{index + 1}"))
        except ConversionJournalError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(attempt, (0, 1)))
    assert results.count(True) == 1
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        assert db.execute("SELECT COUNT(*) FROM credits").fetchone() == (1,)
        assert db.execute("SELECT COUNT(*) FROM jobs").fetchone() == (1,)


def test_refund_promise_serializes_with_conversion_reservation(journal: ConversionJournal) -> None:
    barrier = Barrier(2)
    hold = Allocation(payment_hash=CREDIT.payment_hash, amount_msat=10_000_000)

    def attempt(kind: str) -> bool:
        instance = reopen(journal)
        barrier.wait()
        try:
            if kind == "refund":
                instance.reserve_refund(
                    "refund_promise_01",
                    hold,
                    credits=(CREDIT,),
                    availability=availability(instance),
                )
            else:
                reserve(instance)
        except ConversionJournalError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(attempt, ("refund", "conversion")))
    assert results.count(True) == 1
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        assert db.execute("SELECT SUM(amount_msat) FROM holds").fetchone()[0] <= CREDIT.amount_msat


def test_fixed_wallet_reserve_and_other_credit_holds_are_not_spendable(
    journal: ConversionJournal,
) -> None:
    journal.reserve_refund(
        "refund_promise_01",
        Allocation(payment_hash=CREDIT.payment_hash, amount_msat=1_000_000),
        credits=(CREDIT,),
        availability=availability(journal),
    )
    with pytest.raises(ConversionJournalError, match="capacity"):
        journal.reserve(
            request(),
            credits=(CREDIT,),
            availability=availability(journal, spendable_msat=46_000_000),
        )
    journal.reserve_refund(
        "refund_promise_01",
        Allocation(payment_hash=CREDIT.payment_hash, amount_msat=1_000_000),
        credits=(CREDIT,),
        availability=availability(journal),
    )
    with pytest.raises(ConversionJournalError, match="changed"):
        journal.reserve_refund(
            "refund_promise_01",
            Allocation(payment_hash=CREDIT.payment_hash, amount_msat=2_000_000),
            credits=(CREDIT,),
            availability=availability(journal),
        )


@pytest.mark.parametrize(
    "phase", ["reserved", "invoked", "checkpointing", "prepared", "dispatched"]
)
def test_restart_retains_budget_never_restores_invocation(
    journal: ConversionJournal, phase: str
) -> None:
    approved = request()
    reservation = reserve(journal, approved)
    if phase != "reserved":
        right = journal.invoke(reservation)
        if phase == "checkpointing":
            with pytest.raises(RecoveryPublicationError):
                journal.checkpoint(
                    right,
                    PREPARED,
                    CIPHERTEXT,
                    verify_from_disk=lambda _stored: (_ for _ in ()).throw(
                        ValueError("invalid recovery")
                    ),
                )
        elif phase in {"prepared", "dispatched"}:
            journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)
            if phase == "dispatched":
                journal.dispatch(right, PREPARED.payment_hash)
    restarted = reopen(journal)
    assert restarted.status(approved.operation_id).state == phase
    with pytest.raises(ConversionJournalError, match="no invocation owner"):
        restarted.invoke(reserve(restarted, approved))
    with pytest.raises(ConversionJournalError, match="reserved"):
        reserve(restarted, request("conversion_op_02"))


@pytest.mark.parametrize("after_commit", [False, True])
@pytest.mark.parametrize("phase", ["invoke", "dispatch"])
def test_uncertain_commit_consumes_live_right_even_if_store_unchanged(
    journal: ConversionJournal, monkeypatch: pytest.MonkeyPatch, phase: str, *, after_commit: bool
) -> None:
    reservation = reserve(journal)
    if phase == "dispatch":
        right = journal.invoke(reservation)
        journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)
    original = journal._transaction  # noqa: SLF001 - exact durable-before-effect fault

    @contextmanager
    def failure() -> Iterator[sqlite3.Connection]:
        with original() as db:
            yield db
            if not after_commit:
                raise OSError("commit not reached")
        raise OSError("committed, acknowledgement lost")

    monkeypatch.setattr(journal, "_transaction", failure)
    action: Callable[[], object]
    if phase == "invoke":
        action = lambda: journal.invoke(reservation)  # noqa: E731 - same effect checked twice
    else:
        action = lambda: journal.dispatch(right, PREPARED.payment_hash)  # noqa: E731 - same effect checked twice
    with pytest.raises(OSError, match="commit"):
        action()
    monkeypatch.setattr(journal, "_transaction", original)
    with pytest.raises(ConversionJournalError):
        action()
    expected = (
        ("invoked" if phase == "invoke" else "dispatched")
        if after_commit
        else ("reserved" if phase == "invoke" else "prepared")
    )
    assert reopen(journal).status("conversion_op_01").state == expected


@pytest.mark.parametrize(
    "updates",
    [
        {"invoice_amount_msat": 46_000_000},
        {"routing_fee_ceiling_msat": 1_000_001},
        {"minimum_net_output_sat": 34_999},
        {"invoice_amount_msat": 44_999_999},
    ],
)
def test_verified_quote_still_must_fit_operator_caps(
    journal: ConversionJournal, updates: dict[str, object]
) -> None:
    right = journal.invoke(reserve(journal))
    with pytest.raises(ConversionJournalError, match="quote exceeds"):
        journal.checkpoint(
            right,
            PreparedConversion.model_validate(PREPARED.model_dump() | updates),
            CIPHERTEXT,
            verify_from_disk=verify,
        )
    assert not list((journal.directory / "recovery").iterdir())
    with pytest.raises(ConversionJournalError, match="quote already"):
        journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)


def test_recovery_publication_uncertainty_never_enables_payment(
    journal: ConversionJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    right = journal.invoke(reserve(journal))

    def fail(path: Path) -> None:
        path.write_bytes(CIPHERTEXT)
        path.chmod(0o600)
        raise RecoveryPublicationUncertainError("simulated uncertain directory sync")

    monkeypatch.setattr(
        module, "publish_new_ciphertext", lambda path, *_args, **_kwargs: fail(path)
    )
    with pytest.raises(RecoveryPublicationUncertainError):
        journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)
    assert reopen(journal).status("conversion_op_01").state == "checkpointing"
    with pytest.raises(ConversionJournalError):
        journal.dispatch(right, PREPARED.payment_hash)


def test_dispatch_checks_checkpoint_and_hash_and_is_once(journal: ConversionJournal) -> None:
    right = dispatched(journal)
    with pytest.raises(ConversionJournalError, match="unavailable"):
        journal.dispatch(right, PREPARED.payment_hash)
    assert (
        reopen(journal).status("conversion_op_01").recovery_sha256
        == hashlib.sha256(CIPHERTEXT).hexdigest()
    )


@pytest.mark.parametrize("fault", ["changed_checkpoint", "wrong_hash", "expired"])
def test_dispatch_refusal_never_restores_live_permission(
    journal: ConversionJournal, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    right = journal.invoke(reserve(journal))
    path = journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)
    payment_hash = PREPARED.payment_hash
    if fault == "changed_checkpoint":
        path.write_bytes(b"changed")
    elif fault == "wrong_hash":
        payment_hash = "4" * 64
    else:
        monkeypatch.setattr(time, "time", lambda: 9_999_999_999)
    with pytest.raises(ConversionJournalError):
        journal.dispatch(right, payment_hash)
    with pytest.raises(ConversionJournalError, match="unavailable"):
        journal.dispatch(right, PREPARED.payment_hash)


@pytest.mark.parametrize(
    "updates",
    [
        {"network": NETWORK.model_copy(update={"deployment_namespace": "foreign"})},
        {"source_node": "03" + NODE[2:]},
        {"payment_hash": "4" * 64},
        {"invoice_sha256": "4" * 64},
        {"amount_msat": 39_999_999},
        {"routing_fee_msat": 1_000_001},
        {"destination_script": "5120" + "4" * 64},
        {"destination_value_sat": 34_999},
        {"confirmation_blocks": 5},
    ],
)
def test_independent_completion_cannot_accept_wrong_source_or_nominal_output(
    journal: ConversionJournal, updates: dict[str, object]
) -> None:
    dispatched(journal)
    with pytest.raises(ConversionJournalError, match="receipt refused"):
        journal.complete("conversion_op_01", receipt(**updates))
    assert reopen(journal).status("conversion_op_01").state == "dispatched"
    with pytest.raises(ConversionJournalError):
        reserve(journal, request("conversion_op_02"))


def test_actual_debit_consumed_unused_budget_released_and_history_stable(
    journal: ConversionJournal,
) -> None:
    dispatched(journal)
    verified = receipt()
    job = journal.complete("conversion_op_01", verified)
    assert job.state == "complete"
    assert job.receipt is not None
    assert job.receipt.destination_value_sat == 35_000
    assert reopen(journal).complete("conversion_op_01", verified) == job
    with pytest.raises(ConversionJournalError, match="receipt changed"):
        journal.complete("conversion_op_01", receipt(destination_txid="5" * 64))
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        assert db.execute("SELECT consumed_msat FROM credits").fetchone() == (40_001_000,)
        assert db.execute("SELECT * FROM holds").fetchall() == []
    remainder = 9_999_000
    small = request(
        "conversion_op_02",
        allocations=(Allocation(payment_hash=CREDIT.payment_hash, amount_msat=remainder),),
        max_source_debit_msat=remainder,
        max_fee_msat=1_000_000,
        max_routing_fee_msat=1000,
        requested_payout_sat=9000,
        minimum_output_sat=9000,
    )
    reserve(reopen(journal), small)
    with pytest.raises(ConversionJournalError, match="consumed or reserved"):
        reserve(journal, small.model_copy(update={"operation_id": "conversion_op_03"}))


def test_completed_credit_not_recreated_by_replenished_wallet(journal: ConversionJournal) -> None:
    dispatched(journal)
    journal.complete("conversion_op_01", receipt())
    with pytest.raises(ConversionJournalError, match="consumed or reserved"):
        reserve(reopen(journal), request("conversion_op_02"))


@pytest.mark.parametrize(
    "updates",
    [
        {"max_source_debit_msat": 44_999_999},
        {"minimum_output_sat": 35_001},
        {"max_routing_fee_msat": 10_000_001},
        {"confirmation_blocks": True},
        {"allocations": (Allocation(payment_hash=CREDIT.payment_hash, amount_msat=1),) * 2},
        {"unknown": True},
    ],
)
def test_requests_are_closed_strict_and_complete(updates: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        request(**updates)


def test_one_invocation_owner_for_concurrent_same_operation(journal: ConversionJournal) -> None:
    approved = request()
    barrier = Barrier(2)

    def attempt(_index: int) -> bool:
        instance = reopen(journal)
        barrier.wait()
        reservation = reserve(instance, approved)
        try:
            instance.invoke(reservation)
        except ConversionJournalError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(attempt, (0, 1))).count(True) == 1
    assert reopen(journal).status(approved.operation_id).state == "invoked"


def test_same_owned_destination_output_cannot_complete_two_jobs(journal: ConversionJournal) -> None:
    dispatched(journal)
    journal.complete("conversion_op_01", receipt())
    second_credit = CREDIT.model_copy(update={"payment_hash": "7" * 64, "invoice_sha256": "8" * 64})
    second_request = request(
        "conversion_op_02",
        allocations=(Allocation(payment_hash=second_credit.payment_hash, amount_msat=45_000_000),),
    )
    second_prepared = PREPARED.model_copy(
        update={"payment_hash": "9" * 64, "invoice_sha256": "8" * 64}
    )
    reservation = journal.reserve(
        second_request, credits=(second_credit,), availability=availability(journal)
    )
    right = journal.invoke(reservation)
    journal.checkpoint(right, second_prepared, CIPHERTEXT, verify_from_disk=verify)
    journal.dispatch(right, second_prepared.payment_hash)
    with pytest.raises(ConversionJournalError, match="counted twice"):
        journal.complete(
            second_request.operation_id,
            receipt(
                payment_hash=second_prepared.payment_hash,
                invoice_sha256=second_prepared.invoice_sha256,
            ),
        )
    assert reopen(journal).status(second_request.operation_id).state == "dispatched"


def test_completed_consumption_cannot_disappear_on_reopen(journal: ConversionJournal) -> None:
    dispatched(journal)
    journal.complete("conversion_op_01", receipt())
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        db.execute("UPDATE credits SET consumed_msat=0")
    with pytest.raises(ConversionJournalError, match="consumption invalid"):
        reopen(journal)


def test_source_fence_must_be_outside_the_lost_journal_directory(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    with pytest.raises(ConversionJournalError, match="outlive"):
        ConversionJournal.provision(directory, directory / "owner.json", AUTHORITY)
    assert not list(directory.iterdir())


@pytest.mark.parametrize("after_commit", [False, True])
def test_failed_reservation_commit_never_returns_owner(
    journal: ConversionJournal, monkeypatch: pytest.MonkeyPatch, *, after_commit: bool
) -> None:
    original = journal._transaction  # noqa: SLF001 - durable reservation fault

    @contextmanager
    def failure() -> Iterator[sqlite3.Connection]:
        with original() as db:
            yield db
            if not after_commit:
                raise OSError("commit not reached")
        raise OSError("committed, acknowledgement lost")

    approved = request()
    current_capacity = availability(journal)
    monkeypatch.setattr(journal, "_transaction", failure)
    with pytest.raises(OSError, match="commit"):
        journal.reserve(approved, credits=(CREDIT,), availability=current_capacity)
    monkeypatch.setattr(journal, "_transaction", original)
    if after_commit:
        with pytest.raises(ConversionJournalError, match="no invocation owner"):
            journal.invoke(reserve(journal, approved))
    else:
        with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
            assert db.execute("SELECT * FROM jobs").fetchall() == []


@pytest.mark.parametrize("kind", ["conversion", "refund"])
@pytest.mark.parametrize(
    "reply_timing", ["returned_before_completion", "returned_after_completion"]
)
def test_pre_debit_capacity_never_reused_after_completed_hold_release(
    journal: ConversionJournal, kind: str, reply_timing: str
) -> None:
    dispatched(journal)
    # RPC begins while A still holds its budget. It may return after completion,
    # still with a fresh timestamp, and include A's now-consumed source liquidity.
    query = journal.begin_capacity_query()
    stale = availability(journal, query=query)
    journal.complete("conversion_op_01", receipt())
    if reply_timing == "returned_after_completion":
        stale = WalletAvailability.model_validate(
            stale.model_dump() | {"observed_at": int(time.time())}
        )
    another = CREDIT.model_copy(
        update={"payment_hash": "7" * 64, "invoice_sha256": "8" * 64, "amount_msat": 100_000_000}
    )
    allocation = Allocation(payment_hash=another.payment_hash, amount_msat=70_000_000)
    approved = request(
        "conversion_op_02",
        allocations=(allocation,),
        max_source_debit_msat=70_000_000,
        requested_payout_sat=60_000,
        minimum_output_sat=60_000,
    )

    def authorize(current: WalletAvailability) -> None:
        if kind == "conversion":
            journal.reserve(approved, credits=(another,), availability=current)
        else:
            journal.reserve_refund(
                "refund_promise_01", allocation, credits=(another,), availability=current
            )

    with pytest.raises(ConversionJournalError, match="capacity required"):
        authorize(stale)
    # Only a query begun after completion is compatible, and its actual balance
    # is too small despite another historical credit having enough provenance.
    fresh = availability(journal, spendable_msat=59_999_000)
    with pytest.raises(ConversionJournalError, match="exceed available capacity"):
        authorize(fresh)
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        assert db.execute("SELECT COUNT(*) FROM jobs").fetchone() == (1,)
        assert db.execute("SELECT COUNT(*) FROM holds").fetchone() == (0,)


@pytest.mark.parametrize("kind", ["conversion", "refund"])
def test_query_started_before_dispatch_is_invalidated_even_if_response_is_new(
    journal: ConversionJournal, kind: str
) -> None:
    right = journal.invoke(reserve(journal))
    journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)
    query = journal.begin_capacity_query()
    journal.dispatch(right, PREPARED.payment_hash)
    stale = availability(journal, query=query)
    another = CREDIT.model_copy(update={"payment_hash": "7" * 64, "invoice_sha256": "8" * 64})
    allocation = Allocation(payment_hash=another.payment_hash, amount_msat=45_000_000)

    def authorize() -> None:
        if kind == "conversion":
            journal.reserve(
                request("conversion_op_02", allocations=(allocation,)),
                credits=(another,),
                availability=stale,
            )
        else:
            journal.reserve_refund(
                "refund_promise_01", allocation, credits=(another,), availability=stale
            )

    with pytest.raises(ConversionJournalError, match="capacity required"):
        authorize()


@pytest.mark.parametrize("fault", ["missing", "negative", "wrong_journal", "missing_query"])
def test_capacity_generation_missing_or_unknown_never_implies_fresh(
    journal: ConversionJournal, fault: str
) -> None:
    if fault in {"missing", "negative"}:
        with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
            if fault == "missing":
                db.execute("ALTER TABLE metadata DROP COLUMN capacity_generation")
            else:
                db.execute("PRAGMA ignore_check_constraints=ON")
                db.execute("UPDATE metadata SET capacity_generation=-1")
        with pytest.raises((ConversionJournalError, sqlite3.Error)):
            reopen(journal)
    elif fault == "missing_query":
        value = availability(journal).model_dump()
        del value["query"]
        with pytest.raises(ValidationError):
            WalletAvailability.model_validate(value)
    else:
        wrong = journal.begin_capacity_query().model_copy(update={"journal_id": "9" * 64})
        with pytest.raises(ConversionJournalError, match="capacity required"):
            journal.reserve(
                request(), credits=(CREDIT,), availability=availability(journal, query=wrong)
            )


@pytest.mark.parametrize("kind", ["conversion", "refund"])
def test_pre_completion_query_stays_invalid_after_journal_reopen(
    journal: ConversionJournal, kind: str
) -> None:
    dispatched(journal)
    stale = availability(journal)
    journal.complete("conversion_op_01", receipt())
    restarted = reopen(journal)
    assert restarted.begin_capacity_query().generation > stale.query.generation
    allocation = Allocation(payment_hash=CREDIT.payment_hash, amount_msat=5_000_000)

    def authorize() -> None:
        if kind == "refund":
            restarted.reserve_refund(
                "refund_promise_01", allocation, credits=(CREDIT,), availability=stale
            )
        else:
            approved = request(
                "conversion_op_02",
                allocations=(allocation,),
                max_source_debit_msat=5_000_000,
                max_fee_msat=1_000_000,
                max_routing_fee_msat=1000,
                requested_payout_sat=4000,
                minimum_output_sat=4000,
            )
            restarted.reserve(approved, credits=(CREDIT,), availability=stale)

    with pytest.raises(ConversionJournalError, match="capacity required"):
        authorize()
