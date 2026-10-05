"""Optional observed-generation completion fence, preserving manual contracts."""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from importlib import import_module
from typing import TYPE_CHECKING

import pytest

from rill_cli.conversion_journal import ConversionJournal, ConversionJournalError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

helpers = import_module("test_conversion_journal")
NOW = int(time.time())


@pytest.fixture
def journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ConversionJournal:
    monkeypatch.setattr(time, "time", lambda: NOW)
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    value = ConversionJournal.provision(
        directory, tmp_path / "source-owner.json", helpers.AUTHORITY
    )
    helpers.dispatched(value)
    return value


def financial_state(journal: ConversionJournal) -> tuple[object, ...]:
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        return tuple(
            db.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608 - fixed local test-owned table names
            for table in ("metadata", "credits", "holds", "jobs")
        )


def test_fenced_completion_consumes_actual_debit_and_releases_full_hold_once(
    journal: ConversionJournal,
) -> None:
    query = journal.begin_capacity_query()
    receipt = helpers.receipt()
    completed = journal.complete("conversion_op_01", receipt, expected_query=query)
    assert completed.state == "complete"
    assert completed.receipt == receipt
    assert journal.begin_capacity_query().generation == query.generation + 1
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        assert db.execute("SELECT consumed_msat FROM credits").fetchall() == [(40001000,)]
        assert db.execute("SELECT * FROM holds").fetchall() == []
    before = financial_state(journal)
    stale = query.model_copy(update={"journal_id": "f" * 64, "started_at": query.started_at - 1000})
    assert (
        helpers.reopen(journal).complete("conversion_op_01", receipt, expected_query=stale)
        == completed
    )
    assert financial_state(journal) == before
    with pytest.raises(ConversionJournalError, match="receipt changed"):
        journal.complete(
            "conversion_op_01", helpers.receipt(destination_txid="f" * 64), expected_query=stale
        )
    assert financial_state(journal) == before


@pytest.mark.parametrize(
    "fault",
    [
        "journal",
        "generation",
        "future",
        "expired",
        "nan",
        "inf",
        "huge_clock",
        "clock_rollback",
        "coerced_generation",
        "invalid_query",
    ],
)
def test_invalid_observation_refuses_before_financial_mutation(
    journal: ConversionJournal, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    query = journal.begin_capacity_query()
    before = financial_state(journal)
    if fault == "journal":
        query = query.model_copy(update={"journal_id": "f" * 64})
    elif fault == "generation":
        query = query.model_copy(update={"generation": query.generation + 1})
    elif fault == "future":
        query = query.model_copy(update={"started_at": NOW + 1})
    elif fault == "expired":
        query = query.model_copy(update={"started_at": NOW - 11})
    elif fault == "nan":
        monkeypatch.setattr(time, "time", lambda: float("nan"))
    elif fault == "inf":
        monkeypatch.setattr(time, "time", lambda: float("inf"))
    elif fault == "huge_clock":
        monkeypatch.setattr(time, "time", lambda: 10**1000)
    elif fault == "clock_rollback":
        monkeypatch.setattr(time, "time", lambda: NOW - 1)
    elif fault == "coerced_generation":
        query = query.model_copy(update={"generation": True})
    else:
        query = object()  # type: ignore[assignment] # Explicit invalid runtime query admission.
    with pytest.raises(ConversionJournalError, match="observation changed or expired"):
        journal.complete("conversion_op_01", helpers.receipt(), expected_query=query)
    assert financial_state(journal) == before


def test_lock_admission_clock_is_checked_after_transaction_acquisition(
    journal: ConversionJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    query = journal.begin_capacity_query()
    before = financial_state(journal)
    original = journal._transaction  # noqa: SLF001 - inject only time after actual BEGIN IMMEDIATE

    @contextmanager
    def locked() -> Iterator[sqlite3.Connection]:
        with original() as db:
            # Model a BEGIN IMMEDIATE wait ending after the age bound. No RPC
            # delay and no financial statement is skipped or stubbed.
            monkeypatch.setattr(time, "time", lambda: NOW + 11)
            yield db

    monkeypatch.setattr(journal, "_transaction", locked)
    with pytest.raises(ConversionJournalError, match="observation changed or expired"):
        journal.complete("conversion_op_01", helpers.receipt(), expected_query=query)
    assert financial_state(journal) == before


@pytest.mark.parametrize("effect", ["dispatch", "complete"])
def test_other_job_financial_effect_between_acquisition_and_completion_invalidates_query(
    journal: ConversionJournal, effect: str
) -> None:
    second = helpers.reserve(
        journal,
        helpers.request(
            "conversion_op_02",
            allocations=(
                helpers.Allocation(payment_hash=helpers.CREDIT.payment_hash, amount_msat=3000000),
            ),
            max_source_debit_msat=3000000,
            max_fee_msat=200000,
            max_routing_fee_msat=1000,
            requested_payout_sat=2800,
            minimum_output_sat=2800,
        ),
    )
    right = journal.invoke(second)
    prepared = helpers.PREPARED.model_copy(
        update={
            "contract_hash": "f" * 64,
            "payment_hash": "e" * 64,
            "invoice_sha256": "d" * 64,
            "invoice_amount_msat": 2900000,
            "minimum_net_output_sat": 2800,
            "routing_fee_ceiling_msat": 1000,
        }
    )
    journal.checkpoint(right, prepared, helpers.CIPHERTEXT, verify_from_disk=helpers.verify)
    if effect == "complete":
        journal.dispatch(right, prepared.payment_hash)
    query = journal.begin_capacity_query()
    if effect == "dispatch":
        journal.dispatch(right, prepared.payment_hash)
    else:
        journal.complete(
            "conversion_op_02",
            helpers.receipt(
                payment_hash=prepared.payment_hash,
                invoice_sha256=prepared.invoice_sha256,
                amount_msat=prepared.invoice_amount_msat,
                destination_txid="e" * 64,
                destination_value_sat=2800,
            ),
        )
    before = financial_state(journal)
    with pytest.raises(ConversionJournalError, match="observation changed or expired"):
        journal.complete("conversion_op_01", helpers.receipt(), expected_query=query)
    assert financial_state(journal) == before
    assert journal.status("conversion_op_01").state == "dispatched"
