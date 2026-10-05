"""Accounting admission shares liabilities, never the spendable/refund contract."""

from __future__ import annotations

import sqlite3
import time
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError
from test_conversion_journal import (
    AUTHORITY,
    CIPHERTEXT,
    CREDIT,
    NETWORK,
    NODE,
    PREPARED,
    availability,
    receipt,
    reopen,
    request,
    verify,
)
from test_conversion_journal import (
    journal as _journal_fixture,
)

from rill_cli.conversion_journal import (
    Allocation,
    ConversionJournal,
    ConversionJournalError,
    InventoryAccountingEligibility,
)

if TYPE_CHECKING:
    from pathlib import Path

journal = _journal_fixture


def accounting(journal: ConversionJournal, **updates: object) -> InventoryAccountingEligibility:
    return InventoryAccountingEligibility.model_validate(
        {
            "source_node": NODE,
            "network": NETWORK,
            "query": journal.begin_capacity_query(),
            "observed_at": int(time.time()),
            "accounting_net_msat": 100_000_000,
            "coverage_complete": True,
            "commitments_known": True,
        }
        | updates
    )


def test_explicit_accounting_admission_does_not_persist_payability_or_change_schema(
    journal: ConversionJournal,
) -> None:
    reserved = journal.reserve_accounting_conversion(
        request(), credits=(CREDIT,), eligibility=accounting(journal)
    )
    assert reserved.job.state == "reserved"
    assert not hasattr(reserved.job, "spendable_msat")
    assert not hasattr(reserved.job, "accounting_net_msat")
    assert reopen(journal).status(reserved.job.request.operation_id) == reserved.job
    assert not hasattr(accounting(journal), "spendable_msat")


@pytest.mark.parametrize("field", ["coverage_complete", "commitments_known"])
@pytest.mark.parametrize("value", [False, 1, "true", None])
def test_assertions_are_affirmative_not_coerced(
    journal: ConversionJournal, field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        accounting(journal, **{field: value})


@pytest.mark.parametrize("budget", [45_999_999, 0])
def test_accounting_threshold_respects_fixed_reserve_and_rolls_back_credit(
    journal: ConversionJournal, budget: int
) -> None:
    approved = request()
    with pytest.raises(ConversionJournalError, match="commitments exceed"):
        journal.reserve_accounting_conversion(
            approved, credits=(CREDIT,), eligibility=accounting(journal, accounting_net_msat=budget)
        )
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        for table in ("credits", "holds", "jobs"):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)  # noqa: S608 - closed test-only table names
    with pytest.raises(ConversionJournalError, match="unknown"):
        journal.status(approved.operation_id)
    # A fresh complete observation can create the same job only because the
    # failed transaction imported no credit or hold and granted no live right.
    result = journal.reserve_accounting_conversion(
        approved, credits=(CREDIT,), eligibility=accounting(journal, accounting_net_msat=46_000_000)
    )
    assert result.job.request == approved


def test_accounting_and_refund_compete_but_accounting_never_promises_refunds(
    journal: ConversionJournal,
) -> None:
    journal.reserve_refund(
        "refund_promise_01",
        Allocation(payment_hash=CREDIT.payment_hash, amount_msat=1_000_000),
        credits=(CREDIT,),
        availability=availability(journal),
    )
    with pytest.raises(ConversionJournalError, match="commitments exceed"):
        journal.reserve_accounting_conversion(
            request(),
            credits=(CREDIT,),
            eligibility=accounting(journal, accounting_net_msat=46_000_000),
        )
    reserved = journal.reserve_accounting_conversion(
        request(),
        credits=(CREDIT,),
        eligibility=accounting(journal, accounting_net_msat=47_000_000),
    )
    assert reserved.job.state == "reserved"
    with pytest.raises(ConversionJournalError, match=r"spendable.*refunds"):
        journal.reserve_refund(
            "refund_promise_02",
            Allocation(payment_hash=CREDIT.payment_hash, amount_msat=1),
            credits=(CREDIT,),
            availability=accounting(journal),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("first_accounting", [True, False])
def test_cross_method_replay_never_grants_new_invocation_right(
    journal: ConversionJournal, *, first_accounting: bool
) -> None:
    approved = request()
    if first_accounting:
        original = journal.reserve_accounting_conversion(
            approved, credits=(CREDIT,), eligibility=accounting(journal)
        )
        replay = journal.reserve(approved, credits=(CREDIT,), availability=availability(journal))
    else:
        original = journal.reserve(approved, credits=(CREDIT,), availability=availability(journal))
        replay = journal.reserve_accounting_conversion(
            approved, credits=(CREDIT,), eligibility=accounting(journal)
        )
    assert replay.job == original.job
    with pytest.raises(ConversionJournalError, match="no invocation owner"):
        journal.invoke(replay)
    journal.invoke(original)
    opened = reopen(journal)
    replay = opened.reserve_accounting_conversion(
        approved, credits=(CREDIT,), eligibility=accounting(opened)
    )
    assert replay.job.state == "invoked"
    with pytest.raises(ConversionJournalError, match="no invocation owner"):
        opened.invoke(replay)


def test_old_conversion_entry_refuses_accounting_even_for_replay(
    journal: ConversionJournal,
) -> None:
    approved = request()
    journal.reserve_accounting_conversion(
        approved, credits=(CREDIT,), eligibility=accounting(journal)
    )
    with pytest.raises(ConversionJournalError, match="spendable"):
        journal.reserve(approved, credits=(CREDIT,), availability=accounting(journal))  # type: ignore[arg-type]
    with pytest.raises(ConversionJournalError, match="explicit inventory accounting"):
        journal.reserve_accounting_conversion(
            approved,
            credits=(CREDIT,),
            eligibility=availability(journal),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("fault", ["source_node", "network", "query", "observed_at"])
def test_accounting_identity_or_freshness_mismatch_refuses(
    journal: ConversionJournal, fault: str
) -> None:
    evidence = accounting(journal)
    updates = {
        "source_node": "03" + NODE[2:],
        "network": NETWORK.model_copy(update={"deployment_namespace": "another-source"}),
        "query": evidence.query.model_copy(update={"started_at": int(time.time()) - 11}),
        "observed_at": int(time.time()) + 1,
    }
    changed = evidence.model_copy(update={fault: updates[fault]})
    with pytest.raises(ConversionJournalError, match="fresh"):
        journal.reserve_accounting_conversion(request(), credits=(CREDIT,), eligibility=changed)


def test_modified_model_cannot_fake_coverage(journal: ConversionJournal) -> None:
    evidence = accounting(journal).model_copy(update={"coverage_complete": 1})
    with pytest.raises(ValidationError):
        journal.reserve_accounting_conversion(request(), credits=(CREDIT,), eligibility=evidence)


@pytest.mark.parametrize("phase", ["reserved", "invoked", "prepared", "dispatched"])
def test_restart_retains_accounting_holds_without_observation_or_live_right(
    journal: ConversionJournal,
    phase: str,
) -> None:
    approved = request()
    reservation = journal.reserve_accounting_conversion(
        approved, credits=(CREDIT,), eligibility=accounting(journal)
    )
    if phase != "reserved":
        right = journal.invoke(reservation)
        if phase in ("prepared", "dispatched"):
            journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)
        if phase == "dispatched":
            journal.dispatch(right, PREPARED.payment_hash)
    opened = reopen(journal)
    assert opened.status(approved.operation_id).state == phase
    other = request("another_accounting_01")
    with pytest.raises(ConversionJournalError, match="already consumed or reserved"):
        opened.reserve_accounting_conversion(
            other, credits=(CREDIT,), eligibility=accounting(opened)
        )


@pytest.mark.parametrize("invalidate", ["dispatch", "complete"])
def test_accounting_generation_refuses_delayed_pre_effect_observation(
    journal: ConversionJournal,
    invalidate: str,
) -> None:
    delayed = accounting(journal)
    reservation = journal.reserve_accounting_conversion(
        request(), credits=(CREDIT,), eligibility=accounting(journal)
    )
    right = journal.invoke(reservation)
    journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)
    journal.dispatch(right, PREPARED.payment_hash)
    if invalidate == "complete":
        delayed = accounting(journal)
        journal.complete("conversion_op_01", receipt())
    # Fresh response timestamps cannot refresh an obsolete durable generation.
    delayed = delayed.model_copy(update={"observed_at": int(time.time())})
    with pytest.raises(ConversionJournalError, match="fresh"):
        journal.reserve_accounting_conversion(
            request("another_generation_01"), credits=(CREDIT,), eligibility=delayed
        )


def test_accounting_completion_releases_only_unused_budget_not_credit_consumption(
    journal: ConversionJournal,
) -> None:
    reserved = journal.reserve_accounting_conversion(
        request(), credits=(CREDIT,), eligibility=accounting(journal)
    )
    right = journal.invoke(reserved)
    journal.checkpoint(right, PREPARED, CIPHERTEXT, verify_from_disk=verify)
    journal.dispatch(right, PREPARED.payment_hash)
    journal.complete("conversion_op_01", receipt())
    with pytest.raises(ConversionJournalError, match="already consumed"):
        journal.reserve_accounting_conversion(
            request("another_completed_01"), credits=(CREDIT,), eligibility=accounting(journal)
        )


def test_compatible_store_open_performs_no_migration_or_auto_import(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    old = ConversionJournal.provision(directory, tmp_path / "source-owner.json", AUTHORITY)
    old.reserve(request(), credits=(CREDIT,), availability=availability(old))
    with sqlite3.connect(directory / "inventory.sqlite") as db:
        before = tuple(db.iterdump())
    opened = reopen(old)
    with sqlite3.connect(directory / "inventory.sqlite") as db:
        assert tuple(db.iterdump()) == before
    assert opened.status("conversion_op_01").state == "reserved"
