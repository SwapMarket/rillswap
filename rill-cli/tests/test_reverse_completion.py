"""Explicit completion uses native receipt evidence, never a persisted receipt."""

from __future__ import annotations

import os
import sqlite3
import time
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from rill_crypto import Context
from test_reverse_reconciliation import Case

from rill_cli import reverse_reconciliation as module
from rill_cli.conversion_journal import ConversionJob, ConversionJournal, ConversionReceipt

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

pytestmark = [
    pytest.mark.native_crypto,
    pytest.mark.skipif(
        os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
        reason="explicit native completion conformance opt-in",
    ),
]


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Case]:
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        value = Case(tmp_path, monkeypatch, crypto)
        # Receipt-only tests retain their strict never-complete spy. This fixture
        # explicitly restores the REAL transactional journal completion method.
        monkeypatch.setattr(
            value.harness.journal,
            "complete",
            ConversionJournal.complete.__get__(value.harness.journal),
        )
        yield value


def reconcile(case: Case, **changes: Any) -> ConversionJob:  # noqa: ANN401 - explicit input-fault matrix
    arguments = {
        "config": case.harness.config,
        "credentials": case.credentials,
        "crypto": case.crypto,
        "funding_recovery_path": case.candidate_path,
        "funding_attempt_id": case.binding.funding_attempt_id,
        "binding_revision": 0,
        "funding_block": module.BlockHint(height=970, block_hash="b" * 64),
        "claim_txid": case.claim.txid,
        "claim_path": case.path,
        "custody": case.custody,
    } | changes
    return module.reconcile_conversion(
        case.harness.journal, case.harness.request.operation_id, **arguments
    )


def inventory(case: Case) -> tuple[object, ...]:
    with sqlite3.connect(case.harness.journal.directory / "inventory.sqlite") as db:
        return (
            db.execute("SELECT * FROM metadata").fetchall(),
            db.execute("SELECT * FROM credits").fetchall(),
            db.execute("SELECT * FROM holds").fetchall(),
            db.execute("SELECT * FROM jobs").fetchall(),
        )


def refused(case: Case, **changes: Any) -> None:  # noqa: ANN401 - explicit input-fault matrix
    with pytest.raises(
        module.ReverseReconciliationError, match="original conversion reconciliation unavailable"
    ) as failure:
        reconcile(case, **changes)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


@pytest.mark.parametrize("path", ["cooperative", "unilateral"])
def test_explicit_native_reconciliation_consumes_actual_debit_and_is_history_only_when_terminal(
    case: Case, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    case.set_path(path)
    journal = case.harness.journal
    generation = journal.begin_capacity_query().generation
    completed = reconcile(case)
    assert completed.state == "complete"
    assert completed.receipt is not None
    assert completed.receipt.destination_txid == case.claim.txid
    assert journal.begin_capacity_query().generation == generation + 1
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        assert db.execute("SELECT consumed_msat FROM credits").fetchall() == [
            (case.payment.amount_msat + case.payment.routing_fee_msat,)
        ]
        assert db.execute("SELECT * FROM holds").fetchall() == []
    before = inventory(case)
    # A repeated terminal call is status, not another proof/payment/custody read.
    case.candidate_path.unlink()
    case.initial_path.unlink()
    for name in (
        "CoreTransactionReader",
        "WalletRpc",
        "LndTreasuryObserver",
        "collect_conversion_receipt",
    ):
        monkeypatch.setattr(
            module, name, Mock(side_effect=AssertionError("no terminal acquisition"))
        )
    assert reconcile(case) == completed
    assert inventory(case) == before


def test_generation_change_after_native_collection_refuses_completion_with_full_hold(
    case: Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = case.harness.journal
    collect = module.collect_conversion_receipt

    def changed(*args: Any, **kwargs: Any) -> ConversionReceipt:  # noqa: ANN401 - real acquisition followed by concurrent persisted generation
        receipt = collect(*args, **kwargs)
        with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
            db.execute("UPDATE metadata SET capacity_generation=capacity_generation+1")
        return receipt

    monkeypatch.setattr(module, "collect_conversion_receipt", changed)
    before = inventory(case)
    refused(case)
    after = inventory(case)
    assert after[1:] == before[1:]
    assert journal.status(case.harness.request.operation_id).state == "dispatched"


@pytest.mark.parametrize(
    "fault",
    ["receipt_unavailable", "custody", "wall_age", "monotonic", "monotonic_nan", "commit_ack_lost"],
)
def test_explicit_completion_never_replays_effects_or_overstates_unknown_commit(
    case: Case, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    before = inventory(case)
    collect = module.collect_conversion_receipt
    changes: dict[str, Any] = {}
    if fault == "custody":
        changes["custody"] = case.custody.model_copy(update={"core_wallet": "unknown"})
    elif fault == "receipt_unavailable":
        case.hashes[990] = "e" * 64
    elif fault in {"wall_age", "monotonic", "monotonic_nan"}:

        def late(*args: Any, **kwargs: Any) -> ConversionReceipt:  # noqa: ANN401 - preserve native proof, invalidate boundary time only
            receipt = collect(*args, **kwargs)
            if fault == "wall_age":
                case.now += 11
            else:
                monkeypatch.setattr(
                    time, "monotonic", lambda: 110.0 if fault == "monotonic" else float("nan")
                )
            return receipt

        monkeypatch.setattr(module, "collect_conversion_receipt", late)
    else:
        complete = case.harness.journal.complete

        def lost(*args: Any, **kwargs: Any) -> None:  # noqa: ANN401 - simulate durable commit with lost caller acknowledgment
            complete(*args, **kwargs)
            raise OSError("SECRET_CANARY")

        monkeypatch.setattr(case.harness.journal, "complete", lost)
    refused(case, **changes)
    if fault == "commit_ack_lost":
        job = case.harness.journal.status(case.harness.request.operation_id)
        assert job.state == "complete"
        assert job.receipt is not None
        assert reconcile(case) == job
    else:
        assert inventory(case) == before
        assert case.harness.journal.status(case.harness.request.operation_id).state == "dispatched"
