"""Native collector through the operator CLI with synthetic RPC observations."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import replace
from importlib import import_module
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from rill_crypto import Context
from test_reverse_reconciliation import Case

from rill_cli import main as cli
from rill_cli import reverse_reconciliation as reconciliation
from rill_cli import treasury_cli as module
from rill_cli.conversion_journal import ConversionJob, ConversionJournal, ConversionReceipt

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

helpers = import_module("test_treasury_cli")
pytestmark = [
    pytest.mark.native_crypto,
    pytest.mark.skipif(
        os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
        reason="explicit native operator completion conformance opt-in",
    ),
]


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Case]:
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        value = Case(tmp_path, monkeypatch, crypto)
        monkeypatch.setattr(
            value.harness.journal,
            "complete",
            ConversionJournal.complete.__get__(value.harness.journal),
        )
        yield value


def inputs(case: Case) -> dict[str, Any]:
    root = case.harness.journal.directory.parent
    authority = case.harness.journal.authority
    authority_path = helpers.private(
        root / "operator-authority.json", authority.model_dump(mode="json")
    )
    identity_path = root / "operator.identity"
    identity_path.write_text(case.credentials.identity + "\n")
    identity_path.chmod(0o600)
    configuration = case.harness.config
    document = {
        "version": "conversion-reconciliation/regtest/v1",
        "rpc": {
            "lnd_port": configuration.lnd_port,
            "lnd_tls_root_path": str(configuration.lnd_tls_root_path),
            "lnd_read_macaroon_path": str(configuration.lnd_read_macaroon_path),
            "core_port": configuration.core_port,
            "core_cookie_path": str(configuration.core_cookie_path),
        },
        "identity_path": str(identity_path),
        "funding_recovery_path": str(case.candidate_path),
        "funding_attempt_id": case.binding.funding_attempt_id,
        "binding_revision": 0,
        "funding_block": {"height": 970, "block_hash": "b" * 64},
        "claim_txid": case.claim.txid,
        "claim_path": case.path,
        "custody": case.custody.model_dump(mode="json"),
    }
    return {
        "journal": case.harness.journal,
        "authority": authority,
        "authority_path": authority_path,
        "identity_path": identity_path,
        "document": document,
        "evidence": helpers.private(root / "operator-evidence.json", document),
        "base": [
            "--journal-directory",
            str(case.harness.journal.directory),
            "--source-fence",
            str(case.harness.journal.source_fence),
            "--authority",
            str(authority_path),
            "--operation-id",
            case.harness.request.operation_id,
        ],
    }


def arguments(value: dict[str, Any]) -> list[str]:
    args: list[str] = helpers.arguments(value)
    args[-1] = os.environ["RILL_CRYPTO_LIBRARY"]
    return args


@pytest.mark.parametrize("path", ["cooperative", "unilateral"])
def test_real_native_cli_completion_consumes_once_and_terminal_bypasses_all_acquisition(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], path: str
) -> None:
    case.set_path(path)
    value = inputs(case)
    journal = case.harness.journal
    generation = journal.begin_capacity_query().generation
    assert cli.main(arguments(value)) == 0
    output = capsys.readouterr()
    assert (
        output.out
        == "Recorded conversion state: complete (historical status, not fresh validation).\n"
    )
    assert output.err == ""
    assert journal.status(case.harness.request.operation_id).state == "complete"
    assert journal.begin_capacity_query().generation == generation + 1
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        assert db.execute("SELECT consumed_msat FROM credits").fetchall() == [
            (case.payment.amount_msat + case.payment.routing_fee_msat,)
        ]
        assert db.execute("SELECT * FROM holds").fetchall() == []
    before = helpers.rows(journal)
    value["evidence"].unlink()
    value["identity_path"].unlink()
    monkeypatch.setattr(module, "Context", Mock(side_effect=AssertionError("SECRET_CANARY")))
    monkeypatch.setattr(
        module, "reconcile_conversion", Mock(side_effect=AssertionError("SECRET_CANARY"))
    )
    assert cli.main(arguments(value)) == 0
    assert capsys.readouterr().out == output.out
    assert helpers.rows(journal) == before


@pytest.mark.parametrize(
    "fault", ["native_signature", "generation", "lost_ack", "concurrent_complete"]
)
def test_native_cli_errors_preserve_or_report_actual_commit_without_reexecution(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], fault: str
) -> None:
    value = inputs(case)
    journal = case.harness.journal
    before = helpers.rows(journal)
    generation = journal.begin_capacity_query().generation
    actual = reconciliation.reconcile_conversion
    if fault == "native_signature":
        original = case.transaction
        mutated = bytearray(case.claim.raw_transaction)
        mutated[case.claim.raw_transaction.index(case.signature)] ^= 1
        case.core.observe_block_transaction.side_effect = lambda txid, **kwargs: (
            replace(original(txid, **kwargs), raw_transaction=bytes(mutated))
            if txid == case.claim.txid
            else original(txid, **kwargs)
        )
    elif fault == "generation":
        collect = reconciliation.collect_conversion_receipt

        def changed(*args: Any, **kwargs: Any) -> ConversionReceipt:  # noqa: ANN401 - actual native acquisition, then a competing persisted effect
            receipt = collect(*args, **kwargs)
            with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
                db.execute("UPDATE metadata SET capacity_generation=capacity_generation+1")
            return receipt

        monkeypatch.setattr(reconciliation, "collect_conversion_receipt", changed)
    else:

        def completed(*args: Any, **kwargs: Any) -> ConversionJob:  # noqa: ANN401 - real guarded completion followed by acknowledgment/race disposition
            actual(*args, **kwargs)
            if fault == "lost_ack":
                raise OSError("SECRET_CANARY")
            # Model the competing caller finishing after CLI precheck; the real
            # wrapper's second invocation now returns only persisted history.
            return actual(*args, **kwargs)

        monkeypatch.setattr(module, "reconcile_conversion", completed)
    expected = 0 if fault == "concurrent_complete" else 2
    assert cli.main(arguments(value)) == expected
    output = capsys.readouterr()
    assert "SECRET_CANARY" not in output.out + output.err
    after = helpers.rows(journal)
    if fault in ("lost_ack", "concurrent_complete"):
        assert journal.status(case.harness.request.operation_id).state == "complete"
        assert journal.begin_capacity_query().generation == generation + 1
        with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
            assert db.execute("SELECT consumed_msat FROM credits").fetchall() == [
                (case.payment.amount_msat + case.payment.routing_fee_msat,)
            ]
            assert db.execute("SELECT * FROM holds").fetchall() == []
        assert cli.main(helpers.arguments(value, "status")) == 0
        assert "Recorded conversion state: complete" in capsys.readouterr().out
        assert helpers.rows(journal) == after
        if fault == "lost_ack":
            assert "may already be recorded" in output.err
    elif fault == "generation":
        assert after[1:] == before[1:]
    else:
        assert after == before
