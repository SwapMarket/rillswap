"""Explicit v2 lookup input, never producer proof or saved confirmation authority."""

from __future__ import annotations

import inspect
import os
import sqlite3
from dataclasses import replace
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar
from unittest.mock import Mock

import pyrage
import pytest
from pyrage import x25519
from rill_core.wire.canonical import canonicalize
from rill_crypto import Context
from test_reverse_reconciliation import CLAIM_HASH, FUND_HASH, Case
from test_treasury_cli import arguments, private, rows
from test_treasury_cli import inputs as _inputs_fixture

from rill_cli import main as cli
from rill_cli import reverse_reconciliation as reconciliation
from rill_cli import treasury_cli as module
from rill_cli.conversion_journal import ConversionJournal
from rill_cli.funding_inclusion import (
    FundingInclusionHint,
    LookupBlock,
    publish_funding_inclusion_hint,
)

HELPERS = import_module("test_treasury_cli")
inputs = _inputs_fixture  # re-export the existing fixture without editing its body

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rill_cli.wallet_rpc import HistoricalWalletOutput


def saved_document(value: dict[str, Any], path: Path) -> dict[str, Any]:
    document = dict(value["document"])
    document["version"] = "conversion-reconciliation/regtest/v2"
    del document["funding_block"]
    document["funding_inclusion_hint_path"] = str(path)
    private(value["evidence"], document)
    return document


def test_lookup_versions_preserve_required_v1_fields_and_old_library_omission_errors() -> None:
    old = module.ReconciliationEvidence.model_json_schema()["required"]
    saved = module.SavedReconciliationEvidence.model_json_schema()["required"]
    assert "funding_block" in old
    assert "funding_inclusion_hint_path" not in old
    assert "funding_inclusion_hint_path" in saved
    assert "funding_block" not in saved
    assert module.ReconciliationEvidence.model_fields["version"].is_required()
    for function in (
        reconciliation.collect_conversion_receipt,
        reconciliation.reconcile_conversion,
    ):
        assert (
            inspect.signature(function).parameters["funding_block"].default
            is inspect.Parameter.empty
        )


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "relative",
        "plain_block",
        "old_version",
        "unknown_version",
        "unknown_field",
        "duplicate",
    ],
)
def test_saved_manifest_is_strict_and_never_reinterprets_v1(
    inputs: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fault: str,
) -> None:
    document = saved_document(inputs, inputs["evidence"].parent / "saved.age")
    if fault == "missing":
        del document["funding_inclusion_hint_path"]
    elif fault == "relative":
        document["funding_inclusion_hint_path"] = "saved.age"
    elif fault == "plain_block":
        document["funding_block"] = {"height": 1, "block_hash": "b" * 64}
    elif fault == "old_version":
        document["version"] = "conversion-reconciliation/regtest/v1"
    elif fault == "unknown_version":
        document["version"] = "conversion-reconciliation/regtest/v3"
    elif fault == "unknown_field":
        document["recorded_receipt"] = {"PRIVATE_CANARY": True}
    private(inputs["evidence"], document)
    if fault == "duplicate":
        inputs["evidence"].write_bytes(b'{"version":"PRIVATE_CANARY",' + canonicalize(document)[1:])
    context = Mock(side_effect=AssertionError("PRIVATE_CANARY"))
    monkeypatch.setattr(module, "Context", context)
    before = rows(inputs["journal"])
    assert cli.main(arguments(inputs)) == 2
    assert "PRIVATE_CANARY" not in capsys.readouterr().err
    context.assert_not_called()
    assert rows(inputs["journal"]) == before


def test_saved_manifest_forwards_only_explicit_path_and_never_loads_payment_credential(
    inputs: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = inputs["evidence"].parent / "saved.age"
    saved_document(inputs, path)
    crypto = Mock()
    context = Mock()
    context.return_value.__enter__ = Mock(return_value=crypto)
    context.return_value.__exit__ = Mock(return_value=None)
    monkeypatch.setattr(module, "Context", context)
    seen = []

    def complete(_journal: object, operation_id: str, **kwargs: Any) -> object:  # noqa: ANN401 - preserve exact new/old forwarding contract
        seen.append(kwargs)
        assert operation_id == "conversion_op_01"
        assert kwargs["funding_block"] is None
        assert kwargs["funding_inclusion_hint_path"] == path
        config = kwargs["config"]
        assert config.lnd_read_macaroon_path == config.lnd_payment_macaroon_path
        return inputs["journal"].complete(
            operation_id, HELPERS.helpers.receipt(network=inputs["authority"].network)
        )

    monkeypatch.setattr(module, "reconcile_conversion", complete)
    assert cli.main(arguments(inputs)) == 0
    assert len(seen) == 1
    assert capsys.readouterr().err == ""
    before = rows(inputs["journal"])
    inputs["evidence"].unlink()
    inputs["identity_path"].unlink()
    monkeypatch.setattr(module, "_evidence", Mock(side_effect=AssertionError("PRIVATE_CANARY")))
    context.reset_mock()
    assert cli.main(arguments(inputs)) == 0
    assert "historical status" in capsys.readouterr().out
    context.assert_not_called()
    assert rows(inputs["journal"]) == before


@pytest.mark.parametrize(
    "inputs", ["reserved", "invoked", "checkpointing", "prepared"], indirect=True
)
def test_other_recorded_states_never_admit_saved_manifest(
    inputs: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    saved_document(inputs, inputs["evidence"].parent / "absent.age")
    evidence = Mock(side_effect=AssertionError("PRIVATE_CANARY"))
    context = Mock(side_effect=AssertionError("PRIVATE_CANARY"))
    monkeypatch.setattr(module, "_evidence", evidence)
    monkeypatch.setattr(module, "Context", context)
    before = rows(inputs["journal"])
    assert cli.main(arguments(inputs)) == 2
    assert "PRIVATE_CANARY" not in capsys.readouterr().err
    evidence.assert_not_called()
    context.assert_not_called()
    assert rows(inputs["journal"]) == before


class TestNativeSavedFunding:
    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [
        pytest.mark.native_crypto,
        pytest.mark.skipif(
            os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
            reason="explicit native saved-hint admission opt-in",
        ),
    ]

    @pytest.fixture
    def case(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Case]:
        # Set the new explicit approval before reservation, never mutate persisted
        # requests or weaken/rewrite the old fixture's depth-1 contract.
        old = import_module("test_reverse_conversion")
        request = old.ConversionRequest

        def approved(**kwargs: Any) -> object:  # noqa: ANN401 - actual request construction with this test's depth policy
            return request(**kwargs).model_copy(update={"confirmation_blocks": 3})

        monkeypatch.setattr(old, "ConversionRequest", approved)
        with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
            value = Case(tmp_path, monkeypatch, crypto)
            monkeypatch.setattr(
                value.harness.journal,
                "complete",
                ConversionJournal.complete.__get__(value.harness.journal),
            )
            yield value

    @staticmethod
    def hint(case: Case) -> FundingInclusionHint:
        return FundingInclusionHint(
            version="conversion-funding-inclusion/regtest/v1",
            operation_id=case.harness.request.operation_id,
            network=case.harness.authority.network,
            original_recovery_sha256=case.job.recovery_sha256,
            funding_binding=case.binding,
            funding_block=LookupBlock(height=970, block_hash=FUND_HASH),
            sampled_tip=LookupBlock(height=1000, block_hash="a" * 64),
            confirmations=31,
        )

    @classmethod
    def saved(cls, case: Case) -> tuple[dict[str, Any], Path]:
        native = import_module("test_treasury_cli_native")
        value = native.inputs(case)
        path = case.harness.journal.directory.parent / "saved-funding.age"
        publish_funding_inclusion_hint(
            path, cls.hint(case), credentials=case.credentials, publication_allowed=lambda: None
        )
        saved_document(value, path)
        return value, path

    @pytest.mark.parametrize("path", ["cooperative", "unilateral"])
    def test_native_saved_lookup_completes_once_and_terminal_needs_no_artifacts(
        self,
        case: Case,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        path: str,
    ) -> None:
        case.set_path(path)
        value, hint = self.saved(case)
        native = import_module("test_treasury_cli_native")
        journal = case.harness.journal
        generation = journal.begin_capacity_query().generation
        assert journal.status(case.harness.request.operation_id).request.confirmation_blocks == 3
        assert cli.main(native.arguments(value)) == 0
        recorded = capsys.readouterr()
        assert recorded.err == ""
        assert "complete (historical status" in recorded.out
        assert journal.begin_capacity_query().generation == generation + 1
        with sqlite3.connect(journal.directory / "inventory.sqlite") as database:
            assert database.execute("SELECT consumed_msat FROM credits").fetchall() == [
                (case.payment.amount_msat + case.payment.routing_fee_msat,)
            ]
            assert database.execute("SELECT * FROM holds").fetchall() == []
        before = rows(journal)
        hint.unlink()
        value["evidence"].unlink()
        value["identity_path"].unlink()
        monkeypatch.setattr(module, "Context", Mock(side_effect=AssertionError("PRIVATE_CANARY")))
        assert cli.main(arguments(value)) == 0  # deliberately missing library path
        assert capsys.readouterr().out == recorded.out
        assert rows(journal) == before

    @pytest.mark.parametrize(
        "fault",
        [
            "absent",
            "partial",
            "public",
            "symlink",
            "hardlink",
            "version",
            "operation",
            "network",
            "digest",
            "binding",
        ],
    )
    def test_bad_saved_hint_refuses_before_clients_without_fallback(  # noqa: PLR0912 - explicit unsafe-file and correlation failures
        self,
        case: Case,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        fault: str,
    ) -> None:
        value, path = self.saved(case)
        if fault == "absent":
            path.unlink()
        elif fault == "partial":
            path.write_bytes(b"PRIVATE_CANARY")
        elif fault == "public":
            path.chmod(0o644)
        elif fault == "symlink":
            path.unlink()
            path.symlink_to(path.parent / "absent.age")
        elif fault == "hardlink":
            os.link(path, path.parent / "second-link.age")
        else:
            document = self.hint(case).model_dump(mode="json")
            if fault == "version":
                document["version"] = "conversion-funding-inclusion/regtest/v0"
            elif fault == "operation":
                document["operation_id"] = "different-operation"
            elif fault == "network":
                document["network"]["deployment_namespace"] = "different"
            elif fault == "digest":
                document["original_recovery_sha256"] = "f" * 64
            elif fault == "binding":
                document["funding_binding"]["binding_revision"] = 1
            path.write_bytes(
                pyrage.encrypt(
                    canonicalize(document), [x25519.Recipient.from_str(case.credentials.recipient)]
                )
            )
        spies = [Mock(side_effect=AssertionError("PRIVATE_CANARY")) for _ in range(3)]
        for name, spy in zip(
            ("CoreTransactionReader", "WalletRpc", "LndTreasuryObserver"), spies, strict=True
        ):
            monkeypatch.setattr(reconciliation, name, spy)
        before = rows(case.harness.journal)
        native = import_module("test_treasury_cli_native")
        assert cli.main(native.arguments(value)) == 2
        assert "PRIVATE_CANARY" not in capsys.readouterr().err
        for spy in spies:
            spy.assert_not_called()
        assert rows(case.harness.journal) == before

    def test_fabricated_matching_history_cannot_override_fresh_required_claim_depth(
        self, case: Case, capsys: pytest.CaptureFixture[str]
    ) -> None:
        value, path = self.saved(case)
        invented = self.hint(case).model_copy(
            update={
                "sampled_tip": LookupBlock(height=1069, block_hash="f" * 64),
                "confirmations": 100,
            }
        )
        # No original AGE identity or SDK producer is used to fabricate this file.
        path.write_bytes(
            pyrage.encrypt(
                canonicalize(invented.model_dump(mode="json")),
                [x25519.Recipient.from_str(case.credentials.recipient)],
            )
        )
        history = case.history

        def two_confirmations(*args: Any, **kwargs: Any) -> HistoricalWalletOutput:  # noqa: ANN401 - coherent fresh observation, independent of saved count
            return replace(history(*args, **kwargs), confirmations=2, block_height=999)

        case.wallet.observe_historical_wallet_output.side_effect = two_confirmations
        case.hashes[999] = CLAIM_HASH
        before = rows(case.harness.journal)
        native = import_module("test_treasury_cli_native")
        assert cli.main(native.arguments(value)) == 2
        assert "PRIVATE_CANARY" not in capsys.readouterr().err
        assert case.calls  # hint was admitted, fresh acquisition still rejected
        assert case.wallet.observe_historical_wallet_output.call_count == 1
        assert rows(case.harness.journal) == before

    @pytest.mark.parametrize("fault", ["hash", "height"])
    def test_matching_saved_hint_still_requires_fresh_canonical_block_correspondence(
        self, case: Case, capsys: pytest.CaptureFixture[str], fault: str
    ) -> None:
        value, path = self.saved(case)
        if fault == "hash":
            hint = self.hint(case).model_copy(
                update={"funding_block": LookupBlock(height=970, block_hash="f" * 64)}
            )
        else:
            hint = self.hint(case).model_copy(
                update={
                    "funding_block": LookupBlock(height=971, block_hash=FUND_HASH),
                    "sampled_tip": LookupBlock(height=1001, block_hash="f" * 64),
                }
            )
        path.write_bytes(
            pyrage.encrypt(
                canonicalize(hint.model_dump(mode="json")),
                [x25519.Recipient.from_str(case.credentials.recipient)],
            )
        )
        before = rows(case.harness.journal)
        native = import_module("test_treasury_cli_native")
        assert cli.main(native.arguments(value)) == 2
        assert "PRIVATE_CANARY" not in capsys.readouterr().err
        assert case.calls
        assert rows(case.harness.journal) == before

    @pytest.mark.parametrize("choice", ["both", "neither", "relative", "string"])
    def test_exactly_one_explicit_lookup_source(self, case: Case, choice: str) -> None:
        _value, path = self.saved(case)
        options = {"funding_block": None, "funding_inclusion_hint_path": path}
        if choice == "both":
            options["funding_block"] = reconciliation.BlockHint(height=970, block_hash=FUND_HASH)
        elif choice == "neither":
            options["funding_inclusion_hint_path"] = None
        elif choice == "relative":
            options["funding_inclusion_hint_path"] = Path("saved.age")
        else:
            options["funding_inclusion_hint_path"] = str(path)
        before = rows(case.harness.journal)
        with pytest.raises(reconciliation.ReverseReconciliationError):
            case.collect(**options)
        assert case.calls == []
        assert rows(case.harness.journal) == before

    def test_valid_hint_that_exhausts_budget_never_constructs_observation_clients(
        self, case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        value, _path = self.saved(case)
        original = reconciliation.read_funding_inclusion_hint
        read = []

        def expired(*args: Any, **kwargs: Any) -> FundingInclusionHint:  # noqa: ANN401 - real decrypt/correlation before deterministic expiry
            hint = original(*args, **kwargs)
            read.append(hint)
            monkeypatch.setattr(reconciliation.time, "monotonic", lambda: 111.0)
            return hint

        monkeypatch.setattr(reconciliation, "read_funding_inclusion_hint", expired)
        spies = [Mock(side_effect=AssertionError("PRIVATE_CANARY")) for _ in range(3)]
        for name, spy in zip(
            ("CoreTransactionReader", "WalletRpc", "LndTreasuryObserver"), spies, strict=True
        ):
            monkeypatch.setattr(reconciliation, name, spy)
        before = rows(case.harness.journal)
        native = import_module("test_treasury_cli_native")
        assert cli.main(native.arguments(value)) == 2
        assert "PRIVATE_CANARY" not in capsys.readouterr().err
        assert len(read) == 1
        for spy in spies:
            spy.assert_not_called()
        assert case.calls == []
        assert rows(case.harness.journal) == before
