"""Local operator input boundaries and recorded status, with no financial RPCs."""

# ruff: noqa: C408
# Keyword-shaped fixture dictionaries mirror the nested operator configuration.

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from pyrage import x25519
from rill_core.networks import REGTEST_CONSENSUS_PROFILE
from rill_core.wire.canonical import canonicalize

from rill_cli import main as cli
from rill_cli import treasury_cli as module
from rill_cli.conversion_journal import ConversionJournal
from rill_cli.publication import RecoveryPublicationError

if TYPE_CHECKING:
    from rill_core.wire.canonical import JsonValue

helpers = import_module("test_conversion_journal")


def private(path: Path, value: JsonValue) -> Path:
    path.write_bytes(canonicalize(value))
    path.chmod(0o600)
    return path


@pytest.fixture
def inputs(tmp_path: Path, request: pytest.FixtureRequest) -> dict[str, Any]:
    network = helpers.NETWORK.model_copy(
        update={
            "genesis_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            "consensus_profile": REGTEST_CONSENSUS_PROFILE,
        }
    )
    authority = helpers.AUTHORITY.model_copy(update={"network": network})
    directory = tmp_path / "inventory"
    directory.mkdir(mode=0o700)
    journal = ConversionJournal.provision(directory, tmp_path / "fence.json", authority)
    reserved = journal.reserve(
        helpers.request(),
        credits=(helpers.CREDIT,),
        availability=helpers.availability(journal, network=network),
    )
    stage = getattr(request, "param", "dispatched")
    if stage != "reserved":
        right = journal.invoke(reserved)
        if stage == "checkpointing":
            with pytest.raises(RecoveryPublicationError):
                journal.checkpoint(
                    right,
                    helpers.PREPARED,
                    helpers.CIPHERTEXT,
                    verify_from_disk=lambda _stored: (_ for _ in ()).throw(
                        ValueError("unverified recovery")
                    ),
                )
        elif stage != "invoked":
            journal.checkpoint(
                right, helpers.PREPARED, helpers.CIPHERTEXT, verify_from_disk=helpers.verify
            )
            if stage != "prepared":
                journal.dispatch(right, helpers.PREPARED.payment_hash)
    authority_path = private(tmp_path / "authority.json", authority.model_dump(mode="json"))
    identity = x25519.Identity.generate()
    identity_path = tmp_path / "original.identity"
    identity_path.write_text(str(identity) + "\n")
    identity_path.chmod(0o600)
    document: dict[str, JsonValue] = dict(
        version="conversion-reconciliation/regtest/v1",
        rpc=dict(
            lnd_port=10010,
            lnd_tls_root_path=str(tmp_path / "lnd.cert"),
            lnd_read_macaroon_path=str(tmp_path / "read.mac"),
            core_port=18443,
            core_cookie_path=str(tmp_path / "core.cookie"),
        ),
        identity_path=str(identity_path),
        funding_recovery_path=str(tmp_path / "funded.age"),
        funding_attempt_id="a" * 64,
        binding_revision=0,
        funding_block=dict(height=1, block_hash="b" * 64),
        claim_txid="c" * 64,
        claim_path="cooperative",
        custody=dict(
            network=network.model_dump(mode="json"),
            script=authority.treasury_script,
            core_wallet="merchant",
            destination_keys_controlled=True,
        ),
    )
    evidence = private(tmp_path / "evidence.json", document)
    return dict(
        journal=journal,
        authority=authority,
        authority_path=authority_path,
        identity_path=identity_path,
        evidence=evidence,
        document=document,
        base=[
            "--journal-directory",
            str(directory),
            "--source-fence",
            str(journal.source_fence),
            "--authority",
            str(authority_path),
            "--operation-id",
            "conversion_op_01",
        ],
    )


def arguments(inputs: dict[str, Any], command: str = "reconcile") -> list[str]:
    return [
        "treasury",
        command,
        *inputs["base"],
        *(
            ["--evidence", str(inputs["evidence"]), "--crypto-library", "/missing/SECRET_CANARY.so"]
            if command == "reconcile"
            else []
        ),
    ]


def rows(journal: ConversionJournal) -> tuple[object, ...]:
    with sqlite3.connect(journal.directory / "inventory.sqlite") as db:
        return (
            db.execute("SELECT * FROM metadata").fetchall(),
            db.execute("SELECT * FROM jobs").fetchall(),
            db.execute("SELECT * FROM holds").fetchall(),
            db.execute("SELECT * FROM credits").fetchall(),
        )


def test_status_and_completed_reconcile_never_load_evidence_keys_or_library(
    inputs: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    journal = inputs["journal"]
    context = Mock(side_effect=AssertionError("SECRET_CANARY"))
    acquire = Mock(side_effect=AssertionError("SECRET_CANARY"))
    monkeypatch.setattr(module, "Context", context)
    monkeypatch.setattr(module, "reconcile_conversion", acquire)
    before = rows(journal)
    assert cli.main(arguments(inputs, "status")) == 0
    assert "dispatched" in capsys.readouterr().out
    assert rows(journal) == before
    completed = journal.complete(
        "conversion_op_01", helpers.receipt(network=inputs["authority"].network)
    )
    assert completed.state == "complete"
    before = rows(journal)
    inputs["identity_path"].unlink()
    inputs["evidence"].unlink()
    assert cli.main(arguments(inputs)) == 0
    output = capsys.readouterr()
    assert (
        output.out
        == "Recorded conversion state: complete (historical status, not fresh validation).\n"
    )
    assert output.err == ""
    assert rows(journal) == before
    assert context.call_count == acquire.call_count == 0


def test_installed_command_reports_only_recorded_state(inputs: dict[str, Any]) -> None:
    before = rows(inputs["journal"])
    completed = subprocess.run(  # noqa: S603 - fixed installed entrypoint, private values never argv
        [str(Path(sys.executable).with_name("rill")), *arguments(inputs, "status")],
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0
    assert (
        completed.stdout
        == b"Recorded conversion state: dispatched (historical status, not fresh validation).\n"
    )
    assert completed.stderr == b""
    assert rows(inputs["journal"]) == before


@pytest.mark.parametrize(
    "inputs", ["reserved", "invoked", "checkpointing", "prepared"], indirect=True
)
def test_nondispatched_jobs_refuse_before_evidence_or_crypto(
    inputs: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    inputs["evidence"].unlink()
    inputs["identity_path"].unlink()
    context = Mock(side_effect=AssertionError("SECRET_CANARY"))
    acquire = Mock(side_effect=AssertionError("SECRET_CANARY"))
    monkeypatch.setattr(module, "Context", context)
    monkeypatch.setattr(module, "reconcile_conversion", acquire)
    before = rows(inputs["journal"])
    assert cli.main(arguments(inputs)) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "SECRET_CANARY" not in output.err
    assert context.call_count == acquire.call_count == 0
    assert rows(inputs["journal"]) == before


@pytest.mark.parametrize(
    "fault",
    [
        "unknown_version",
        "extra",
        "custody_false",
        "custody_coerced",
        "custody_network",
        "custody_script",
        "relative_path",
        "spending_credential",
        "bool_port",
        "bool_revision",
        "missing_block",
        "missing_evidence",
        "public_evidence",
        "hardlink_evidence",
        "symlink_evidence",
        "oversized_evidence",
        "duplicate_field",
        "public_identity",
        "wrong_identity",
        "wrong_authority",
        "nonregtest",
        "missing_journal",
        "unknown_job",
    ],
)
def test_input_faults_refuse_without_acquisition_or_financial_mutation(  # noqa: PLR0912, PLR0915 - single explicit input-fault matrix
    inputs: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fault: str,
) -> None:
    document = inputs["document"]
    authority = inputs["authority"].model_dump(mode="json")
    evidence = inputs["evidence"]
    if fault == "unknown_version":
        document["version"] = "conversion-reconciliation/regtest/v0"
    elif fault == "extra":
        document["extra"] = "SECRET_CANARY"
    elif fault == "custody_false":
        document["custody"]["destination_keys_controlled"] = False
    elif fault == "custody_coerced":
        document["custody"]["destination_keys_controlled"] = 1
    elif fault == "custody_network":
        document["custody"]["network"]["deployment_namespace"] = "other"
    elif fault == "custody_script":
        document["custody"]["script"] = "5120" + "f" * 64
    elif fault == "relative_path":
        document["identity_path"] = "relative.identity"
    elif fault == "spending_credential":
        document["rpc"]["lnd_payment_macaroon_path"] = "SECRET_CANARY"
    elif fault == "bool_port":
        document["rpc"]["lnd_port"] = True
    elif fault == "bool_revision":
        document["binding_revision"] = True
    elif fault == "missing_block":
        del document["funding_block"]
    elif fault == "wrong_authority":
        authority["source_epoch"] = "f" * 64
    elif fault == "nonregtest":
        authority["network"]["name"] = "mainnet"
    private(evidence, document)
    private(inputs["authority_path"], authority)
    if fault == "missing_evidence":
        evidence.unlink()
    elif fault == "public_evidence":
        evidence.chmod(0o644)
    elif fault == "hardlink_evidence":
        os.link(evidence, evidence.with_suffix(".copy"))
    elif fault == "symlink_evidence":
        target = evidence.with_suffix(".real")
        evidence.rename(target)
        evidence.symlink_to(target)
    elif fault == "oversized_evidence":
        evidence.write_bytes(b"SECRET_CANARY" * (module.MAX_EVIDENCE_BYTES // 12 + 1))
    elif fault == "duplicate_field":
        evidence.write_bytes(b'{"version":"SECRET_CANARY",' + canonicalize(document)[1:])
    elif fault == "public_identity":
        inputs["identity_path"].chmod(0o644)
    elif fault == "wrong_identity":
        inputs["identity_path"].write_text("SECRET_CANARY")
    elif fault == "missing_journal":
        inputs["base"][1] = str(evidence.parent / "missing-inventory")
    elif fault == "unknown_job":
        inputs["base"][-1] = "unknown_operation_01"
    context = Mock(side_effect=AssertionError("SECRET_CANARY"))
    acquire = Mock(side_effect=AssertionError("SECRET_CANARY"))
    monkeypatch.setattr(module, "Context", context)
    monkeypatch.setattr(module, "reconcile_conversion", acquire)
    before = rows(inputs["journal"])
    assert cli.main(arguments(inputs)) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "SECRET_CANARY" not in output.err
    assert "may already be recorded" in output.err
    assert "rill treasury status" in output.err
    assert context.call_count == acquire.call_count == 0
    assert rows(inputs["journal"]) == before
    assert not (evidence.parent / "missing-inventory").exists()
