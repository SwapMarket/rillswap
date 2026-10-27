"""Explicit regtest completion for a trusted local operator's existing job.

Private operator files supply independent assertions, not custody or liability
proof. Missing state grants no provisioning, discovery, payment or SDK rights.
There is no startup caller, receipt-file admission or production enablement.
"""

from __future__ import annotations

import sys
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import AfterValidator, Field
from pyrage import x25519
from rill_core.networks import REGTEST_CONSENSUS_PROFILE, require_supported_network
from rill_core.wire.canonical import parse_json_strict, parse_model_json
from rill_core.wire.types import Hex32, StrictModel
from rill_crypto import Context

from rill_cli.age_container import X25519Credentials
from rill_cli.conversion_journal import ConversionJournal, SourceAuthority, _read_private
from rill_cli.reverse_conversion import ReverseExecutionConfig
from rill_cli.reverse_reconciliation import BlockHint, DestinationCustody, reconcile_conversion

if TYPE_CHECKING:
    import argparse

MAX_AUTHORITY_BYTES = 4096
MAX_EVIDENCE_BYTES = 16384
MAX_IDENTITY_BYTES = 1024


def _absolute_path(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("absolute operator path required")
    return path


type OperatorPath = Annotated[Path, AfterValidator(_absolute_path)]
type Port = Annotated[int, Field(strict=True, ge=1, le=65535)]


class ReadOnlyRpcInputs(StrictModel):
    """Exact loopback observations, with no spending credential or URL discovery."""

    lnd_port: Port
    lnd_tls_root_path: OperatorPath
    lnd_read_macaroon_path: OperatorPath
    core_port: Port
    core_cookie_path: OperatorPath


class ReconciliationEvidence(StrictModel):
    """Manually selected input, never a stored receipt or transferable capability."""

    version: Literal["conversion-reconciliation/regtest/v1"]
    rpc: ReadOnlyRpcInputs
    identity_path: OperatorPath
    funding_recovery_path: OperatorPath
    funding_attempt_id: Hex32
    binding_revision: Annotated[int, Field(strict=True, ge=0)]
    funding_block: BlockHint
    claim_txid: Hex32
    claim_path: Literal["cooperative", "unilateral"]
    custody: DestinationCustody


class SavedReconciliationEvidence(StrictModel):
    """Explicit saved coordinates; independent fresh evidence still admits effects.

    Keep the immutable v1 schema untouched rather than inheriting or changing its
    required fields. These versions may evolve independently.
    """

    version: Literal["conversion-reconciliation/regtest/v2"]
    rpc: ReadOnlyRpcInputs
    identity_path: OperatorPath
    funding_recovery_path: OperatorPath
    funding_attempt_id: Hex32
    binding_revision: Annotated[int, Field(strict=True, ge=0)]
    funding_inclusion_hint_path: OperatorPath
    claim_txid: Hex32
    claim_path: Literal["cooperative", "unilateral"]
    custody: DestinationCustody


def _evidence(path: Path) -> ReconciliationEvidence | SavedReconciliationEvidence:
    document = _read_private(path, MAX_EVIDENCE_BYTES)
    value = parse_json_strict(document)
    if not isinstance(value, dict):
        raise TypeError("explicit reconciliation evidence required")
    if value.get("version") == "conversion-reconciliation/regtest/v1":
        return parse_model_json(ReconciliationEvidence, document)
    if value.get("version") == "conversion-reconciliation/regtest/v2":
        return parse_model_json(SavedReconciliationEvidence, document)
    raise ValueError("unsupported reconciliation evidence version")


def add_parser(categories: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register explicit existing-job commands without provisioning or SDK options."""
    treasury = categories.add_parser(
        "treasury", help="explicit regtest existing-job reconciliation and recorded status"
    )
    commands = treasury.add_subparsers(dest="command", required=True)
    for name, description in (
        ("status", "inspect recorded state, not fresh custody or settlement validation"),
        ("reconcile", "financial action: acquire fresh original evidence and complete once"),
    ):
        command = commands.add_parser(name, help=description)
        command.add_argument("--journal-directory", required=True)
        command.add_argument("--source-fence", required=True)
        command.add_argument(
            "--authority", required=True, help="independently pinned private SourceAuthority JSON"
        )
        command.add_argument("--operation-id", required=True)
        if name == "reconcile":
            command.add_argument(
                "--evidence",
                required=True,
                help="private versioned original-evidence manifest (not a receipt)",
            )
            command.add_argument(
                "--crypto-library", required=True, help="verified native library path"
            )


def _credentials(path: Path) -> X25519Credentials:
    document = _read_private(path, MAX_IDENTITY_BYTES).decode("ascii").strip()
    if not document.startswith("AGE-SECRET-KEY-1") or len(document.splitlines()) != 1:
        raise ValueError("one protected age identity required")
    identity = x25519.Identity.from_str(document)
    return X25519Credentials(recipient=str(identity.to_public()), identity=document)


def _run(args: argparse.Namespace) -> str:
    authority = parse_model_json(
        SourceAuthority, _read_private(Path(args.authority), MAX_AUTHORITY_BYTES)
    )
    require_supported_network(authority.network)
    if (
        authority.network.name != "regtest"
        or authority.network.consensus_profile != REGTEST_CONSENSUS_PROFILE
    ):
        raise ValueError("treasury reconciliation is regtest-only")
    journal = ConversionJournal.open(
        Path(args.journal_directory).absolute(), Path(args.source_fence).absolute(), authority
    )
    job = journal.status(args.operation_id)
    if args.command == "status" or job.state == "complete":
        return f"Recorded conversion state: {job.state} (historical status, not fresh validation)."
    if job.state != "dispatched":
        raise ValueError("original conversion is not dispatched")
    evidence = _evidence(Path(args.evidence))
    if (
        evidence.custody.network != authority.network
        or evidence.custody.script != authority.treasury_script
    ):
        raise ValueError("independent destination assertion does not match original authority")
    credentials = _credentials(evidence.identity_path)
    rpc = evidence.rpc
    # The execution dataclass has an unused payment-path member. Supplying the
    # read-only path does not load a spending credential or grant payment rights.
    config = ReverseExecutionConfig(
        rpc.lnd_port,
        rpc.lnd_tls_root_path,
        rpc.lnd_read_macaroon_path,
        rpc.lnd_read_macaroon_path,
        rpc.core_port,
        rpc.core_cookie_path,
        evidence.custody.core_wallet,
    )
    with Context(library_path=args.crypto_library) as crypto:
        reconcile = partial(
            reconcile_conversion,
            journal,
            args.operation_id,
            config=config,
            credentials=credentials,
            crypto=crypto,
            funding_recovery_path=evidence.funding_recovery_path,
            funding_attempt_id=evidence.funding_attempt_id,
            binding_revision=evidence.binding_revision,
            funding_block=evidence.funding_block
            if isinstance(evidence, ReconciliationEvidence)
            else None,
            claim_txid=evidence.claim_txid,
            claim_path=evidence.claim_path,
            custody=evidence.custody,
        )
        if isinstance(evidence, SavedReconciliationEvidence):
            completed = reconcile(funding_inclusion_hint_path=evidence.funding_inclusion_hint_path)
        else:
            completed = reconcile()
    # A concurrent caller may have completed after our precheck. Never label this
    # result "fresh" or treat historical status as renewed finality/custody proof.
    return (
        f"Recorded conversion state: {completed.state} (historical status, not fresh validation)."
    )


def run(args: argparse.Namespace) -> int:
    """Detach private errors, including uncertain acknowledgment after real commit."""
    try:
        result = _run(args)
    except Exception:  # noqa: BLE001 - no private keys, paths, invoice data or upstream/native errors
        if args.command == "reconcile":
            sys.stderr.write(
                "Conversion reconciliation unavailable; completion may already be recorded. "
                "Inspect the original job with rill treasury status; "
                "never start replacement execution.\n"
            )
        else:
            sys.stderr.write("Conversion status unavailable; application state was not repaired.\n")
        return 2
    sys.stdout.write(result + "\n")
    return 0
