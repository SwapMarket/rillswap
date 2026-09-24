"""Explicit age recovery, Core sampling, and create-only refund construction."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
import warnings
from pathlib import Path
from typing import TYPE_CHECKING

from pyrage import x25519
from rill_core.recovery import inspect_recovery_successor
from rill_core.settlement import FundingOutput, UnilateralAuthorization, validate_unilateral_spend
from rill_core.wire.types import NetworkIdentity
from rill_crypto import Context

from rill_cli.age_container import (
    MAX_CIPHERTEXT_BYTES,
    MAX_PLAINTEXT_BYTES,
    PassphraseCredentials,
    X25519Credentials,
    construct_container_selected_refund,
    decrypt_verified_plaintext,
    encrypt_verified_plaintext,
    inspect_container,
    inspect_container_selected_funding_context,
    verify_export_ciphertext,
)
from rill_cli.claim_plan import prepare_encrypted_claim_plan, verify_encrypted_claim_plan
from rill_cli.publication import (
    RecoveryPublicationUncertainError,
    publish_new_ciphertext,
)
from rill_cli.recovery_core_observation import RegtestRecoveryCoreReader
from rill_cli.refund_broadcast import (
    RefundPreflightError,
    RefundSubmissionUnknownError,
    create_refund_intent,
    submit_prepared_refund,
    verify_refund_intent,
)
from rill_cli.refund_publication import (
    RefundPublicationUncertainError,
    publish_new_broadcast_intent,
    publish_new_signed_refund,
)

if TYPE_CHECKING:
    from rill_core.recovery import OfflineRecoveryInspection


class RecoveryCLIError(ValueError):
    """CLI input is incomplete or unsupported for an explicit recovery action."""


MAX_NETWORK_FILE_BYTES = 4096
MAX_IDENTITY_FILE_BYTES = 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rill", description="Offline, pre-release recovery tools")
    recover = parser.add_subparsers(dest="category", required=True)
    recovery = recover.add_parser("recover", help="encrypted recovery files (no chain or payments)")
    commands = recovery.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("export", "create a new age file from canonical stdin"),
        ("export-update", "create a successor snapshot relative to one supplied prior file"),
    ):
        export = commands.add_parser(name, help=help_text)
        export.add_argument("--network", required=True, help="complete trusted network JSON file")
        export.add_argument(
            "--crypto-library", required=True, help="verified local native library path"
        )
        export.add_argument("--recipient", required=True, help="one X25519 age public recipient")
        export.add_argument(
            "--identity", required=True, help="protected matching age secret-key file"
        )
        export.add_argument(
            "--output", required=True, help="create-only destination under trusted directory"
        )
        if name == "export-update":
            export.add_argument("--previous", required=True, help="explicit prior X25519 age file")
    inspect = commands.add_parser("inspect", help="redacted offline static inspection")
    inspect.add_argument("--network", required=True, help="complete trusted network JSON file")
    inspect.add_argument(
        "--crypto-library", required=True, help="verified local native library path"
    )
    decrypt_mode = inspect.add_mutually_exclusive_group(required=True)
    decrypt_mode.add_argument("--identity", help="protected age X25519 secret-key file")
    decrypt_mode.add_argument(
        "--passphrase-prompt", action="store_true", help="prompt via terminal"
    )
    inspect.add_argument("file", help="encrypted age v1 binary recovery file")
    for command, description in (
        ("observe-funding", "explicit regtest candidate (never signing authority)"),
        ("observe-claim", "read-only LN-to-BTC claim candidate (no preimage)"),
        ("prepare-claim", "create encrypted LN-to-BTC claim plan (no disclosure)"),
        ("sign-refund", "explicit BTC-to-LN refund artifact (never broadcasts)"),
        ("broadcast-refund", "explicit regtest refund submit (never retries)"),
    ):
        operation = commands.add_parser(command, help=description)
        operation.add_argument(
            "--network", required=True, help="complete trusted regtest network JSON"
        )
        operation.add_argument(
            "--crypto-library", required=True, help="verified native library path"
        )
        operation.add_argument(
            "--funding-attempt-id", required=True, help="exact recorded attempt hex"
        )
        operation.add_argument("--binding-revision", required=True, type=int, help="exact revision")
        operation.add_argument(
            "--rpc-cookie", required=True, help="protected local Core cookie path"
        )
        operation.add_argument("--rpc-port", required=True, type=int, help="local Core RPC port")
        operation.add_argument("--rpc-host", default="127.0.0.1", help="numeric loopback only")
        mode = operation.add_mutually_exclusive_group(required=True)
        mode.add_argument("--identity", help="protected age X25519 secret-key file")
        mode.add_argument("--passphrase-prompt", action="store_true", help="prompt via terminal")
        if command in {"sign-refund", "broadcast-refund", "prepare-claim"}:
            operation.add_argument("--fee-sat", required=True, type=int, help="exact spend fee")
            if command == "sign-refund":
                operation.add_argument(
                    "--output", required=True, help="create-only raw transaction file"
                )
            elif command == "broadcast-refund":
                operation.add_argument(
                    "--intent",
                    required=True,
                    help="create-only durable exact-byte submission intent",
                )
            else:
                operation.add_argument(
                    "--output", required=True, help="create-only encrypted claim plan file"
                )
        operation.add_argument("file", help="explicit encrypted age recovery file")
    return parser


def _network(path: str) -> NetworkIdentity:
    with Path(path).open("rb") as stream:
        payload = stream.read(MAX_NETWORK_FILE_BYTES + 1)
    if len(payload) > MAX_NETWORK_FILE_BYTES:
        raise RecoveryCLIError("network file exceeds size limit")
    return NetworkIdentity.model_validate_json(payload)


def _identity(path: str) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb", closefd=True) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise RecoveryCLIError("age identity must be a private regular file")
        document = stream.read(MAX_IDENTITY_FILE_BYTES + 1)
    if len(document) > MAX_IDENTITY_FILE_BYTES:
        raise RecoveryCLIError("age identity file exceeds size limit")
    lines = document.decode("ascii").strip().splitlines()
    if len(lines) != 1 or not lines[0].startswith("AGE-SECRET-KEY-1"):
        raise RecoveryCLIError("age identity file must contain one X25519 key")
    return lines[0]


def _previous_ciphertext(path: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb", closefd=True) as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RecoveryCLIError("prior snapshot must be a regular file")
        ciphertext = stream.read(MAX_CIPHERTEXT_BYTES + 1)
    if not 0 < len(ciphertext) <= MAX_CIPHERTEXT_BYTES:
        raise RecoveryCLIError("prior snapshot exceeds size limit")
    return ciphertext


def _prompt() -> str:
    # getpass opens its own input terminal and can fall back to echoed stdin
    # even when given a tty for prompt output. Turn that warning into failure.
    with Path("/dev/tty").open("r+") as terminal, warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        answer = getpass.getpass("Age passphrase: ", stream=terminal)
    if not answer:
        raise RecoveryCLIError("passphrase must not be empty")
    return answer


def _report(report: OfflineRecoveryInspection) -> str:
    return json.dumps(
        {
            "network": report.network_name,
            "profile": report.profile_id,
            "refund_lock_height": report.refund_lock_height,
            "first_refund_eligible_height": report.first_refund_eligible_height,
            "recorded_binding_count": report.recorded_binding_count,
            "unproven": report.unproven,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _run(args: argparse.Namespace) -> str:  # noqa: PLR0911, PLR0912, PLR0915 - recovery boundaries
    network = _network(args.network)
    with Context(library_path=args.crypto_library) as crypto:
        if args.command in ("export", "export-update"):
            plaintext = sys.stdin.buffer.read(MAX_PLAINTEXT_BYTES + 1)
            if len(plaintext) > MAX_PLAINTEXT_BYTES:
                raise RecoveryCLIError("recovery input exceeds size limit")
            credentials = X25519Credentials(args.recipient, _identity(args.identity))
            previous = None
            if args.command == "export-update":
                previous = decrypt_verified_plaintext(
                    _previous_ciphertext(args.previous),
                    network,
                    credentials=credentials,
                    crypto=crypto,
                )
                inspect_recovery_successor(previous, plaintext, network, crypto=crypto)
            ciphertext = encrypt_verified_plaintext(
                plaintext, network, credentials=credentials, crypto=crypto
            )

            def readback(stored: bytes) -> OfflineRecoveryInspection:
                report = verify_export_ciphertext(
                    stored, plaintext, network, credentials=credentials, crypto=crypto
                )
                if previous is not None:
                    return inspect_recovery_successor(previous, plaintext, network, crypto=crypto)
                return report

            report = publish_new_ciphertext(
                args.output,
                ciphertext,
                verify_from_disk=readback,
            )
            prefix = (
                "Created encrypted successor snapshot relative only to supplied previous file. "
                if previous is not None
                else "Created encrypted recovery file. "
            )
            return prefix + "No funding authority. " + _report(report)
        if args.command in {
            "inspect",
            "observe-funding",
            "observe-claim",
            "prepare-claim",
            "sign-refund",
            "broadcast-refund",
        }:
            if args.command == "prepare-claim" and not args.identity:
                raise RecoveryCLIError("protected X25519 identity required for claim plan")
            inspection_credentials = (
                PassphraseCredentials(_prompt())
                if args.passphrase_prompt
                else _inspect_identity_credentials(args.identity)
            )
            with Path(args.file).open("rb") as stream:
                ciphertext = stream.read(MAX_CIPHERTEXT_BYTES + 1)
            if args.command == "inspect":
                return _report(
                    inspect_container(
                        ciphertext, network, credentials=inspection_credentials, crypto=crypto
                    )
                )
            selected = inspect_container_selected_funding_context(
                ciphertext,
                network,
                credentials=inspection_credentials,
                funding_attempt_id=args.funding_attempt_id,
                binding_revision=args.binding_revision,
                crypto=crypto,
            )
            if args.command in {"sign-refund", "broadcast-refund"} and (
                selected.terms.profile_id != "btc-to-ln/v1"
                or selected.terms.refund_party != "client"
            ):
                raise RecoveryCLIError("selected recovery is not a client refund")
            if args.command in {"observe-claim", "prepare-claim"} and (
                selected.terms.profile_id != "ln-to-btc/v1" or selected.terms.claimant != "client"
            ):
                raise RecoveryCLIError("selected recovery is not a client claim")
            reader = RegtestRecoveryCoreReader(
                port=args.rpc_port,
                host=args.rpc_host,
                cookie_path=Path(args.rpc_cookie),
                network=network,
            )
            if args.command in {"observe-claim", "prepare-claim"}:
                candidate = reader.observe_claim(selected.binding, selected.terms, keys=crypto)
            else:
                candidate = reader.observe(
                    selected.binding,
                    selected.terms,
                    keys=crypto,
                    for_refund=args.command in {"sign-refund", "broadcast-refund"},
                )
            if args.command in {"sign-refund", "broadcast-refund"}:
                funding = FundingOutput(
                    bytes.fromhex(selected.binding.funding_txid),
                    selected.binding.contract_vout,
                    int(selected.binding.contract_value_sat),
                    bytes.fromhex(selected.binding.contract_script_pubkey),
                )
                signed = construct_container_selected_refund(
                    ciphertext,
                    network,
                    credentials=inspection_credentials,
                    funding_attempt_id=args.funding_attempt_id,
                    binding_revision=args.binding_revision,
                    live_funding=funding,
                    sampled_tip_height=candidate.tip_height,
                    fee_sat=args.fee_sat,
                    auxiliary_random=os.urandom(32),
                    crypto=crypto,
                )
                authorization = UnilateralAuthorization.from_terms(
                    selected.terms,
                    funding,
                    "refund",
                    keys=crypto,
                )
                if args.command == "broadcast-refund":
                    validated = validate_unilateral_spend(signed, authorization, verifier=crypto)
                    if validated.fee_sat != args.fee_sat:
                        raise RecoveryCLIError("signed refund fee differs from requested fee")
                    intent = create_refund_intent(
                        signed,
                        txid=validated.txid,
                        binding=selected.binding,
                        terms=selected.terms,
                        fee_sat=args.fee_sat,
                        candidate=candidate,
                    )

                    def check_intent_readback(stored: bytes) -> None:
                        persisted_raw = verify_refund_intent(stored, intent)
                        persisted_spend = validate_unilateral_spend(
                            persisted_raw,
                            authorization,
                            verifier=crypto,
                        )
                        if (
                            persisted_raw != signed
                            or persisted_spend.txid != validated.txid
                            or persisted_spend.fee_sat != args.fee_sat
                        ):
                            raise RecoveryCLIError("persisted refund differs from selected spend")

                    publish_new_broadcast_intent(
                        args.intent,
                        intent,
                        verify_from_disk=check_intent_readback,
                    )
                    submitted_tip = submit_prepared_refund(
                        reader,
                        selected.binding,
                        selected.terms,
                        keys=crypto,
                        raw=signed,
                        expected_txid=validated.txid,
                    )
                    return json.dumps(
                        {
                            "kind": "explicit-regtest-refund-submission/v1",
                            "refund_txid": validated.txid,
                            "submission": "node_accepted",
                            "chain_observation": "unobserved_after_send",
                            "intent_path": str(Path(args.intent).absolute()),
                            "sampled_tip_hash": submitted_tip.tip_hash,
                            "broadcast_attempts_this_invocation": 1,
                            "authority": "none (not confirmed; no payment or lineage proof)",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                checked = None

                def verify_from_disk(stored: bytes) -> None:
                    nonlocal checked
                    checked = validate_unilateral_spend(stored, authorization, verifier=crypto)
                    if checked.fee_sat != args.fee_sat:
                        raise RecoveryCLIError("signed refund fee differs from requested fee")

                publish_new_signed_refund(args.output, signed, verify_from_disk=verify_from_disk)
                if checked is None:
                    raise RecoveryCLIError("signed refund readback was not verified")
                return json.dumps(
                    {
                        "kind": "offline-signed-btc-to-ln-refund/v1",
                        "funding_txid": selected.binding.funding_txid,
                        "contract_vout": selected.binding.contract_vout,
                        "refund_txid": checked.txid,
                        "fee_sat": checked.fee_sat,
                        "sampled_tip_hash": candidate.tip_hash,
                        "sampled_tip_height": candidate.tip_height,
                        "broadcast": False,
                        "authority": "none (manual chain recheck required before broadcast)",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            if args.command == "prepare-claim":
                if not isinstance(inspection_credentials, X25519Credentials):
                    raise RecoveryCLIError("protected X25519 identity required")
                prepared = prepare_encrypted_claim_plan(
                    ciphertext,
                    network,
                    credentials=inspection_credentials,
                    funding_attempt_id=args.funding_attempt_id,
                    binding_revision=args.binding_revision,
                    candidate=candidate,
                    fee_sat=args.fee_sat,
                    auxiliary_random=os.urandom(32),
                    crypto=crypto,
                )

                def verify_claim_readback(stored: bytes) -> object:
                    checked = verify_encrypted_claim_plan(
                        stored,
                        ciphertext,
                        network,
                        credentials=inspection_credentials,
                        funding_attempt_id=args.funding_attempt_id,
                        binding_revision=args.binding_revision,
                        crypto=crypto,
                    )
                    if checked != prepared.receipt:
                        raise RecoveryCLIError("encrypted claim plan readback differs")
                    return checked

                publish_new_ciphertext(
                    args.output,
                    prepared.ciphertext,
                    verify_from_disk=verify_claim_readback,
                )
                return json.dumps(
                    {
                        "kind": "encrypted-ln-to-btc-claim-preparation/v1",
                        "funding_txid": prepared.receipt.funding_txid,
                        "contract_vout": prepared.receipt.contract_vout,
                        "claim_txid": prepared.receipt.claim_txid,
                        "fee_sat": prepared.receipt.fee_sat,
                        "sampled_tip_hash": candidate.tip_hash,
                        "sampled_tip_height": candidate.tip_height,
                        "broadcast": False,
                        "preimage_external_disclosure": False,
                        "authority": "none (encrypted plan; no permission to reveal or broadcast)",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            if args.command == "observe-claim":
                return json.dumps(
                    {
                        "kind": "selected-claim-candidate-observation/v1",
                        "network_identity": network.model_dump(mode="json"),
                        "funding_attempt_id": selected.binding.funding_attempt_id,
                        "binding_revision": selected.binding.binding_revision,
                        "funding_txid": candidate.static_match.funding_txid,
                        "contract_vout": candidate.static_match.contract_vout,
                        "static_transaction_bytes_match": True,
                        "tip_hash": candidate.tip_hash,
                        "tip_height": candidate.tip_height,
                        "chain_only_confirmations": candidate.chain_only_confirmations,
                        "mempool_aware_unspent_sampled": True,
                        "refund_first_eligible_height": candidate.refund_first_eligible_height,
                        "required_funding_confirmations": selected.terms.funding_confirmations,
                        "claim_confirmation_blocks": (
                            selected.terms.timing_policy.claim_confirmation_blocks
                        ),
                        "authority": (
                            "none (staleable sample; no preimage release or claim permission)"
                        ),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            return json.dumps(
                {
                    "kind": "selected-funding-candidate-observation/v1",
                    "network_identity": network.model_dump(mode="json"),
                    "funding_attempt_id": selected.binding.funding_attempt_id,
                    "binding_revision": selected.binding.binding_revision,
                    "funding_txid": candidate.static_match.funding_txid,
                    "contract_vout": candidate.static_match.contract_vout,
                    "static_transaction_bytes_match": True,
                    "tip_hash": candidate.tip_hash,
                    "tip_height": candidate.tip_height,
                    "transaction_lookup_block_hash": candidate.transaction_lookup_block_hash,
                    "sampled_inclusion_height": candidate.sampled_inclusion_height,
                    "chain_only_confirmations": candidate.chain_only_confirmations,
                    "first_refund_eligible_height": candidate.refund_first_eligible_height,
                    "authority": "none (staleable candidate; no signing or action permission)",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        raise RecoveryCLIError("unsupported recovery command")


def _inspect_identity_credentials(path: str) -> X25519Credentials:
    identity = _identity(path)
    recipient = x25519.Identity.from_str(identity).to_public()
    return X25519Credentials(str(recipient), identity)


def main(argv: list[str] | None = None) -> int:
    """Run explicit recovery commands only; sanitize errors and private input."""
    args = _parser().parse_args(argv)
    try:
        result = _run(args)
    except RecoveryPublicationUncertainError:
        sys.stderr.write(
            "Recovery destination may be published, durability unconfirmed; "
            "verify manually, do not fund, pay, reveal a preimage, or broadcast.\n"
        )
        return 3
    except RefundPublicationUncertainError:
        sys.stderr.write(
            "Signed refund output may exist, durability unconfirmed; verify manually; "
            "do not automatically retry or broadcast.\n"
        )
        return 3
    except RefundSubmissionUnknownError:
        sys.stderr.write(
            "Refund submission may have occurred; inspect exact durable intent and chain "
            "manually. Do not retry automatically or create another signed attempt.\n"
        )
        return 4
    except RefundPreflightError:
        sys.stderr.write(
            "Refund preflight refused; no send attempted by this invocation. "
            "An intent may remain; do not automatically retry.\n"
        )
        return 2
    except Exception:  # noqa: BLE001 - must not print secret native/library errors
        sys.stderr.write("Recovery operation failed; no payment or funding authority.\n")
        return 2
    sys.stdout.write(result + "\n")
    return 0
