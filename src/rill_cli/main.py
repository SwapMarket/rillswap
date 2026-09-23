"""Explicit create-only age recovery export and redacted offline inspection."""

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
from rill_core.wire.types import NetworkIdentity
from rill_crypto import Context

from rill_cli.age_container import (
    MAX_CIPHERTEXT_BYTES,
    MAX_PLAINTEXT_BYTES,
    PassphraseCredentials,
    X25519Credentials,
    decrypt_verified_plaintext,
    encrypt_verified_plaintext,
    inspect_container,
    verify_export_ciphertext,
)
from rill_cli.publication import (
    RecoveryPublicationUncertainError,
    publish_new_ciphertext,
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


def _run(args: argparse.Namespace) -> str:
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
        if args.command == "inspect":
            inspection_credentials = (
                PassphraseCredentials(_prompt())
                if args.passphrase_prompt
                else _inspect_identity_credentials(args.identity)
            )
            with Path(args.file).open("rb") as stream:
                ciphertext = stream.read(MAX_CIPHERTEXT_BYTES + 1)
            return _report(
                inspect_container(
                    ciphertext, network, credentials=inspection_credentials, crypto=crypto
                )
            )
        raise RecoveryCLIError("unsupported recovery command")


def _inspect_identity_credentials(path: str) -> X25519Credentials:
    identity = _identity(path)
    recipient = x25519.Identity.from_str(identity).to_public()
    return X25519Credentials(str(recipient), identity)


def main(argv: list[str] | None = None) -> int:
    """Run only explicitly requested, offline-only commands; sanitize errors."""
    args = _parser().parse_args(argv)
    try:
        result = _run(args)
    except RecoveryPublicationUncertainError:
        sys.stderr.write(
            "Recovery destination may be published, durability unconfirmed; "
            "verify manually, do not fund or pay.\n"
        )
        return 3
    except Exception:  # noqa: BLE001 - must not print secret native/library errors
        sys.stderr.write("Recovery operation failed; no payment or funding authority.\n")
        return 2
    sys.stdout.write(result + "\n")
    return 0
