"""Narrow binary age v1 container boundary for offline recovery inspection.

The public report never authorizes funding, payment, signing, scanning or
retries. Preflight bounds the attacker-controlled age header before scrypt;
it is not authentication and does not replace pyrage's MAC/AEAD verification.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

import pyrage
from pyrage import passphrase, x25519
from rill_core.recovery import (
    OfflineRecoveryInspection,
    inspect_recovery_plaintext,
    inspect_recovery_selected_funding_binding,
)

if TYPE_CHECKING:
    from rill_core.recovery.inspection import RecoveryCrypto
    from rill_core.wire.messages import FundingBinding
    from rill_core.wire.types import NetworkIdentity

MAX_HEADER_BYTES = 8192
MAX_CIPHERTEXT_BYTES = 256 * 1024
MAX_PLAINTEXT_BYTES = 128 * 1024
MAX_GREASE_STANZAS = 4
MAX_GREASE_LINE_BYTES = 256
MAX_GREASE_BODY_BYTES = 1024
MAX_SCRYPT_LOG_N = 19
PAYLOAD_NONCE_BYTES = 16
BASE64_LINE_BYTES = 64
MAC_LINE_BYTES = 47
ASCII_GRAPHIC_FIRST = 33
ASCII_GRAPHIC_LAST = 126
MAX_GREASE_ARGUMENTS = 4
SCRYPT_ARGUMENTS = 2
VERSION_LINE = b"age-encryption.org/v1"
BASE64_RAW = re.compile(rb"[A-Za-z0-9+/]*\Z")
DECIMAL = re.compile(rb"[1-9][0-9]*\Z")


class RecoveryContainerError(ValueError):
    """Unsupported, invalid, or unverifiable recovery ciphertext or credentials."""


@dataclass(frozen=True, slots=True)
class X25519Credentials:
    """One exact age recipient and its independently supplied matching identity."""

    recipient: str
    identity: str


@dataclass(frozen=True, slots=True)
class PassphraseCredentials:
    """A protected-input passphrase, never a command-line argument."""

    passphrase: str


type RecoveryCredentials = X25519Credentials | PassphraseCredentials
type ContainerMode = Literal["X25519", "scrypt"]


def _raw_b64(value: bytes, size: int) -> None:
    if len(value) not in (22, 43) or BASE64_RAW.fullmatch(value) is None or b"=" in value:
        raise RecoveryContainerError("invalid age header")
    try:
        decoded = base64.b64decode(value + b"=" * (-len(value) % 4), validate=True)
    except binascii.Error as exc:
        raise RecoveryContainerError("invalid age header") from exc
    if len(decoded) != size or base64.b64encode(decoded).rstrip(b"=") != value:
        raise RecoveryContainerError("invalid age header")


def _body(lines: list[bytes], *, required_length: int | None) -> None:
    if not lines or len(lines[-1]) >= BASE64_LINE_BYTES:
        raise RecoveryContainerError("invalid age stanza body")
    if any(len(line) != BASE64_LINE_BYTES for line in lines[:-1]):
        raise RecoveryContainerError("invalid age stanza body")
    total = 0
    for line in lines:
        if BASE64_RAW.fullmatch(line) is None or b"=" in line:
            raise RecoveryContainerError("invalid age stanza body")
        try:
            decoded = base64.b64decode(line + b"=" * (-len(line) % 4), validate=True)
        except binascii.Error as exc:
            raise RecoveryContainerError("invalid age stanza body") from exc
        if base64.b64encode(decoded).rstrip(b"=") != line:
            raise RecoveryContainerError("invalid age stanza body")
        total += len(decoded)
        if total > MAX_GREASE_BODY_BYTES:
            raise RecoveryContainerError("age stanza body exceeds resource limit")
    if required_length is not None and total != required_length:
        raise RecoveryContainerError("unexpected age stanza length")


def _line(data: bytes, cursor: int) -> tuple[bytes, int]:
    boundary = data.find(b"\n", cursor, MAX_HEADER_BYTES + 1)
    if boundary < 0 or boundary + 1 > MAX_HEADER_BYTES:
        raise RecoveryContainerError("age header exceeds resource limit")
    return data[cursor:boundary], boundary + 1


def validate_age_profile(ciphertext: bytes, mode: ContainerMode) -> None:  # noqa: PLR0912, PLR0915
    """Require a bounded RS-007 age v1 header before decrypting untrusted bytes."""
    if not isinstance(ciphertext, bytes) or not 0 < len(ciphertext) <= MAX_CIPHERTEXT_BYTES:
        raise RecoveryContainerError("recovery ciphertext exceeds resource limit")
    if mode not in ("X25519", "scrypt"):
        raise RecoveryContainerError("unsupported age recipient mode")
    first, cursor = _line(ciphertext, 0)
    if first != VERSION_LINE:
        raise RecoveryContainerError("unsupported age header")
    native = 0
    grease = 0
    while True:
        opening, cursor = _line(ciphertext, cursor)
        if opening.startswith(b"--- "):
            if len(opening) != MAC_LINE_BYTES:
                raise RecoveryContainerError("invalid age header MAC")
            _raw_b64(opening[4:], 32)
            break
        if not opening.startswith(b"-> ") or len(opening) > MAX_GREASE_LINE_BYTES:
            raise RecoveryContainerError("invalid age stanza")
        tokens = opening[3:].split(b" ")
        if not tokens or any(
            not token
            or any(char < ASCII_GRAPHIC_FIRST or char > ASCII_GRAPHIC_LAST for char in token)
            for token in tokens
        ):
            raise RecoveryContainerError("invalid age stanza arguments")
        tag, *arguments = tokens
        if tag == b"X25519" and mode == "X25519" and len(arguments) == 1:
            _raw_b64(arguments[0], 32)
            native += 1
            expected_body = 32
        elif tag == b"scrypt" and mode == "scrypt" and len(arguments) == SCRYPT_ARGUMENTS:
            _raw_b64(arguments[0], 16)
            work = arguments[1]
            if (
                DECIMAL.fullmatch(work) is None
                or len(work) > len(str(MAX_SCRYPT_LOG_N))
                or (
                    len(work) == len(str(MAX_SCRYPT_LOG_N))
                    and work > str(MAX_SCRYPT_LOG_N).encode()
                )
            ):
                raise RecoveryContainerError("scrypt work factor exceeds resource limit")
            native += 1
            expected_body = 32
        elif mode == "X25519" and tag.endswith(b"-grease") and len(tag) > len(b"-grease"):
            if len(arguments) > MAX_GREASE_ARGUMENTS:
                raise RecoveryContainerError("too many GREASE arguments")
            grease += 1
            expected_body = None
        else:
            raise RecoveryContainerError("unsupported age recipient stanza")
        if native > 1 or grease > MAX_GREASE_STANZAS:
            raise RecoveryContainerError("too many age recipient stanzas")
        body_lines = []
        while True:
            next_line, next_cursor = _line(ciphertext, cursor)
            if next_line.startswith((b"-> ", b"--- ")):
                break
            body_lines.append(next_line)
            cursor = next_cursor
            if len(body_lines) > (MAX_GREASE_BODY_BYTES // 48) + 2:
                raise RecoveryContainerError("age stanza body exceeds resource limit")
        _body(body_lines, required_length=expected_body)
    if native != 1 or (mode == "scrypt" and grease):
        raise RecoveryContainerError("invalid age recipient count")
    if len(ciphertext) - cursor < PAYLOAD_NONCE_BYTES:
        raise RecoveryContainerError("missing age payload nonce")


def _identity(credentials: X25519Credentials) -> tuple[x25519.Identity, x25519.Recipient]:
    identity = x25519.Identity.from_str(credentials.identity)
    recipient = x25519.Recipient.from_str(credentials.recipient)
    if str(identity.to_public()) != str(recipient):
        raise RecoveryContainerError("recipient and decryption identity do not match")
    return identity, recipient


def _mode(credentials: RecoveryCredentials) -> ContainerMode:
    if isinstance(credentials, X25519Credentials):
        return "X25519"
    if isinstance(credentials, PassphraseCredentials) and credentials.passphrase:
        return "scrypt"
    raise RecoveryContainerError("exactly one recovery encryption mode is required")


def _decrypt(ciphertext: bytes, credentials: RecoveryCredentials) -> bytes:
    mode = _mode(credentials)
    validate_age_profile(ciphertext, mode)
    if isinstance(credentials, X25519Credentials):
        identity, _ = _identity(credentials)
        return cast("bytes", pyrage.decrypt(ciphertext, [identity]))
    return cast("bytes", passphrase.decrypt(ciphertext, credentials.passphrase))


def _bounded_plaintext(ciphertext: bytes, credentials: RecoveryCredentials) -> bytes:
    plaintext = _decrypt(ciphertext, credentials)
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise RecoveryContainerError("decrypted recovery plaintext exceeds resource limit")
    return plaintext


def inspect_container(
    ciphertext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: RecoveryCredentials,
    crypto: RecoveryCrypto,
) -> OfflineRecoveryInspection:
    """Decrypt and inspect only; never return secrets or action authority."""
    try:
        return _inspect_container(ciphertext, expected_network, credentials, crypto)
    except Exception:  # noqa: BLE001, S110 - never log secret-bearing native errors
        pass
    raise RecoveryContainerError("recovery decryption or static inspection failed")


def inspect_container_selected_funding_binding(  # noqa: PLR0913 - explicit selected record
    ciphertext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: RecoveryCredentials,
    funding_attempt_id: str,
    binding_revision: int,
    crypto: RecoveryCrypto,
) -> FundingBinding:
    """Decrypt and return one public, explicitly selected static candidate.

    The result is never a live UTXO, authorized outpoint, or latest revision.
    The recovery plaintext, secrets, and third-party exceptions do not escape.
    """
    try:
        plaintext = _bounded_plaintext(ciphertext, credentials)
        result = inspect_recovery_selected_funding_binding(
            plaintext,
            expected_network,
            funding_attempt_id=funding_attempt_id,
            binding_revision=binding_revision,
            crypto=crypto,
        )
    except Exception:  # noqa: BLE001, S110 - third-party errors may contain secrets
        pass
    else:
        return result
    raise RecoveryContainerError("recovery decryption or static inspection failed")


def decrypt_verified_plaintext(
    ciphertext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: RecoveryCredentials,
    crypto: RecoveryCrypto,
) -> bytes:
    """Decrypt one successor input for internal comparison, not for public reports."""
    try:
        plaintext = _verified_plaintext(ciphertext, expected_network, credentials, crypto)
    except Exception:  # noqa: BLE001, S110 - third-party errors may contain plaintext
        pass
    else:
        return plaintext
    raise RecoveryContainerError("recovery decryption or static inspection failed")


def _verified_plaintext(
    ciphertext: bytes,
    expected_network: NetworkIdentity,
    credentials: RecoveryCredentials,
    crypto: RecoveryCrypto,
) -> bytes:
    plaintext = _bounded_plaintext(ciphertext, credentials)
    inspect_recovery_plaintext(plaintext, expected_network, crypto=crypto)
    return plaintext


def _inspect_container(
    ciphertext: bytes,
    expected_network: NetworkIdentity,
    credentials: RecoveryCredentials,
    crypto: RecoveryCrypto,
) -> OfflineRecoveryInspection:
    plaintext = _bounded_plaintext(ciphertext, credentials)
    return inspect_recovery_plaintext(plaintext, expected_network, crypto=crypto)


def verify_export_ciphertext(
    ciphertext: bytes,
    original_plaintext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: RecoveryCredentials,
    crypto: RecoveryCrypto,
) -> OfflineRecoveryInspection:
    """Read back a ciphertext, check exact contents and repeat static inspection."""
    try:
        result = _verify_export_ciphertext(
            ciphertext, original_plaintext, expected_network, credentials, crypto
        )
    except Exception:  # noqa: BLE001, S110 - suppress secret-bearing native diagnostics
        pass
    else:
        return result
    raise RecoveryContainerError("encrypted recovery verification failed")


def _verify_export_ciphertext(
    ciphertext: bytes,
    original_plaintext: bytes,
    expected_network: NetworkIdentity,
    credentials: RecoveryCredentials,
    crypto: RecoveryCrypto,
) -> OfflineRecoveryInspection:
    plaintext = _decrypt(ciphertext, credentials)
    if plaintext != original_plaintext:
        raise RecoveryContainerError("recovery plaintext differs from export input")
    return inspect_recovery_plaintext(plaintext, expected_network, crypto=crypto)


def encrypt_verified_plaintext(
    plaintext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: RecoveryCredentials,
    crypto: RecoveryCrypto,
) -> bytes:
    """Encrypt a statically valid canonical package and verify its exact round trip.

    The returned ciphertext has no durability or funding semantics until it is
    separately published, fsynced, and explicitly reconciled against live state.
    """
    try:
        result = _encrypt_validated(plaintext, expected_network, credentials, crypto)
    except Exception:  # noqa: BLE001, S110 - do not leak native or Pydantic secret inputs
        pass
    else:
        return result
    raise RecoveryContainerError("recovery encryption or static inspection failed")


def _encrypt_validated(
    plaintext: bytes,
    expected_network: NetworkIdentity,
    credentials: RecoveryCredentials,
    crypto: RecoveryCrypto,
) -> bytes:
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise RecoveryContainerError("recovery plaintext exceeds resource limit")
    inspect_recovery_plaintext(plaintext, expected_network, crypto=crypto)
    mode = _mode(credentials)
    if isinstance(credentials, X25519Credentials):
        _, recipient = _identity(credentials)
        ciphertext = pyrage.encrypt(plaintext, [recipient])
    elif isinstance(credentials, PassphraseCredentials):
        # pyrage chooses a machine-dependent scrypt factor before it returns.
        # We cannot bound the export KDF by checking its output afterward.
        # Keep decrypt-only support for <=19 until a pinned backend lets us
        # set an explicit work factor before the KDF runs.
        raise RecoveryContainerError("bounded scrypt export is not implemented")
    else:
        raise RecoveryContainerError("invalid recovery credentials")
    validate_age_profile(ciphertext, mode)
    if _decrypt(ciphertext, credentials) != plaintext:
        raise RecoveryContainerError("encrypted recovery bytes failed verification")
    return cast("bytes", ciphertext)
