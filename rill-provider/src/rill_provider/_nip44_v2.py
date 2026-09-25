"""Internal, bounded NIP-44 v2 codec, not a NIP-59 send or receive boundary.

NIP-44 requires the enclosing NIP-01 event's signature and author to be
validated BEFORE calling this decoder. There is intentionally no relay caller
or public receive API yet. Decrypted text is not an authenticated RillSwap
application frame, session admission, or authority for any financial effect.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import secrets
from typing import TYPE_CHECKING

from Cryptodome.Cipher import ChaCha20

if TYPE_CHECKING:
    from rill_crypto import Context

MAX_ENCODED_PAYLOAD = 128 * 1024
MIN_ENCODED_PAYLOAD = 132
MIN_DECODED_PAYLOAD = 99
VERSION = 2
EXTENDED_PREFIX = 65536
SHA256_SIZE = 32
MIN_PADDED_LENGTH = 32
MIN_PADDED_WITH_PREFIX = 34
PADDING_THRESHOLD = 256
EXTENDED_PREFIX_BYTES = 6


class Nip44InvalidPayloadError(ValueError):
    """The input cannot be accepted as a NIP-44 v2 message."""


class Nip44UnavailableError(RuntimeError):
    """The configured crypto library cannot perform NIP-44 v2 ECDH."""


class Nip44UnsupportedVersionError(Nip44InvalidPayloadError):
    """The encoded payload requests a version this decoder cannot process."""


def _invalid(condition: bool) -> None:  # noqa: FBT001 - internal guard
    if not condition:
        raise Nip44InvalidPayloadError("NIP-44 v2 payload refused")


def _decode(payload: str) -> tuple[bytes, bytes, bytes]:
    _invalid(type(payload) is str and 0 < len(payload) <= MAX_ENCODED_PAYLOAD)
    if payload.startswith("#"):
        raise Nip44UnsupportedVersionError("NIP-44 encryption version unsupported")
    _invalid(len(payload) >= MIN_ENCODED_PAYLOAD and len(payload) % 4 == 0)
    try:
        encoded = payload.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise Nip44InvalidPayloadError("NIP-44 v2 payload refused") from None
    _invalid(base64.b64encode(decoded) == encoded and len(decoded) >= MIN_DECODED_PAYLOAD)
    if decoded[0] != VERSION:
        raise Nip44UnsupportedVersionError("NIP-44 encryption version unsupported")
    return decoded[1:33], decoded[33:-32], decoded[-32:]


def _message_keys(conversation_key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
    _invalid(type(conversation_key) is bytes and len(conversation_key) == SHA256_SIZE)
    _invalid(type(nonce) is bytes and len(nonce) == SHA256_SIZE)
    info = nonce
    first = hmac.digest(conversation_key, info + b"\x01", "sha256")
    second = hmac.digest(conversation_key, first + info + b"\x02", "sha256")
    third = hmac.digest(conversation_key, second + info + b"\x03", "sha256")
    material = first + second + third
    return material[:32], material[32:44], material[44:76]


def _padded_length(length: int) -> int:
    _invalid(type(length) is int and 1 <= length <= MAX_ENCODED_PAYLOAD)
    if length <= MIN_PADDED_LENGTH:
        return MIN_PADDED_LENGTH
    next_power = 1 << (length - 1).bit_length()
    chunk = MIN_PADDED_LENGTH if next_power <= PADDING_THRESHOLD else next_power // 8
    return chunk * ((length - 1) // chunk + 1)


def _unpad(padded: bytes) -> str:
    _invalid(len(padded) >= MIN_PADDED_WITH_PREFIX)
    length = int.from_bytes(padded[:2], "big")
    prefix = 2
    if length == 0:
        _invalid(len(padded) >= EXTENDED_PREFIX_BYTES)
        length = int.from_bytes(padded[2:6], "big")
        prefix = EXTENDED_PREFIX_BYTES
        _invalid(length >= EXTENDED_PREFIX)
    _invalid(prefix + _padded_length(length) == len(padded))
    _invalid(not any(padded[prefix + length :]))
    try:
        return padded[prefix : prefix + length].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Nip44InvalidPayloadError("NIP-44 v2 payload refused") from None


def _decrypt(
    payload: str,
    *,
    recipient_secret: bytes,
    sender_public_key: bytes,
    crypto: Context,
) -> str:
    nonce, ciphertext, mac = _decode(payload)
    _invalid(type(recipient_secret) is bytes and len(recipient_secret) == SHA256_SIZE)
    _invalid(type(sender_public_key) is bytes and len(sender_public_key) == SHA256_SIZE)
    try:
        shared_x = crypto.nip44_shared_x(recipient_secret, sender_public_key)
    except (AttributeError, RuntimeError):
        raise Nip44UnavailableError("NIP-44 v2 ECDH unavailable") from None
    conversation_key = hmac.digest(b"nip44-v2", shared_x, "sha256")
    return _decrypt_with_conversation_key(nonce, ciphertext, mac, conversation_key)


def _decrypt_with_conversation_key(
    nonce: bytes,
    ciphertext: bytes,
    mac: bytes,
    conversation_key: bytes,
) -> str:
    chacha_key, chacha_nonce, hmac_key = _message_keys(conversation_key, nonce)
    _invalid(hmac.compare_digest(mac, hmac.digest(hmac_key, nonce + ciphertext, "sha256")))
    padded = ChaCha20.new(key=chacha_key, nonce=chacha_nonce).decrypt(ciphertext)
    return _unpad(padded)


def _decrypt_payload(
    payload: str,
    *,
    recipient_secret: bytes,
    sender_public_key: bytes,
    crypto: Context,
) -> str:
    """Decode internally only after an enclosing signed event is verified."""
    result: str | None = None
    unavailable = False
    unsupported = False
    interrupted: type[BaseException] | None = None
    try:
        try:
            result = _decrypt(
                payload,
                recipient_secret=recipient_secret,
                sender_public_key=sender_public_key,
                crypto=crypto,
            )
        finally:
            del recipient_secret  # Do not retain caller's scalar in sanitized tracebacks.
    except Nip44UnavailableError:
        unavailable = True
    except Nip44UnsupportedVersionError:
        unsupported = True
    except KeyboardInterrupt:
        interrupted = KeyboardInterrupt
    except SystemExit:
        interrupted = SystemExit
    except asyncio.CancelledError:
        interrupted = asyncio.CancelledError
    except GeneratorExit:
        interrupted = GeneratorExit
    except Exception:  # noqa: BLE001, S110 - do not retain native/decoder traceback locals
        pass
    if interrupted is not None:
        raise interrupted("NIP-44 v2 decoding interrupted")
    if unavailable:
        raise Nip44UnavailableError("NIP-44 v2 ECDH unavailable")
    if unsupported:
        raise Nip44UnsupportedVersionError("NIP-44 encryption version unsupported")
    if result is None:
        raise Nip44InvalidPayloadError("NIP-44 v2 payload refused")
    return result


def _pad(plaintext: str) -> bytes:
    raw = plaintext.encode("utf-8") if type(plaintext) is str else b""
    _invalid(0 < len(raw) <= MAX_ENCODED_PAYLOAD)
    if len(raw) < EXTENDED_PREFIX:
        prefix = len(raw).to_bytes(2, "big")
    else:  # Same bounded extension the decoder accepts, never above its limit.
        prefix = b"\x00\x00" + len(raw).to_bytes(4, "big")
    return prefix + raw + bytes(_padded_length(len(raw)) - len(raw))


def _encrypt_with_conversation_key(plaintext: str, conversation_key: bytes, nonce: bytes) -> str:
    chacha_key, chacha_nonce, hmac_key = _message_keys(conversation_key, nonce)
    ciphertext = ChaCha20.new(key=chacha_key, nonce=chacha_nonce).encrypt(_pad(plaintext))
    mac = hmac.digest(hmac_key, nonce + ciphertext, "sha256")
    encoded = base64.b64encode(bytes([VERSION]) + nonce + ciphertext + mac).decode("ascii")
    _invalid(len(encoded) <= MAX_ENCODED_PAYLOAD)
    return encoded


def _encrypt_payload(
    plaintext: str,
    *,
    sender_secret: bytes,
    recipient_public_key: bytes,
    crypto: Context,
) -> str:
    """Encrypt with a fresh random nonce; the caller signs the enclosing event."""
    _invalid(type(sender_secret) is bytes and len(sender_secret) == SHA256_SIZE)
    _invalid(type(recipient_public_key) is bytes and len(recipient_public_key) == SHA256_SIZE)
    try:
        shared_x = crypto.nip44_shared_x(sender_secret, recipient_public_key)
    except (AttributeError, RuntimeError):
        raise Nip44UnavailableError("NIP-44 v2 ECDH unavailable") from None
    finally:
        del sender_secret
    conversation_key = hmac.digest(b"nip44-v2", shared_x, "sha256")
    return _encrypt_with_conversation_key(plaintext, conversation_key, secrets.token_bytes(32))
