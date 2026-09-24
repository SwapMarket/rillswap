"""Internal NIP-01 signed-event verifier, disconnected from relay receive.

Matching a signed event ID and signature proves control of its stated pubkey,
not the expected recipient, client session, transport peer, or swap authority.
Gift-wrap kind and recipient routing are distinct NIP-59 policy checks.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rill_crypto import CryptoError

if TYPE_CHECKING:
    from rill_crypto import Context

MAX_EVENT_BYTES = 128 * 1024
MAX_SAFE_TIMESTAMP = (1 << 53) - 1
MAX_KIND = 65535
MAX_TAGS = 256
MAX_TAG_MEMBERS = 16
SIGNED_MEMBERS = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
HEX64 = re.compile(r"[0-9a-f]{128}\Z")


class Nip01InvalidEventError(ValueError):
    """The signed event is malformed or its ID/signature did not verify."""


class Nip01VerifierUnavailableError(RuntimeError):
    """The configured native signature verifier is unavailable."""


@dataclass(frozen=True, slots=True)
class _SignedEvent:
    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: tuple[tuple[str, ...], ...]
    content: str
    sig: str


def _require(condition: bool) -> None:  # noqa: FBT001 - internal guard
    if not condition:
        raise Nip01InvalidEventError("NIP-01 signed event refused")


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        _require(name not in result)
        result[name] = value
    return result


def _parse(raw: bytes) -> _SignedEvent:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_EVENT_BYTES)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_members)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise Nip01InvalidEventError("NIP-01 signed event refused") from None
    _require(type(document) is dict and document.keys() == SIGNED_MEMBERS)
    _require(type(document["id"]) is str and HEX32.fullmatch(document["id"]) is not None)
    _require(type(document["pubkey"]) is str and HEX32.fullmatch(document["pubkey"]) is not None)
    _require(type(document["sig"]) is str and HEX64.fullmatch(document["sig"]) is not None)
    _require(
        type(document["created_at"]) is int and 0 <= document["created_at"] <= MAX_SAFE_TIMESTAMP
    )
    _require(type(document["kind"]) is int and 0 <= document["kind"] <= MAX_KIND)
    _require(type(document["content"]) is str)
    _require(type(document["tags"]) is list and len(document["tags"]) <= MAX_TAGS)
    tags = document["tags"]
    for tag in tags:
        _require(type(tag) is list and 1 <= len(tag) <= MAX_TAG_MEMBERS)
        _require(all(type(member) is str for member in tag))
    try:
        serialized = json.dumps(
            [
                0,
                document["pubkey"],
                document["created_at"],
                document["kind"],
                tags,
                document["content"],
            ],
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except UnicodeEncodeError:
        raise Nip01InvalidEventError("NIP-01 signed event refused") from None
    _require(hashlib.sha256(serialized).hexdigest() == document["id"])
    return _SignedEvent(
        id=document["id"],
        pubkey=document["pubkey"],
        created_at=document["created_at"],
        kind=document["kind"],
        tags=tuple(tuple(tag) for tag in tags),
        content=document["content"],
        sig=document["sig"],
    )


def _verify(raw: bytes, verifier: Context) -> _SignedEvent:
    event = _parse(raw)
    try:
        verifier.schnorr_verify(
            bytes.fromhex(event.pubkey),
            bytes.fromhex(event.id),
            bytes.fromhex(event.sig),
        )
    except CryptoError:
        raise Nip01InvalidEventError("NIP-01 signed event refused") from None
    except (AttributeError, RuntimeError):
        raise Nip01VerifierUnavailableError("NIP-01 verifier unavailable") from None
    return event


def _verify_signed_event(raw: bytes, *, verifier: Context) -> _SignedEvent:
    """Verify an event, with no implicit kind, recipient, or session policy."""
    result: _SignedEvent | None = None
    unavailable = False
    interrupted: type[BaseException] | None = None
    try:
        try:
            result = _verify(raw, verifier)
        finally:
            del raw  # Do not retain the original event in sanitized library traceback frames.
    except Nip01VerifierUnavailableError:
        unavailable = True
    except KeyboardInterrupt:
        interrupted = KeyboardInterrupt
    except SystemExit:
        interrupted = SystemExit
    except asyncio.CancelledError:
        interrupted = asyncio.CancelledError
    except GeneratorExit:
        interrupted = GeneratorExit
    except Exception:  # noqa: BLE001, S110 - discard native and parser traceback locals
        pass
    if interrupted is not None:
        raise interrupted("NIP-01 verification interrupted")
    if unavailable:
        raise Nip01VerifierUnavailableError("NIP-01 verifier unavailable")
    if result is None:
        raise Nip01InvalidEventError("NIP-01 signed event refused")
    return result
