"""Internal RS-006 transport proof of work: NIP-13 on provider-bound gift wraps.

A provider that advertises ``rillswap/transport-pow`` requires work on every
kind-1059 outer event sent to it and checks it before any decryption. Work is
the number of leading zero bits of the recomputed NIP-01 event ID, counted
only up to the target committed by exactly one ``["nonce", counter, target]``
tag, so a lucky event never proves more than its sender committed to. Mining
varies only the counter, keeping the randomized NIP-59 ``created_at``. Work
raises the cost of floods; it is not authentication or principal protection.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from rill_provider import _nip01_event as nip01

TRANSPORT_POW_EXTENSION = "rillswap/transport-pow"
MAX_WORK_BITS = 20  # about a million hashes: seconds in a browser, never minutes
OUTER_KIND = 1059
_TARGET = re.compile(r"(0|[1-9][0-9]{0,2})\Z")
_PLACEHOLDER = "\x00"  # JSON always escapes it, and no NIP-59 field contains it


class TransportWorkError(ValueError):
    """A transport proof-of-work requirement or mining request is malformed."""


def leading_zero_bits(event_id: str) -> int:
    """Return the leading zero bits of a 32-byte hex event ID."""
    return 256 - int(event_id, 16).bit_length()


def committed_work(event_id: str, tags: Sequence[Sequence[str]]) -> int:
    """Return the work an event proves: its zero bits, capped by its committed target."""
    nonces = [tag for tag in tags if tag[0] == "nonce"]
    if len(nonces) != 1 or len(nonces[0]) != 3 or _TARGET.fullmatch(nonces[0][2]) is None:  # noqa: PLR2004
        return 0
    return min(leading_zero_bits(event_id), int(nonces[0][2]))


def outer_work(raw: bytes) -> tuple[str, int] | None:
    """Return a kind-1059 event's recipient and proven work, or None if malformed.

    Recomputes the event ID but never verifies the signature: callers use this
    only to drop events before any EC work, and the receive path still
    authenticates everything it keeps.
    """
    try:
        event = nip01._parse(raw)  # noqa: SLF001 - shared NIP-01 hash invariant
    except nip01.Nip01InvalidEventError:
        return None
    recipients = [tag for tag in event.tags if tag[0] == "p"]
    if event.kind != OUTER_KIND or len(recipients) != 1 or len(recipients[0]) != 2:  # noqa: PLR2004
        return None
    return recipients[0][1], committed_work(event.id, event.tags)


def requirement(extensions: Mapping[str, Any]) -> int | None:
    """Return the work an announcement or init requires, or None when absent."""
    if not isinstance(extensions, Mapping):
        raise TransportWorkError("extensions refused")
    if TRANSPORT_POW_EXTENSION not in extensions:
        return None
    value = extensions[TRANSPORT_POW_EXTENSION]
    if not (
        type(value) is dict
        and value.keys() == {"bits"}
        and type(value["bits"]) is int
        and 1 <= value["bits"] <= MAX_WORK_BITS
    ):
        raise TransportWorkError("transport proof-of-work requirement refused")
    bits: int = value["bits"]
    return bits


def mine(  # noqa: PLR0913 - explicit NIP-01 fields
    pubkey: str,
    created_at: int,
    kind: int,
    tags: list[list[str]],
    content: str,
    *,
    bits: int,
) -> list[list[str]]:
    """Return ``tags`` plus a nonce tag whose event ID has ``bits`` leading zeros.

    Hashes the fixed prefix once and only the counter and the rest of the
    event per attempt; the content follows the tags in NIP-01's array, so it
    is rehashed every time.
    """
    if type(bits) is not int or not 1 <= bits <= MAX_WORK_BITS:
        raise TransportWorkError("transport proof-of-work target refused")
    template = [*tags, ["nonce", _PLACEHOLDER, str(bits)]]
    serialized = json.dumps(
        [0, pubkey, created_at, kind, template, content],
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    marker = json.dumps(_PLACEHOLDER)
    if serialized.count(marker) != 1:
        raise TransportWorkError("transport proof-of-work template refused")
    prefix, _, suffix = serialized.partition(marker)
    head = hashlib.sha256(f'{prefix}"'.encode())
    tail = f'"{suffix}'.encode()
    shift = 256 - bits
    for counter in range(1 << (bits + 16)):  # failing this bound has probability e**-65536
        attempt = head.copy()
        attempt.update(str(counter).encode() + tail)
        if int.from_bytes(attempt.digest(), "big") >> shift == 0:
            mined = [*tags, ["nonce", str(counter), str(bits)]]
            event_id = nip01._event_id(pubkey, created_at, kind, mined, content)  # noqa: SLF001
            if leading_zero_bits(event_id) < bits:  # the splice must equal NIP-01 hashing
                raise TransportWorkError("transport proof-of-work splice mismatch")
            return mined
    raise TransportWorkError("transport proof-of-work not found")
