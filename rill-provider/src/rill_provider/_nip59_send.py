"""Internal RS-006 NIP-59 wrapper for one committed RS-001 envelope.

The exact inverse of ``_nip59_receive``: rumor (kind 21417, RillSwap binding
tag) authored by the sender session key, sealed (kind 13) and signed by that
key, then gift-wrapped (kind 1059) by a fresh one-time key to exactly one
recipient mailbox. Every call uses fresh seal/wrapper randomness and
randomized past timestamps, so retransmissions of one logical message are
unlinkable. Wrapping is NOT publication, and the caller must have durably
committed the envelope bytes first.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import TYPE_CHECKING, Any

from rill_core.wire.canonical import MAX_JSON_BYTES, canonicalize, parse_json_strict
from rill_core.wire.messages import Envelope

from rill_provider import _nip01_event as nip01
from rill_provider import _nip44_v2 as nip44
from rill_provider import _transport_pow as transport_pow
from rill_provider._nip59_receive import BINDING_TAG, OUTER_KIND, RUMOR_KIND, SEAL_KIND

if TYPE_CHECKING:
    from rill_crypto import Context

TIMESTAMP_JITTER_SECONDS = 2 * 24 * 60 * 60  # NIP-59 randomizes up to two days back.
MAX_WRAPPER_TRIES = 4


class Nip59WrapRefusedError(ValueError):
    """The envelope or keys cannot be wrapped as an RS-006 frame."""


def _require(condition: bool) -> None:  # noqa: FBT001 - local guard
    if not condition:
        raise Nip59WrapRefusedError("NIP-59 wrap refused")


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _signed(  # noqa: PLR0913, PLR0917 - explicit NIP-01 fields
    secret: bytes,
    pubkey: str,
    created_at: int,
    kind: int,
    tags: list[list[str]],
    content: str,
    crypto: Context,
) -> str:
    event_id = nip01._event_id(pubkey, created_at, kind, tags, content)  # noqa: SLF001
    signature = crypto.schnorr_sign(secret, bytes.fromhex(event_id), secrets.token_bytes(32))
    return _json(
        {
            "id": event_id,
            "pubkey": pubkey,
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": content,
            "sig": signature.hex(),
        }
    )


def _past(now: int) -> int:
    return now - secrets.randbelow(TIMESTAMP_JITTER_SECONDS)


def _wrap_envelope(
    envelope_bytes: bytes,
    *,
    sender_session_secret: bytes,
    recipient_xonly_key: str,
    crypto: Context,
    work_bits: int = 0,
) -> bytes:
    """Return one freshly randomized kind-1059 event for a canonical envelope.

    ``work_bits`` > 0 mines RS-006 transport proof of work into the outer
    event, as a provider advertising ``rillswap/transport-pow`` requires.
    """
    _require(type(work_bits) is int and 0 <= work_bits <= transport_pow.MAX_WORK_BITS)
    _require(type(envelope_bytes) is bytes and 0 < len(envelope_bytes) <= MAX_JSON_BYTES)
    _require(canonicalize(parse_json_strict(envelope_bytes)) == envelope_bytes)
    envelope = Envelope.model_validate_json(envelope_bytes, strict=True)
    _require(
        type(recipient_xonly_key) is str and nip01.HEX32.fullmatch(recipient_xonly_key) is not None
    )
    _require(type(sender_session_secret) is bytes and len(sender_session_secret) == 32)  # noqa: PLR2004
    sender = crypto.public_key(sender_session_secret)[1:].hex()
    _require(sender == envelope.sender_session_key and sender != recipient_xonly_key)
    recipient = bytes.fromhex(recipient_xonly_key)
    now = int(time.time())
    tags = [list(tag) for tag in BINDING_TAG]
    content = envelope_bytes.decode("utf-8")
    rumor = {
        "id": nip01._event_id(sender, now, RUMOR_KIND, tags, content),  # noqa: SLF001
        "pubkey": sender,
        "created_at": now,
        "kind": RUMOR_KIND,
        "tags": tags,
        "content": content,
    }
    sealed = nip44._encrypt_payload(  # noqa: SLF001 - internal codec
        _json(rumor),
        sender_secret=sender_session_secret,
        recipient_public_key=recipient,
        crypto=crypto,
    )
    seal = _signed(sender_session_secret, sender, _past(now), SEAL_KIND, [], sealed, crypto)
    del sender_session_secret
    for _ in range(MAX_WRAPPER_TRIES):
        wrapper_secret = secrets.token_bytes(32)
        try:
            wrapper = crypto.public_key(wrapper_secret)[1:].hex()
        except Exception:  # noqa: BLE001, S112 - invalid scalar, draw again
            continue
        if wrapper not in (sender, recipient_xonly_key):
            break
    else:
        raise Nip59WrapRefusedError("one-time wrapper key unavailable")
    outer_content = nip44._encrypt_payload(  # noqa: SLF001 - internal codec
        seal, sender_secret=wrapper_secret, recipient_public_key=recipient, crypto=crypto
    )
    created_at = _past(now)
    tags = [["p", recipient_xonly_key]]
    if work_bits:
        tags = transport_pow.mine(
            wrapper, created_at, OUTER_KIND, tags, outer_content, bits=work_bits
        )
    outer = _signed(wrapper_secret, wrapper, created_at, OUTER_KIND, tags, outer_content, crypto)
    del wrapper_secret
    result = outer.encode("utf-8")
    _require(len(result) <= nip01.MAX_EVENT_BYTES)
    return result
