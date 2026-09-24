"""Disconnected private-regtest NIP-59 frame decoder, never session admission.

This validates one already-received gift wrap and its encrypted seal/rumor.
It has no relay listener, authenticated sender registry, replay disposition,
inbox/outbox, provider signer, financial effects, or recovery authority.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from rill_core.wire.canonical import MAX_JSON_BYTES, canonicalize, parse_json_strict
from rill_core.wire.messages import Envelope

from rill_provider import _nip01_event as nip01
from rill_provider import _nip44_v2 as nip44

if TYPE_CHECKING:
    from rill_core.wire.types import NetworkIdentity
    from rill_crypto import Context

RUMOR_MEMBERS = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content"})
RUMOR_KIND = 21417
OUTER_KIND = 1059
SEAL_KIND = 13
BINDING_TAG = (("rillswap", "nostr-experimental-1"),)


class Nip59ReceiveRefusedError(ValueError):
    """The gift wrap is not a valid private-regtest RillSwap frame candidate."""


class Nip59CapabilityUnavailableError(RuntimeError):
    """The configured local native verifier or ECDH primitive is unavailable."""


@dataclass(frozen=True, slots=True)
class _UntrustedFrameCandidate:
    """Transport-validated bytes, without peer authorization or replay authority."""

    outer_event_id: str
    rumor_id: str
    seal_author_xonly_key: str
    envelope: Envelope


def _require(condition: bool) -> None:  # noqa: FBT001 - local guard
    if not condition:
        raise Nip59ReceiveRefusedError("NIP-59 frame candidate refused")


def _rumor(raw: bytes) -> tuple[str, str, Envelope]:
    _require(0 < len(raw) <= nip01.MAX_EVENT_BYTES)
    parsed_document = parse_json_strict(raw, max_bytes=nip01.MAX_EVENT_BYTES)
    _require(type(parsed_document) is dict and parsed_document.keys() == RUMOR_MEMBERS)
    document = cast("dict[str, Any]", parsed_document)
    _require(type(document["id"]) is str and nip01.HEX32.fullmatch(document["id"]) is not None)
    _require(
        type(document["pubkey"]) is str and nip01.HEX32.fullmatch(document["pubkey"]) is not None
    )
    _require(
        type(document["created_at"]) is int
        and 0 <= document["created_at"] <= nip01.MAX_SAFE_TIMESTAMP
    )
    _require(document["kind"] == RUMOR_KIND and type(document["kind"]) is int)
    _require(document["tags"] == [["rillswap", "nostr-experimental-1"]])
    _require(type(document["content"]) is str)
    content = document["content"].encode("utf-8")
    _require(0 < len(content) <= MAX_JSON_BYTES)
    computed = nip01._event_id(  # noqa: SLF001 - shared NIP-01 hash invariant
        document["pubkey"],
        document["created_at"],
        document["kind"],
        document["tags"],
        document["content"],
    )
    _require(computed == document["id"])
    parsed = parse_json_strict(content)
    _require(canonicalize(parsed) == content)
    envelope = Envelope.model_validate_json(content, strict=True)
    _require(envelope.sender_session_key == document["pubkey"])
    return document["id"], document["pubkey"], envelope


def _decode(  # noqa: PLR0913 - independent local trust roots explicit
    outer_raw: bytes,
    *,
    recipient_mailbox_secret: bytes,
    expected_recipient_xonly_key: str,
    expected_network: NetworkIdentity,
    expected_profile_id: str,
    crypto: Context,
) -> _UntrustedFrameCandidate:
    _require(
        type(expected_recipient_xonly_key) is str
        and nip01.HEX32.fullmatch(expected_recipient_xonly_key) is not None
    )
    _require(
        type(recipient_mailbox_secret) is bytes
        and len(recipient_mailbox_secret) == nip44.SHA256_SIZE
    )
    _require(type(expected_profile_id) is str)
    # Never decrypt before authenticating the outer event, its ID, and signature.
    outer = nip01._verify_signed_event(outer_raw, verifier=crypto)  # noqa: SLF001
    _require(outer.kind == OUTER_KIND)
    recipient_tags = tuple(tag for tag in outer.tags if tag[0] == "p")
    _require(recipient_tags == (("p", expected_recipient_xonly_key),))
    # The configured mailbox key must actually correspond to the scalar used
    # for decryption; neither is a provider identity nor contract signing key.
    _require(crypto.public_key(recipient_mailbox_secret)[1:].hex() == expected_recipient_xonly_key)
    seal_raw = nip44._decrypt_payload(  # noqa: SLF001 - outer signature already checked
        outer.content,
        recipient_secret=recipient_mailbox_secret,
        sender_public_key=bytes.fromhex(outer.pubkey),
        crypto=crypto,
    ).encode("utf-8")
    seal = nip01._verify_signed_event(seal_raw, verifier=crypto)  # noqa: SLF001
    _require(seal.kind == SEAL_KIND and seal.tags == ())
    rumor_raw = nip44._decrypt_payload(  # noqa: SLF001 - seal signature already checked
        seal.content,
        recipient_secret=recipient_mailbox_secret,
        sender_public_key=bytes.fromhex(seal.pubkey),
        crypto=crypto,
    ).encode("utf-8")
    rumor_id, rumor_author, envelope = _rumor(rumor_raw)
    _require(rumor_author == seal.pubkey)
    _require(envelope.network_identity == expected_network)
    _require(envelope.profile_id == expected_profile_id)
    return _UntrustedFrameCandidate(
        outer_event_id=outer.id,
        rumor_id=rumor_id,
        seal_author_xonly_key=seal.pubkey,
        envelope=envelope,
    )


def _decode_gift_wrap_candidate(  # noqa: PLR0913 - explicit independent trust roots
    outer_raw: bytes,
    *,
    recipient_mailbox_secret: bytes,
    expected_recipient_xonly_key: str,
    expected_network: NetworkIdentity,
    expected_profile_id: str,
    crypto: Context,
) -> _UntrustedFrameCandidate:
    """Decode a received candidate without admitting or persisting a swap."""
    result: _UntrustedFrameCandidate | None = None
    unavailable = False
    interrupted: type[BaseException] | None = None
    try:
        try:
            result = _decode(
                outer_raw,
                recipient_mailbox_secret=recipient_mailbox_secret,
                expected_recipient_xonly_key=expected_recipient_xonly_key,
                expected_network=expected_network,
                expected_profile_id=expected_profile_id,
                crypto=crypto,
            )
        finally:
            del outer_raw, recipient_mailbox_secret  # Do not retain inputs in error frames.
    except (nip01.Nip01VerifierUnavailableError, nip44.Nip44UnavailableError):
        unavailable = True
    except KeyboardInterrupt:
        interrupted = KeyboardInterrupt
    except SystemExit:
        interrupted = SystemExit
    except asyncio.CancelledError:
        interrupted = asyncio.CancelledError
    except GeneratorExit:
        interrupted = GeneratorExit
    except Exception:  # noqa: BLE001, S110 - drop helper/native decrypted-data frames
        pass
    if interrupted is not None:
        raise interrupted("NIP-59 candidate decoding interrupted")
    if unavailable:
        raise Nip59CapabilityUnavailableError("NIP-59 native capability unavailable")
    if result is None:
        raise Nip59ReceiveRefusedError("NIP-59 frame candidate refused")
    return result
