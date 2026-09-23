"""Static RS-001 envelope signature check, without admission or action authority.

Expectations must be derived from an independently authenticated session. A
successful check does not establish handshake completion, sender role, message
order, replay disposition, response linkage, or permission for any effect.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Protocol

from pydantic import TypeAdapter

from rill_core.errors import ValidationError
from rill_core.wire.canonical import parse_model_json
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from rill_core.wire.types import Hex32, Identifier, NetworkIdentity, ProfileId, XOnlyKey

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Set as AbstractSet


class EnvelopeSchnorrVerifier(Protocol):
    """BIP340 verifier whose success return is None, failure raises."""

    def schnorr_verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        """Verify an RS-001 envelope signature or raise."""
        ...


def _require(condition: bool) -> None:  # noqa: FBT001 - internal predicate
    if not condition:
        raise ValidationError("invalid static envelope expectation")


def verify_static_signed_envelope(  # noqa: PLR0913 - caller trust anchors stay explicit
    document: bytes,
    *,
    expected_session_id: Hex32,
    expected_profile: ProfileId,
    expected_network: NetworkIdentity,
    expected_sender_key: XOnlyKey,
    supported_features: AbstractSet[str],
    crypto: EnvelopeSchnorrVerifier,
) -> bytes:
    """Return the unsigned digest only if the given session-key signature holds.

    Handshake init/accept envelopes use different signature rules and are
    excluded. The caller must separately validate handshake confirmation,
    policy, role, and durable transcript ordering before processing an effect.
    All malformed or unverified inputs fail with the same redacted error.
    """
    try:
        envelope = parse_model_json(Envelope, document)
        session_id: str = TypeAdapter[str](Hex32).validate_python(expected_session_id, strict=True)
        profile: ProfileId = TypeAdapter[ProfileId](ProfileId).validate_python(
            expected_profile, strict=True
        )
        sender_key: str = TypeAdapter[str](XOnlyKey).validate_python(
            expected_sender_key, strict=True
        )
        # Revalidate even if a caller supplied a validation-bypassing model.
        network = NetworkIdentity.model_validate_json(
            json.dumps(expected_network.model_dump(mode="json")), strict=True
        )
        features = frozenset(supported_features)
        for feature in features:
            TypeAdapter(Identifier).validate_python(feature, strict=True)
        _require(
            not (
                envelope.session_id != session_id
                or envelope.profile_id != profile
                or envelope.network_identity != network
                or envelope.sender_session_key != sender_key
                or envelope.message_type in {"handshake_init", "handshake_accept"}
                or envelope.signature is None
                or not set(envelope.required_features).issubset(features)
            )
        )
        digest = unsigned_envelope_hash(envelope)
        # SchnorrVerifier's success contract is None, never a boolean result.
        verify: Callable[[bytes, bytes, bytes], object] = crypto.schnorr_verify
        _require(
            verify(bytes.fromhex(sender_key), digest, bytes.fromhex(envelope.signature or ""))
            is None
        )
    except Exception:  # noqa: BLE001, S110 - no parsing or adapter details may escape
        pass
    else:
        return digest
    raise ValidationError("invalid static signed envelope")
