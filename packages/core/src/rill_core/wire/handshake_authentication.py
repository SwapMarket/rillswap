"""Static RS-001 three-envelope transcript check, not session establishment.

Historical transcripts remain valid here. No message was necessarily received
live or in order, and no provider challenge or session key is proven locally
owned. Durable provider admission must establish those facts separately.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pydantic import TypeAdapter

from rill_core.errors import ValidationError
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.envelope_authentication import (
    EnvelopeSchnorrVerifier,
    verify_static_signed_envelope,
)
from rill_core.wire.hashes import handshake_accept_hash, handshake_hash
from rill_core.wire.messages import (
    Envelope,
    HandshakeAcceptPayload,
    HandshakeConfirm,
    HandshakeInit,
)
from rill_core.wire.types import Identifier, NetworkIdentity, ProfileId, XOnlyKey

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Set as AbstractSet


def _require(condition: bool) -> None:  # noqa: FBT001 - internal predicate
    if not condition:
        raise ValidationError("static handshake transcript differs")


def _identifiers(values: AbstractSet[str]) -> frozenset[str]:
    checked = frozenset(values)
    for value in checked:
        TypeAdapter[str](Identifier).validate_python(value, strict=True)
    return checked


def verify_static_handshake_transcript(  # noqa: PLR0913 - independent expectations explicit
    init_document: bytes,
    accept_document: bytes,
    confirm_document: bytes,
    *,
    expected_provider_identity: XOnlyKey,
    expected_profile: ProfileId,
    expected_network: NetworkIdentity,
    supported_features: AbstractSet[str],
    supported_encryption_suites: AbstractSet[str],
    supported_capabilities: AbstractSet[str],
    crypto: EnvelopeSchnorrVerifier,
) -> bytes:
    """Return the transcript digest, never a verified or admitted session.

    Init and accept outer envelopes are unsigned; only the inner acceptance is
    identity-signed. A separately signed confirm binds their reconstructed
    transcript, not transport order, freshness, or local provider key custody.
    """
    try:
        init_envelope = parse_model_json(Envelope, init_document)
        accept_envelope = parse_model_json(Envelope, accept_document)
        confirm_envelope = parse_model_json(Envelope, confirm_document)
        initiation = HandshakeInit.model_validate_json(canonicalize(init_envelope.payload))
        accepted = HandshakeAcceptPayload.model_validate_json(canonicalize(accept_envelope.payload))
        confirmation = HandshakeConfirm.model_validate_json(canonicalize(confirm_envelope.payload))
        selection = accepted.accept
        profile = TypeAdapter[ProfileId](ProfileId).validate_python(expected_profile, strict=True)
        provider_key: str = TypeAdapter[str](XOnlyKey).validate_python(
            expected_provider_identity, strict=True
        )
        network = NetworkIdentity.model_validate_json(
            json.dumps(expected_network.model_dump(mode="json")), strict=True
        )
        features = _identifiers(supported_features)
        suites = _identifiers(supported_encryption_suites)
        capabilities = _identifiers(supported_capabilities)
        _require(
            init_envelope.message_type == "handshake_init"
            and init_envelope.sequence == 0
            and init_envelope.in_reply_to is None
            and init_envelope.contract_hash is None
            and init_envelope.signature is None
            and init_envelope.sender_session_key == initiation.client_session_xonly_key
            and accept_envelope.message_type == "handshake_accept"
            and accept_envelope.sequence == 0
            and accept_envelope.in_reply_to == init_envelope.message_id
            and accept_envelope.contract_hash is None
            and accept_envelope.signature is None
            and accept_envelope.sender_session_key == selection.provider_session_xonly_key
            and confirm_envelope.message_type == "handshake_confirm"
            and confirm_envelope.sequence == 1
            and confirm_envelope.in_reply_to == accept_envelope.message_id
            and confirm_envelope.contract_hash is None
            and confirm_envelope.sender_session_key == initiation.client_session_xonly_key
            # RS-001 uniqueness is per sender stream, not across both roles.
            and init_envelope.message_id != confirm_envelope.message_id
        )
        _require(
            all(
                envelope.profile_id == profile
                and envelope.network_identity == network
                and envelope.session_id == initiation.session_id
                and set(envelope.required_features).issubset(features)
                for envelope in (init_envelope, accept_envelope, confirm_envelope)
            )
            and initiation.profile_id == selection.profile_id == profile
            and initiation.network_identity == selection.network_identity == network
            and initiation.expected_provider_identity_xonly_key == provider_key
            and selection.provider_identity_xonly_key == provider_key
        )
        selection.validate_against(initiation, supported_features=features)
        _require(
            selection.selected_encryption_suite in suites
            and set(selection.selected_capabilities).issubset(capabilities)
        )
        verify: Callable[[bytes, bytes, bytes], object] = crypto.schnorr_verify
        _require(
            verify(
                bytes.fromhex(provider_key),
                handshake_accept_hash(selection),
                bytes.fromhex(accepted.provider_identity_signature),
            )
            is None
        )
        digest = handshake_hash(initiation, selection)
        _require(
            confirmation.handshake_hash == digest.hex()
            and confirmation.session_id == initiation.session_id
            and confirmation.client_session_xonly_key == initiation.client_session_xonly_key
            and confirmation.provider_session_xonly_key == selection.provider_session_xonly_key
        )
        verify_static_signed_envelope(
            confirm_document,
            expected_session_id=initiation.session_id,
            expected_profile=profile,
            expected_network=network,
            expected_sender_key=initiation.client_session_xonly_key,
            supported_features=features,
            crypto=crypto,
        )
    except Exception:  # noqa: BLE001, S110 - never echo signed input or adapter details
        pass
    else:
        return digest
    raise ValidationError("invalid static handshake transcript")
