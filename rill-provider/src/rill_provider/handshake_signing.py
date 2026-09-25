"""Purpose-scoped provider handshake signing, not session admission.

An independently configured provider key and available session-key custody
are prerequisites. Signed bytes alone are not evidence of live receipt,
ordering, freshness, durable replay disposition, or financial authority.
There is no production custody implementation in this package yet.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from pydantic import TypeAdapter
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import handshake_accept_hash, handshake_init_hash
from rill_core.wire.messages import HandshakeAccept, HandshakeInit
from rill_core.wire.types import Identifier, NetworkIdentity, ProfileId, XOnlyKey

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Set as AbstractSet

    from rill_core.wire.envelope_authentication import EnvelopeSchnorrVerifier

SIGNATURE_LENGTH = 64


@dataclass(frozen=True, slots=True)
class SessionKeyRef:
    """Public opaque custody reference, never a raw key or permission token."""

    custody_id: str
    key_id: str
    xonly_public_key: str


@dataclass(frozen=True, slots=True)
class SessionReservation:
    """Immutable public intent including the complete canonical network value."""

    session_id: str
    handshake_init_hash: str
    profile_id: str
    network_identity_jcs: bytes
    provider_identity_key: str


class HandshakeSigningError(Exception):
    """Refuse signing without disclosing signed input or custody details."""


class HandshakeCustody(Protocol):
    """Purpose-specific, externally managed signer and session-key custody."""

    def reserve_session(self, binding: SessionReservation) -> SessionKeyRef:
        """Idempotently reserve a live session key for an immutable binding."""
        ...

    def require_session(self, binding: SessionReservation, ref: SessionKeyRef) -> None:
        """Fail if the exact session key is unavailable; never replace it."""
        ...

    def identity_xonly_public_key(self) -> str:
        """Return independently provisioned provider identity x-only public key."""
        ...

    def sign_handshake_accept_hash(self, digest: bytes) -> bytes:
        """Sign only the domain-tagged RS-001 acceptance digest."""
        ...


def _identifiers(values: AbstractSet[str]) -> frozenset[str]:
    checked = frozenset(values)
    for item in checked:
        TypeAdapter[str](Identifier).validate_python(item, strict=True)
    return checked


def _validate_trust(
    expected_network: NetworkIdentity,
    expected_profile: ProfileId,
    expected_identity: XOnlyKey,
) -> tuple[NetworkIdentity, ProfileId, str]:
    network = NetworkIdentity.model_validate_json(
        json.dumps(expected_network.model_dump(mode="json")),
        strict=True,
    )
    profile = TypeAdapter[ProfileId](ProfileId).validate_python(expected_profile, strict=True)
    identity: str = TypeAdapter[str](XOnlyKey).validate_python(expected_identity, strict=True)
    return network, profile, identity


def _require(condition: bool) -> None:  # noqa: FBT001 - local protocol predicate
    if not condition:
        raise ValueError("acceptance does not match independently expected custody")


def session_reservation_for_init(
    init_document: bytes,
    *,
    expected_network: NetworkIdentity,
    expected_profile: ProfileId,
    expected_provider_identity: XOnlyKey,
    supported_features: AbstractSet[str],
) -> SessionReservation:
    """Construct a public reservation binding from bounded init bytes.

    The caller must separately enforce local receipt, freshness, and durable
    uniqueness. Parsing an init is not evidence that it was received once.
    """
    try:
        network, profile, identity = _validate_trust(
            expected_network,
            expected_profile,
            expected_provider_identity,
        )
        init = parse_model_json(HandshakeInit, init_document)
        features = _identifiers(supported_features)
        _require(
            init.network_identity == network
            and init.profile_id == profile
            and init.expected_provider_identity_xonly_key == identity
            and set(init.required_features).issubset(features)
        )
        result = SessionReservation(
            init.session_id,
            handshake_init_hash(init).hex(),
            profile,
            canonicalize(network.model_dump(mode="json")),
            identity,
        )
    except Exception:  # noqa: BLE001, S110 - never expose input or adapter errors
        pass
    else:
        return result
    raise HandshakeSigningError("invalid handshake reservation")


def sign_handshake_accept(  # noqa: PLR0913 - independent policy inputs explicit
    init_document: bytes,
    accept_document: bytes,
    *,
    expected_network: NetworkIdentity,
    expected_profile: ProfileId,
    expected_provider_identity: XOnlyKey,
    supported_features: AbstractSet[str],
    supported_encryption_suites: AbstractSet[str],
    supported_capabilities: AbstractSet[str],
    session_ref: SessionKeyRef,
    custody: HandshakeCustody,
    crypto: EnvelopeSchnorrVerifier,
) -> str:
    """Return an identity signature over a validated inner acceptance only.

    The caller must persist exact pending intent and response before exposing
    an accept envelope. This function does not authenticate its unsigned outer
    wrapper, admit a session, retain a secret, or authorize an effect.
    """
    try:
        network, profile, identity = _validate_trust(
            expected_network,
            expected_profile,
            expected_provider_identity,
        )
        binding = session_reservation_for_init(
            init_document,
            expected_network=network,
            expected_profile=profile,
            expected_provider_identity=identity,
            supported_features=supported_features,
        )
        initiation = parse_model_json(HandshakeInit, init_document)
        acceptance = parse_model_json(HandshakeAccept, accept_document)
        features = _identifiers(supported_features)
        suites = _identifiers(supported_encryption_suites)
        capabilities = _identifiers(supported_capabilities)
        acceptance.validate_against(initiation, supported_features=features)
        _require(
            acceptance.network_identity == network
            and acceptance.profile_id == profile
            and acceptance.provider_identity_xonly_key == identity
            and acceptance.selected_encryption_suite in suites
            and set(acceptance.selected_capabilities).issubset(capabilities)
            and type(session_ref) is SessionKeyRef
            and acceptance.provider_session_xonly_key == session_ref.xonly_public_key
            and custody.identity_xonly_public_key() == identity
        )
        custody.require_session(binding, session_ref)
        digest = handshake_accept_hash(acceptance)
        signature = custody.sign_handshake_accept_hash(digest)
        _require(type(signature) is bytes and len(signature) == SIGNATURE_LENGTH)
        verify: Callable[[bytes, bytes, bytes], object] = crypto.schnorr_verify
        _require(verify(bytes.fromhex(identity), digest, signature) is None)
        result = signature.hex()
    except Exception:  # noqa: BLE001, S110 - no key/adapter/error text or context escapes
        pass
    else:
        return result
    raise HandshakeSigningError("handshake acceptance signing unavailable")
