"""Canonical versioned tagged hashes used by the wire protocol."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, cast

from rill_core.wire.canonical import JsonValue, canonicalize

if TYPE_CHECKING:
    from pydantic import BaseModel

    from rill_core.wire.messages import (
        ClientAcceptance,
        ContractTerms,
        Envelope,
        FundingBinding,
        HandshakeAccept,
        HandshakeInit,
        ProviderTerms,
    )


def tagged_hash(tag: str, message: bytes) -> bytes:
    """Return SHA256(SHA256(tag) || SHA256(tag) || message)."""
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def canonical_model(model: BaseModel, *, exclude: set[str] | None = None) -> bytes:
    """Serialize a closed Pydantic model as canonical protocol JSON."""
    value = model.model_dump(mode="json", exclude=exclude)
    return canonicalize(cast("JsonValue", value))


def contract_hash(terms: ContractTerms) -> bytes:
    """Hash complete contract terms with the version-one domain."""
    return tagged_hash("RillSwap/contract/v1", canonical_model(terms))


def handshake_init_hash(initiation: HandshakeInit) -> bytes:
    """Hash the exact closed handshake initiation object."""
    return tagged_hash("RillSwap/handshake-init/v1", canonical_model(initiation))


def handshake_accept_hash(acceptance: HandshakeAccept) -> bytes:
    """Hash the provider's exact closed handshake acceptance object."""
    return tagged_hash("RillSwap/handshake/v1", canonical_model(acceptance))


def handshake_hash(initiation: HandshakeInit, acceptance: HandshakeAccept) -> bytes:
    """Hash the ordered closed init and acceptance transcript."""
    transcript: JsonValue = {
        "accept": cast("JsonValue", acceptance.model_dump(mode="json")),
        "init": cast("JsonValue", initiation.model_dump(mode="json")),
    }
    return tagged_hash("RillSwap/transcript/v1", canonicalize(transcript))


def provider_terms_hash(provider_terms: ProviderTerms) -> bytes:
    """Hash provider terms for the provider identity signature."""
    return tagged_hash("RillSwap/provider-terms/v1", canonical_model(provider_terms))


def client_acceptance_hash(acceptance: ClientAcceptance) -> bytes:
    """Hash client acceptance for the client session-key signature."""
    return tagged_hash("RillSwap/client-acceptance/v1", canonical_model(acceptance))


def funding_binding_hash(binding: FundingBinding) -> bytes:
    """Hash a funding binding for the funder's session-key signature."""
    return tagged_hash("RillSwap/funding-binding/v1", canonical_model(binding))


def unsigned_envelope_hash(envelope: Envelope) -> bytes:
    """Hash the entire envelope with only its signature member omitted."""
    return tagged_hash(
        "RillSwap/envelope/v1",
        canonical_model(envelope, exclude={"signature"}),
    )
