"""Provider identity key custody with purpose-scoped signing only.

The long-lived identity scalar lives in one explicitly provisioned,
age-encrypted file. It is never created implicitly, never replaced, and never
returned. Callers can only ask for signatures over digests this module derives
itself from typed inputs: an RS-001 handshake accept for this identity, or a
single-network RS-005 announcement. There is no raw-digest signing API.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pyrage  # type: ignore[import-untyped]
from pyrage import x25519
from rill_core.errors import ValidationError
from rill_core.networks import require_supported_network
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import (
    EPOCH_SESSION_FEATURE,
    HANDSHAKE_FEATURES_EXTENSION,
    handshake_accept_hash,
    provider_terms_hash,
    tagged_hash,
)
from rill_core.wire.messages import HandshakeAccept, ProviderTerms
from rill_core.wire.types import NetworkIdentity

from rill_provider import _nip01_event as nip01

if TYPE_CHECKING:
    from os import PathLike

    from rill_crypto import Context

RECORD_KIND = "rill-provider/identity-key/v1"
MAX_FILE_BYTES = 4096
ANNOUNCEMENT_KIND = 39417
BINDING_VERSION = "nostr-experimental-1"
COMMUNICATION_SUITE = "nostr-nip44v2-nip59/v1"
ADVERTISEMENT_TAG = "RillSwap/advertisement/v1"
MAX_EPOCH_KEYS = 4
MAX_CONTENT_BYTES = 64 * 1024
COMPRESSED_KEY_BYTES = 33


class ProviderIdentityError(ValueError):
    """No identity signature or custody fact was established."""


@dataclass(frozen=True, slots=True)
class AnnouncementTerms:
    """Operator-chosen public terms for one single-network announcement."""

    network: NetworkIdentity
    profiles: tuple[str, ...]
    amount_bands: tuple[tuple[int, int], ...]
    base_fee_sat: int
    proportional_millionths: int
    transport_endpoints: tuple[str, ...]
    epoch_inbox_xonly_keys: tuple[str, ...]
    slot: str
    created_at: int
    expires_at: int
    epoch_bound_sessions: bool = False


def _xonly(public_keys: Context, scalar: bytes) -> str:
    key = public_keys.public_key(scalar)
    if type(key) is not bytes or len(key) != COMPRESSED_KEY_BYTES or key[0] not in (2, 3):
        raise ProviderIdentityError("identity public key derivation failed")
    return key[1:].hex()


class ProviderIdentity:
    """Loaded identity; signs only digests it derives from typed inputs."""

    def __init__(self, scalar: bytes, xonly: str, crypto: Context) -> None:
        """Use load(); never construct directly."""
        self._scalar = scalar
        self.xonly_public_key = xonly
        self._crypto = crypto

    def __repr__(self) -> str:
        """Never render secret material."""
        return f"ProviderIdentity({self.xonly_public_key})"

    @staticmethod
    def provision(path: str | PathLike[str], *, recipient: str, crypto: Context) -> str:
        """Create a new identity file exclusively; return only its public key."""
        location = Path(path).absolute()
        try:
            scalar = secrets.token_bytes(32)
            xonly = _xonly(crypto, scalar)
            record = canonicalize(
                {"kind": RECORD_KIND, "secret_scalar": scalar.hex(), "xonly_public_key": xonly}
            )
            unlocking = x25519.Recipient.from_str(recipient)
            sealed = pyrage.encrypt(record, [unlocking])
            descriptor = os.open(
                location, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(descriptor, "wb") as target:
                target.write(sealed)
                target.flush()
                os.fsync(target.fileno())
            directory = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:  # noqa: BLE001 - never echo secret material; partial file stays
            raise ProviderIdentityError("identity provisioning refused") from None
        return xonly

    @classmethod
    def load(
        cls,
        path: str | PathLike[str],
        *,
        custody_identity: str,
        expected_xonly_public_key: str,
        crypto: Context,
    ) -> ProviderIdentity:
        """Decrypt and check against the independently configured identity key."""
        try:
            location = Path(path)
            descriptor = os.open(location, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as source:
                sealed = source.read(MAX_FILE_BYTES + 1)
            unlocking = x25519.Identity.from_str(custody_identity)
            plaintext = pyrage.decrypt(sealed, [unlocking])
            record: dict[str, Any] = json.loads(plaintext)
            scalar = bytes.fromhex(record["secret_scalar"])
            valid = (
                len(sealed) <= MAX_FILE_BYTES
                and canonicalize(record) == plaintext
                and record.keys() == {"kind", "secret_scalar", "xonly_public_key"}
                and record["kind"] == RECORD_KIND
                and len(scalar) == 32  # noqa: PLR2004
                and _xonly(crypto, scalar) == record["xonly_public_key"]
                and record["xonly_public_key"] == expected_xonly_public_key
            )
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            valid = False
        if not valid:
            raise ProviderIdentityError("provider identity unavailable or not the configured key")
        return cls(scalar, expected_xonly_public_key, crypto)

    def _sign(self, digest: bytes) -> str:
        signature = self._crypto.schnorr_sign(self._scalar, digest, secrets.token_bytes(32))
        self._crypto.schnorr_verify(bytes.fromhex(self.xonly_public_key), digest, signature)
        return signature.hex()

    def sign_handshake_accept(self, accept: HandshakeAccept) -> str:
        """Sign a typed accept, only if it names this identity."""
        if type(accept) is not HandshakeAccept or (
            accept.provider_identity_xonly_key != self.xonly_public_key
        ):
            raise ProviderIdentityError("accept does not name this provider identity")
        return self._sign(handshake_accept_hash(accept))

    def sign_provider_terms(self, offer: ProviderTerms) -> str:
        """Sign typed, hash-checked terms, only if they name this identity."""
        if type(offer) is not ProviderTerms or (
            offer.contract_terms.provider_identity_key != self.xonly_public_key
        ):
            raise ProviderIdentityError("terms do not name this provider identity")
        return self._sign(provider_terms_hash(offer))

    def build_announcement(self, terms: AnnouncementTerms) -> bytes:
        """Return one signed kind-39417 event for one supported network (RS-005).

        ``revision`` equals ``created_at``, so it strictly increases across
        restarts without extra state as long as the clock does not go back.
        """
        advertisement = _advertisement(self.xonly_public_key, terms)
        application = canonicalize(advertisement)
        wrapper = canonicalize(
            {
                "advertisement": advertisement,
                "signature": self._sign(tagged_hash(ADVERTISEMENT_TAG, application)),
            }
        )
        if len(wrapper) > MAX_CONTENT_BYTES:
            raise ProviderIdentityError("announcement content too large")
        content = wrapper.decode("utf-8")
        tags = [
            ["rillswap", BINDING_VERSION],
            ["network", terms.network.name],  # coarse public selector
            ["d", announcement_address(terms.network, terms.slot)],
        ]
        event_id = nip01._event_id(  # noqa: SLF001 - shared NIP-01 hash invariant
            self.xonly_public_key, terms.created_at, ANNOUNCEMENT_KIND, tags, content
        )
        event = {
            "id": event_id,
            "pubkey": self.xonly_public_key,
            "created_at": terms.created_at,
            "kind": ANNOUNCEMENT_KIND,
            "tags": tags,
            "content": content,
            "sig": self._sign(bytes.fromhex(event_id)),
        }
        return json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def announcement_address(network: NetworkIdentity, slot: str) -> str:
    """RS-005 ``d`` tag: sha256(JCS([protocol, binding, network, slot]))."""
    return hashlib.sha256(
        canonicalize(["rillswap", BINDING_VERSION, network.model_dump(mode="json"), slot])
    ).hexdigest()


def _supported(network: NetworkIdentity) -> bool:
    try:
        require_supported_network(network)
    except ValidationError:
        return False
    return True


def _advertisement(identity: str, terms: AnnouncementTerms) -> dict[str, Any]:
    endpoints = terms.transport_endpoints
    epochs = terms.epoch_inbox_xonly_keys
    bands = terms.amount_bands
    if not (
        type(terms.epoch_bound_sessions) is bool
        and type(terms.network) is NetworkIdentity
        and _supported(terms.network)
        and 1 <= len(terms.profiles) <= 8  # noqa: PLR2004
        and len(set(terms.profiles)) == len(terms.profiles)
        and set(terms.profiles) <= {"btc-to-ln/v1", "ln-to-btc/v1"}
        and 1 <= len(bands) <= 16  # noqa: PLR2004
        and all(0 < low <= high for low, high in bands)
        and terms.base_fee_sat >= 0
        and 0 <= terms.proportional_millionths <= 1_000_000  # noqa: PLR2004
        and 1 <= len(endpoints) <= 16  # noqa: PLR2004
        and len(set(endpoints)) == len(endpoints)
        and all(0 < len(endpoint) <= 2048 for endpoint in endpoints)  # noqa: PLR2004
        and 1 <= len(epochs) <= MAX_EPOCH_KEYS
        and len(set(epochs)) == len(epochs)
        and all(nip01.HEX32.fullmatch(key) for key in epochs)
        and identity not in epochs
        and 0 < terms.created_at < terms.expires_at <= nip01.MAX_SAFE_TIMESTAMP
    ):
        raise ProviderIdentityError("announcement terms unsupported")
    return {
        "protocol": "rillswap",
        "binding_version": BINDING_VERSION,
        "provider_identity_xonly_key": identity,
        "network_identities": [terms.network.model_dump(mode="json")],
        "profiles": list(terms.profiles),
        "amount_bands": [
            {"minimum_sat": str(low), "maximum_sat": str(high)} for low, high in bands
        ],
        "indicative_fee_policy": {
            "base_sat": str(terms.base_fee_sat),
            "proportional_millionths": terms.proportional_millionths,
        },
        "communication_suites": [COMMUNICATION_SUITE],
        "transport_endpoints": list(endpoints),
        "epoch_inbox_xonly_keys": list(epochs),
        "slot": terms.slot,
        "revision": terms.created_at,
        "created_at": terms.created_at,
        "expires_at": terms.expires_at,
        "extensions": (
            {HANDSHAKE_FEATURES_EXTENSION: [EPOCH_SESSION_FEATURE]}
            if terms.epoch_bound_sessions
            else {}
        ),
    }
