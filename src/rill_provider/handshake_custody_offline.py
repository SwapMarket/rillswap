"""Explicit offline, age-encrypted provider key availability, never admission.

No key is created on lookup, startup, absence, restore, or protocol receipt.
The operator separately pins the returned custody and identity references.
Decryption and exact binding establish only local availability, never that a
restored store is fresh, exclusive, or authorized to sign or send an accept.
"""

from __future__ import annotations

import os
import secrets
import stat
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, cast

import pyrage  # type: ignore[import-untyped]
from pydantic import Field, TypeAdapter
from pyrage import x25519
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.types import Hex32, NetworkIdentity, ProfileId, StrictModel, XOnlyKey

from rill_provider.handshake_signing import SessionKeyRef, SessionReservation

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from os import PathLike

MAX_OBJECT_BYTES = 8 * 1024
COMPRESSED_KEY_BYTES = 33
HEX32_LENGTH = 64
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
IDENTITY_FILE = "identity.age"
MANIFEST_FILE = "manifest.json"


class CustodyError(ValueError):
    """No key availability or exclusive session ownership has been proven."""


class CustodyPublicationUncertainError(CustodyError):
    """Object may exist but its durable state is not confirmed; never retry."""


class CustodyPublicKeys(Protocol):
    """Native public-key derivation, not a signing or admission interface."""

    def public_key(self, secret_key: bytes) -> bytes:
        """Derive a compressed secp256k1 public key from a valid scalar."""
        ...


class _Manifest(StrictModel):
    kind: Literal["rillswap-offline-provider-custody/v1"]
    custody_id: Hex32
    network_identity: NetworkIdentity
    recipient: str = Field(min_length=1, max_length=128)


class _IdentityObject(StrictModel):
    kind: Literal["rillswap-offline-provider-identity/v1"]
    custody_id: Hex32
    network_identity: NetworkIdentity
    key_id: Hex32
    xonly_public_key: XOnlyKey
    secret_scalar: Hex32


class _SessionObject(StrictModel):
    kind: Literal["rillswap-offline-provider-session/v1"]
    custody_id: Hex32
    network_identity: NetworkIdentity
    key_id: Hex32
    xonly_public_key: XOnlyKey
    secret_scalar: Hex32
    session_id: Hex32
    handshake_init_hash: Hex32
    profile_id: ProfileId
    provider_identity_key: XOnlyKey


@dataclass(frozen=True, slots=True)
class IdentityRef:
    """Independently pin this public identity outside the writable store."""

    custody_id: str
    key_id: str
    xonly_public_key: str


def _require(condition: bool) -> None:  # noqa: FBT001 - local validity predicate
    if not condition:
        raise CustodyError("offline custody object unavailable or inconsistent")


def _jcs(model: StrictModel) -> bytes:
    return canonicalize(model.model_dump(mode="json"))


def _parse_exact[T: StrictModel](model: type[T], document: bytes) -> T:
    _require(type(document) is bytes and 0 < len(document) <= MAX_OBJECT_BYTES)
    result = parse_model_json(model, document)
    _require(_jcs(result) == document)
    return result


def _public(crypto: CustodyPublicKeys, scalar: bytes) -> str:
    key = crypto.public_key(scalar)
    _require(type(key) is bytes and len(key) == COMPRESSED_KEY_BYTES and key[0] in (2, 3))
    return key[1:].hex()


@contextmanager
def _directory(path: Path) -> Iterator[int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_mode & 0o077 == 0
            and info.st_mode & PRIVATE_DIRECTORY_MODE == PRIVATE_DIRECTORY_MODE
        )
        yield descriptor
    finally:
        os.close(descriptor)


def _read_object(directory: int, name: str) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        _require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_mode & 0o777 == PRIVATE_FILE_MODE
            and info.st_nlink == 1
            and 0 < info.st_size <= MAX_OBJECT_BYTES
        )
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            return stream.read(MAX_OBJECT_BYTES + 1)
    finally:
        os.close(descriptor)


def _publish(directory: int, name: str, document: bytes, verify: Callable[[bytes], object]) -> None:
    _require(type(document) is bytes and 0 < len(document) <= MAX_OBJECT_BYTES)
    temp = f".rill-custody-{secrets.token_hex(16)}.tmp"
    published = False
    created = False
    try:
        descriptor = os.open(
            temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(document)
            stream.flush()
            os.fsync(stream.fileno())
        stored = _read_object(directory, temp)
        _require(stored == document)
        verify(stored)
        os.link(temp, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        published = True
        os.fsync(directory)
        os.unlink(temp, dir_fd=directory)
        created = False
        os.fsync(directory)
    except Exception:  # noqa: BLE001 - native and encryption details stay private
        if created and not published:
            with suppress(OSError):
                os.unlink(temp, dir_fd=directory)
    else:
        return
    if published:
        raise CustodyPublicationUncertainError("custody publication may have occurred")
    raise CustodyError("offline custody publication refused")


class OfflineHandshakeCustody:
    """Immutable key availability, deliberately NOT the live HandshakeCustody API."""

    def __init__(self, path: Path, identity: x25519.Identity, manifest: _Manifest) -> None:
        """Store only the operator-selected protection root and public namespace."""
        self._path = path
        self._identity = identity
        self._manifest = manifest

    @classmethod
    def create_new(
        cls,
        path: str | PathLike[str],
        *,
        protection_identity: str,
        expected_network: NetworkIdentity,
    ) -> OfflineHandshakeCustody:
        """Explicitly bootstrap one empty namespace; never repair a partial one."""
        uncertain = False
        try:
            try:
                result = cls._create_new(path, protection_identity, expected_network)
            finally:
                del (
                    protection_identity
                )  # Do not retain the protection root in sanitized tracebacks.
        except CustodyPublicationUncertainError:
            uncertain = True
        except Exception:  # noqa: BLE001, S110 - operator credential stays private
            pass
        else:
            return result
        if uncertain:
            raise CustodyPublicationUncertainError("offline custody creation is uncertain")
        raise CustodyError("offline custody creation refused")

    @classmethod
    def _create_new(
        cls,
        path: str | PathLike[str],
        protection_identity: str,
        expected_network: NetworkIdentity,
    ) -> OfflineHandshakeCustody:
        root = Path(path).absolute()
        identity = x25519.Identity.from_str(protection_identity)
        network = NetworkIdentity.model_validate(expected_network.model_dump(mode="json"))
        manifest = _Manifest(
            kind="rillswap-offline-provider-custody/v1",
            custody_id=secrets.token_hex(32),
            network_identity=network,
            recipient=str(identity.to_public()),
        )
        with _directory(root.parent) as parent:
            os.mkdir(root.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        with _directory(root) as directory:
            _publish(
                directory,
                MANIFEST_FILE,
                _jcs(manifest),
                lambda stored: _parse_exact(_Manifest, stored),
            )
        return cls(root, identity, manifest)

    @classmethod
    def open_existing(
        cls,
        path: str | PathLike[str],
        *,
        protection_identity: str,
        expected_network: NetworkIdentity,
        expected_custody_id: str,
    ) -> OfflineHandshakeCustody:
        """Require a separately pinned namespace; absence never provisions."""
        try:
            try:
                result = cls._open_existing(
                    path, protection_identity, expected_network, expected_custody_id
                )
            finally:
                del protection_identity  # Caller frames still own their supplied credential.
        except Exception:  # noqa: BLE001, S110 - no file/credential details escape
            pass
        else:
            return result
        raise CustodyError("offline custody namespace unavailable")

    @classmethod
    def _open_existing(
        cls,
        path: str | PathLike[str],
        protection_identity: str,
        expected_network: NetworkIdentity,
        expected_custody_id: str,
    ) -> OfflineHandshakeCustody:
        root = Path(path).absolute()
        identity = x25519.Identity.from_str(protection_identity)
        with _directory(root) as directory:
            manifest = _parse_exact(_Manifest, _read_object(directory, MANIFEST_FILE))
        _require(
            manifest.custody_id == expected_custody_id
            and manifest.network_identity == expected_network
            and manifest.recipient == str(identity.to_public())
        )
        return cls(root, identity, manifest)

    @property
    def custody_id(self) -> str:
        """Public namespace identifier to pin independently, not an authority."""
        return self._manifest.custody_id

    def _decode_identity(self, directory: int, crypto: CustodyPublicKeys) -> _IdentityObject:
        plaintext = cast(
            "bytes", pyrage.decrypt(_read_object(directory, IDENTITY_FILE), [self._identity])
        )
        record = _parse_exact(_IdentityObject, plaintext)
        _require(
            record.custody_id == self.custody_id
            and record.network_identity == self._manifest.network_identity
            and _public(crypto, bytes.fromhex(record.secret_scalar)) == record.xonly_public_key
        )
        return record

    def _encode(self, document: bytes) -> bytes:
        _require(len(document) <= MAX_OBJECT_BYTES)
        result = cast("bytes", pyrage.encrypt(document, [self._identity.to_public()]))
        _require(
            result.startswith(b"age-encryption.org/v1\n-> X25519 ")
            and len(result) <= MAX_OBJECT_BYTES
            and cast("bytes", pyrage.decrypt(result, [self._identity])) == document
        )
        return result

    def provision_identity_new(self, *, crypto: CustodyPublicKeys) -> IdentityRef:
        """Explicitly encrypt and publish a new identity, never replace one."""
        uncertain = False
        try:
            result = self._provision_identity_new(crypto)
        except CustodyPublicationUncertainError:
            uncertain = True
        except Exception:  # noqa: BLE001, S110 - no private scalar in error chain
            pass
        else:
            return result
        if uncertain:
            raise CustodyPublicationUncertainError("identity publication uncertain")
        raise CustodyError("offline identity provisioning refused")

    def _provision_identity_new(self, crypto: CustodyPublicKeys) -> IdentityRef:
        scalar = secrets.token_bytes(32)
        public = _public(crypto, scalar)
        record = _IdentityObject(
            kind="rillswap-offline-provider-identity/v1",
            custody_id=self.custody_id,
            network_identity=self._manifest.network_identity,
            key_id=secrets.token_hex(32),
            xonly_public_key=public,
            secret_scalar=scalar.hex(),
        )
        with _directory(self._path) as directory:
            _publish(
                directory,
                IDENTITY_FILE,
                self._encode(_jcs(record)),
                lambda stored: self._verify_identity_bytes(stored, record, crypto),
            )
        return IdentityRef(self.custody_id, record.key_id, public)

    def _verify_identity_bytes(
        self,
        stored: bytes,
        expected: _IdentityObject,
        crypto: CustodyPublicKeys,
    ) -> None:
        decoded = _parse_exact(
            _IdentityObject, cast("bytes", pyrage.decrypt(stored, [self._identity]))
        )
        _require(
            decoded == expected
            and _public(crypto, bytes.fromhex(decoded.secret_scalar)) == expected.xonly_public_key
        )

    def require_identity_exact(self, ref: IdentityRef, *, crypto: CustodyPublicKeys) -> None:
        """Verify a separately pinned identity exists; never allocate on absence."""
        try:
            self._require_identity_exact(ref, crypto)
        except Exception:  # noqa: BLE001, S110 - no decrypted scalar escapes
            pass
        else:
            return
        raise CustodyError("offline identity unavailable")

    def _require_identity_exact(self, ref: IdentityRef, crypto: CustodyPublicKeys) -> None:
        with _directory(self._path) as directory:
            record = self._decode_identity(directory, crypto)
        _require(
            type(ref) is IdentityRef
            and ref == IdentityRef(self.custody_id, record.key_id, record.xonly_public_key)
        )

    def _checked_binding(self, binding: SessionReservation, identity: IdentityRef) -> None:
        _require(
            type(binding) is SessionReservation
            and type(identity) is IdentityRef
            and binding.network_identity_jcs == _jcs(self._manifest.network_identity)
            and binding.provider_identity_key == identity.xonly_public_key
            and len(binding.session_id) == HEX32_LENGTH
            and len(binding.handshake_init_hash) == HEX32_LENGTH
            and all(
                char in "0123456789abcdef"
                for char in binding.session_id + binding.handshake_init_hash
            )
        )
        TypeAdapter[ProfileId](ProfileId).validate_python(binding.profile_id, strict=True)

    def provision_session_new(
        self,
        binding: SessionReservation,
        identity: IdentityRef,
        *,
        crypto: CustodyPublicKeys,
    ) -> SessionKeyRef:
        """Explicitly provision one immutable slot, never infer an absent slot unused."""
        uncertain = False
        try:
            result = self._provision_session_new(binding, identity, crypto)
        except CustodyPublicationUncertainError:
            uncertain = True
        except Exception:  # noqa: BLE001, S110 - key material remains private
            pass
        else:
            return result
        if uncertain:
            raise CustodyPublicationUncertainError("session publication uncertain")
        raise CustodyError("offline session provisioning refused")

    def _provision_session_new(
        self,
        binding: SessionReservation,
        identity: IdentityRef,
        crypto: CustodyPublicKeys,
    ) -> SessionKeyRef:
        self.require_identity_exact(identity, crypto=crypto)
        self._checked_binding(binding, identity)
        scalar = secrets.token_bytes(32)
        public = _public(crypto, scalar)
        profile = TypeAdapter[ProfileId](ProfileId).validate_python(
            binding.profile_id,
            strict=True,
        )
        record = _SessionObject(
            kind="rillswap-offline-provider-session/v1",
            custody_id=self.custody_id,
            network_identity=self._manifest.network_identity,
            key_id=secrets.token_hex(32),
            xonly_public_key=public,
            secret_scalar=scalar.hex(),
            session_id=binding.session_id,
            handshake_init_hash=binding.handshake_init_hash,
            profile_id=profile,
            provider_identity_key=binding.provider_identity_key,
        )
        name = f"session-{binding.session_id}.age"
        with _directory(self._path) as directory:
            _publish(
                directory,
                name,
                self._encode(_jcs(record)),
                lambda stored: self._verify_session_bytes(stored, record, crypto),
            )
        return SessionKeyRef(self.custody_id, record.key_id, public)

    def _verify_session_bytes(
        self,
        stored: bytes,
        expected: _SessionObject,
        crypto: CustodyPublicKeys,
    ) -> None:
        decoded = _parse_exact(
            _SessionObject, cast("bytes", pyrage.decrypt(stored, [self._identity]))
        )
        _require(
            decoded == expected
            and _public(crypto, bytes.fromhex(decoded.secret_scalar)) == expected.xonly_public_key
        )

    def require_session_exact(
        self,
        binding: SessionReservation,
        ref: SessionKeyRef,
        identity: IdentityRef,
        *,
        crypto: CustodyPublicKeys,
    ) -> None:
        """Check local key availability only; never sign, admit, or resume."""
        try:
            self._require_session_exact(binding, ref, identity, crypto)
        except Exception:  # noqa: BLE001, S110 - no secret-bearing errors escape
            pass
        else:
            return
        raise CustodyError("offline session key unavailable")

    def _require_session_exact(
        self,
        binding: SessionReservation,
        ref: SessionKeyRef,
        identity: IdentityRef,
        crypto: CustodyPublicKeys,
    ) -> None:
        self.require_identity_exact(identity, crypto=crypto)
        self._checked_binding(binding, identity)
        _require(type(ref) is SessionKeyRef)
        with _directory(self._path) as directory:
            document = _read_object(directory, f"session-{binding.session_id}.age")
        record = _parse_exact(
            _SessionObject, cast("bytes", pyrage.decrypt(document, [self._identity]))
        )
        _require(
            record.custody_id == self.custody_id
            and record.network_identity == self._manifest.network_identity
            and record.session_id == binding.session_id
            and record.handshake_init_hash == binding.handshake_init_hash
            and record.profile_id == binding.profile_id
            and record.provider_identity_key == binding.provider_identity_key
            and ref == SessionKeyRef(self.custody_id, record.key_id, record.xonly_public_key)
            and _public(crypto, bytes.fromhex(record.secret_scalar)) == record.xonly_public_key
        )
