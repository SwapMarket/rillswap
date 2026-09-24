"""Offline PREPARED-only RS-001 handshake registry, never admission authority.

The two outer handshake envelopes are unsigned. Only the inner acceptance is
provider-identity-signed. This store does not establish live receipt, client
authentication, custody availability, exclusive writer ownership, freshness
of a restored database, permission to send, or any financial authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, cast

from pydantic import TypeAdapter
from rill_core.wire.canonical import (
    MAX_JSON_BYTES,
    canonicalize,
    parse_json_strict,
    parse_model_json,
)
from rill_core.wire.hashes import handshake_accept_hash, unsigned_envelope_hash
from rill_core.wire.messages import Envelope, HandshakeAcceptPayload, HandshakeInit
from rill_core.wire.types import Identifier, NetworkIdentity, ProfileId, XOnlyKey

from rill_provider.handshake_signing import SessionKeyRef

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from collections.abc import Set as AbstractSet
    from os import PathLike

    from rill_core.wire.envelope_authentication import EnvelopeSchnorrVerifier

APPLICATION_ID = 0x52485331  # RHS1, distinct from payment and reservation stores.
SCHEMA_VERSION = 1
MAX_ENVELOPE_BYTES = MAX_JSON_BYTES
MAX_REF_BYTES = 1024
REF_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
ROW_DOMAIN = b"rill-provider/prepared-handshake/v1\0"
SCHEMA = (
    (
        "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "version INTEGER NOT NULL, store_id TEXT NOT NULL, network_jcs BLOB NOT NULL, "
        "provider_identity TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE prepared (session_id TEXT PRIMARY KEY, init_jcs BLOB NOT NULL, "
        "accept_jcs BLOB NOT NULL, ref_jcs BLOB NOT NULL, init_message_id TEXT NOT NULL, "
        "init_unsigned_hash TEXT NOT NULL, state TEXT NOT NULL CHECK (state = 'PREPARED'), "
        "row_hash TEXT NOT NULL)"
    ),
)


class HandshakeStoreError(ValueError):
    """No usable trusted prepared record or admission evidence was established."""


class HandshakeConflictError(HandshakeStoreError):
    """Indicate different immutable data is already recorded for this session."""


class UnknownPrepared(Enum):
    """No local record is known; this never means unused or safe to accept."""

    UNKNOWN = "unknown (no authority)"


@dataclass(frozen=True, slots=True)
class HandshakePolicy:
    """Independently configured selections supported by this local diagnostic."""

    profile: ProfileId
    features: frozenset[str]
    encryption_suites: frozenset[str]
    capabilities: frozenset[str]


@dataclass(frozen=True, slots=True)
class PreparedHandshake:
    """Locally recorded immutable bytes, NOT a verified live session."""

    session_id: str
    init_envelope_jcs: bytes
    accept_envelope_jcs: bytes
    session_ref: SessionKeyRef
    init_message_id: str
    init_unsigned_hash: str


def _expected(network: NetworkIdentity, identity: str) -> tuple[bytes, str]:
    if not isinstance(network, NetworkIdentity):
        raise HandshakeStoreError("trusted complete network required")
    checked_network = NetworkIdentity.model_validate_json(
        json.dumps(network.model_dump(mode="json")),
        strict=True,
    )
    checked_identity: str = TypeAdapter[str](XOnlyKey).validate_python(identity, strict=True)
    return canonicalize(checked_network.model_dump(mode="json")), checked_identity


def _features(values: AbstractSet[str]) -> frozenset[str]:
    result = frozenset(values)
    for value in result:
        TypeAdapter[str](Identifier).validate_python(value, strict=True)
    return result


def _require_policy(policy: HandshakePolicy) -> None:
    if type(policy) is not HandshakePolicy:
        raise HandshakeStoreError("independent handshake policy required")


def _require_equivalent(
    existing: PreparedHandshake | UnknownPrepared,
    record: PreparedHandshake,
) -> None:
    if existing != record:
        raise HandshakeConflictError("session has different prepared bytes")


def _bounded_envelope(document: bytes) -> Envelope:
    if type(document) is not bytes or not 0 < len(document) <= MAX_ENVELOPE_BYTES:
        raise HandshakeStoreError("handshake envelope size unsupported")
    parsed = parse_json_strict(document, max_bytes=MAX_ENVELOPE_BYTES)
    if canonicalize(parsed) != document:
        raise HandshakeStoreError("store requires canonical envelope bytes")
    return parse_model_json(Envelope, document)


def _reference(ref: SessionKeyRef) -> bytes:
    if type(ref) is not SessionKeyRef:
        raise HandshakeStoreError("public session reference required")
    for part in (ref.custody_id, ref.key_id):
        if type(part) is not str or REF_NAME.fullmatch(part) is None:
            raise HandshakeStoreError("public session reference is malformed")
    key: str = TypeAdapter[str](XOnlyKey).validate_python(ref.xonly_public_key, strict=True)
    result = canonicalize(
        {"custody_id": ref.custody_id, "key_id": ref.key_id, "xonly_public_key": key}
    )
    if len(result) > MAX_REF_BYTES:
        raise HandshakeStoreError("public session reference exceeds size limit")
    return result


def _row_hash(store_id: str, record: PreparedHandshake, ref_jcs: bytes) -> str:
    digest = hashlib.sha256(ROW_DOMAIN)
    for value in (
        store_id.encode("ascii"),
        b"PREPARED",
        record.session_id.encode("ascii"),
        record.init_envelope_jcs,
        record.accept_envelope_jcs,
        ref_jcs,
        record.init_message_id.encode("ascii"),
        record.init_unsigned_hash.encode("ascii"),
    ):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _prepared(  # noqa: PLR0913 - independent policy and transcript inputs
    init_document: bytes,
    accept_document: bytes,
    ref: SessionKeyRef,
    *,
    network_jcs: bytes,
    identity: str,
    policy: HandshakePolicy,
    crypto: EnvelopeSchnorrVerifier,
) -> tuple[PreparedHandshake, bytes]:
    init_outer = _bounded_envelope(init_document)
    accept_outer = _bounded_envelope(accept_document)
    initiation = HandshakeInit.model_validate_json(canonicalize(init_outer.payload), strict=True)
    accepted = HandshakeAcceptPayload.model_validate_json(
        canonicalize(accept_outer.payload),
        strict=True,
    )
    selection = accepted.accept
    profile: str = TypeAdapter[ProfileId](ProfileId).validate_python(policy.profile, strict=True)
    features = _features(policy.features)
    suites = _features(policy.encryption_suites)
    capabilities = _features(policy.capabilities)
    configured_network = parse_model_json(NetworkIdentity, network_jcs)
    if not (
        init_outer.message_type == "handshake_init"
        and init_outer.sequence == 0
        and init_outer.in_reply_to is None
        and init_outer.contract_hash is None
        and init_outer.signature is None
        and init_outer.sender_session_key == initiation.client_session_xonly_key
        and accept_outer.message_type == "handshake_accept"
        and accept_outer.sequence == 0
        and accept_outer.in_reply_to == init_outer.message_id
        and accept_outer.contract_hash is None
        and accept_outer.signature is None
        and accept_outer.sender_session_key == selection.provider_session_xonly_key
        and all(
            envelope.profile_id == profile
            and envelope.network_identity == configured_network
            and envelope.session_id == initiation.session_id
            and set(envelope.required_features).issubset(features)
            for envelope in (init_outer, accept_outer)
        )
        and initiation.profile_id == selection.profile_id == profile
        and initiation.network_identity == selection.network_identity == configured_network
        and initiation.expected_provider_identity_xonly_key == identity
        and selection.provider_identity_xonly_key == identity
    ):
        raise HandshakeStoreError("handshake pair is inconsistent")
    selection.validate_against(initiation, supported_features=features)
    if (
        selection.selected_encryption_suite not in suites
        or not set(selection.selected_capabilities).issubset(capabilities)
        or selection.provider_session_xonly_key != ref.xonly_public_key
    ):
        raise HandshakeStoreError("handshake selection or session reference inconsistent")
    ref_jcs = _reference(ref)
    verify: Callable[[bytes, bytes, bytes], object] = crypto.schnorr_verify
    if (
        verify(
            bytes.fromhex(identity),
            handshake_accept_hash(selection),
            bytes.fromhex(accepted.provider_identity_signature),
        )
        is not None
    ):
        raise HandshakeStoreError("identity signature verification did not succeed")
    return PreparedHandshake(
        initiation.session_id,
        init_document,
        accept_document,
        ref,
        init_outer.message_id,
        unsigned_envelope_hash(init_outer).hex(),
    ), ref_jcs


class PreparedHandshakeStore:
    """Explicit isolated bookkeeping, never creates records on startup or lookup."""

    def __init__(self, path: Path, network_jcs: bytes, identity: str) -> None:
        """Retain the explicitly selected location and complete network binding."""
        self.path = path
        self._network_jcs = network_jcs
        self._identity = identity

    @classmethod
    def create_new(
        cls,
        path: str | PathLike[str],
        network: NetworkIdentity,
        identity: str,
    ) -> PreparedHandshakeStore:
        """Explicit exclusive bootstrap; a partial file is never repaired on retry."""
        network_jcs, checked_identity = _expected(network, identity)
        location = Path(path).absolute()
        directory = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            file = os.open(
                location.name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            os.close(file)
            store = cls(location, network_jcs, checked_identity)
            with store._connection(check=False, write=True) as connection:
                connection.execute("BEGIN IMMEDIATE")
                for statement in SCHEMA:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO metadata VALUES (1, ?, ?, ?, ?)",
                    (SCHEMA_VERSION, secrets.token_hex(16), network_jcs, checked_identity),
                )
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                connection.commit()
            os.fsync(directory)
            store._check_existing()
            return store
        finally:
            os.close(directory)

    @classmethod
    def open_existing(
        cls,
        path: str | PathLike[str],
        network: NetworkIdentity,
        identity: str,
    ) -> PreparedHandshakeStore:
        """Read one explicit database, never auto-create, migrate, or repair."""
        network_jcs, checked_identity = _expected(network, identity)
        store = cls(Path(path).absolute(), network_jcs, checked_identity)
        store._check_existing()
        return store

    @contextmanager
    def _connection(
        self,
        *,
        check: bool = True,
        write: bool = False,
    ) -> Iterator[sqlite3.Connection]:
        if not self.path.is_file() or self.path.is_symlink():
            raise HandshakeStoreError("handshake store unavailable")
        mode = "rw" if write else "ro"
        connection = sqlite3.connect(self.path.as_uri() + f"?mode={mode}", uri=True, timeout=5)
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            if check:
                self._check_connection(connection)
            if write:
                if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
                    raise HandshakeStoreError("WAL durability is unavailable")
                connection.execute("PRAGMA synchronous=FULL")
                if connection.execute("PRAGMA synchronous").fetchone() != (2,):
                    raise HandshakeStoreError("FULL durability is unavailable")
            yield connection
        finally:
            connection.close()

    def _check_connection(self, connection: sqlite3.Connection) -> str:
        if connection.execute("PRAGMA application_id").fetchone() != (
            APPLICATION_ID,
        ) or connection.execute("PRAGMA user_version").fetchone() != (SCHEMA_VERSION,):
            raise HandshakeStoreError("handshake store version is incompatible")
        schemas = {
            (row[0], row[1]): row[2]
            for row in connection.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
            )
        }
        if schemas != {("table", "metadata"): SCHEMA[0], ("table", "prepared"): SCHEMA[1]}:
            raise HandshakeStoreError("handshake store schema is incomplete")
        row = connection.execute(
            "SELECT version, store_id, network_jcs, provider_identity "
            "FROM metadata WHERE singleton=1"
        ).fetchone()
        if (
            row is None
            or row[0] != SCHEMA_VERSION
            or type(row[1]) is not str
            or re.fullmatch(r"[0-9a-f]{32}", row[1]) is None
            or row[2] != self._network_jcs
            or row[3] != self._identity
            or connection.execute("SELECT count(*) FROM metadata").fetchone() != (1,)
        ):
            raise HandshakeStoreError("handshake store namespace or metadata is incompatible")
        return row[1]

    def _check_existing(self) -> None:
        with self._connection() as connection:
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise HandshakeStoreError("handshake store is inconsistent")

    def lookup_prepared(self, session_id: str) -> PreparedHandshake | UnknownPrepared:
        """Missing rows are UNKNOWN, not permission for new acceptance."""
        if type(session_id) is not str or re.fullmatch(r"[0-9a-f]{64}", session_id) is None:
            raise HandshakeStoreError("session selector is malformed")
        try:
            with self._connection() as connection:
                store_id = self._check_connection(connection)
                record = self._read(connection, session_id, store_id)
        except Exception:  # noqa: BLE001, S110 - no database contents escape
            pass
        else:
            return record
        raise HandshakeStoreError("handshake store lookup unavailable")

    def _read(
        self,
        connection: sqlite3.Connection,
        session_id: str,
        store_id: str,
    ) -> PreparedHandshake | UnknownPrepared:
        row = connection.execute(
            "SELECT init_jcs, accept_jcs, ref_jcs, init_message_id, init_unsigned_hash, "
            "state, row_hash FROM prepared WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if row is None:
            return UnknownPrepared.UNKNOWN
        init_jcs, accept_jcs, ref_jcs, message_id, digest, state, checksum = row
        if (
            type(init_jcs) is not bytes
            or len(init_jcs) > MAX_ENVELOPE_BYTES
            or type(accept_jcs) is not bytes
            or len(accept_jcs) > MAX_ENVELOPE_BYTES
            or type(ref_jcs) is not bytes
            or len(ref_jcs) > MAX_REF_BYTES
            or state != "PREPARED"
        ):
            raise HandshakeStoreError("handshake record is inconsistent")
        parsed = parse_json_strict(ref_jcs, max_bytes=MAX_REF_BYTES)
        if (
            not isinstance(parsed, dict)
            or set(parsed) != {"custody_id", "key_id", "xonly_public_key"}
            or any(type(value) is not str for value in parsed.values())
        ):
            raise HandshakeStoreError("handshake reference is inconsistent")
        ref = SessionKeyRef(
            cast("str", parsed["custody_id"]),
            cast("str", parsed["key_id"]),
            cast("str", parsed["xonly_public_key"]),
        )
        if _reference(ref) != ref_jcs:
            raise HandshakeStoreError("handshake reference is inconsistent")
        record = PreparedHandshake(session_id, init_jcs, accept_jcs, ref, message_id, digest)
        if _row_hash(store_id, record, ref_jcs) != checksum:
            raise HandshakeStoreError("handshake record checksum differs")
        return record

    def record_prepared(
        self,
        init_envelope_jcs: bytes,
        accept_envelope_jcs: bytes,
        session_ref: SessionKeyRef,
        *,
        policy: HandshakePolicy,
        crypto: EnvelopeSchnorrVerifier,
    ) -> PreparedHandshake:
        """Commit supplied bytes only, never sign, admit, receive, or send."""
        try:
            _require_policy(policy)
            record, ref_jcs = _prepared(
                init_envelope_jcs,
                accept_envelope_jcs,
                session_ref,
                network_jcs=self._network_jcs,
                identity=self._identity,
                policy=policy,
                crypto=crypto,
            )
            with self._connection(write=True) as connection:
                connection.execute("BEGIN IMMEDIATE")
                store_id = self._check_connection(connection)
                existing = self._read(connection, record.session_id, store_id)
                if existing is not UnknownPrepared.UNKNOWN:
                    _require_equivalent(existing, record)
                    connection.commit()
                    return existing
                connection.execute(
                    "INSERT INTO prepared VALUES (?, ?, ?, ?, ?, ?, 'PREPARED', ?)",
                    (
                        record.session_id,
                        record.init_envelope_jcs,
                        record.accept_envelope_jcs,
                        ref_jcs,
                        record.init_message_id,
                        record.init_unsigned_hash,
                        _row_hash(store_id, record, ref_jcs),
                    ),
                )
                connection.commit()
        except HandshakeConflictError:
            raise HandshakeConflictError("session has different prepared bytes") from None
        except Exception:  # noqa: BLE001, S110 - no caller document or storage details escape
            pass
        else:
            return record
        raise HandshakeStoreError("handshake preparation unavailable")
