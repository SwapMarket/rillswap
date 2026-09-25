"""Explicit RS-001 initiation reservation, never send or admission authority.

This separate store does not upgrade offline prepared handshakes. It cannot
detect restoration of an older valid database or fence another copy. Only a
future independently fenced session owner may decide whether to issue an accept.
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
from pathlib import Path
from typing import TYPE_CHECKING, cast

from pydantic import TypeAdapter
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import handshake_init_hash, unsigned_envelope_hash
from rill_core.wire.messages import HandshakeInit
from rill_core.wire.types import NetworkIdentity, ProfileId

from rill_provider.handshake_store import (
    HandshakePolicy,
    _bounded_envelope,
    _expected,
    _features,
    _require_policy,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from os import PathLike

APPLICATION_ID = 0x52495231  # RIR1, not the prepared-handshake store.
SCHEMA_VERSION = 1
MAX_CHALLENGE_TRIES = 4
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
ROW_DOMAIN = b"rill-provider/init-reservation/v1\x00"
SCHEMA = (
    (
        "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "version INTEGER NOT NULL, network_jcs BLOB NOT NULL, provider_identity TEXT NOT NULL, "
        "policy_jcs BLOB NOT NULL)"
    ),
    (
        "CREATE TABLE reservations (session_id TEXT PRIMARY KEY, init_jcs BLOB NOT NULL, "
        "init_message_id TEXT NOT NULL, init_sender_key TEXT NOT NULL, "
        "handshake_init_digest TEXT NOT NULL, init_envelope_digest TEXT NOT NULL, "
        "provider_challenge TEXT NOT NULL UNIQUE, revision INTEGER NOT NULL, "
        "state TEXT NOT NULL CHECK (state IN ('RESERVED', 'CONFLICT')), "
        "row_hash TEXT NOT NULL)"
    ),
)


class IssuanceReservationError(ValueError):
    """No trusted local challenge reservation has been established."""


class IssuanceConflictError(IssuanceReservationError):
    """One session has conflicting initiation bytes and is permanently blocked."""


@dataclass(frozen=True, slots=True)
class ReservedInit:
    """Stable challenge and source digests, without permission to sign or send."""

    session_id: str
    init_message_id: str
    handshake_init_digest: str
    init_envelope_digest: str
    provider_challenge: str
    revision: int


def _policy_bytes(policy: HandshakePolicy) -> bytes:
    _require_policy(policy)
    profile: str = TypeAdapter[ProfileId](ProfileId).validate_python(policy.profile, strict=True)
    return json.dumps(
        {
            "profile": profile,
            "features": sorted(_features(policy.features)),
            "encryption_suites": sorted(_features(policy.encryption_suites)),
            "capabilities": sorted(_features(policy.capabilities)),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class IssuanceReservationStore:
    """Only reserves locally generated challenges, never exposes an accept."""

    def __init__(self, path: Path, network_jcs: bytes, identity: str, policy_jcs: bytes) -> None:
        """Keep one explicit location and immutable namespace policy."""
        self.path = path
        self._network_jcs = network_jcs
        self._identity = identity
        self._policy_jcs = policy_jcs

    @classmethod
    def create_new(
        cls,
        path: str | PathLike[str],
        network: NetworkIdentity,
        provider_identity: str,
        policy: HandshakePolicy,
    ) -> IssuanceReservationStore:
        """Explicitly create a different v1 store; leave partial files untouched."""
        network_jcs, identity = _expected(network, provider_identity)
        policy_jcs = _policy_bytes(policy)
        location = Path(path).absolute()
        directory = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(
                location.name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            os.close(descriptor)
            store = cls(location, network_jcs, identity, policy_jcs)
            with store._connection(check=False, write=True) as connection:
                connection.execute("BEGIN IMMEDIATE")
                for statement in SCHEMA:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO metadata VALUES (1, ?, ?, ?, ?)",
                    (SCHEMA_VERSION, network_jcs, identity, policy_jcs),
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
        provider_identity: str,
        policy: HandshakePolicy,
    ) -> IssuanceReservationStore:
        """No implicit create, upgrade, replay, key rotation, or repair."""
        network_jcs, identity = _expected(network, provider_identity)
        store = cls(Path(path).absolute(), network_jcs, identity, _policy_bytes(policy))
        store._check_existing()
        return store

    @contextmanager
    def _connection(
        self, *, check: bool = True, write: bool = False
    ) -> Iterator[sqlite3.Connection]:
        if not self.path.is_file() or self.path.is_symlink():
            raise IssuanceReservationError("issuance reservation store unavailable")
        try:
            mode = "rw" if write else "ro"
            connection = sqlite3.connect(self.path.as_uri() + f"?mode={mode}", uri=True, timeout=5)
            try:
                connection.execute("PRAGMA busy_timeout=5000")
                if check:
                    self._check_connection(connection)
                if write:
                    if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
                        raise IssuanceReservationError("issuance WAL unavailable")
                    connection.execute("PRAGMA synchronous=FULL")
                    if connection.execute("PRAGMA synchronous").fetchone() != (2,):
                        raise IssuanceReservationError("issuance FULL sync unavailable")
                yield connection
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise IssuanceReservationError("issuance reservation storage unavailable") from exc

    def _check_connection(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA application_id").fetchone() != (
            APPLICATION_ID,
        ) or connection.execute("PRAGMA user_version").fetchone() != (SCHEMA_VERSION,):
            raise IssuanceReservationError("issuance store version unsupported")
        schema = {
            (kind, name): definition
            for kind, name, definition in connection.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
            )
        }
        if schema != {("table", "metadata"): SCHEMA[0], ("table", "reservations"): SCHEMA[1]}:
            raise IssuanceReservationError("issuance store schema incompatible")
        metadata = connection.execute(
            "SELECT version, network_jcs, provider_identity, policy_jcs FROM metadata"
        ).fetchall()
        if metadata != [(SCHEMA_VERSION, self._network_jcs, self._identity, self._policy_jcs)]:
            raise IssuanceReservationError("issuance store namespace or policy mismatch")

    def _check_existing(self) -> None:
        with self._connection() as connection:
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise IssuanceReservationError("issuance store integrity unavailable")

    def _init(self, raw: bytes) -> tuple[HandshakeInit, str, str, str]:
        outer = _bounded_envelope(raw)
        init = HandshakeInit.model_validate_json(canonicalize(outer.payload), strict=True)
        policy: dict[str, object] = json.loads(self._policy_jcs)
        features = cast("list[str]", policy["features"])
        suites = cast("list[str]", policy["encryption_suites"])
        network = NetworkIdentity.model_validate_json(self._network_jcs, strict=True)
        if not (
            outer.message_type == "handshake_init"
            and outer.sequence == 0
            and outer.in_reply_to is None
            and outer.contract_hash is None
            and outer.signature is None
            and outer.session_id == init.session_id
            and outer.sender_session_key == init.client_session_xonly_key
            and outer.profile_id == init.profile_id == policy["profile"]
            and outer.network_identity == init.network_identity == network
            and init.expected_provider_identity_xonly_key == self._identity
            and set(outer.required_features).issubset(features)
            and set(init.required_features).issubset(features)
            and bool(set(init.requested_encryption_suites).intersection(suites))
        ):
            raise IssuanceReservationError("untrusted or unsupported handshake initiation")
        return (
            init,
            outer.message_id,
            handshake_init_hash(init).hex(),
            unsigned_envelope_hash(outer).hex(),
        )

    def _record_hash(self, raw: bytes, record: ReservedInit, sender: str, state: str) -> str:
        digest = hashlib.sha256(ROW_DOMAIN)
        for field in (
            self._network_jcs,
            self._identity.encode("ascii"),
            self._policy_jcs,
            record.session_id.encode("ascii"),
            raw,
            sender.encode("ascii"),
            record.init_message_id.encode("ascii"),
            record.handshake_init_digest.encode("ascii"),
            record.init_envelope_digest.encode("ascii"),
            record.provider_challenge.encode("ascii"),
            str(record.revision).encode("ascii"),
            state.encode("ascii"),
        ):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
        return digest.hexdigest()

    def _read(
        self, connection: sqlite3.Connection, session_id: str
    ) -> tuple[bytes, ReservedInit, str, str] | None:
        row = connection.execute(
            "SELECT init_jcs, init_message_id, init_sender_key, handshake_init_digest, "
            "init_envelope_digest, provider_challenge, revision, state, row_hash "
            "FROM reservations WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        (
            raw,
            message_id,
            sender,
            init_digest,
            envelope_digest,
            challenge,
            revision,
            state,
            checksum,
        ) = row
        if (
            type(raw) is not bytes
            or type(sender) is not str
            or any(
                type(value) is not str or HEX32.fullmatch(value) is None
                for value in (
                    message_id,
                    init_digest,
                    envelope_digest,
                    challenge,
                )
            )
            or (state, revision) not in (("RESERVED", 0), ("CONFLICT", 1))
            or type(checksum) is not str
            or HEX32.fullmatch(checksum) is None
        ):
            raise IssuanceReservationError("issuance record inconsistent")
        record = ReservedInit(
            session_id, message_id, init_digest, envelope_digest, challenge, revision
        )
        if checksum != self._record_hash(raw, record, sender, state):
            raise IssuanceReservationError("issuance record checksum differs")
        return raw, record, state, sender

    def lookup(self, session_id: str) -> ReservedInit | None:
        """Missing means unknown, NOT fresh; neither result authorizes live use."""
        if type(session_id) is not str or HEX32.fullmatch(session_id) is None:
            raise IssuanceReservationError("session selector malformed")
        try:
            with self._connection() as connection:
                entry = self._read(connection, session_id)
                if entry is None:
                    return None
                raw, record, state, sender = entry
                self._check_record(raw, record, sender)
                if state != "RESERVED":
                    raise IssuanceConflictError(  # noqa: TRY301 - distinct durable disposition
                        "session initiation conflict is durable"
                    )
                return record
        except IssuanceConflictError:
            raise
        except Exception:  # noqa: BLE001 - no stored caller bytes in failure
            raise IssuanceReservationError("issuance lookup unavailable") from None

    def _check_record(self, raw: bytes, record: ReservedInit, sender: str) -> None:
        init, message_id, init_digest, envelope_digest = self._init(raw)
        if (
            record.session_id != init.session_id
            or sender != init.client_session_xonly_key
            or record.init_message_id != message_id
            or record.handshake_init_digest != init_digest
            or record.init_envelope_digest != envelope_digest
            or record.provider_challenge in (init.session_id, init.client_challenge)
        ):
            raise IssuanceReservationError("issuance record differs from initiation")

    def reserve_init(self, raw: bytes) -> ReservedInit:
        """Commit a locally generated challenge; no accept, receipt, or admission."""
        try:
            init, message_id, init_digest, envelope_digest = self._init(raw)
            with self._connection(write=True) as connection:
                connection.execute("BEGIN IMMEDIATE")
                entry = self._read(connection, init.session_id)
                if entry is not None:
                    existing_raw, record, state, sender = entry
                    self._check_record(existing_raw, record, sender)
                    if state == "CONFLICT":
                        raise IssuanceConflictError(  # noqa: TRY301 - durable conflict
                            "session initiation conflict is durable"
                        )
                    if existing_raw != raw:
                        conflicted = ReservedInit(
                            record.session_id,
                            record.init_message_id,
                            record.handshake_init_digest,
                            record.init_envelope_digest,
                            record.provider_challenge,
                            1,
                        )
                        connection.execute(
                            "UPDATE reservations SET state='CONFLICT', revision=1, row_hash=? "
                            "WHERE session_id=?",
                            (
                                self._record_hash(existing_raw, conflicted, sender, "CONFLICT"),
                                init.session_id,
                            ),
                        )
                        connection.commit()
                        raise IssuanceConflictError(  # noqa: TRY301 - commit precedes refusal
                            "session initiation conflict is durable"
                        )
                    connection.commit()
                    return record
                for _ in range(MAX_CHALLENGE_TRIES):
                    challenge = secrets.token_hex(32)
                    if (
                        type(challenge) is str
                        and HEX32.fullmatch(challenge) is not None
                        and challenge not in (init.session_id, init.client_challenge)
                        and connection.execute(
                            "SELECT 1 FROM reservations WHERE provider_challenge=?", (challenge,)
                        ).fetchone()
                        is None
                    ):
                        break
                else:
                    raise IssuanceReservationError(  # noqa: TRY301 - sanitized below
                        "independent challenge unavailable"
                    )
                result = ReservedInit(
                    init.session_id, message_id, init_digest, envelope_digest, challenge, 0
                )
                connection.execute(
                    "INSERT INTO reservations VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'RESERVED', ?)",
                    (
                        init.session_id,
                        raw,
                        message_id,
                        init.client_session_xonly_key,
                        init_digest,
                        envelope_digest,
                        challenge,
                        self._record_hash(raw, result, init.client_session_xonly_key, "RESERVED"),
                    ),
                )
                connection.commit()
                return result
        except IssuanceConflictError:
            raise
        except Exception:  # noqa: BLE001 - no caller document, storage, or secrets in errors
            raise IssuanceReservationError("issuance reservation refused") from None
