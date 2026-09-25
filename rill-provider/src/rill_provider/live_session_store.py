"""Authoritative single-owner RS-001 handshake session store.

This is the only provider store whose rows may authorize exposing a
handshake_accept or admitting a handshake_confirm. Its guarantees are
conditional on a deployment fact it cannot verify: the database and its owner
lock live on an explicitly provisioned volume OUTSIDE the application's backup
and restore domain, used by exactly one host. The operator attests to that at
provisioning time.

What it enforces locally:
- explicit provisioning only; absent, partial, foreign, or newer files refuse;
- one lifetime exclusive owner (flock on a stable lock inode, no takeover);
- a generation counter bumped per owner and checked in every write;
- copied or file-restored databases (different inode) refuse to open;
- the exact accept bytes are durably committed before they may be exposed;
- confirm admission requires the full static transcript over those bytes.

It does NOT detect an in-place rollback of the authoritative volume, a clone
on another host, or authorize any economic effect. Confirmation grants no
funding, payment, or claim authority.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import pyrage  # type: ignore[import-untyped]
from pyrage import x25519
from rill_core.wire import verify_static_handshake_accept, verify_static_handshake_transcript
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.hashes import handshake_init_hash, unsigned_envelope_hash
from rill_core.wire.messages import (
    Envelope,
    HandshakeAccept,
    HandshakeAcceptPayload,
    HandshakeInit,
)
from rill_core.wire.types import NetworkIdentity

from rill_provider._nip59_receive import _decode_gift_wrap_candidate
from rill_provider._nip59_send import _wrap_envelope
from rill_provider.handshake_store import HandshakePolicy, _expected, _features, _require_policy
from rill_provider.issuance_reservation import _policy_bytes

if TYPE_CHECKING:
    from collections.abc import Iterator
    from os import PathLike

    from rill_core.wire.envelope_authentication import EnvelopeSchnorrVerifier
    from rill_crypto import Context

    from rill_provider.handshake_custody_offline import CustodyPublicKeys
    from rill_provider.provider_identity import ProviderIdentity

APPLICATION_ID = 0x524C5331  # RLS1, distinct from all diagnostic stores.
SCHEMA_VERSION = 4  # v1-v3 (unreleased development formats) are refused unchanged.
DEFAULT_MAX_SESSIONS = 1000  # live (unexpired) sessions
DEFAULT_MAX_TOMBSTONES = 1_000_000  # permanent expired-session IDs (~100 bytes each)
DEFAULT_NEW_SESSIONS_PER_MINUTE = 60  # global admission rate; known sessions exempt
MAX_DOCUMENT_BYTES = 65_536
MAX_CHALLENGE_TRIES = 4
MAX_LABEL_CHARS = 256
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
LOCK_SUFFIX = ".owner-lock"
MAX_OUTER_EVENT_BYTES = 128 * 1024
COMPRESSED_KEY_BYTES = 33
KEY_RECORD_KIND = "rill-provider/live-session-key/v1"
EPOCH_RECORD_KIND = "rill-provider/epoch-inbox-key/v1"
MAX_ADVERTISED_EPOCHS = 4  # RS-005 epoch_inbox_xonly_keys maximum
SCHEMA = (
    (
        "CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "schema_version INTEGER NOT NULL, store_uuid TEXT NOT NULL, network_jcs BLOB NOT NULL, "
        "provider_identity TEXT NOT NULL, policy_jcs BLOB NOT NULL, authority_jcs BLOB NOT NULL, "
        "db_inode INTEGER NOT NULL, lock_inode INTEGER NOT NULL, generation INTEGER NOT NULL, "
        "custody_recipient TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE sessions (session_id TEXT PRIMARY KEY, init_bytes BLOB NOT NULL, "
        "init_message_id TEXT NOT NULL, client_key TEXT NOT NULL, "
        "provider_challenge TEXT NOT NULL UNIQUE, provider_session_key TEXT NOT NULL UNIQUE, "
        "session_secret_age BLOB NOT NULL, key_state TEXT NOT NULL CHECK "
        "(key_state IN ('LIVE', 'RETIRED')), accept_bytes BLOB, accept_message_id TEXT, "
        "transcript_digest TEXT, phase TEXT NOT NULL CHECK "
        "(phase IN ('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED')), "
        "blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)), revision INTEGER NOT NULL, "
        "next_client_seq INTEGER NOT NULL, next_provider_seq INTEGER NOT NULL, "
        "active_at INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE inbox (session_id TEXT NOT NULL, sender_key TEXT NOT NULL, "
        "message_id TEXT NOT NULL, seq INTEGER NOT NULL, unsigned_digest TEXT NOT NULL, "
        "canonical_bytes BLOB NOT NULL, admitted_revision INTEGER NOT NULL, "
        "PRIMARY KEY (session_id, sender_key, message_id), "
        "UNIQUE (session_id, sender_key, seq))"
    ),
    (
        "CREATE TABLE outbox (message_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, "
        "seq INTEGER NOT NULL, in_reply_to TEXT, canonical_bytes BLOB NOT NULL, "
        "committed_revision INTEGER NOT NULL, delivery_state TEXT NOT NULL CHECK "
        "(delivery_state IN ('PENDING', 'ACKED', 'RECONCILED')), UNIQUE (session_id, seq))"
    ),
    (
        "CREATE TABLE conflicts (session_id TEXT NOT NULL, kind TEXT NOT NULL CHECK "
        "(kind IN ('init', 'confirm')), evidence_bytes BLOB NOT NULL, "
        "PRIMARY KEY (session_id, kind))"
    ),
    (
        "CREATE TABLE epochs (epoch_key TEXT PRIMARY KEY, secret_age BLOB NOT NULL, "
        "created_at INTEGER NOT NULL, retire_after INTEGER NOT NULL)"
    ),
    ("CREATE TABLE expired (session_id TEXT PRIMARY KEY, expired_at INTEGER NOT NULL)"),
    (
        "CREATE TABLE announcements (slot INTEGER PRIMARY KEY CHECK (slot = 1), "
        "created_at INTEGER NOT NULL)"
    ),
)


class LiveSessionStoreError(ValueError):
    """No authoritative session fact was established; nothing may be exposed."""


class StaleOwnerError(LiveSessionStoreError):
    """The handle no longer owns the store; stop all exposure immediately."""


class SessionCapacityError(LiveSessionStoreError):
    """No new session fits; existing sessions and replays are unaffected."""


class SessionExpiredError(LiveSessionStoreError):
    """The session expired; its recorded result is final and keys are gone."""


class SessionBlockedError(LiveSessionStoreError):
    """Durable conflict evidence blocks new risk for this session."""


@dataclass(frozen=True, slots=True)
class AuthorityDeclaration:
    """Operator attestation of the deployment boundary this store relies on."""

    volume_label: str
    outside_restore_domain: bool
    single_host: bool

    def jcs(self) -> bytes:
        """Return canonical attestation bytes, refusing anything not explicit."""
        if not (
            type(self.volume_label) is str
            and 0 < len(self.volume_label) <= MAX_LABEL_CHARS
            and self.volume_label.isprintable()
            and self.outside_restore_domain is True
            and self.single_host is True
        ):
            raise LiveSessionStoreError("explicit authority attestation required")
        return canonicalize(
            {
                "volume_label": self.volume_label,
                "outside_restore_domain": True,
                "single_host": True,
            }
        )


@dataclass(frozen=True, slots=True)
class SessionReservation:
    """A reserved challenge; permits only building and committing one accept."""

    session_id: str
    init_message_id: str
    provider_challenge: str
    provider_session_key: str
    revision: int


@dataclass(frozen=True, slots=True)
class AcceptCommit:
    """Exact accept bytes durably committed; only now may they be published."""

    session_id: str
    message_id: str
    canonical_bytes: bytes
    transcript_digest: str
    revision: int


@dataclass(frozen=True, slots=True)
class ConfirmAdmission:
    """Client confirmation admitted; grants no economic authority."""

    session_id: str
    message_id: str
    transcript_digest: str
    revision: int
    replay: bool


@dataclass(frozen=True, slots=True)
class OutboxEntry:
    """Committed provider bytes awaiting application acknowledgment."""

    message_id: str
    session_id: str
    canonical_bytes: bytes


def _canonical_envelope(document: bytes) -> Envelope:
    if type(document) is not bytes or not 0 < len(document) <= MAX_DOCUMENT_BYTES:
        raise LiveSessionStoreError("envelope size unsupported")
    if canonicalize(parse_json_strict(document, max_bytes=MAX_DOCUMENT_BYTES)) != document:
        raise LiveSessionStoreError("canonical envelope bytes required")
    return parse_model_json(Envelope, document)


def _stable_file(directory: int, name: str, *, create: bool) -> int:
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise LiveSessionStoreError("store path is not a regular file")
    return descriptor


class LiveSessionStore:
    """Single owner of authoritative handshake sessions for one provider."""

    def __init__(  # noqa: PLR0913 - explicit owned resources
        self,
        *,
        path: Path,
        lock_fd: int,
        connection: sqlite3.Connection,
        generation: int,
        network: NetworkIdentity,
        identity: str,
        policy: HandshakePolicy,
        crypto: EnvelopeSchnorrVerifier,
        store_uuid: str,
        custody_identity: x25519.Identity,
        public_keys: CustodyPublicKeys,
        max_sessions: int,
        max_tombstones: int,
        new_sessions_per_minute: int,
    ) -> None:
        """Use provision() or acquire(); never construct directly."""
        self.path = path
        self._lock_fd: int | None = lock_fd
        self._connection = connection
        self._generation = generation
        self._network = network
        self._identity = identity
        self._policy = policy
        self._crypto = crypto
        self._store_uuid = store_uuid
        self._custody_identity = custody_identity
        self._public_keys = public_keys
        self._max_sessions = max_sessions
        self._max_tombstones = max_tombstones
        self._admission = _TokenBucket(new_sessions_per_minute)
        self._pid = os.getpid()

    @staticmethod
    def provision(  # noqa: PLR0913 - independent provisioning facts explicit
        path: str | PathLike[str],
        network: NetworkIdentity,
        provider_identity: str,
        policy: HandshakePolicy,
        authority: AuthorityDeclaration,
        *,
        custody_recipient: str,
    ) -> None:
        """Explicitly create a new empty store and owner lock; never overwrite.

        Session secrets are age-encrypted to ``custody_recipient``. Its identity
        must be kept outside this volume's images, or encryption adds nothing.
        """
        network_jcs, identity = _expected(network, provider_identity)
        recipient = _recipient(custody_recipient)
        policy_jcs = _policy_bytes(policy)
        authority_jcs = authority.jcs()
        location = Path(path).absolute()
        directory = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            lock_fd = _stable_file(directory, location.name + LOCK_SUFFIX, create=True)
            try:
                db_fd = _stable_file(directory, location.name, create=True)
                db_inode = os.fstat(db_fd).st_ino
                os.close(db_fd)
                lock_inode = os.fstat(lock_fd).st_ino
                os.fsync(lock_fd)
            finally:
                os.close(lock_fd)
            connection = sqlite3.connect(
                location.as_uri() + "?mode=rw", uri=True, isolation_level=None
            )
            try:
                _configure(connection)
                connection.execute("BEGIN IMMEDIATE")
                for statement in SCHEMA:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO meta VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                    (
                        SCHEMA_VERSION,
                        str(uuid.uuid4()),
                        network_jcs,
                        identity,
                        policy_jcs,
                        authority_jcs,
                        db_inode,
                        lock_inode,
                        recipient,
                    ),
                )
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                connection.execute("COMMIT")
            finally:
                connection.close()
            os.fsync(directory)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - partial files are left for the operator
            raise LiveSessionStoreError("live session store provisioning refused") from None
        finally:
            os.close(directory)

    @classmethod
    def acquire(  # noqa: PLR0913, PLR0915 - independent expectations explicit
        cls,
        path: str | PathLike[str],
        network: NetworkIdentity,
        provider_identity: str,
        policy: HandshakePolicy,
        *,
        crypto: EnvelopeSchnorrVerifier,
        custody_identity: str,
        public_keys: CustodyPublicKeys,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_tombstones: int = DEFAULT_MAX_TOMBSTONES,
        new_sessions_per_minute: int = DEFAULT_NEW_SESSIONS_PER_MINUTE,
    ) -> Self:
        """Take lifetime exclusive ownership; refuse any unknown or copied state.

        ``max_sessions`` caps retained sessions so strangers cannot grow the
        store without bound; ``expire_unconfirmed`` reclaims capacity.
        """
        if not all(
            type(limit) is int and limit >= 1
            for limit in (max_sessions, max_tombstones, new_sessions_per_minute)
        ):
            raise LiveSessionStoreError("session capacity unsupported")
        network_jcs, identity = _expected(network, provider_identity)
        try:
            unlocking = x25519.Identity.from_str(custody_identity)
        except Exception:  # noqa: BLE001 - never echo credential material
            raise LiveSessionStoreError("custody identity malformed") from None
        _require_policy(policy)
        policy_jcs = _policy_bytes(policy)
        location = Path(path).absolute()
        lock_fd = -1
        connection: sqlite3.Connection | None = None
        try:
            directory = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                lock_fd = _stable_file(directory, location.name + LOCK_SUFFIX, create=False)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise LiveSessionStoreError("store owned by another process") from None
                db_fd = _stable_file(directory, location.name, create=False)
                db_inode = os.fstat(db_fd).st_ino
                os.close(db_fd)
            finally:
                os.close(directory)
            connection = sqlite3.connect(
                location.as_uri() + "?mode=rw", uri=True, isolation_level=None
            )
            connection.execute("PRAGMA busy_timeout=5000")
            _check_schema(connection)  # before any pragma that could modify a foreign file
            _configure(connection)
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT schema_version, network_jcs, provider_identity, policy_jcs, "
                "db_inode, lock_inode, generation, store_uuid, authority_jcs, custody_recipient "
                "FROM meta"
            ).fetchall()
            if len(row) != 1 or row[0][:4] != (SCHEMA_VERSION, network_jcs, identity, policy_jcs):
                raise LiveSessionStoreError("store namespace or policy mismatch")  # noqa: TRY301
            _check_provisioning(row[0][7], row[0][8])
            if row[0][9] != str(unlocking.to_public()):
                raise LiveSessionStoreError("custody identity does not match store")  # noqa: TRY301
            if row[0][4:6] != (db_inode, os.fstat(lock_fd).st_ino):
                raise LiveSessionStoreError(  # noqa: TRY301 - copied or restored file
                    "store files are not the provisioned authoritative copy"
                )
            generation = row[0][6] + 1
            connection.execute("UPDATE meta SET generation=?", (generation,))
            connection.execute("COMMIT")
            owned = cls(
                path=location,
                lock_fd=lock_fd,
                connection=connection,
                generation=generation,
                network=NetworkIdentity.model_validate_json(network_jcs, strict=True),
                identity=identity,
                policy=policy,
                crypto=crypto,
                store_uuid=row[0][7],
                custody_identity=unlocking,
                public_keys=public_keys,
                max_sessions=max_sessions,
                max_tombstones=max_tombstones,
                new_sessions_per_minute=new_sessions_per_minute,
            )
        except LiveSessionStoreError:
            _discard(connection, lock_fd)
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            _discard(connection, lock_fd)
            raise LiveSessionStoreError("live session store unavailable") from None
        return owned

    def close(self) -> None:
        """Release ownership; the handle can never write again."""
        lock_fd, self._lock_fd = self._lock_fd, None
        if os.getpid() != self._pid:
            # Inherited across fork: never touch the parent's SQLite connection.
            # Closing our descriptor copy does not release the parent's flock.
            if lock_fd is not None:
                os.close(lock_fd)
            return
        _discard(self._connection, -1 if lock_fd is None else lock_fd)

    def __enter__(self) -> Self:
        """Own the store for the block."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Release ownership."""
        self.close()

    @property
    def generation(self) -> int:
        """Owner generation; increases on every acquire."""
        return self._generation

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        if os.getpid() != self._pid:
            raise StaleOwnerError("store handle inherited across fork; reacquire")
        if self._lock_fd is None:
            raise StaleOwnerError("store handle closed")
        connection = self._connection
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise LiveSessionStoreError("live session store busy or unavailable") from None
        try:
            if connection.execute("SELECT generation FROM meta").fetchone() != (self._generation,):
                raise StaleOwnerError("store owned by a newer generation")  # noqa: TRY301
            yield connection
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                self.close()  # transaction state unknown; this handle may not continue
            raise
        try:
            connection.execute("COMMIT")
        except sqlite3.Error:
            # Outcome unknown: the write may or may not be durable. Release
            # ownership so the caller must reacquire and re-read the truth.
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            self.close()
            raise StaleOwnerError("commit outcome uncertain; ownership released") from None

    def _expectations(self) -> dict[str, object]:
        return {
            "expected_provider_identity": self._identity,
            "expected_profile": self._policy.profile,
            "expected_network": self._network,
            "supported_features": _features(self._policy.features),
            "supported_encryption_suites": _features(self._policy.encryption_suites),
            "supported_capabilities": _features(self._policy.capabilities),
            "crypto": self._crypto,
        }

    def _init(self, document: bytes) -> tuple[Envelope, HandshakeInit]:
        outer = _canonical_envelope(document)
        init = HandshakeInit.model_validate_json(canonicalize(outer.payload), strict=True)
        policy = self._policy
        if not (
            outer.message_type == "handshake_init"
            and outer.sequence == 0
            and outer.in_reply_to is None
            and outer.contract_hash is None
            and outer.signature is None
            and outer.session_id == init.session_id
            and outer.sender_session_key == init.client_session_xonly_key
            and outer.profile_id == init.profile_id == policy.profile
            and outer.network_identity == init.network_identity == self._network
            and init.expected_provider_identity_xonly_key == self._identity
            and set(outer.required_features).issubset(policy.features)
            and set(init.required_features).issubset(policy.features)
            and bool(set(init.requested_encryption_suites) & policy.encryption_suites)
        ):
            raise LiveSessionStoreError("untrusted or unsupported handshake initiation")
        return outer, init

    def reserve(self, init_document: bytes, *, now: int | None = None) -> SessionReservation:
        """Reserve one fresh provider challenge per session; replay is stable.

        The init is unsigned, so different bytes for a known session may come
        from a stranger. They are kept as bounded conflict evidence and block
        new risk for that session (an availability cost, never exposure).
        An expired session ID is answered ``SessionExpiredError`` forever.
        New sessions need free live capacity, free tombstone capacity, and a
        token from the global admission rate limit.
        """
        now = int(time.time()) if now is None else now
        try:
            outer, init = self._init(init_document)
            with self._write() as connection:
                if connection.execute(
                    "SELECT 1 FROM expired WHERE session_id=?", (init.session_id,)
                ).fetchone():
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, blocked, revision FROM sessions "
                    "WHERE session_id=?",
                    (init.session_id,),
                ).fetchone()
                if row is not None:
                    if row[0] == init_document and not row[2]:
                        # Replay reuses the key; broken custody is never replaced.
                        key = self._require_custody(connection, init.session_id)
                        return SessionReservation(
                            init.session_id, outer.message_id, row[1], key, row[3]
                        )
                    if row[0] != init_document:
                        _record_conflict(connection, init.session_id, "init", init_document)
                    blocked = True
                else:
                    blocked = False
                    (live,) = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()
                    (dead,) = connection.execute("SELECT COUNT(*) FROM expired").fetchone()
                    if live >= self._max_sessions or dead >= self._max_tombstones:
                        raise SessionCapacityError("session capacity reached")  # noqa: TRY301
                    if not self._admission.take(now):
                        raise SessionCapacityError("session admission rate exceeded")  # noqa: TRY301
                    challenge = _fresh_challenge(connection, init)
                    key, sealed = self._new_session_key(init, challenge)
                    connection.execute(
                        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, 'LIVE', "
                        "NULL, NULL, NULL, 'RESERVED', 0, 0, 1, 0, ?)",
                        (
                            init.session_id,
                            init_document,
                            outer.message_id,
                            init.client_session_xonly_key,
                            challenge,
                            key,
                            sealed,
                            now,
                        ),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents
            raise LiveSessionStoreError("session reservation refused") from None
        if blocked:
            raise SessionBlockedError("session initiation conflict is durable")
        return SessionReservation(init.session_id, outer.message_id, challenge, key, 0)

    def _key_record(
        self, session_id: str, init_digest: str, challenge: str, scalar: bytes, xonly: str
    ) -> bytes:
        return canonicalize(
            {
                "kind": KEY_RECORD_KIND,
                "secret_scalar": scalar.hex(),
                "xonly_public_key": xonly,
                "store_uuid": self._store_uuid,
                "network_identity": self._network.model_dump(mode="json"),
                "provider_identity": self._identity,
                "session_id": session_id,
                "handshake_init_digest": init_digest,
                "provider_challenge": challenge,
            }
        )

    def _new_session_key(self, init: HandshakeInit, challenge: str) -> tuple[str, bytes]:
        scalar = _new_session_scalar()
        xonly = _xonly(self._public_keys, scalar)
        record = self._key_record(
            init.session_id, handshake_init_hash(init).hex(), challenge, scalar, xonly
        )
        sealed = pyrage.encrypt(record, [self._custody_identity.to_public()])
        if type(sealed) is not bytes or pyrage.decrypt(sealed, [self._custody_identity]) != record:
            raise LiveSessionStoreError("session key custody not verifiable")
        return xonly, sealed

    def _require_custody(self, connection: sqlite3.Connection, session_id: str) -> str:
        """Return the bound public key only if its sealed secret is intact and usable."""
        _, xonly = self._unseal(connection, session_id)
        return xonly

    def _unseal(self, connection: sqlite3.Connection, session_id: str) -> tuple[bytes, str]:
        row = connection.execute(
            "SELECT init_bytes, provider_challenge, provider_session_key, session_secret_age, "
            "key_state FROM sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        try:
            init_bytes, challenge, xonly, sealed, state = row
            _, init = self._init(init_bytes)
            plaintext = pyrage.decrypt(sealed, [self._custody_identity])
            record = json.loads(plaintext)
            scalar = bytes.fromhex(record["secret_scalar"])
            valid = (
                state == "LIVE"
                and plaintext
                == self._key_record(
                    session_id, handshake_init_hash(init).hex(), challenge, scalar, xonly
                )
                and _xonly(self._public_keys, scalar) == xonly
            )
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            valid = False
        if not valid:
            raise LiveSessionStoreError("session key custody unavailable")
        return scalar, str(xonly)

    def wrap_pending(self, message_id: str, *, transport: Context) -> bytes:
        """Return a fresh NIP-59 wrap of one committed, still-owed outbox message.

        Each call re-randomizes seal and wrapper around the unchanged logical
        message. The recipient is the peer's session mailbox from the
        committed transcript, never a caller-chosen key.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT o.session_id, o.canonical_bytes, s.client_key FROM outbox o "
                    "JOIN sessions s ON s.session_id = o.session_id "
                    "WHERE o.message_id=? AND o.delivery_state='PENDING'",
                    (message_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no pending outbox message")  # noqa: TRY301
                session_id, document, recipient = row
                scalar, _ = self._unseal(connection, session_id)
                try:
                    return _wrap_envelope(
                        document,
                        sender_session_secret=scalar,
                        recipient_xonly_key=recipient,
                        crypto=transport,
                    )
                finally:
                    del scalar
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            raise LiveSessionStoreError("outbox wrap refused") from None

    def open_mailbox_frame(self, outer_event: bytes, *, transport: Context) -> bytes:
        """Decode a gift wrap sent to one of our session mailboxes.

        Returns the exact canonical envelope bytes only if the seal author is
        that session's client key and the envelope names that session. This is
        NOT admission: the caller must still pass the bytes to the matching
        admission method (for example ``admit_confirm``).
        """
        try:
            recipient = _routing_recipient(outer_event)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT session_id, client_key FROM sessions WHERE provider_session_key=?",
                    (recipient,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("mailbox frame for unknown session")  # noqa: TRY301
                session_id, client = row
                scalar, mailbox = self._unseal(connection, session_id)
                try:
                    candidate = _decode_gift_wrap_candidate(
                        outer_event,
                        recipient_mailbox_secret=scalar,
                        expected_recipient_xonly_key=mailbox,
                        expected_network=self._network,
                        expected_profile_id=self._policy.profile,
                        crypto=transport,
                    )
                finally:
                    del scalar
            if not (
                candidate.seal_author_xonly_key == client
                and candidate.envelope.sender_session_key == client
                and candidate.envelope.session_id == session_id
            ):
                raise LiveSessionStoreError("mailbox frame sender not bound to session")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - uniform, redacted refusal (RS-006)
            raise LiveSessionStoreError("mailbox frame refused") from None
        return candidate.envelope_bytes

    def create_accept(
        self,
        session_id: str,
        *,
        identity: ProviderIdentity,
        transport_endpoints: tuple[str, ...],
    ) -> AcceptCommit:
        """Build, identity-sign, and durably commit this session's one accept.

        Negotiation picks the client's most preferred supported suite and the
        requested capabilities we support, in the client's order. A session
        that already committed an accept returns that record, never a new one.
        Nothing is exposed here; publish only via ``wrap_pending``.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, accept_bytes, blocked "
                    "FROM sessions WHERE session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no reservation for session")  # noqa: TRY301
                init_bytes, challenge, stored, blocked = row
                key = (
                    None
                    if stored is not None or blocked
                    else self._require_custody(connection, session_id)
                )
            if stored is not None:
                return self.commit_accept(stored)
            if blocked or key is None:
                raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
            outer, init = self._init(init_bytes)
            if identity.xonly_public_key != self._identity:
                raise LiveSessionStoreError("identity is not this store's provider")  # noqa: TRY301
            policy = self._policy
            suites = [s for s in init.requested_encryption_suites if s in policy.encryption_suites]
            capabilities = tuple(c for c in init.requested_capabilities if c in policy.capabilities)
            if not suites or not capabilities:
                raise LiveSessionStoreError("no mutually supported selection")  # noqa: TRY301
            selection = HandshakeAccept(
                handshake_init_hash=handshake_init_hash(init).hex(),
                protocol="rillswap",
                wire_version="1",
                profile_id=init.profile_id,
                network_identity=init.network_identity,
                session_id=init.session_id,
                client_challenge=init.client_challenge,
                provider_challenge=challenge,
                client_session_xonly_key=init.client_session_xonly_key,
                provider_session_xonly_key=key,
                provider_identity_xonly_key=self._identity,
                selected_encryption_suite=suites[0],
                selected_capabilities=capabilities,
                transport_endpoints=tuple(transport_endpoints),
                required_features=(),
                extensions={},
            )
            payload: dict[str, Any] = {
                "accept": selection.model_dump(mode="json"),
                "provider_identity_signature": identity.sign_handshake_accept(selection),
            }
            document = canonicalize(
                {
                    "protocol": "rillswap",
                    "wire_version": "1",
                    "profile_id": init.profile_id,
                    "network_identity": init.network_identity.model_dump(mode="json"),
                    "session_id": init.session_id,
                    "message_id": _new_message_id(),
                    "sender_session_key": key,
                    "sequence": 0,
                    "in_reply_to": outer.message_id,
                    "contract_hash": None,
                    "message_type": "handshake_accept",
                    "payload": payload,
                    "required_features": [],
                    "extensions": {},
                    "signature": None,
                }
            )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            raise LiveSessionStoreError("accept construction refused") from None
        # A concurrent identical build is impossible (single owner); a crash
        # before this commit leaves nothing exposed and simply rebuilds.
        return self.commit_accept(document)

    def commit_accept(self, accept_document: bytes) -> AcceptCommit:
        """Durably commit exact accept bytes BEFORE any publication.

        Only after this returns may the bytes be exposed. At most one accept is
        ever committed per session; identical resubmission returns the record.
        """
        try:
            outer = _canonical_envelope(accept_document)
            accepted = HandshakeAcceptPayload.model_validate_json(
                canonicalize(outer.payload), strict=True
            )
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, accept_bytes, accept_message_id, "
                    "transcript_digest, phase, blocked, revision FROM sessions "
                    "WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no reservation for session")  # noqa: TRY301
                init_bytes, challenge, stored, stored_id, digest, phase, blocked, revision = row
                if phase != "RESERVED":
                    if stored != accept_document:
                        raise LiveSessionStoreError(  # noqa: TRY301
                            "a different accept is already committed"
                        )
                    return AcceptCommit(
                        outer.session_id,
                        stored_id,
                        stored,
                        digest,
                        _accept_revision(connection, stored_id),
                    )
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                transcript = verify_static_handshake_accept(
                    init_bytes,
                    accept_document,
                    **self._expectations(),  # type: ignore[arg-type]
                ).hex()
                if accepted.accept.provider_challenge != challenge:
                    raise LiveSessionStoreError("accept challenge not reserved")  # noqa: TRY301
                custody_key = self._require_custody(connection, outer.session_id)
                if accepted.accept.provider_session_xonly_key != custody_key:
                    raise LiveSessionStoreError(  # noqa: TRY301
                        "accept session key is not the reserved custody key"
                    )
                committed = revision + 1
                connection.execute(
                    "INSERT INTO outbox VALUES (?, ?, 0, ?, ?, ?, 'PENDING')",
                    (
                        outer.message_id,
                        outer.session_id,
                        outer.in_reply_to,
                        accept_document,
                        committed,
                    ),
                )
                connection.execute(
                    "UPDATE sessions SET accept_bytes=?, accept_message_id=?, "
                    "transcript_digest=?, phase='ACCEPT_COMMITTED', revision=?, "
                    "next_provider_seq=1 WHERE session_id=?",
                    (accept_document, outer.message_id, transcript, committed, outer.session_id),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("accept commit refused") from None
        return AcceptCommit(
            outer.session_id, outer.message_id, accept_document, transcript, committed
        )

    def admit_confirm(self, confirm_document: bytes, *, now: int | None = None) -> ConfirmAdmission:
        """Atomically admit the signed confirm over the committed transcript.

        Unverifiable documents are refused without any record. A second,
        different, validly signed confirm is client equivocation: it is kept
        as evidence and blocks the session.
        """
        try:
            outer = _canonical_envelope(confirm_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, accept_bytes, accept_message_id, transcript_digest, "
                    "client_key, phase, blocked, revision FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if (
                    row is None
                    and connection.execute(
                        "SELECT 1 FROM expired WHERE session_id=?", (outer.session_id,)
                    ).fetchone()
                ):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                if row is None or row[5] == "RESERVED":
                    raise LiveSessionStoreError("no committed accept for session")  # noqa: TRY301
                init_bytes, accept_bytes, accept_id, digest, client, phase, blocked, revision = row
                admitted = None
                if phase == "CONFIRMED":
                    admitted = connection.execute(
                        "SELECT message_id, canonical_bytes, admitted_revision, unsigned_digest "
                        "FROM inbox WHERE session_id=? AND sender_key=? AND seq=1",
                        (outer.session_id, client),
                    ).fetchone()
                    if admitted is not None and admitted[1] == confirm_document and not blocked:
                        return ConfirmAdmission(
                            outer.session_id, admitted[0], digest, admitted[2], replay=True
                        )
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                transcript = verify_static_handshake_transcript(
                    init_bytes,
                    accept_bytes,
                    confirm_document,
                    **self._expectations(),  # type: ignore[arg-type]
                ).hex()
                if transcript != digest:
                    raise LiveSessionStoreError("confirm transcript differs")  # noqa: TRY301
                # RS-001 conflicts are defined over unsigned canonical bytes: a
                # different valid signature over the same content is a replay,
                # answered with the originally recorded result.
                if admitted is not None and unsigned_envelope_hash(outer).hex() == admitted[3]:
                    return ConfirmAdmission(
                        outer.session_id, admitted[0], digest, admitted[2], replay=True
                    )
                equivocation = phase == "CONFIRMED"
                if equivocation:
                    _record_conflict(connection, outer.session_id, "confirm", confirm_document)
                else:
                    admitted_revision = revision + 1
                    connection.execute(
                        "INSERT INTO inbox VALUES (?, ?, ?, 1, ?, ?, ?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            unsigned_envelope_hash(outer).hex(),
                            confirm_document,
                            admitted_revision,
                        ),
                    )
                    connection.execute(
                        "UPDATE sessions SET phase='CONFIRMED', revision=?, next_client_seq=2, "
                        "active_at=? WHERE session_id=?",
                        (
                            admitted_revision,
                            int(time.time()) if now is None else now,
                            outer.session_id,
                        ),
                    )
                    # The confirm is the application acknowledgment of the accept.
                    connection.execute(
                        "UPDATE outbox SET delivery_state='ACKED' "
                        "WHERE message_id=? AND delivery_state='PENDING'",
                        (accept_id,),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("confirm admission refused") from None
        if equivocation:
            raise SessionBlockedError("conflicting signed confirm is durable")
        return ConfirmAdmission(
            outer.session_id, outer.message_id, digest, admitted_revision, replay=False
        )

    def rotate_epochs(
        self, *, now: int, period: int, retention: int, advertise_for: int
    ) -> tuple[str, ...]:
        """Ensure a current epoch inbox key; return keys to advertise, newest first.

        A new epoch starts when the newest is ``period`` seconds old. Each key
        keeps decoding until ``created_at + period + retention``; set
        ``retention`` to at least the announcement lifetime so late inits
        still decode. Only keys that stay decodable for ``advertise_for``
        more seconds are returned (announcement lifetime plus delivery grace),
        so a valid announcement never names a key about to retire. Epoch keys
        only receive public inits (availability, not authority), and their
        sealed secrets bind this store.
        """
        if not (
            type(now) is int
            and type(period) is int
            and type(retention) is int
            and type(advertise_for) is int
            and 0 <= advertise_for <= retention
            and now > 0
            and period > 0
            and retention >= 0
        ):
            raise LiveSessionStoreError("epoch schedule unsupported")
        try:
            with self._write() as connection:
                newest = connection.execute("SELECT MAX(created_at) FROM epochs").fetchone()[0]
                if newest is not None and now < newest:
                    raise LiveSessionStoreError("clock is behind the newest epoch")  # noqa: TRY301
                if newest is None or now >= newest + period:
                    xonly, sealed = self._new_epoch_key(now)
                    connection.execute(
                        "INSERT INTO epochs VALUES (?, ?, ?, ?)",
                        (xonly, sealed, now, now + period + retention),
                    )
                rows = connection.execute(
                    "SELECT epoch_key FROM epochs WHERE retire_after > ? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (now + advertise_for, MAX_ADVERTISED_EPOCHS),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            raise LiveSessionStoreError("epoch rotation refused") from None
        return tuple(row[0] for row in rows)

    def _epoch_record(self, scalar: bytes, xonly: str, created_at: int) -> bytes:
        return canonicalize(
            {
                "kind": EPOCH_RECORD_KIND,
                "secret_scalar": scalar.hex(),
                "xonly_public_key": xonly,
                "store_uuid": self._store_uuid,
                "created_at": created_at,
            }
        )

    def _new_epoch_key(self, created_at: int) -> tuple[str, bytes]:
        scalar = _new_epoch_scalar()
        xonly = _xonly(self._public_keys, scalar)
        if xonly == self._identity:
            raise LiveSessionStoreError("epoch key collides with identity")
        record = self._epoch_record(scalar, xonly, created_at)
        sealed = pyrage.encrypt(record, [self._custody_identity.to_public()])
        if type(sealed) is not bytes or pyrage.decrypt(sealed, [self._custody_identity]) != record:
            raise LiveSessionStoreError("epoch key custody not verifiable")
        return xonly, sealed

    def open_epoch_frame(self, outer_event: bytes, *, now: int, transport: Context) -> bytes:
        """Decode a gift-wrapped handshake_init sent to an unretired epoch inbox.

        Returns exact canonical init bytes whose envelope sender is the seal
        author. The sender is still a stranger: pass the bytes to ``reserve``,
        which applies every init rule. Refusals are uniform and redacted.
        """
        try:
            recipient = _routing_recipient(outer_event)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT secret_age, created_at FROM epochs "
                    "WHERE epoch_key=? AND retire_after > ?",
                    (recipient, now),
                ).fetchone()
            if row is None:
                raise LiveSessionStoreError("frame for unknown or retired epoch")  # noqa: TRY301
            plaintext = pyrage.decrypt(row[0], [self._custody_identity])
            scalar = bytes.fromhex(json.loads(plaintext)["secret_scalar"])
            try:
                if not (
                    plaintext == self._epoch_record(scalar, recipient, row[1])
                    and _xonly(self._public_keys, scalar) == recipient
                ):
                    raise LiveSessionStoreError("epoch key custody unavailable")
                candidate = _decode_gift_wrap_candidate(
                    outer_event,
                    recipient_mailbox_secret=scalar,
                    expected_recipient_xonly_key=recipient,
                    expected_network=self._network,
                    expected_profile_id=self._policy.profile,
                    crypto=transport,
                )
            finally:
                del scalar
            if not (
                candidate.envelope.message_type == "handshake_init"
                and candidate.envelope.sender_session_key == candidate.seal_author_xonly_key
            ):
                raise LiveSessionStoreError("epoch frame is not a sender-bound init")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - uniform, redacted refusal (RS-006)
            raise LiveSessionStoreError("epoch frame refused") from None
        return candidate.envelope_bytes

    def expire_idle(self, *, now: int, idle_timeout: int) -> int:
        """Expire idle pre-economic sessions into permanent compact tombstones.

        A session idle for ``idle_timeout`` (reserved, accepted, or confirmed
        with nothing after the confirm) loses its key, messages, and conflict
        evidence (SQLite ``secure_delete``). Its ID stays in ``expired``
        forever, so any later init or confirm for it gets
        ``SessionExpiredError``, never a second accept (RS-001 stable replay).
        Tombstones count against ``max_tombstones``. Returns how many expired.
        """
        if not (type(now) is int and type(idle_timeout) is int and idle_timeout > 0):
            raise LiveSessionStoreError("expiry schedule unsupported")
        try:
            with self._write() as connection:
                idle = [
                    (row[0],)
                    for row in connection.execute(
                        "SELECT session_id FROM sessions WHERE phase IN "
                        "('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED') AND active_at <= ?",
                        (now - idle_timeout,),
                    )
                ]
                connection.executemany(
                    "INSERT INTO expired VALUES (?, ?)", [(sid, now) for (sid,) in idle]
                )
                for table in ("inbox", "outbox", "conflicts", "sessions"):
                    connection.executemany(
                        f"DELETE FROM {table} WHERE session_id=?",  # noqa: S608 - fixed names
                        idle,
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session expiry refused") from None
        return len(idle)

    def receiving_epochs(self, *, now: int) -> tuple[str, ...]:
        """Return every still-decodable epoch key, advertised or not."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT epoch_key FROM epochs WHERE retire_after > ? ORDER BY created_at DESC",
                    (now,),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("epoch keys unavailable") from None
        return tuple(row[0] for row in rows)

    def record_announcement(self, created_at: int) -> None:
        """Durably order an RS-005 announcement revision before publishing it.

        Revisions equal ``created_at`` and must strictly increase across
        restarts; a clock rollback is refused rather than published lower.
        """
        if type(created_at) is not int or created_at <= 0:
            raise LiveSessionStoreError("announcement time unsupported")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT created_at FROM announcements WHERE slot=1"
                ).fetchone()
                if row is not None and created_at <= row[0]:
                    raise LiveSessionStoreError("announcement revision would not increase")  # noqa: TRY301
                connection.execute(
                    "INSERT OR REPLACE INTO announcements VALUES (1, ?)", (created_at,)
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("announcement ordering refused") from None

    def awaiting_confirm_mailboxes(self) -> tuple[str, ...]:
        """Return our session mailbox keys that still expect a client confirm."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT provider_session_key FROM sessions "
                    "WHERE phase='ACCEPT_COMMITTED' AND blocked=0 ORDER BY revision"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session mailboxes unavailable") from None
        return tuple(row[0] for row in rows)

    def pending_outbox(self) -> tuple[OutboxEntry, ...]:
        """Return committed bytes still owed to peers; current owner only."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT message_id, session_id, canonical_bytes FROM outbox "
                    "WHERE delivery_state='PENDING' ORDER BY committed_revision, message_id"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("outbox unavailable") from None
        return tuple(OutboxEntry(*row) for row in rows)


def _configure(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA busy_timeout=5000")
    if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
        raise LiveSessionStoreError("WAL unavailable")
    connection.execute("PRAGMA synchronous=FULL")
    if connection.execute("PRAGMA synchronous").fetchone() != (2,):
        raise LiveSessionStoreError("FULL sync unavailable")
    connection.execute("PRAGMA secure_delete=ON")  # expired sealed keys leave no old pages


def _check_schema(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA application_id").fetchone() != (
        APPLICATION_ID,
    ) or connection.execute("PRAGMA user_version").fetchone() != (SCHEMA_VERSION,):
        raise LiveSessionStoreError("live session store version unsupported")
    tables = {
        name: definition
        for kind, name, definition in connection.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
        )
        if kind == "table"
    }
    expected = {statement.split()[2]: statement for statement in SCHEMA}
    if tables != expected:
        raise LiveSessionStoreError("live session store schema incompatible")
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise LiveSessionStoreError("live session store integrity unavailable")


class _TokenBucket:
    """In-memory global admission rate (a restart refills it; capacity still binds)."""

    def __init__(self, per_minute: int) -> None:
        self._capacity = float(per_minute)
        self._tokens = float(per_minute)
        self._rate = per_minute / 60.0
        self._last: int | None = None

    def take(self, now: int) -> bool:
        if self._last is not None and now > self._last:
            self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
        self._last = now if self._last is None else max(self._last, now)
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True


def _new_session_scalar() -> bytes:
    return secrets.token_bytes(32)


def _new_epoch_scalar() -> bytes:
    return secrets.token_bytes(32)


def _routing_recipient(outer_event: bytes) -> str:
    """Return the single ``p`` tag as a routing hint; the decoder re-verifies it."""
    if type(outer_event) is not bytes or len(outer_event) > MAX_OUTER_EVENT_BYTES:
        raise LiveSessionStoreError("frame size unsupported")
    tags: list[Any] = json.loads(outer_event)["tags"]
    recipients = [
        tag[1]
        for tag in tags
        if type(tag) is list and len(tag) >= 2 and tag[0] == "p"  # noqa: PLR2004
    ]
    if len(recipients) != 1 or type(recipients[0]) is not str:
        raise LiveSessionStoreError("frame recipient unsupported")
    return recipients[0]


def _new_challenge() -> str:
    return secrets.token_hex(32)


def _new_message_id() -> str:
    return secrets.token_hex(32)


def _recipient(value: str) -> str:
    try:
        parsed = x25519.Recipient.from_str(value)
    except Exception:  # noqa: BLE001 - never echo caller input
        raise LiveSessionStoreError("custody recipient malformed") from None
    if str(parsed) != value:
        raise LiveSessionStoreError("custody recipient malformed")
    return value


def _xonly(public_keys: CustodyPublicKeys, scalar: bytes) -> str:
    key = public_keys.public_key(scalar)
    if type(key) is not bytes or len(key) != COMPRESSED_KEY_BYTES or key[0] not in (2, 3):
        raise LiveSessionStoreError("session public key derivation failed")
    return key[1:].hex()


def _check_provisioning(store_uuid: object, authority_jcs: object) -> None:
    try:
        parsed = uuid.UUID(str(store_uuid))
        authority: dict[str, object] = json.loads(authority_jcs)  # type: ignore[arg-type]
        declared = AuthorityDeclaration(
            authority["volume_label"],  # type: ignore[arg-type]
            outside_restore_domain=authority["outside_restore_domain"],  # type: ignore[arg-type]
            single_host=authority["single_host"],  # type: ignore[arg-type]
        )
        valid = str(parsed) == store_uuid and declared.jcs() == authority_jcs
    except Exception:  # noqa: BLE001 - malformed metadata is simply not trusted
        valid = False
    if not valid:
        raise LiveSessionStoreError("store provisioning metadata untrusted")


def _discard(connection: sqlite3.Connection | None, lock_fd: int) -> None:
    if connection is not None:
        with suppress(sqlite3.Error):
            connection.close()
    if lock_fd >= 0:
        os.close(lock_fd)  # closing the descriptor releases the flock


def _fresh_challenge(connection: sqlite3.Connection, init: HandshakeInit) -> str:
    for _ in range(MAX_CHALLENGE_TRIES):
        challenge = _new_challenge()
        if (
            HEX32.fullmatch(challenge) is not None
            and challenge not in (init.session_id, init.client_challenge)
            and connection.execute(
                "SELECT 1 FROM sessions WHERE provider_challenge=?", (challenge,)
            ).fetchone()
            is None
        ):
            return challenge
    raise LiveSessionStoreError("independent challenge unavailable")


def _record_conflict(
    connection: sqlite3.Connection, session_id: str, kind: str, evidence: bytes
) -> None:
    # One bounded evidence row per session and kind; later conflicts add nothing.
    connection.execute(
        "INSERT OR IGNORE INTO conflicts VALUES (?, ?, ?)", (session_id, kind, evidence)
    )
    connection.execute(
        "UPDATE sessions SET blocked=1, revision=revision+1 WHERE session_id=? AND blocked=0",
        (session_id,),
    )


def _accept_revision(connection: sqlite3.Connection, message_id: str) -> int:
    row = connection.execute(
        "SELECT committed_revision FROM outbox WHERE message_id=?", (message_id,)
    ).fetchone()
    if row is None:
        raise LiveSessionStoreError("committed accept missing from outbox")
    return int(row[0])
