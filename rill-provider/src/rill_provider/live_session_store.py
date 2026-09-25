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
import uuid
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Self

from rill_core.wire import verify_static_handshake_accept, verify_static_handshake_transcript
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope, HandshakeAcceptPayload, HandshakeInit
from rill_core.wire.types import NetworkIdentity

from rill_provider.handshake_store import HandshakePolicy, _expected, _features, _require_policy
from rill_provider.issuance_reservation import _policy_bytes

if TYPE_CHECKING:
    from collections.abc import Iterator
    from os import PathLike

    from rill_core.wire.envelope_authentication import EnvelopeSchnorrVerifier

APPLICATION_ID = 0x524C5331  # RLS1, distinct from all diagnostic stores.
SCHEMA_VERSION = 1
MAX_DOCUMENT_BYTES = 65_536
MAX_CHALLENGE_TRIES = 4
MAX_LABEL_CHARS = 256
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
LOCK_SUFFIX = ".owner-lock"
SCHEMA = (
    (
        "CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "schema_version INTEGER NOT NULL, store_uuid TEXT NOT NULL, network_jcs BLOB NOT NULL, "
        "provider_identity TEXT NOT NULL, policy_jcs BLOB NOT NULL, authority_jcs BLOB NOT NULL, "
        "db_inode INTEGER NOT NULL, lock_inode INTEGER NOT NULL, generation INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE sessions (session_id TEXT PRIMARY KEY, init_bytes BLOB NOT NULL, "
        "init_message_id TEXT NOT NULL, client_key TEXT NOT NULL, "
        "provider_challenge TEXT NOT NULL UNIQUE, accept_bytes BLOB, accept_message_id TEXT, "
        "transcript_digest TEXT, phase TEXT NOT NULL CHECK "
        "(phase IN ('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED')), "
        "blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)), revision INTEGER NOT NULL, "
        "next_client_seq INTEGER NOT NULL, next_provider_seq INTEGER NOT NULL)"
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
)


class LiveSessionStoreError(ValueError):
    """No authoritative session fact was established; nothing may be exposed."""


class StaleOwnerError(LiveSessionStoreError):
    """The handle no longer owns the store; stop all exposure immediately."""


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
        self._pid = os.getpid()

    @staticmethod
    def provision(
        path: str | PathLike[str],
        network: NetworkIdentity,
        provider_identity: str,
        policy: HandshakePolicy,
        authority: AuthorityDeclaration,
    ) -> None:
        """Explicitly create a new empty store and owner lock; never overwrite."""
        network_jcs, identity = _expected(network, provider_identity)
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
                    "INSERT INTO meta VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                    (
                        SCHEMA_VERSION,
                        str(uuid.uuid4()),
                        network_jcs,
                        identity,
                        policy_jcs,
                        authority_jcs,
                        db_inode,
                        lock_inode,
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
    def acquire(
        cls,
        path: str | PathLike[str],
        network: NetworkIdentity,
        provider_identity: str,
        policy: HandshakePolicy,
        *,
        crypto: EnvelopeSchnorrVerifier,
    ) -> Self:
        """Take lifetime exclusive ownership; refuse any unknown or copied state."""
        network_jcs, identity = _expected(network, provider_identity)
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
                "db_inode, lock_inode, generation, store_uuid, authority_jcs FROM meta"
            ).fetchall()
            if len(row) != 1 or row[0][:4] != (SCHEMA_VERSION, network_jcs, identity, policy_jcs):
                raise LiveSessionStoreError("store namespace or policy mismatch")  # noqa: TRY301
            _check_provisioning(row[0][7], row[0][8])
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

    def reserve(self, init_document: bytes) -> SessionReservation:
        """Reserve one fresh provider challenge per session; replay is stable.

        The init is unsigned, so different bytes for a known session may come
        from a stranger. They are kept as bounded conflict evidence and block
        new risk for that session (an availability cost, never exposure).
        """
        try:
            outer, init = self._init(init_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, blocked, revision FROM sessions "
                    "WHERE session_id=?",
                    (init.session_id,),
                ).fetchone()
                if row is not None:
                    if row[0] == init_document and not row[2]:
                        return SessionReservation(init.session_id, outer.message_id, row[1], row[3])
                    if row[0] != init_document:
                        _record_conflict(connection, init.session_id, "init", init_document)
                    blocked = True
                else:
                    blocked = False
                    challenge = _fresh_challenge(connection, init)
                    connection.execute(
                        "INSERT INTO sessions VALUES "
                        "(?, ?, ?, ?, ?, NULL, NULL, NULL, 'RESERVED', 0, 0, 1, 0)",
                        (
                            init.session_id,
                            init_document,
                            outer.message_id,
                            init.client_session_xonly_key,
                            challenge,
                        ),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents
            raise LiveSessionStoreError("session reservation refused") from None
        if blocked:
            raise SessionBlockedError("session initiation conflict is durable")
        return SessionReservation(init.session_id, outer.message_id, challenge, 0)

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

    def admit_confirm(self, confirm_document: bytes) -> ConfirmAdmission:
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
                        "UPDATE sessions SET phase='CONFIRMED', revision=?, next_client_seq=2 "
                        "WHERE session_id=?",
                        (admitted_revision, outer.session_id),
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
        challenge = secrets.token_hex(32)
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
