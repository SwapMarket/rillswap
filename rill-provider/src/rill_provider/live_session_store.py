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
from collections.abc import Callable
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, Self

import pyrage  # type: ignore[import-untyped]
from pyrage import x25519
from rill_core.wire import verify_static_handshake_accept, verify_static_handshake_transcript
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.envelope_authentication import verify_static_signed_envelope
from rill_core.wire.hashes import EPOCH_SESSION_FEATURE, handshake_init_hash, unsigned_envelope_hash
from rill_core.wire.messages import (
    Envelope,
    HandshakeAccept,
    HandshakeAcceptPayload,
    HandshakeInit,
)
from rill_core.wire.quotes import TermsOfferPayload
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
SCHEMA_VERSION = 7  # v5/v6 require explicit upgrade; v1-v4 are refused unchanged.
CONTRACT_KEY_RECORD_KIND = "rillswap-provider-contract-key"
OPEN_PHASES = ("CONFIRMED", "ACCEPTED")  # sessions that may still send requests
SWAP_TRANSITIONS = frozenset(
    {
        ("FUNDING_SEEN", "PAYING"),
        ("FUNDING_SEEN", "FAILED"),
        ("PAYING", "PAID"),
        ("PAYING", "FAILED"),
        ("PAID", "CLAIMING"),
        ("CLAIMING", "CLAIMED"),
    }
)
CLIENT_REQUEST_TYPES = ("quote_request", "terms_accept", "funding_binding")
SWAP_COLUMNS = (
    "session_id, contract_hash, terms_offer, terms_accept, state, funding_binding, "
    "preimage, claim_txid"
)
FIRST_REQUEST_SEQUENCE = 2  # RS-001: first client message after the confirm
MAX_REQUESTS_PER_SESSION = 16  # further requests are refused unanswered
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
MAX_INSPECTION_PAGE = 1000
SCHEMA_V5 = (
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
        "(phase IN ('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED', 'ACCEPTED')), "
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
        "(kind IN ('init', 'confirm', 'request')), evidence_bytes BLOB NOT NULL, "
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
    (
        "CREATE TABLE contract_keys (session_id TEXT PRIMARY KEY, "
        "compressed_key TEXT NOT NULL UNIQUE, secret_age BLOB NOT NULL)"
    ),
    # Accepted contracts are never idle-expired (RS-003 acceptance).
    (
        "CREATE TABLE swaps (session_id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL UNIQUE, "
        "terms_offer BLOB NOT NULL, terms_accept BLOB NOT NULL, state TEXT NOT NULL CHECK "
        "(state IN ('ACCEPTED', 'FUNDING_SEEN', 'PAYING', 'PAID', 'FAILED', 'CLAIMING', "
        "'CLAIMED')), funding_binding BLOB, preimage TEXT, claim_txid TEXT, claim_tx BLOB, "
        "updated_at INTEGER NOT NULL)"
    ),
    # Never deleted: a payment hash is offered at most once, forever (RS-003).
    (
        "CREATE TABLE payment_hashes (payment_hash TEXT PRIMARY KEY, "
        "session_id TEXT NOT NULL, reserved_at INTEGER NOT NULL)"
    ),
)
PAYMENT_DISPATCH_SCHEMA = (
    "CREATE TABLE payment_dispatch (session_id TEXT PRIMARY KEY, "
    "payment_hash TEXT NOT NULL UNIQUE, "
    "state TEXT NOT NULL CHECK (state IN ('UNSENT', 'SUBMITTED')), request BLOB)"
)
SCHEMA_V6 = (*SCHEMA_V5, PAYMENT_DISPATCH_SCHEMA)
EPOCH_ADMISSION_SCHEMA = (
    "CREATE TABLE epoch_admissions (session_id TEXT PRIMARY KEY, epoch_key TEXT NOT NULL, "
    "retire_after INTEGER NOT NULL, expired INTEGER NOT NULL CHECK (expired IN (0, 1)))"
)
EPOCH_RETIREMENT_SCHEMA = (
    "CREATE TABLE epoch_retirement (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
    "retired_through INTEGER NOT NULL CHECK (retired_through >= 0))"
)
EPOCH_KEY_HISTORY_SCHEMA = "CREATE TABLE epoch_key_history (epoch_key TEXT PRIMARY KEY)"
SCHEMA = (
    *SCHEMA_V6,
    EPOCH_ADMISSION_SCHEMA,
    EPOCH_RETIREMENT_SCHEMA,
    EPOCH_KEY_HISTORY_SCHEMA,
)
ADMISSION_INDEXES = (
    "CREATE INDEX epoch_admissions_expiry ON epoch_admissions (expired, retire_after)",
)


@dataclass(frozen=True, slots=True)
class EpochInitiation:
    """Canonical init and authenticated recipient provenance from open_epoch_frame()."""

    document: bytes
    epoch_key: str


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
class RequestAnswer:
    """A client request admitted with its recorded, signed answer (not yet sent)."""

    session_id: str
    request_message_id: str
    response_message_id: str
    replay: bool


class EnvelopeSigner(Protocol):
    """BIP-340 signing, e.g. ``rill_crypto.Context``."""

    def schnorr_sign(self, secret_key: bytes, message: bytes, auxiliary_random: bytes) -> bytes:
        """Sign a 32-byte digest."""
        ...


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Session facts a responder may bind into its answer."""

    handshake_hash: str
    provider_contract_key: str  # compressed; fresh per session, sealed like the session key
    is_payment_hash_reserved: Callable[[str], bool]
    replied_to: Envelope | None = None  # our outbox message named by in_reply_to
    swap: SwapRecord | None = None


@dataclass(frozen=True, slots=True)
class SwapRecord:
    """Durable accepted-swap state; byte fields are exact canonical envelopes."""

    session_id: str
    contract_hash: str
    terms_offer: bytes
    terms_accept: bytes
    state: str
    funding_binding: bytes | None
    preimage: str | None
    claim_txid: str | None


@dataclass(frozen=True, slots=True)
class SettlementItem:
    """One funded swap the settlement engine still has to move forward."""

    session_id: str
    state: str
    blocked: bool
    terms_offer: bytes
    funding_binding: bytes
    invoice: str
    preimage: str | None
    claim_tx: bytes | None
    claim_txid: str | None
    payment_dispatch: str = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class SwapInspection:
    """Offline custody summary, never live chain evidence or dispatch authority."""

    session_id: str
    contract_hash: str
    state: str
    session_present: bool
    blocked: bool | None
    dispatch_state: str
    dispatch_recorded: bool
    funding_binding_recorded: bool
    preimage_recorded: bool
    claim_recorded: bool
    claim_txid: str | None


@dataclass(frozen=True, slots=True)
class SwapInspectionPage:
    """Bounded keyset page; cursor does not claim a snapshot across invocations."""

    swaps: tuple[SwapInspection, ...]
    next_after: str | None


class StaleSwapError(LiveSessionStoreError):
    """The swap is no longer in the state the caller observed."""


@dataclass(frozen=True, slots=True)
class AcceptSwap:
    """Effect: record acceptance of the replied-to terms offer."""

    contract_hash: str


@dataclass(frozen=True, slots=True)
class BindFunding:
    """Effect: record the client's funding binding for the accepted swap."""


@dataclass(frozen=True, slots=True)
class Answer:
    """A responder's answer; ``payment_hash`` is reserved forever with it."""

    message_type: str
    payload: dict[str, Any]
    payment_hash: str | None = None
    contract_hash: str | None = None  # envelope binding, e.g. for terms_offer
    effect: AcceptSwap | BindFunding | None = None


if TYPE_CHECKING:
    from collections.abc import Callable

    # Policy: (request, earlier admitted requests, session context) -> answer.
    Responder = Callable[[Envelope, tuple[Envelope, ...], RequestContext], Answer]


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
                for statement in ADMISSION_INDEXES:
                    connection.execute(statement)
                connection.execute("INSERT INTO epoch_retirement VALUES (1, 0)")
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
    def acquire(  # noqa: PLR0912, PLR0913, PLR0915 - independent custody guards explicit
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
        upgrade_from_v5: bool = False,
    ) -> Self:
        """Take lifetime exclusive ownership; refuse any unknown or copied state.

        ``max_sessions`` caps retained sessions. ``expire_idle`` reclaims
        pre-economic capacity; accepted-contract quota policy is unchanged.
        The historical ``upgrade_from_v5=True`` spelling authorizes supported
        v5/v6 schema upgrades and adding the epoch-bound admission feature.
        No old payment or handshake gains new authority from the migration.
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
            version = _check_schema(connection, allow_v5=upgrade_from_v5 is True)
            _configure(connection)
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT schema_version, network_jcs, provider_identity, policy_jcs, "
                "db_inode, lock_inode, generation, store_uuid, authority_jcs, custody_recipient "
                "FROM meta"
            ).fetchall()
            if len(row) != 1 or row[0][:3] != (version, network_jcs, identity):
                raise LiveSessionStoreError("store namespace or policy mismatch")  # noqa: TRY301
            if row[0][3] != policy_jcs and not (
                upgrade_from_v5 is True
                and EPOCH_SESSION_FEATURE in policy.features
                and row[0][3]
                == _policy_bytes(
                    replace(policy, features=policy.features - {EPOCH_SESSION_FEATURE})
                )
            ):
                raise LiveSessionStoreError("store namespace or policy mismatch")  # noqa: TRY301
            _check_provisioning(row[0][7], row[0][8])
            if row[0][9] != str(unlocking.to_public()):
                raise LiveSessionStoreError("custody identity does not match store")  # noqa: TRY301
            if row[0][4:6] != (db_inode, os.fstat(lock_fd).st_ino):
                raise LiveSessionStoreError(  # noqa: TRY301 - copied or restored file
                    "store files are not the provisioned authoritative copy"
                )
            if version == 5:  # noqa: PLR2004 - exact legacy schema
                _upgrade_v5(connection)
            if version in (5, 6):
                _upgrade_v6(connection)
            _epoch_watermark(connection)
            if connection.execute(
                "SELECT 1 FROM epochs e LEFT JOIN epoch_key_history h "
                "ON h.epoch_key=e.epoch_key WHERE h.epoch_key IS NULL LIMIT 1"
            ).fetchone():
                raise LiveSessionStoreError("epoch key history unavailable")  # noqa: TRY301
            connection.execute("UPDATE meta SET policy_jcs=?", (policy_jcs,))
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

    @property
    def requires_epoch_bound_sessions(self) -> bool:
        """Whether all new sessions require epoch binding (legacy replays remain valid)."""
        return EPOCH_SESSION_FEATURE in self._policy.features

    def reserve(  # noqa: PLR0912, PLR0915 - replay, provenance, and capacity share one transaction
        self, initiation: bytes | EpochInitiation, *, now: int | None = None
    ) -> SessionReservation:
        """Reserve one fresh provider challenge per session; replay is stable.

        The init is unsigned, so different bytes for a known session may come
        from a stranger. They are kept as bounded conflict evidence and block
        new risk for that session (an availability cost, never exposure).
        Legacy expired IDs remain tombstoned forever. Epoch-bound idle sessions
        keep a temporary tombstone until their epoch has durably retired. That
        mode rejects every new unbound initiation, so legacy input cannot reuse
        a retired epoch-bound ID. Existing legacy records still replay exactly.
        """
        now = int(time.time()) if now is None else now
        ingress = initiation if isinstance(initiation, EpochInitiation) else None
        init_document = (
            initiation.document if isinstance(initiation, EpochInitiation) else initiation
        )
        try:
            outer, init = self._init(init_document)
            with self._write() as connection:
                if _session_expired(connection, init.session_id):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                epoch = init.epoch_inbox_xonly_key
                retire_after = None
                if epoch is not None:
                    if ingress is None or ingress.epoch_key != epoch:
                        raise LiveSessionStoreError("epoch admission provenance unavailable")  # noqa: TRY301
                    epoch_row = connection.execute(
                        "SELECT retire_after FROM epochs WHERE epoch_key=? AND retire_after > ?",
                        (epoch, max(now, _epoch_watermark(connection))),
                    ).fetchone()
                    if epoch_row is None:
                        raise SessionExpiredError("admission epoch retired")  # noqa: TRY301
                    retire_after = epoch_row[0]
                admission = connection.execute(
                    "SELECT epoch_key, retire_after FROM epoch_admissions WHERE session_id=?",
                    (init.session_id,),
                ).fetchone()
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, blocked, revision FROM sessions "
                    "WHERE session_id=?",
                    (init.session_id,),
                ).fetchone()
                if admission is not None and (row is None or admission != (epoch, retire_after)):
                    # An unbound or differently bound init must not poison a
                    # known epoch session through the legacy conflict path.
                    raise LiveSessionStoreError("epoch admission custody unavailable")  # noqa: TRY301
                if row is not None and epoch is not None and admission is None:
                    raise LiveSessionStoreError("epoch admission custody unavailable")  # noqa: TRY301
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
                    if self.requires_epoch_bound_sessions and epoch is None:
                        raise LiveSessionStoreError("new session requires epoch-bound admission")  # noqa: TRY301
                    (live,) = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()
                    if epoch is None:
                        (dead,) = connection.execute("SELECT COUNT(*) FROM expired").fetchone()
                    else:
                        (dead,) = connection.execute(
                            "SELECT COUNT(*) FROM epoch_admissions WHERE expired=1"
                        ).fetchone()
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
                    if epoch is not None:
                        connection.execute(
                            "INSERT INTO epoch_admissions VALUES (?, ?, ?, 0)",
                            (init.session_id, epoch, retire_after),
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
                required_features=(EPOCH_SESSION_FEATURE,) if init.epoch_inbox_xonly_key else (),
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
                if row is None and _session_expired(connection, outer.session_id):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                if row is None or row[5] == "RESERVED":
                    raise LiveSessionStoreError("no committed accept for session")  # noqa: TRY301
                init_bytes, accept_bytes, accept_id, digest, client, phase, blocked, revision = row
                admitted = None
                if phase in OPEN_PHASES:
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
                equivocation = phase in OPEN_PHASES
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
                if now < _epoch_watermark(connection) or (newest is not None and now < newest):
                    raise LiveSessionStoreError("clock is behind the newest epoch")  # noqa: TRY301
                _retire_epochs(connection, now)
                if newest is None or now >= newest + period:
                    xonly, sealed = self._new_epoch_key(now)
                    connection.execute("INSERT INTO epoch_key_history VALUES (?)", (xonly,))
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

    def open_epoch_frame(
        self, outer_event: bytes, *, now: int, transport: Context
    ) -> EpochInitiation:
        """Decode a gift-wrapped handshake_init sent to an unretired epoch inbox.

        Returns exact canonical init bytes whose envelope sender is the seal
        author, plus its recipient epoch. Pass this result to ``reserve``,
        which applies every init rule. Refusals are uniform and redacted.
        """
        try:
            recipient = _routing_recipient(outer_event)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT secret_age, created_at FROM epochs "
                    "WHERE epoch_key=? AND retire_after > ?",
                    (recipient, max(now, _epoch_watermark(connection))),
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
        return EpochInitiation(candidate.envelope_bytes, recipient)

    def expire_idle(self, *, now: int, idle_timeout: int) -> int:
        """Expire idle pre-economic sessions without discarding replay protection.

        A session idle for ``idle_timeout`` (reserved, accepted, or confirmed
        with nothing after the confirm) loses its key, messages, and conflict
        evidence (SQLite ``secure_delete``). Legacy IDs stay in ``expired``
        forever. Epoch-bound IDs stay in ``epoch_admissions`` until their
        recipient epoch has durably retired. Accepted contracts never enter
        this deletion path. Returns how many sessions expired.
        """
        if not (type(now) is int and type(idle_timeout) is int and idle_timeout > 0):
            raise LiveSessionStoreError("expiry schedule unsupported")
        try:
            with self._write() as connection:
                _retire_epochs(connection, now)
                idle = [
                    (row[0],)
                    for row in connection.execute(
                        "SELECT session_id FROM sessions WHERE phase IN "
                        "('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED') AND active_at <= ?",
                        (now - idle_timeout,),
                    )
                ]
                for (sid,) in idle:
                    marked = connection.execute(
                        "UPDATE epoch_admissions SET expired=1 WHERE session_id=?", (sid,)
                    ).rowcount
                    if not marked:
                        connection.execute("INSERT INTO expired VALUES (?, ?)", (sid, now))
                for table in ("inbox", "outbox", "conflicts", "contract_keys", "sessions"):
                    connection.executemany(
                        f"DELETE FROM {table} WHERE session_id=?",  # noqa: S608 - fixed names
                        idle,
                    )
                connection.execute(
                    "DELETE FROM epoch_admissions WHERE expired=1 AND retire_after <= ?",
                    (_epoch_watermark(connection),),
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
                    (max(now, _epoch_watermark(connection)),),
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

    def answer_request(  # noqa: PLR0912, PLR0915 - one admission transaction
        self,
        request_document: bytes,
        *,
        responder: Responder,
        signer: EnvelopeSigner,
        now: int | None = None,
    ) -> RequestAnswer:
        """Admit one signed client request and durably record its signed answer.

        One transaction checks the client session-key signature and the
        contiguous sequence, calls the pure ``responder`` for the answer
        payload, signs it with the session key, and records both. Only then may
        the answer be published (via ``pending_outbox``). An exact replay,
        even with a fresh signature, returns the recorded answer. A different
        validly signed message reusing a message ID or sequence is kept as
        evidence and blocks the session. Anything unverifiable, out of order,
        or over budget is refused with no record and no reply.
        """
        now = int(time.time()) if now is None else now
        conflict = False
        try:
            outer = _canonical_envelope(request_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT client_key, provider_session_key, phase, blocked, revision, "
                    "next_client_seq, next_provider_seq, transcript_digest "
                    "FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None and _session_expired(connection, outer.session_id):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                if row is None or row[2] not in OPEN_PHASES:
                    raise LiveSessionStoreError("no confirmed session")  # noqa: TRY301
                client, key, _, blocked, revision, client_seq, provider_seq, transcript = row
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                digest = verify_static_signed_envelope(
                    request_document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                seen = connection.execute(
                    "SELECT message_id, seq, unsigned_digest FROM inbox "
                    "WHERE session_id=? AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
                if seen:
                    if seen == [(outer.message_id, outer.sequence, digest)]:
                        answer = connection.execute(
                            "SELECT message_id FROM outbox WHERE session_id=? AND in_reply_to=?",
                            (outer.session_id, outer.message_id),
                        ).fetchone()
                        return RequestAnswer(
                            outer.session_id, outer.message_id, answer[0], replay=True
                        )
                    _record_conflict(connection, outer.session_id, "request", request_document)
                    connection.execute(
                        "UPDATE sessions SET blocked=1, revision=revision + 1 WHERE session_id=?",
                        (outer.session_id,),
                    )
                    conflict = True
                else:
                    replied = None
                    if outer.in_reply_to is not None:
                        replied = connection.execute(
                            "SELECT canonical_bytes FROM outbox "
                            "WHERE session_id=? AND message_id=?",
                            (outer.session_id, outer.in_reply_to),
                        ).fetchone()
                    if not (
                        outer.sequence == client_seq
                        and outer.message_type in CLIENT_REQUEST_TYPES
                        and (outer.in_reply_to is None or replied is not None)
                        and client_seq - FIRST_REQUEST_SEQUENCE < MAX_REQUESTS_PER_SESSION
                    ):
                        raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
                    prior = tuple(
                        _canonical_envelope(document)
                        for (document,) in connection.execute(
                            "SELECT canonical_bytes FROM inbox WHERE session_id=? "
                            "AND sender_key=? AND seq>=? ORDER BY seq",
                            (outer.session_id, client, FIRST_REQUEST_SEQUENCE),
                        )
                    )
                    context = RequestContext(
                        handshake_hash=transcript,
                        provider_contract_key=self._contract_key(connection, outer.session_id),
                        replied_to=None if replied is None else _canonical_envelope(replied[0]),
                        swap=_swap(connection, outer.session_id),
                        is_payment_hash_reserved=lambda digest: (
                            connection.execute(
                                "SELECT 1 FROM payment_hashes WHERE payment_hash=?", (digest,)
                            ).fetchone()
                            is not None
                        ),
                    )
                    reply = responder(outer, prior, context)
                    if reply.effect is not None:
                        _apply_effect(connection, outer, reply.effect, replied, now)
                    if reply.payment_hash is not None:
                        connection.execute(
                            "INSERT INTO payment_hashes VALUES (?, ?, ?)",
                            (reply.payment_hash, outer.session_id, now),
                        )
                    scalar, _ = self._unseal(connection, outer.session_id)
                    try:
                        response = self._signed_envelope(
                            outer, key, provider_seq, reply, scalar, signer, outer.message_id
                        )
                    finally:
                        del scalar
                    admitted = revision + 1
                    connection.execute(
                        "INSERT INTO inbox VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            outer.sequence,
                            digest,
                            request_document,
                            admitted,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO outbox VALUES (?, ?, ?, ?, ?, ?, 'PENDING')",
                        (
                            response.message_id,
                            outer.session_id,
                            provider_seq,
                            outer.message_id,
                            canonicalize(response.model_dump(mode="json")),
                            admitted,
                        ),
                    )
                    connection.execute(
                        "UPDATE sessions SET revision=?, next_client_seq=?, "
                        "next_provider_seq=?, active_at=? WHERE session_id=?",
                        (admitted, client_seq + 1, provider_seq + 1, now, outer.session_id),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("request refused") from None
        if conflict:
            raise SessionBlockedError("conflicting signed request is durable")
        return RequestAnswer(outer.session_id, outer.message_id, response.message_id, replay=False)

    def _signed_envelope(  # noqa: PLR0913, PLR0917 - one envelope's explicit parts
        self,
        request: Envelope,
        key: str,
        sequence: int,
        reply: Answer,
        scalar: bytes,
        signer: EnvelopeSigner,
        in_reply_to: str | None,
    ) -> Envelope:
        unsigned = Envelope.model_validate_json(
            canonicalize(
                {
                    "protocol": "rillswap",
                    "wire_version": "1",
                    "profile_id": request.profile_id,
                    "network_identity": request.network_identity.model_dump(mode="json"),
                    "session_id": request.session_id,
                    "message_id": _new_message_id(),
                    "sender_session_key": key,
                    "sequence": sequence,
                    "in_reply_to": in_reply_to,
                    "contract_hash": reply.contract_hash,
                    "message_type": reply.message_type,
                    "payload": reply.payload,
                    "required_features": [],
                    "extensions": {},
                    "signature": None,
                }
            ),
            strict=True,
        )
        digest = unsigned_envelope_hash(unsigned)
        signature = signer.schnorr_sign(scalar, digest, secrets.token_bytes(32))
        self._crypto.schnorr_verify(bytes.fromhex(key), digest, signature)
        return unsigned.model_copy(update={"signature": signature.hex()})

    def _contract_key(self, connection: sqlite3.Connection, session_id: str) -> str:
        """Return this session's provider contract key, creating it once."""
        row = connection.execute(
            "SELECT compressed_key FROM contract_keys WHERE session_id=?", (session_id,)
        ).fetchone()
        if row is not None:
            return str(row[0])
        scalar = _new_session_scalar()
        compressed = bytes(self._public_keys.public_key(scalar)).hex()
        record = canonicalize(
            {
                "kind": CONTRACT_KEY_RECORD_KIND,
                "secret_scalar": scalar.hex(),
                "compressed_public_key": compressed,
                "session_id": session_id,
                "store_uuid": self._store_uuid,
            }
        )
        del scalar
        sealed = pyrage.encrypt(record, [self._custody_identity.to_public()])
        if type(sealed) is not bytes or pyrage.decrypt(sealed, [self._custody_identity]) != record:
            raise LiveSessionStoreError("contract key custody not verifiable")
        connection.execute(
            "INSERT INTO contract_keys VALUES (?, ?, ?)", (session_id, compressed, sealed)
        )
        return compressed

    def classify_request(self, request_document: bytes) -> str:
        """Read-only preflight: ``"new"``, ``"replay"``, or ``"conflict"``.

        Lets the caller skip expensive work (e.g. invoice decoding) for
        replays and unadmissible messages. ``answer_request`` rechecks
        everything; this grants nothing and records nothing.
        """
        try:
            outer = _canonical_envelope(request_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT client_key, phase, blocked, next_client_seq FROM sessions "
                    "WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None or row[1] not in OPEN_PHASES or row[2]:
                    raise LiveSessionStoreError("no open confirmed session")  # noqa: TRY301
                client, _, _, client_seq = row
                digest = verify_static_signed_envelope(
                    request_document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                seen = connection.execute(
                    "SELECT message_id, seq, unsigned_digest FROM inbox "
                    "WHERE session_id=? AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("request refused") from None
        if seen:
            return "replay" if seen == [(outer.message_id, outer.sequence, digest)] else "conflict"
        if outer.sequence != client_seq:
            raise LiveSessionStoreError("request not admissible")
        return "new"

    def settlement_work(self, *, session_id: str | None = None) -> tuple[SettlementItem, ...]:
        """Return funded work, optionally restricted to one exact retained session."""
        if session_id is not None and (
            type(session_id) is not str or HEX32.fullmatch(session_id) is None
        ):
            raise LiveSessionStoreError("settlement session ID unsupported")
        selected = "AND w.session_id=? " if session_id is not None else ""
        parameters = (
            (FIRST_REQUEST_SEQUENCE, session_id)
            if session_id is not None
            else (FIRST_REQUEST_SEQUENCE,)
        )
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT w.session_id, w.state, s.blocked, w.terms_offer, w.funding_binding, "  # noqa: S608 - only static SQL fragments; bound session ID
                    "i.canonical_bytes, w.preimage, w.claim_tx, w.claim_txid, "
                    "COALESCE(p.state, 'UNKNOWN') FROM swaps w "
                    "JOIN sessions s ON s.session_id = w.session_id "
                    "LEFT JOIN payment_dispatch p ON p.session_id = w.session_id "
                    "JOIN inbox i ON i.session_id = w.session_id AND i.sender_key = s.client_key "
                    "AND i.seq = ? WHERE w.state IN ('FUNDING_SEEN', 'PAYING', 'PAID', 'CLAIMING') "
                    + selected
                    + "ORDER BY w.updated_at, w.session_id",
                    parameters,
                ).fetchall()
                items = tuple(
                    SettlementItem(
                        session_id,
                        state,
                        bool(blocked),
                        offer,
                        binding,
                        str(_canonical_envelope(request).payload["invoice"]),
                        preimage,
                        claim_tx,
                        claim_txid,
                        payment_dispatch,
                    )
                    for (
                        session_id,
                        state,
                        blocked,
                        offer,
                        binding,
                        request,
                        preimage,
                        claim_tx,
                        claim_txid,
                        payment_dispatch,
                    ) in rows
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("settlement work unavailable") from None
        return items

    def advance_swap(  # noqa: PLR0913 - one atomic transition's explicit parts
        self,
        session_id: str,
        *,
        from_state: str,
        to_state: str,
        signer: EnvelopeSigner,
        now: int,
        preimage: str | None = None,
        claim_tx: bytes | None = None,
        claim_txid: str | None = None,
        observation: dict[str, Any] | None = None,
    ) -> None:
        """Move one swap forward and record its observation in one transaction.

        Raises ``StaleSwapError`` unless the swap is still in ``from_state``,
        so a crash or a concurrent tick can never apply a transition twice.
        The observation is committed to the outbox before anything sends it.
        """
        if (from_state, to_state) not in SWAP_TRANSITIONS:
            raise LiveSessionStoreError("swap transition unsupported")
        try:
            with self._write() as connection:
                updated = connection.execute(
                    "UPDATE swaps SET state=?, preimage=COALESCE(?, preimage), "
                    "claim_tx=COALESCE(?, claim_tx), claim_txid=COALESCE(?, claim_txid), "
                    "updated_at=? WHERE session_id=? AND state=?",
                    (to_state, preimage, claim_tx, claim_txid, now, session_id, from_state),
                ).rowcount
                if updated != 1:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                if (from_state, to_state) == ("FUNDING_SEEN", "PAYING"):
                    (offer_bytes,) = connection.execute(
                        "SELECT terms_offer FROM swaps WHERE session_id=?", (session_id,)
                    ).fetchone()
                    offer = parse_model_json(
                        TermsOfferPayload, canonicalize(_canonical_envelope(offer_bytes).payload)
                    )
                    connection.execute(
                        "INSERT INTO payment_dispatch VALUES (?, ?, 'UNSENT', NULL)",
                        (session_id, offer.terms.contract_terms.invoice_binding.payment_hash),
                    )
                if observation is not None:
                    self._record_observation(connection, session_id, observation, signer, now)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage or crypto details
            raise LiveSessionStoreError("swap transition refused") from None

    def commit_payment_dispatch(self, session_id: str, payment_hash: str, request: bytes) -> bool:
        """Durably consume one explicit UNSENT grant before its external effect.

        Missing state is never permission to send. This transaction also orders
        authorization against conflict blocking: a blocked session cannot gain
        a new grant. A later conflict cannot undo an already committed dispatch.
        Lost responses and interrupted callers must reconcile, never recreate
        the grant or resubmit the saved request automatically.
        """
        if type(request) is not bytes or not 0 < len(request) <= MAX_DOCUMENT_BYTES:
            raise LiveSessionStoreError("payment request size unsupported")
        try:
            with self._write() as connection:
                return (
                    connection.execute(
                        "UPDATE payment_dispatch SET state='SUBMITTED', request=? "
                        "WHERE session_id=? AND payment_hash=? AND state='UNSENT' "
                        "AND EXISTS (SELECT 1 FROM swaps w JOIN sessions s "
                        "ON s.session_id=w.session_id "
                        "WHERE w.session_id=payment_dispatch.session_id "
                        "AND w.state='PAYING' AND s.blocked=0)",
                        (request, session_id, payment_hash),
                    ).rowcount
                    == 1
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo routing or payment details
            raise LiveSessionStoreError("payment dispatch refused") from None

    def _record_observation(
        self,
        connection: sqlite3.Connection,
        session_id: str,
        payload: dict[str, Any],
        signer: EnvelopeSigner,
        now: int,
    ) -> None:
        offer_bytes, contract, key, revision, provider_seq = connection.execute(
            "SELECT w.terms_offer, w.contract_hash, s.provider_session_key, s.revision, "
            "s.next_provider_seq FROM swaps w JOIN sessions s ON s.session_id = w.session_id "
            "WHERE w.session_id=?",
            (session_id,),
        ).fetchone()
        reply = Answer("observation", payload, contract_hash=contract)
        scalar, _ = self._unseal(connection, session_id)
        try:
            envelope = self._signed_envelope(
                _canonical_envelope(offer_bytes), key, provider_seq, reply, scalar, signer, None
            )
        finally:
            del scalar
        connection.execute(
            "INSERT INTO outbox VALUES (?, ?, ?, NULL, ?, ?, 'PENDING')",
            (
                envelope.message_id,
                session_id,
                provider_seq,
                canonicalize(envelope.model_dump(mode="json")),
                revision + 1,
            ),
        )
        connection.execute(
            "UPDATE sessions SET revision=?, next_provider_seq=?, active_at=? WHERE session_id=?",
            (revision + 1, provider_seq + 1, now, session_id),
        )

    def sign_with_contract_key(
        self, session_id: str, digest: bytes, signer: EnvelopeSigner
    ) -> bytes:
        """BIP340-sign one digest with this swap's sealed provider contract key.

        Only for a swap that reached ``PAID`` or ``CLAIMING`` (the claim leaf);
        the scalar never leaves the store.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT k.compressed_key, k.secret_age FROM contract_keys k "
                    "JOIN swaps w ON w.session_id = k.session_id "
                    "WHERE k.session_id=? AND w.state IN ('PAID', 'CLAIMING')",
                    (session_id,),
                ).fetchone()
                if row is None or type(digest) is not bytes or len(digest) != 32:  # noqa: PLR2004
                    raise LiveSessionStoreError("no claimable swap")  # noqa: TRY301
                compressed, sealed = row
                plaintext = pyrage.decrypt(sealed, [self._custody_identity])
                record = json.loads(plaintext)
                scalar = bytes.fromhex(record["secret_scalar"])
                try:
                    if (
                        record["session_id"] != session_id
                        or record["store_uuid"] != self._store_uuid
                        or bytes(self._public_keys.public_key(scalar)).hex() != compressed
                    ):
                        raise LiveSessionStoreError("contract key custody differs")
                    signature = signer.schnorr_sign(scalar, digest, secrets.token_bytes(32))
                finally:
                    del scalar
                self._crypto.schnorr_verify(bytes.fromhex(compressed)[1:], digest, signature)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material
            raise LiveSessionStoreError("contract key signing refused") from None
        return bytes(signature)

    def session_mailboxes(self) -> tuple[str, ...]:
        """Return our mailbox keys for sessions that may still send to us."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT provider_session_key FROM sessions WHERE blocked=0 "
                    "AND phase IN ('ACCEPT_COMMITTED', 'CONFIRMED', 'ACCEPTED') ORDER BY revision"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session mailboxes unavailable") from None
        return tuple(row[0] for row in rows)

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

    def inspect_swaps(
        self, *, session_id: str | None = None, after: str | None = None, limit: int = 100
    ) -> SwapInspectionPage:
        """Return bounded, secret-free retained state under the exclusive owner.

        This neither runs settlement nor interprets absent payment records as
        authority. Index-ordered pagination avoids rescanning past pages. No
        invoice, preimage, key, route, or exact dispatch request is returned.
        """
        if (
            type(limit) is not int
            or not 1 <= limit <= MAX_INSPECTION_PAGE
            or (session_id is not None and after is not None)
            or any(
                value is not None and (type(value) is not str or HEX32.fullmatch(value) is None)
                for value in (session_id, after)
            )
        ):
            raise LiveSessionStoreError("swap inspection bounds unsupported")
        predicate = "w.session_id = ?" if session_id is not None else "w.session_id > ?"
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT w.session_id, w.contract_hash, w.state, s.session_id IS NOT NULL, "
                    "s.blocked, COALESCE(p.state, 'UNKNOWN'), p.request IS NOT NULL, "
                    "w.funding_binding IS NOT NULL, w.preimage IS NOT NULL, "
                    "w.claim_tx IS NOT NULL, w.claim_txid "
                    "FROM swaps w LEFT JOIN sessions s ON s.session_id=w.session_id "
                    "LEFT JOIN payment_dispatch p ON p.session_id=w.session_id WHERE "
                    + predicate
                    + " ORDER BY w.session_id LIMIT ?",
                    (session_id if session_id is not None else after or "", limit + 1),
                ).fetchall()
            result = []
            for row in rows[:limit]:
                (
                    sid,
                    contract,
                    state,
                    present,
                    blocked,
                    dispatch,
                    request,
                    funding,
                    preimage,
                    claim,
                    txid,
                ) = row
                if not (
                    type(sid) is str
                    and HEX32.fullmatch(sid)
                    and type(contract) is str
                    and HEX32.fullmatch(contract)
                    and (txid is None or (type(txid) is str and HEX32.fullmatch(txid)))
                    and state
                    in {
                        "ACCEPTED",
                        "FUNDING_SEEN",
                        "PAYING",
                        "PAID",
                        "FAILED",
                        "CLAIMING",
                        "CLAIMED",
                    }
                    and dispatch in {"UNKNOWN", "UNSENT", "SUBMITTED"}
                    and blocked in (None, 0, 1)
                ):
                    raise LiveSessionStoreError("swap inspection state unsupported")  # noqa: TRY301
                result.append(
                    SwapInspection(
                        sid,
                        contract,
                        state,
                        bool(present),
                        None if blocked is None else bool(blocked),
                        dispatch,
                        bool(request),
                        bool(funding),
                        bool(preimage),
                        bool(claim),
                        txid,
                    )
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo retained financial or custody material
            raise LiveSessionStoreError("swap inspection unavailable") from None
        return SwapInspectionPage(
            tuple(result), result[-1].session_id if len(rows) > limit else None
        )


def _configure(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA busy_timeout=5000")
    if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
        raise LiveSessionStoreError("WAL unavailable")
    connection.execute("PRAGMA synchronous=FULL")
    if connection.execute("PRAGMA synchronous").fetchone() != (2,):
        raise LiveSessionStoreError("FULL sync unavailable")
    connection.execute("PRAGMA secure_delete=ON")  # expired sealed keys leave no old pages


def _check_schema(connection: sqlite3.Connection, *, allow_v5: bool = False) -> int:
    (version,) = connection.execute("PRAGMA user_version").fetchone()
    if connection.execute("PRAGMA application_id").fetchone() != (
        APPLICATION_ID,
    ) or version not in ((5, 6, SCHEMA_VERSION) if allow_v5 else (SCHEMA_VERSION,)):
        raise LiveSessionStoreError("live session store version unsupported")
    objects = {
        (kind, name): definition
        for kind, name, definition in connection.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
        )
    }
    schema = {5: SCHEMA_V5, 6: SCHEMA_V6, SCHEMA_VERSION: SCHEMA}[version]
    expected = {("table", statement.split()[2]): statement for statement in schema}
    if version == SCHEMA_VERSION:
        expected.update({("index", sql.split()[2]): sql for sql in ADMISSION_INDEXES})
    if objects != expected:
        raise LiveSessionStoreError("live session store schema incompatible")
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise LiveSessionStoreError("live session store integrity unavailable")
    return int(version)


def _upgrade_v5(connection: sqlite3.Connection) -> None:
    """Add dispatch custody inside the verified owner's existing transaction.

    No old swap is labeled UNSENT. Only a future FUNDING_SEEN to PAYING
    transition can create that affirmative marker, before any send occurs.
    """
    connection.execute(PAYMENT_DISPATCH_SCHEMA)


def _upgrade_v6(connection: sqlite3.Connection) -> None:
    """Add empty epoch custody explicitly, without reclassifying any old session."""
    connection.execute(EPOCH_ADMISSION_SCHEMA)
    connection.execute(EPOCH_RETIREMENT_SCHEMA)
    connection.execute(EPOCH_KEY_HISTORY_SCHEMA)
    # v5/v6 kept every epoch row, including retired ones. Preserve that complete
    # public-key history before any v7 secret retirement becomes possible.
    connection.execute("INSERT INTO epoch_key_history SELECT epoch_key FROM epochs")
    for statement in ADMISSION_INDEXES:
        connection.execute(statement)
    # Explicit migration proves only that no epoch retirement has been recorded
    # under this format. It never converts old sessions to the new admission lane.
    connection.execute("INSERT INTO epoch_retirement VALUES (1, 0)")
    connection.execute("UPDATE meta SET schema_version=?", (SCHEMA_VERSION,))
    connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


def _epoch_watermark(connection: sqlite3.Connection) -> int:
    rows = connection.execute("SELECT retired_through FROM epoch_retirement").fetchall()
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 0:
        raise LiveSessionStoreError("epoch retirement custody unavailable")
    return int(rows[0][0])


def _retire_epochs(connection: sqlite3.Connection, now: int) -> None:
    """Retire affirmative expired epochs and persist the barrier before pruning.

    Caller owns the transaction. Neither an absent row nor the watermark alone
    permits deleting session history. Session deletion still requires idle,
    pre-economic state; only its epoch-tagged tombstone can later be pruned.
    """
    watermark = _epoch_watermark(connection)
    if type(now) is not int or now < watermark:
        raise LiveSessionStoreError("clock is behind retired epochs")
    (expired_through,) = connection.execute(
        "SELECT MAX(retire_after) FROM epochs WHERE retire_after <= ?", (now,)
    ).fetchone()
    if expired_through is not None and expired_through > watermark:
        watermark = expired_through
        connection.execute("UPDATE epoch_retirement SET retired_through=?", (watermark,))
    connection.execute("DELETE FROM epochs WHERE retire_after <= ?", (watermark,))


def _session_expired(connection: sqlite3.Connection, session_id: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM expired WHERE session_id=? UNION ALL "
            "SELECT 1 FROM epoch_admissions WHERE session_id=? AND expired=1 LIMIT 1",
            (session_id, session_id),
        ).fetchone()
        is not None
    )


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


def _swap(connection: sqlite3.Connection, session_id: str) -> SwapRecord | None:
    row = connection.execute(
        f"SELECT {SWAP_COLUMNS} FROM swaps WHERE session_id=?",  # noqa: S608 - fixed columns
        (session_id,),
    ).fetchone()
    return None if row is None else SwapRecord(*row)


def _apply_effect(
    connection: sqlite3.Connection,
    request: Envelope,
    effect: AcceptSwap | BindFunding,
    replied: tuple[bytes] | None,
    now: int,
) -> None:
    """Apply one responder effect inside the admitting transaction."""
    document = canonicalize(request.model_dump(mode="json"))
    if isinstance(effect, AcceptSwap):
        if replied is None or request.contract_hash != effect.contract_hash:
            raise LiveSessionStoreError("acceptance not bound to an offer")
        connection.execute(
            "INSERT INTO swaps VALUES (?, ?, ?, ?, 'ACCEPTED', NULL, NULL, NULL, NULL, ?)",
            (request.session_id, effect.contract_hash, replied[0], document, now),
        )
        connection.execute(
            "UPDATE sessions SET phase='ACCEPTED' WHERE session_id=?", (request.session_id,)
        )
        return
    updated = connection.execute(
        "UPDATE swaps SET funding_binding=?, state='FUNDING_SEEN', updated_at=? "
        "WHERE session_id=? AND contract_hash=? AND state='ACCEPTED'",
        (document, now, request.session_id, request.contract_hash),
    ).rowcount
    if updated != 1:
        raise LiveSessionStoreError("funding binding not bound to an accepted swap")
