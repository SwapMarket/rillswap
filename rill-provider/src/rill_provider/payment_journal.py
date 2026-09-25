"""Durable BTC-to-LN outgoing-payment intent and observation bookkeeping.

No method submits, retries, cancels, reconciles, or authorizes a payment.
Absence of records (including from restored snapshots) proves nothing about
backend actions. Inconclusive and contradictory observations stay inspectable.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from rill_core.domain.amounts import MAX_MILLISATS
from rill_core.wire.types import NetworkIdentity

if TYPE_CHECKING:
    from collections.abc import Iterator

SCHEMA_VERSION = 1
APPLICATION_ID = 0x52494C50  # 'RILP'
SQLITE_SYNCHRONOUS_FULL = 2
MAX_ROUTE_BYTES = 16 * 1024
MAX_HEIGHT = 499_999_999
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}\Z")
SCHEMA_SQL = {
    "metadata": "CREATE TABLE metadata (version INTEGER PRIMARY KEY, "
    "network_identity TEXT NOT NULL, backend_identity TEXT NOT NULL)",
    "intents": (
        "CREATE TABLE intents ("
        "idempotency_key TEXT PRIMARY KEY, swap_id TEXT NOT NULL UNIQUE, "
        "attempt_id TEXT NOT NULL UNIQUE, terms_digest TEXT NOT NULL, "
        "payment_hash TEXT NOT NULL UNIQUE, destination_amount_msat INTEGER NOT NULL, "
        "fee_cap_msat INTEGER NOT NULL, absolute_cltv_height INTEGER NOT NULL, "
        "max_absolute_cltv_height INTEGER NOT NULL, route_format TEXT NOT NULL, "
        "route BLOB NOT NULL)"
    ),
    "observations": (
        "CREATE TABLE observations ("
        "observation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL "
        "REFERENCES intents(idempotency_key), backend_identity TEXT NOT NULL, "
        "backend_attempt_id TEXT, reported_status TEXT NOT NULL, "
        "evidence_sha256 TEXT NOT NULL)"
    ),
}


class PaymentJournalError(ValueError):
    """A journal file or supplied payment bookkeeping fact cannot be accepted."""


class PaymentJournalConflictError(PaymentJournalError):
    """An intent or observation identity already represents different content."""


def _hash(value: str, field: str) -> None:
    if not isinstance(value, str) or HEX32.fullmatch(value) is None:
        raise PaymentJournalError(f"{field} must be lowercase 32-byte hex")


def _identifier(value: str, field: str) -> None:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise PaymentJournalError(f"{field} must be a bounded identifier")


def _msat(value: int, field: str, *, positive: bool = False) -> None:
    if type(value) is not int or not (0 if not positive else 1) <= value <= MAX_MILLISATS:
        raise PaymentJournalError(f"{field} is outside the millisatoshi range")


@dataclass(frozen=True, slots=True)
class OutgoingPaymentIntent:
    """Exact declared payment request, route bytes and absolute exposure."""

    idempotency_key: str
    swap_id: str
    attempt_id: str
    terms_digest: str
    payment_hash: str
    destination_amount_msat: int
    fee_cap_msat: int
    absolute_cltv_height: int
    max_absolute_cltv_height: int
    route_format: str
    route: bytes

    def __post_init__(self) -> None:
        for field in ("idempotency_key", "swap_id", "attempt_id", "terms_digest", "payment_hash"):
            _hash(getattr(self, field), field)
        _msat(self.destination_amount_msat, "destination amount", positive=True)
        _msat(self.fee_cap_msat, "fee cap")
        if self.destination_amount_msat + self.fee_cap_msat > MAX_MILLISATS:
            raise PaymentJournalError("total maximum payment exposure exceeds millisatoshi range")
        if (
            type(self.absolute_cltv_height) is not int
            or type(self.max_absolute_cltv_height) is not int
            or not 0 < self.absolute_cltv_height <= self.max_absolute_cltv_height <= MAX_HEIGHT
        ):
            raise PaymentJournalError("outgoing absolute CLTV exceeds the declared height cap")
        _identifier(self.route_format, "route_format")
        if not isinstance(self.route, bytes) or not 0 < len(self.route) <= MAX_ROUTE_BYTES:
            raise PaymentJournalError("route must be bounded nonempty serialized bytes")


type ReportedPaymentStatus = Literal["IN_FLIGHT", "SUCCEEDED", "FAILED", "UNKNOWN"]


@dataclass(frozen=True, slots=True)
class PaymentObservation:
    """One backend-reported fact, not independently reconciled payment truth."""

    observation_id: str
    idempotency_key: str
    backend_identity: str
    backend_attempt_id: str | None
    reported_status: ReportedPaymentStatus
    evidence_sha256: str

    def __post_init__(self) -> None:
        _hash(self.observation_id, "observation_id")
        _hash(self.idempotency_key, "idempotency_key")
        _identifier(self.backend_identity, "backend_identity")
        if self.backend_attempt_id is not None:
            _identifier(self.backend_attempt_id, "backend_attempt_id")
        if self.reported_status not in ("IN_FLIGHT", "SUCCEEDED", "FAILED", "UNKNOWN"):
            raise PaymentJournalError("unsupported backend-reported status")
        _hash(self.evidence_sha256, "evidence_sha256")


def _network(network: NetworkIdentity) -> str:
    if not isinstance(network, NetworkIdentity):
        raise PaymentJournalError("complete validated network identity is required")
    return json.dumps(network.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


class OutgoingPaymentJournal:
    """Separate network- and backend-bound SQLite bookkeeping store."""

    def __init__(self, path: Path, network: str, backend_identity: str) -> None:
        """Bind this handle to an existing exact database identity."""
        self.path = path
        self._network = network
        self._backend_identity = backend_identity

    @classmethod
    def create(
        cls, path: str | os.PathLike[str], network: NetworkIdentity, backend_identity: str
    ) -> OutgoingPaymentJournal:
        """Explicitly initialize a new file; absence never initiates work."""
        serialized = _network(network)
        _identifier(backend_identity, "backend_identity")
        destination = Path(path).absolute()
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
        journal = cls(destination, serialized, backend_identity)
        # A failed create leaves its partial file for diagnosis, never reset.
        with journal._connection(check_schema=False) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                for statement in SCHEMA_SQL.values():
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO metadata(version, network_identity, backend_identity) "
                    "VALUES (?, ?, ?)",
                    (SCHEMA_VERSION, serialized, backend_identity),
                )
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        journal._check_existing()
        return journal

    @classmethod
    def open_existing(
        cls, path: str | os.PathLike[str], network: NetworkIdentity, backend_identity: str
    ) -> OutgoingPaymentJournal:
        """Refuse absent, partial, older, newer, foreign, or mismatched files."""
        _identifier(backend_identity, "backend_identity")
        journal = cls(Path(path).absolute(), _network(network), backend_identity)
        journal._check_existing()
        return journal

    @contextmanager
    def _connection(self, *, check_schema: bool = True) -> Iterator[sqlite3.Connection]:
        """Open a separately configured connection without silently creating files."""
        if not self.path.is_file() or self.path.is_symlink():
            raise PaymentJournalError("payment journal must be an existing regular file")
        try:
            connection = sqlite3.connect(
                self.path.as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None
            )
        except sqlite3.Error as exc:
            raise PaymentJournalError("cannot open payment journal") from exc
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            if check_schema:
                self._validate_schema(connection)
            mode = connection.execute(
                "PRAGMA journal_mode" if check_schema else "PRAGMA journal_mode=WAL"
            ).fetchone()[0]
            connection.execute("PRAGMA synchronous=FULL")
            if mode.lower() != "wal" or (
                connection.execute("PRAGMA synchronous").fetchone()[0] != SQLITE_SYNCHRONOUS_FULL
            ):
                raise PaymentJournalError("payment journal requires WAL and synchronous FULL")
            yield connection
        except sqlite3.DatabaseError as exc:
            raise PaymentJournalError("payment journal cannot be safely read or written") from exc
        finally:
            connection.close()

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
            raise PaymentJournalError("unrecognized payment journal")
        if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise PaymentJournalError("unsupported payment journal version")
        schema = {
            name: (kind, statement)
            for kind, name, statement in connection.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
            )
        }
        if schema != {name: ("table", statement) for name, statement in SCHEMA_SQL.items()}:
            raise PaymentJournalError("payment journal schema is incompatible")
        metadata = connection.execute(
            "SELECT version, network_identity, backend_identity FROM metadata"
        ).fetchall()
        if len(metadata) != 1 or metadata[0][0] != SCHEMA_VERSION:
            raise PaymentJournalError("payment journal metadata is missing or unsupported")
        if (metadata[0][1], metadata[0][2]) != (self._network, self._backend_identity):
            raise PaymentJournalError("payment journal network or backend identity mismatch")

    def _check_existing(self) -> None:
        """Fail closed on anything other than this exact schema and identity."""
        with self._connection():
            pass

    @staticmethod
    def _intent(connection: sqlite3.Connection, key: str) -> OutgoingPaymentIntent | None:
        row = connection.execute(
            "SELECT idempotency_key, swap_id, attempt_id, terms_digest, payment_hash, "
            "destination_amount_msat, fee_cap_msat, absolute_cltv_height, "
            "max_absolute_cltv_height, route_format, route "
            "FROM intents WHERE idempotency_key=?",
            (key,),
        ).fetchone()
        return OutgoingPaymentIntent(*row) if row is not None else None

    def record_intent(self, intent: OutgoingPaymentIntent) -> OutgoingPaymentIntent:
        """Commit an immutable declaration, with NO permission to submit a payment.

        A missing result or ambiguous commit requires backend reconciliation;
        an exact replay is bookkeeping only, never another submission request.
        """
        if not isinstance(intent, OutgoingPaymentIntent):
            raise PaymentJournalError("expected a complete outgoing payment intent")
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                prior = self._intent(connection, intent.idempotency_key)
                if prior is not None:
                    if prior != intent:
                        raise PaymentJournalConflictError(  # noqa: TRY301 - rollback below
                            "idempotency key has different immutable payment content"
                        )
                    connection.commit()
                    return prior
                connection.execute(
                    "INSERT INTO intents(idempotency_key, swap_id, attempt_id, "
                    "terms_digest, payment_hash, destination_amount_msat, fee_cap_msat, "
                    "absolute_cltv_height, max_absolute_cltv_height, route_format, route) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        intent.idempotency_key,
                        intent.swap_id,
                        intent.attempt_id,
                        intent.terms_digest,
                        intent.payment_hash,
                        intent.destination_amount_msat,
                        intent.fee_cap_msat,
                        intent.absolute_cltv_height,
                        intent.max_absolute_cltv_height,
                        intent.route_format,
                        intent.route,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise PaymentJournalConflictError(
                    "swap, attempt, payment hash, or key already has a different owner"
                ) from exc
            except BaseException:
                connection.rollback()
                raise
        return intent

    def get_intent(self, idempotency_key: str) -> OutgoingPaymentIntent | None:
        """Retrieve stored request material for explicit operator reconciliation."""
        _hash(idempotency_key, "idempotency_key")
        with self._connection() as connection:
            return self._intent(connection, idempotency_key)

    def list_intents(self) -> tuple[OutgoingPaymentIntent, ...]:
        """List ALL intents; no stored observation proves external completion."""
        with self._connection() as connection:
            return tuple(
                intent
                for (key,) in connection.execute(
                    "SELECT idempotency_key FROM intents ORDER BY idempotency_key"
                )
                if (intent := self._intent(connection, key)) is not None
            )

    @staticmethod
    def _observation(
        connection: sqlite3.Connection, observation_id: str
    ) -> PaymentObservation | None:
        row = connection.execute(
            "SELECT observation_id, idempotency_key, backend_identity, "
            "backend_attempt_id, reported_status, evidence_sha256 "
            "FROM observations WHERE observation_id=?",
            (observation_id,),
        ).fetchone()
        return PaymentObservation(*row) if row is not None else None

    def record_observation(self, observed: PaymentObservation) -> PaymentObservation:
        """Append a backend-reported observation, preserving disagreement.

        Even a reported failure or success is not a retry, cancellation, or
        finality decision. Missing/not-found evidence must not release risk.
        """
        if not isinstance(observed, PaymentObservation):
            raise PaymentJournalError("expected a complete backend observation")
        if observed.backend_identity != self._backend_identity:
            raise PaymentJournalError("backend-reported identity differs from this journal")
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                prior = self._observation(connection, observed.observation_id)
                if prior is not None:
                    if prior != observed:
                        raise PaymentJournalConflictError(  # noqa: TRY301 - rollback below
                            "observation ID has different immutable content"
                        )
                    connection.commit()
                    return prior
                if self._intent(connection, observed.idempotency_key) is None:
                    raise PaymentJournalError("observation refers to an absent payment intent")  # noqa: TRY301
                connection.execute(
                    "INSERT INTO observations(observation_id, idempotency_key, "
                    "backend_identity, backend_attempt_id, reported_status, evidence_sha256) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        observed.observation_id,
                        observed.idempotency_key,
                        observed.backend_identity,
                        observed.backend_attempt_id,
                        observed.reported_status,
                        observed.evidence_sha256,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise PaymentJournalConflictError("observation identity is already used") from exc
            except BaseException:
                connection.rollback()
                raise
        return observed

    def record_observed_track(
        self,
        expected_intent: OutgoingPaymentIntent,
        observations: tuple[PaymentObservation, ...],
    ) -> tuple[PaymentObservation, ...]:
        """Atomically append read-only reports against the *same* immutable intent.

        This is not payment reconciliation or permission to act. The journal
        may have been restored or replaced during the observer's network call;
        checking only an intent key outside this transaction would be unsafe.
        """
        if not isinstance(expected_intent, OutgoingPaymentIntent):
            raise PaymentJournalError("expected a complete existing payment intent")
        if not isinstance(observations, tuple) or not observations:
            raise PaymentJournalError("expected a nonempty tuple of backend observations")
        for observed in observations:
            if not isinstance(observed, PaymentObservation):
                raise PaymentJournalError("expected complete backend observations")
            if observed.idempotency_key != expected_intent.idempotency_key:
                raise PaymentJournalError("observed payment belongs to another intent")
            if observed.backend_identity != self._backend_identity:
                raise PaymentJournalError("backend-reported identity differs from this journal")
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if self._intent(connection, expected_intent.idempotency_key) != expected_intent:
                    raise PaymentJournalConflictError(  # noqa: TRY301 - rollback below
                        "recorded payment intent differs from observed immutable intent"
                    )
                for observed in observations:
                    prior = self._observation(connection, observed.observation_id)
                    if prior is not None:
                        if prior != observed:
                            raise PaymentJournalConflictError(  # noqa: TRY301 - rollback below
                                "observation ID has different immutable content"
                            )
                        continue
                    connection.execute(
                        "INSERT INTO observations(observation_id, idempotency_key, "
                        "backend_identity, backend_attempt_id, reported_status, evidence_sha256) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            observed.observation_id,
                            observed.idempotency_key,
                            observed.backend_identity,
                            observed.backend_attempt_id,
                            observed.reported_status,
                            observed.evidence_sha256,
                        ),
                    )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise PaymentJournalConflictError("observation identity is already used") from exc
            except BaseException:
                connection.rollback()
                raise
        return observations

    def list_observations(self, idempotency_key: str) -> tuple[PaymentObservation, ...]:
        """List every report, including contradictory and inconclusive ones."""
        _hash(idempotency_key, "idempotency_key")
        with self._connection() as connection:
            return tuple(
                observation
                for (observation_id,) in connection.execute(
                    "SELECT observation_id FROM observations WHERE idempotency_key=? "
                    "ORDER BY rowid",
                    (idempotency_key,),
                )
                if (observation := self._observation(connection, observation_id)) is not None
            )
