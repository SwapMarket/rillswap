"""Append-only SQLite bookkeeping for one deployment's complete UTXO input sets.

Recorded inputs are declarations, not live/spendable UTXO, wallet ownership,
fresh backup, reconciliation, or authorization to select/fund a swap. This
module has no release operation. An external funding adapter MUST reconcile
wallet and chain state before any irreversible action, including after restore.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING

from rill_core.domain.amounts import MAX_SATS
from rill_core.wire.types import NetworkIdentity

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

SCHEMA_VERSION = 1
APPLICATION_ID = 0x52494C4C  # 'RILL'
SQLITE_SYNCHRONOUS_FULL = 2
MAX_UINT32 = 0xFFFFFFFF
MAX_INPUTS = 100
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}\Z")
HASH32 = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA_SQL = {
    "metadata": (
        "CREATE TABLE metadata (version INTEGER PRIMARY KEY, network_identity TEXT NOT NULL)"
    ),
    "reservations": (
        "CREATE TABLE reservations ("
        "idempotency_key TEXT PRIMARY KEY, swap_id TEXT NOT NULL, "
        "funding_attempt_id TEXT NOT NULL, UNIQUE (swap_id, funding_attempt_id))"
    ),
    "reserved_inputs": (
        "CREATE TABLE reserved_inputs ("
        "txid TEXT NOT NULL, vout INTEGER NOT NULL, "
        "idempotency_key TEXT NOT NULL REFERENCES reservations(idempotency_key), "
        "value_sat INTEGER NOT NULL, cluster_id TEXT NOT NULL, "
        "PRIMARY KEY (txid, vout))"
    ),
}


class LedgerError(ValueError):
    """The reservation database or an operation is not usable as requested."""


class ReservationConflictError(LedgerError):
    """A key, attempt, or outpoint already has a different recorded owner."""


def _hash(value: str, field: str) -> None:
    if not isinstance(value, str) or HASH32.fullmatch(value) is None:
        raise LedgerError(f"{field} must be lowercase 32-byte hex")


@dataclass(frozen=True, slots=True)
class ReservedInput:
    """One declared, unverified treasury outpoint and local privacy label."""

    txid: str
    vout: int
    value_sat: int
    cluster_id: str

    def __post_init__(self) -> None:
        _hash(self.txid, "txid")
        if type(self.vout) is not int or not 0 <= self.vout <= MAX_UINT32:
            raise LedgerError("vout must be a uint32")
        if type(self.value_sat) is not int or not 0 < self.value_sat <= MAX_SATS:
            raise LedgerError("input value must be positive and within Bitcoin money range")
        if not isinstance(self.cluster_id, str) or IDENTIFIER.fullmatch(self.cluster_id) is None:
            raise LedgerError("cluster_id must be a bounded identifier")


@dataclass(frozen=True, slots=True)
class Reservation:
    """Recorded immutable input set, never funding or inventory authority."""

    idempotency_key: str
    swap_id: str
    funding_attempt_id: str
    inputs: tuple[ReservedInput, ...]

    def __post_init__(self) -> None:
        for field in ("idempotency_key", "swap_id", "funding_attempt_id"):
            _hash(getattr(self, field), field)
        if not isinstance(self.inputs, tuple) or not 0 < len(self.inputs) <= MAX_INPUTS:
            raise LedgerError("reservation needs a bounded nonempty input set")
        if any(not isinstance(item, ReservedInput) for item in self.inputs):
            raise LedgerError("all reserved inputs must be ReservedInput instances")
        if len({(item.txid, item.vout) for item in self.inputs}) != len(self.inputs):
            raise LedgerError("reservation repeats an outpoint")
        if len({item.cluster_id for item in self.inputs}) != 1:
            raise LedgerError("ordinary reservation cannot mix privacy clusters")
        if sum(item.value_sat for item in self.inputs) > MAX_SATS:
            raise LedgerError("total reserved input value exceeds Bitcoin money range")


def _canonical_network(network: NetworkIdentity) -> str:
    if not isinstance(network, NetworkIdentity):
        raise LedgerError("network must be a validated complete NetworkIdentity")
    return json.dumps(network.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


class ReservationLedger:
    """Network-bound append-only ledger; each operation uses its own connection."""

    def __init__(self, path: Path, canonical_network: str) -> None:
        """Bind a ledger handle to an exact network and absolute path."""
        self.path = path
        self._network = canonical_network

    @classmethod
    def create(cls, path: str | os.PathLike[str], network: NetworkIdentity) -> ReservationLedger:
        """Explicitly create an empty, UNRECONCILED database without overwriting any file."""
        destination = Path(path).absolute()
        canonical_network = _canonical_network(network)
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
        ledger = cls(destination, canonical_network)
        # A failed initialization leaves a partial file to be diagnosed, never
        # silently deleted and recreated on the next startup.
        with ledger._connection(check_schema=False) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                for statement in SCHEMA_SQL.values():
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO metadata(version, network_identity) VALUES (?, ?)",
                    (SCHEMA_VERSION, canonical_network),
                )
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        ledger._check_existing()
        return ledger

    @classmethod
    def open_existing(
        cls, path: str | os.PathLike[str], network: NetworkIdentity
    ) -> ReservationLedger:
        """Open only a matching current database; never create or migrate it."""
        ledger = cls(Path(path).absolute(), _canonical_network(network))
        ledger._check_existing()
        return ledger

    @contextmanager
    def _connection(self, *, check_schema: bool = True) -> Iterator[sqlite3.Connection]:
        if not self.path.is_file() or self.path.is_symlink():
            raise LedgerError("reservation database must be an existing regular file")
        try:
            connection = sqlite3.connect(
                self.path.as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None
            )
        except sqlite3.Error as exc:
            raise LedgerError("cannot open reservation database") from exc
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            if check_schema:
                self._validate_schema(connection)
            journal = connection.execute(
                "PRAGMA journal_mode" if check_schema else "PRAGMA journal_mode=WAL"
            ).fetchone()[0]
            connection.execute("PRAGMA synchronous=FULL")
            synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
            if journal.lower() != "wal" or synchronous != SQLITE_SYNCHRONOUS_FULL:
                raise LedgerError("reservation database requires WAL and synchronous FULL")
            yield connection
        except sqlite3.DatabaseError as exc:
            raise LedgerError("reservation database cannot be safely read or written") from exc
        finally:
            connection.close()

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
            raise LedgerError("unrecognized reservation database")
        if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise LedgerError("unsupported reservation database version")
        schema = {
            name: (object_type, statement)
            for object_type, name, statement in connection.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
            )
        }
        if schema != {name: ("table", statement) for name, statement in SCHEMA_SQL.items()}:
            raise LedgerError("reservation database has an incompatible schema")
        metadata = connection.execute("SELECT version, network_identity FROM metadata").fetchall()
        if len(metadata) != 1:
            raise LedgerError("reservation database has missing or duplicate metadata")
        version, network = metadata[0]
        if version != SCHEMA_VERSION:
            raise LedgerError("unsupported reservation metadata version")
        if network != self._network:
            raise LedgerError("reservation database network identity mismatch")

    def _check_existing(self) -> None:
        with self._connection():
            pass

    def record_reservation(
        self,
        idempotency_key: str,
        swap_id: str,
        funding_attempt_id: str,
        inputs: Iterable[ReservedInput],
    ) -> Reservation:
        """Atomically record a complete immutable input set or fail on overlap.

        The result has no funding authority; an absent row proves nothing about
        external treasury coins, Core locks, or database-snapshot freshness.
        """
        bounded = tuple(islice(inputs, MAX_INPUTS + 1))
        if any(not isinstance(item, ReservedInput) for item in bounded):
            raise LedgerError("all reserved inputs must be ReservedInput instances")
        if len(bounded) > MAX_INPUTS:
            raise LedgerError("reservation input set exceeds local size limit")
        ordered = tuple(sorted(bounded, key=lambda item: (item.txid, item.vout)))
        requested = Reservation(idempotency_key, swap_id, funding_attempt_id, ordered)
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = self._get(connection, idempotency_key)
                if existing is not None:
                    if existing != requested:
                        raise ReservationConflictError(  # noqa: TRY301 - transaction rollback below
                            "idempotency key has different immutable parameters"
                        )
                    connection.commit()
                    return existing
                connection.execute(
                    "INSERT INTO reservations(idempotency_key, swap_id, funding_attempt_id) "
                    "VALUES (?, ?, ?)",
                    (idempotency_key, swap_id, funding_attempt_id),
                )
                connection.executemany(
                    "INSERT INTO reserved_inputs(txid, vout, idempotency_key, "
                    "value_sat, cluster_id) VALUES (?, ?, ?, ?, ?)",
                    (
                        (item.txid, item.vout, idempotency_key, item.value_sat, item.cluster_id)
                        for item in ordered
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ReservationConflictError(
                    "attempt, idempotency key, or input is already reserved"
                ) from exc
            except BaseException:
                connection.rollback()
                raise
        return requested

    @staticmethod
    def _get(connection: sqlite3.Connection, idempotency_key: str) -> Reservation | None:
        row = connection.execute(
            "SELECT swap_id, funding_attempt_id FROM reservations WHERE idempotency_key=?",
            (idempotency_key,),
        ).fetchone()
        if row is None:
            return None
        inputs = tuple(
            ReservedInput(txid, vout, value, cluster)
            for txid, vout, value, cluster in connection.execute(
                "SELECT txid, vout, value_sat, cluster_id FROM reserved_inputs "
                "WHERE idempotency_key=? ORDER BY txid, vout",
                (idempotency_key,),
            )
        )
        return Reservation(idempotency_key, row[0], row[1], inputs)

    def get(self, idempotency_key: str) -> Reservation | None:
        """Read one recorded reservation; no database row implies no UTXO fact."""
        _hash(idempotency_key, "idempotency_key")
        with self._connection() as connection:
            return self._get(connection, idempotency_key)

    def list_reservations(self) -> tuple[Reservation, ...]:
        """List recorded reservations for operator reconciliation, not selection."""
        with self._connection() as connection:
            return tuple(
                reservation
                for (key,) in connection.execute(
                    "SELECT idempotency_key FROM reservations ORDER BY idempotency_key"
                )
                if (reservation := self._get(connection, key)) is not None
            )
