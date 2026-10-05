"""Private, explicitly authorized Lightning inventory allocations.

This is not a checkout handler or a receipt verifier. The trusted operator must
validate receipt provenance and exclusively control ALL source-wallet spending
and refund promises. A settled invoice or replenished balance is not authority.
The retained source fence must live outside the journal directory, at the single
operator-owned location for this wallet. Losing either requires reconciliation,
not another provision call. No method dispatches payments or restores live rights.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, StringConstraints, TypeAdapter, field_validator, model_validator
from rill_core.domain.amounts import MAX_MILLISATS, MAX_SATS
from rill_core.wire.canonical import parse_model_json
from rill_core.wire.types import CompressedKey, Hex32, NetworkIdentity, ScriptHex, StrictModel

from rill_cli.age_container import MAX_CIPHERTEXT_BYTES
from rill_cli.publication import publish_new_ciphertext

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

type Amount = Annotated[int, Field(strict=True, ge=1, le=MAX_MILLISATS)]
type NonnegativeAmount = Annotated[int, Field(strict=True, ge=0, le=MAX_MILLISATS)]
type Sats = Annotated[int, Field(strict=True, ge=1, le=MAX_SATS)]
type Timestamp = Annotated[int, Field(strict=True, ge=1, le=9_007_199_254_740_991)]
type OperationId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,128}$")]
_OPERATION_ID: TypeAdapter[str] = TypeAdapter(OperationId)
_TAPROOT_SCRIPT_HEX_LENGTH = 68
_MAX_CAPACITY_AGE_SECONDS = 10
_MAX_FENCE_BYTES = 16384


class ConversionJournalError(ValueError):
    """Unknown or conflicting custody state, never permission to retry an effect."""


class SourceAuthority(StrictModel):
    """Affirmative exclusive operator custody, not inferred from any receipt."""

    source_node: CompressedKey
    network: NetworkIdentity
    source_epoch: Hex32
    exclusive_wallet: Literal[True]
    commitments_known: Literal[True]
    fixed_reserve_msat: NonnegativeAmount
    treasury_script: ScriptHex
    provider_identity: Hex32

    @field_validator("exclusive_wallet", "commitments_known", mode="before")
    @classmethod
    def affirmative_authority(cls, value: object) -> object:
        """Do not coerce numeric or string custody assertions into approval."""
        if value is not True:
            raise ValueError("affirmative exclusive source authority required")
        return value

    @field_validator("treasury_script")
    @classmethod
    def treasury_taproot(cls, value: str) -> str:
        """Pin one explicit Taproot destination for this first conversion rail."""
        if len(value) != _TAPROOT_SCRIPT_HEX_LENGTH or not value.startswith("5120"):
            raise ValueError("conversion treasury requires a Taproot script")
        return value


class SourceCredit(StrictModel):
    """Previously verified provenance. Extra paid amount is not imported."""

    payment_hash: Hex32
    invoice_sha256: Hex32
    amount_msat: Amount


class Allocation(StrictModel):
    """Maximum consumption of one canonical source credit."""

    payment_hash: Hex32
    amount_msat: Amount


class ConversionRequest(StrictModel):
    """Explicit operator approval, immutable after atomic reservation."""

    operation_id: OperationId
    allocations: tuple[Allocation, ...] = Field(min_length=1, max_length=128)
    requested_payout_sat: Sats
    minimum_output_sat: Sats
    max_source_debit_msat: Amount
    max_fee_msat: NonnegativeAmount
    max_routing_fee_msat: NonnegativeAmount
    confirmation_blocks: Annotated[int, Field(strict=True, ge=1, le=144)]
    expires_at: Timestamp

    @model_validator(mode="after")
    def check_budget(self) -> ConversionRequest:
        """Keep all source ceilings reserved, with no duplicate allocation."""
        if (
            len({item.payment_hash for item in self.allocations}) != len(self.allocations)
            or sum(item.amount_msat for item in self.allocations) != self.max_source_debit_msat
            or self.minimum_output_sat > self.requested_payout_sat
            or self.max_routing_fee_msat > self.max_fee_msat
            or self.max_fee_msat > self.max_source_debit_msat
        ):
            raise ValueError("conversion allocation or budget invalid")
        return self


class CapacityQuery(StrictModel):
    """Capture BEFORE wallet RPC; generation invalidates pre-effect observations."""

    journal_id: Hex32
    generation: Annotated[int, Field(strict=True, ge=0)]
    started_at: Timestamp


class WalletAvailability(StrictModel):
    """Fresh authenticated capacity, usable only with exclusive source custody."""

    source_node: CompressedKey
    network: NetworkIdentity
    query: CapacityQuery
    observed_at: Timestamp
    spendable_msat: NonnegativeAmount
    commitments_known: Literal[True]

    @field_validator("commitments_known", mode="before")
    @classmethod
    def known_commitments(cls, value: object) -> object:
        """Unknown commitments are not a zero liability observation."""
        if value is not True:
            raise ValueError("affirmatively known commitments required")
        return value


class InventoryAccountingEligibility(StrictModel):
    """Accounting inventory threshold, NEVER payment bandwidth or refund payability.

    A trusted runtime must establish complete supported accounting and all known
    commitments under its operational custody restrictions. Exclusive custody
    alone does not freeze forwarding, uncommitted updates or channel lifecycle.
    No automatic observation/projector grants these assertions. Inactive-channel
    accounting can strand holds indefinitely after a failed one-shot attempt.
    """

    source_node: CompressedKey
    network: NetworkIdentity
    query: CapacityQuery
    observed_at: Timestamp
    accounting_net_msat: NonnegativeAmount
    coverage_complete: Literal[True]
    commitments_known: Literal[True]

    @field_validator("coverage_complete", "commitments_known", mode="before")
    @classmethod
    def affirmative_accounting(cls, value: object) -> object:
        """Absent, partial or coerced accounting assertions establish no eligibility."""
        if value is not True:
            raise ValueError("affirmatively complete accounting and known commitments required")
        return value


class PreparedConversion(StrictModel):
    """Verified firm terms, supplied by the trusted reverse-swap worker."""

    contract_hash: Hex32
    payment_hash: Hex32
    invoice_sha256: Hex32
    invoice_amount_msat: Amount
    routing_fee_ceiling_msat: NonnegativeAmount
    minimum_net_output_sat: Sats


class ConversionReceipt(StrictModel):
    """Fresh independently verified source debit and owned destination output."""

    source_node: CompressedKey
    network: NetworkIdentity
    payment_hash: Hex32
    invoice_sha256: Hex32
    amount_msat: Amount
    routing_fee_msat: NonnegativeAmount
    destination_txid: Hex32
    destination_vout: Annotated[int, Field(strict=True, ge=0, le=0xFFFFFFFF)]
    destination_script: ScriptHex
    destination_value_sat: Sats
    confirmation_blocks: Annotated[int, Field(strict=True, ge=1)]


class _Fence(StrictModel):
    version: Literal["merchant-conversion-source/1"]
    journal_id: Hex32
    directory: str
    authority: SourceAuthority


class ConversionJob(StrictModel):
    """Read-only history. This value never carries execution authority."""

    request: ConversionRequest
    state: Literal["reserved", "invoked", "checkpointing", "prepared", "dispatched", "complete"]
    prepared: PreparedConversion | None
    recovery_sha256: Hex32 | None
    receipt: ConversionReceipt | None

    @model_validator(mode="after")
    def check_phase(self) -> ConversionJob:
        """Partial checkpoints cannot masquerade as prepared or paid state."""
        has_prepared = self.state not in {"reserved", "invoked"}
        if (
            (self.prepared is not None) != has_prepared
            or (self.recovery_sha256 is not None) != has_prepared
            or (self.receipt is not None) != (self.state == "complete")
        ):
            raise ValueError("conversion phase incomplete")
        return self


class _LiveRight:
    """Process-local, journal-instance-local single owner, never serialized."""

    def __init__(self, journal: ConversionJournal, operation_id: str) -> None:
        self.journal = journal
        self.operation_id = operation_id
        self.stage = "reserved"
        self.lock = threading.Lock()


class ConversionReservation:
    """Only a freshly committed reservation has a one-time invocation right."""

    def __init__(self, job: ConversionJob, right: _LiveRight | None) -> None:
        """Retain a fresh process-local right, or observation-only history."""
        self.job = job
        self._right = right


_SCHEMA = (
    (
        "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), fence TEXT NOT NULL, "
        "capacity_generation INTEGER NOT NULL CHECK(capacity_generation>=0))"
    ),
    (
        "CREATE TABLE credits (payment_hash TEXT PRIMARY KEY, credit TEXT NOT NULL, "
        "consumed_msat INTEGER NOT NULL)"
    ),
    "CREATE TABLE jobs (operation_id TEXT PRIMARY KEY, job TEXT NOT NULL)",
    (
        "CREATE TABLE holds (kind TEXT NOT NULL, owner TEXT NOT NULL, "
        "payment_hash TEXT NOT NULL REFERENCES credits(payment_hash), "
        "amount_msat INTEGER NOT NULL, PRIMARY KEY(kind,owner,payment_hash))"
    ),
)


def _directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise ConversionJournalError("private conversion directory refused")
    # Reject symlinked ancestors as well as the final directory.
    if path.resolve() != path:
        raise ConversionJournalError("conversion directory indirection refused")


def _private_stat(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
    ):
        raise ConversionJournalError("private conversion file refused")


def _private_file(path: Path) -> None:
    _private_stat(path.lstat())


def _read_private(path: Path, maximum: int) -> bytes:
    _private_file(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        _private_stat(os.fstat(stream.fileno()))
        document = stream.read(maximum + 1)
    if len(document) > maximum:
        raise ConversionJournalError("private conversion document exceeds limit")
    return document


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_fence(path: Path) -> _Fence:
    _directory(path.parent)
    return parse_model_json(_Fence, _read_private(path, _MAX_FENCE_BYTES))


class ConversionJournal:
    """One authoritative, operator-only allocation domain for a source wallet."""

    def __init__(self, directory: Path, source_fence: Path, fence: _Fence) -> None:
        """Use provision/open; direct construction grants no execution right."""
        self.directory = directory
        self.source_fence = source_fence
        self._fence = fence

    @classmethod
    def provision(
        cls, directory: Path, source_fence: Path, authority: SourceAuthority
    ) -> ConversionJournal:
        """Explicit new-source action. Never repair a missing or partial journal."""
        directory, source_fence = directory.absolute(), source_fence.absolute()
        _directory(directory)
        _directory(source_fence.parent)
        if source_fence.parent == directory or directory in source_fence.parents:
            raise ConversionJournalError("source fence must outlive journal directory")
        if any(directory.iterdir()):
            raise ConversionJournalError("conversion journal initialization already attempted")
        fence = _Fence(
            version="merchant-conversion-source/1",
            journal_id=secrets.token_hex(32),
            directory=str(directory),
            authority=authority,
        )
        # Retain the fence on EVERY subsequent error, including failed fsync.
        fd = os.open(source_fence, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(fence.model_dump_json().encode())
            stream.flush()
            os.fsync(stream.fileno())
        _sync_directory(source_fence.parent)
        store = directory / "inventory.sqlite"
        fd = os.open(store, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        db = sqlite3.connect(store)
        try:
            with db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                for statement in _SCHEMA:
                    db.execute(statement)
                db.execute("INSERT INTO metadata VALUES (1,?,0)", (fence.model_dump_json(),))
        finally:
            db.close()
        (directory / "recovery").mkdir(mode=0o700)
        _sync_directory(directory)
        return cls.open(directory, source_fence, authority)

    @classmethod
    def open(  # noqa: PLR0912 - cohesive persisted allocation/consumption validation
        cls, directory: Path, source_fence: Path, authority: SourceAuthority
    ) -> ConversionJournal:
        """Open only. Missing state grants no provisioning or invocation right."""
        directory, source_fence = directory.absolute(), source_fence.absolute()
        fence = _read_fence(source_fence)
        if fence.directory != str(directory) or fence.authority != authority:
            raise ConversionJournalError("conversion source ownership changed")
        journal = cls(directory, source_fence, fence)
        with journal._transaction() as db:
            actual = tuple(
                row[0]
                for row in db.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' ORDER BY rowid"
                )
            )
            if actual != _SCHEMA or db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ConversionJournalError("conversion schema incomplete or incompatible")
            jobs = {}
            for operation_id, document in db.execute("SELECT operation_id, job FROM jobs"):
                job = parse_model_json(ConversionJob, document.encode())
                if job.request.operation_id != operation_id:
                    raise ConversionJournalError("conversion operation identity changed")
                jobs[operation_id] = job
            expected_holds = {
                ("conversion", operation_id, item.payment_hash): item.amount_msat
                for operation_id, job in jobs.items()
                if job.state != "complete"
                for item in job.request.allocations
            }
            actual_holds = {}
            for kind, owner, payment_hash, amount in db.execute(
                "SELECT kind, owner, payment_hash, amount_msat FROM holds"
            ):
                if (
                    kind not in {"conversion", "refund"}
                    or type(amount) is not int
                    or not 0 < amount <= MAX_MILLISATS
                ):
                    raise ConversionJournalError("conversion hold invalid")
                actual_holds[kind, owner, payment_hash] = amount
                _OPERATION_ID.validate_python(owner, strict=True)
            if {
                key: value for key, value in actual_holds.items() if key[0] == "conversion"
            } != expected_holds or db.execute("PRAGMA foreign_key_check").fetchall():
                raise ConversionJournalError("conversion allocation history incomplete")
            expected_consumed: dict[str, int] = {}
            destinations = set()
            for job in jobs.values():
                if job.receipt is None:
                    continue
                destination = job.receipt.destination_txid, job.receipt.destination_vout
                if destination in destinations:
                    raise ConversionJournalError("conversion destination counted twice")
                destinations.add(destination)
                remaining = job.receipt.amount_msat + job.receipt.routing_fee_msat
                for item in job.request.allocations:
                    used = min(remaining, item.amount_msat)
                    expected_consumed[item.payment_hash] = (
                        expected_consumed.get(item.payment_hash, 0) + used
                    )
                    remaining -= used
                if remaining:
                    raise ConversionJournalError("conversion consumption exceeds allocations")
            for payment_hash, document, consumed in db.execute(
                "SELECT payment_hash, credit, consumed_msat FROM credits"
            ):
                credit = parse_model_json(SourceCredit, document.encode())
                held = sum(value for key, value in actual_holds.items() if key[2] == payment_hash)
                if (
                    credit.payment_hash != payment_hash
                    or type(consumed) is not int
                    or not 0 <= consumed <= credit.amount_msat - held
                    or consumed != expected_consumed.pop(payment_hash, 0)
                ):
                    raise ConversionJournalError("conversion consumption invalid")
            if expected_consumed:
                raise ConversionJournalError("consumed source credit missing")
        return journal

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        _directory(self.directory)
        _directory(self.directory / "recovery")
        _private_file(self.directory / "inventory.sqlite")
        if _read_fence(self.source_fence) != self._fence:
            raise ConversionJournalError("conversion source fence changed")
        db = sqlite3.connect((self.directory / "inventory.sqlite").as_uri() + "?mode=rw", uri=True)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT fence, capacity_generation FROM metadata").fetchall()
            if (
                len(rows) != 1
                or parse_model_json(_Fence, rows[0][0].encode()) != self._fence
                or type(rows[0][1]) is not int
                or rows[0][1] < 0
            ):
                raise ConversionJournalError("conversion metadata changed")  # noqa: TRY301 - transaction must roll back
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _get(db: sqlite3.Connection, operation_id: str) -> ConversionJob:
        row = db.execute("SELECT job FROM jobs WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            raise ConversionJournalError("conversion operation unknown")
        return parse_model_json(ConversionJob, row[0].encode())

    @staticmethod
    def _put(db: sqlite3.Connection, job: ConversionJob) -> None:
        db.execute(
            "UPDATE jobs SET job=? WHERE operation_id=?",
            (job.model_dump_json(), job.request.operation_id),
        )

    def status(self, operation_id: str) -> ConversionJob:
        """Read retained history, never restore a live invocation owner."""
        with self._transaction() as db:
            return self._get(db, operation_id)

    @property
    def authority(self) -> SourceAuthority:
        """Return the immutable provisioned source/destination authority, not new rights."""
        return self._fence.authority

    def begin_capacity_query(self) -> CapacityQuery:
        """Snapshot allocation generation BEFORE starting authenticated wallet RPC."""
        with self._transaction() as db:
            (generation,) = db.execute("SELECT capacity_generation FROM metadata").fetchone()
            return CapacityQuery(
                journal_id=self._fence.journal_id,
                generation=generation,
                started_at=int(time.time()),
            )

    @staticmethod
    def _check_reimport(db: sqlite3.Connection, supplied: tuple[SourceCredit, ...]) -> None:
        for credit in supplied:
            row = db.execute(
                "SELECT credit FROM credits WHERE payment_hash=?", (credit.payment_hash,)
            ).fetchone()
            if row is None or parse_model_json(SourceCredit, row[0].encode()) != credit:
                raise ConversionJournalError("canonical source credit conflict")

    def _allocate(  # noqa: PLR0913, PLR0917 - one atomic source authorization
        self,
        db: sqlite3.Connection,
        kind: str,
        owner: str,
        allocations: tuple[Allocation, ...],
        credits: tuple[SourceCredit, ...],  # noqa: A002 - canonical inventory credits
        availability: WalletAvailability | InventoryAccountingEligibility,
    ) -> None:
        now = int(time.time())
        (generation,) = db.execute("SELECT capacity_generation FROM metadata").fetchone()
        if (
            availability.source_node != self._fence.authority.source_node
            or availability.network != self._fence.authority.network
            or availability.query.journal_id != self._fence.journal_id
            or availability.query.generation != generation
            or not 0 <= now - availability.query.started_at <= _MAX_CAPACITY_AGE_SECONDS
            or not availability.query.started_at <= availability.observed_at <= now
            or len({credit.payment_hash for credit in credits}) != len(credits)
        ):
            raise ConversionJournalError("fresh exclusive-wallet capacity required")
        for credit in credits:
            row = db.execute(
                "SELECT credit FROM credits WHERE payment_hash=?", (credit.payment_hash,)
            ).fetchone()
            if row is not None:
                if parse_model_json(SourceCredit, row[0].encode()) != credit:
                    raise ConversionJournalError("canonical source credit conflict")
            else:
                db.execute(
                    "INSERT INTO credits VALUES (?,?,0)",
                    (credit.payment_hash, credit.model_dump_json()),
                )
        outstanding = sum(row[0] for row in db.execute("SELECT amount_msat FROM holds"))
        total = sum(item.amount_msat for item in allocations)
        if isinstance(availability, InventoryAccountingEligibility):
            if kind != "conversion":
                raise ConversionJournalError("accounting eligibility cannot authorize refunds")
            budget = availability.accounting_net_msat
        else:
            budget = availability.spendable_msat
        if outstanding + total + self._fence.authority.fixed_reserve_msat > budget:
            raise ConversionJournalError("wallet commitments exceed available capacity")
        for item in allocations:
            row = db.execute(
                "SELECT credit, consumed_msat FROM credits WHERE payment_hash=?",
                (item.payment_hash,),
            ).fetchone()
            if row is None:
                raise ConversionJournalError("source credit unknown")
            credit = parse_model_json(SourceCredit, row[0].encode())
            held = sum(
                row[0]
                for row in db.execute(
                    "SELECT amount_msat FROM holds WHERE payment_hash=?", (item.payment_hash,)
                )
            )
            if row[1] + held + item.amount_msat > credit.amount_msat:
                raise ConversionJournalError("source credit already consumed or reserved")
            db.execute(
                "INSERT INTO holds VALUES (?,?,?,?)",
                (kind, owner, item.payment_hash, item.amount_msat),
            )

    def reserve(
        self,
        request: ConversionRequest,
        *,
        credits: tuple[SourceCredit, ...],  # noqa: A002 - canonical inventory credits
        availability: WalletAvailability,
    ) -> ConversionReservation:
        """Atomically approve credits and budgets; replays are observation-only."""
        if not isinstance(availability, WalletAvailability):
            raise ConversionJournalError("spendable wallet availability required")
        return self._reserve(request, credits, availability)

    def reserve_accounting_conversion(
        self,
        request: ConversionRequest,
        *,
        credits: tuple[SourceCredit, ...],  # noqa: A002 - canonical inventory credits
        eligibility: InventoryAccountingEligibility,
    ) -> ConversionReservation:
        """Hold accounting inventory for ONE original attempt, never promise payability.

        Existing jobs, refunds, recovery, dispatch and completion retain exactly
        the same liabilities and one-shot rights. No admission observation is
        persisted, no new schema or automatic upgrade action is introduced.
        Replays through either conversion entry point grant no fresh rights.
        """
        if not isinstance(eligibility, InventoryAccountingEligibility):
            raise ConversionJournalError("explicit inventory accounting eligibility required")
        eligibility = InventoryAccountingEligibility.model_validate(
            eligibility.model_dump(), strict=True
        )
        return self._reserve(request, credits, eligibility)

    def _reserve(
        self,
        request: ConversionRequest,
        credits: tuple[SourceCredit, ...],  # noqa: A002 - canonical inventory credits
        availability: WalletAvailability | InventoryAccountingEligibility,
    ) -> ConversionReservation:
        with self._transaction() as db:
            if db.execute(
                "SELECT 1 FROM jobs WHERE operation_id=?", (request.operation_id,)
            ).fetchone():
                job = self._get(db, request.operation_id)
                if job.request != request:
                    raise ConversionJournalError("conversion authorization changed")
                self._check_reimport(db, credits)
                return ConversionReservation(job, None)
            if request.expires_at <= int(time.time()):
                raise ConversionJournalError("conversion approval expired")
            self._allocate(
                db, "conversion", request.operation_id, request.allocations, credits, availability
            )
            job = ConversionJob(
                request=request, state="reserved", prepared=None, recovery_sha256=None, receipt=None
            )
            db.execute(
                "INSERT INTO jobs VALUES (?,?)", (request.operation_id, job.model_dump_json())
            )
        return ConversionReservation(job, _LiveRight(self, request.operation_id))

    def reserve_refund(
        self,
        owner: OperationId,
        allocation: Allocation,
        *,
        credits: tuple[SourceCredit, ...],  # noqa: A002 - canonical inventory credits
        availability: WalletAvailability,
    ) -> None:
        """Hold an explicit refund promise in the SAME source authorization domain."""
        if not isinstance(availability, WalletAvailability):
            raise ConversionJournalError("spendable wallet availability required for refunds")
        _OPERATION_ID.validate_python(owner, strict=True)
        with self._transaction() as db:
            rows = db.execute(
                "SELECT payment_hash, amount_msat FROM holds WHERE kind='refund' AND owner=?",
                (owner,),
            ).fetchall()
            if rows:
                if rows != [(allocation.payment_hash, allocation.amount_msat)]:
                    raise ConversionJournalError("refund commitment changed")
                self._check_reimport(db, credits)
                return
            self._allocate(db, "refund", owner, (allocation,), credits, availability)

    def invoke(self, reservation: ConversionReservation) -> _LiveRight:
        """Consume the fresh reservation right BEFORE invoking a new SDK session."""
        right = reservation._right  # noqa: SLF001 - journal owns process-local invocation rights
        if right is None or right.journal is not self:
            raise ConversionJournalError("conversion has no invocation owner")
        with right.lock:
            if right.stage != "reserved":
                raise ConversionJournalError("conversion invocation already consumed")
            right.stage = "unknown"
            with self._transaction() as db:
                job = self._get(db, right.operation_id)
                if job.state != "reserved" or job.request.expires_at <= int(time.time()):
                    raise ConversionJournalError("conversion invocation refused")
                self._put(db, job.model_copy(update={"state": "invoked"}))
            right.stage = "invoked"
        return right

    def checkpoint(
        self,
        right: _LiveRight,
        prepared: PreparedConversion,
        ciphertext: bytes,
        *,
        verify_from_disk: Callable[[bytes], object],
    ) -> Path:
        """Persist verified quote and encrypted create-only recovery before payment."""
        if right.journal is not self:
            raise ConversionJournalError("conversion invocation owner mismatch")
        with right.lock:
            if right.stage != "invoked":
                raise ConversionJournalError("conversion quote already attempted")
            right.stage = "unknown"
            with self._transaction() as db:
                job = self._get(db, right.operation_id)
                request = job.request
                debit = prepared.invoice_amount_msat + prepared.routing_fee_ceiling_msat
                if (
                    job.state != "invoked"
                    or request.expires_at <= int(time.time())
                    or debit > request.max_source_debit_msat
                    or prepared.routing_fee_ceiling_msat > request.max_routing_fee_msat
                    or prepared.minimum_net_output_sat < request.minimum_output_sat
                    or debit - prepared.minimum_net_output_sat * 1000 > request.max_fee_msat
                ):
                    raise ConversionJournalError("firm conversion quote exceeds approval")
                digest = hashlib.sha256(ciphertext).hexdigest()
                self._put(
                    db,
                    job.model_copy(
                        update={
                            "state": "checkpointing",
                            "prepared": prepared,
                            "recovery_sha256": digest,
                        }
                    ),
                )
            destination = self.directory / "recovery" / f"{right.operation_id}.age"
            publish_new_ciphertext(destination, ciphertext, verify_from_disk=verify_from_disk)
            with self._transaction() as db:
                job = self._get(db, right.operation_id)
                if (
                    job.state != "checkpointing"
                    or job.prepared != prepared
                    or job.recovery_sha256 != digest
                ):
                    raise ConversionJournalError("conversion checkpoint changed")
                self._put(db, job.model_copy(update={"state": "prepared"}))
            right.stage = "prepared"
        return destination

    def dispatch(self, right: _LiveRight, payment_hash: Hex32) -> None:
        """Consume exact outbound payment right durably, before calling the payer."""
        if right.journal is not self:
            raise ConversionJournalError("conversion invocation owner mismatch")
        with right.lock:
            if right.stage != "prepared":
                raise ConversionJournalError("conversion payment right unavailable")
            right.stage = "unknown"
            with self._transaction() as db:
                job = self._get(db, right.operation_id)
                if (
                    job.state != "prepared"
                    or job.prepared is None
                    or job.prepared.payment_hash != payment_hash
                    or job.request.expires_at <= int(time.time())
                ):
                    raise ConversionJournalError("conversion payment dispatch refused")
                path = self.directory / "recovery" / f"{right.operation_id}.age"
                if (
                    hashlib.sha256(_read_private(path, MAX_CIPHERTEXT_BYTES)).hexdigest()
                    != job.recovery_sha256
                ):
                    raise ConversionJournalError("conversion recovery checkpoint changed")
                self._put(db, job.model_copy(update={"state": "dispatched"}))
                db.execute(
                    "UPDATE metadata SET capacity_generation=capacity_generation+1 WHERE id=1"
                )
            right.stage = "dispatched"

    def complete(self, operation_id: str, receipt: ConversionReceipt) -> ConversionJob:
        """Reconcile real debits/output, independently of original order status."""
        with self._transaction() as db:
            job = self._get(db, operation_id)
            if job.state == "complete":
                if job.receipt != receipt:
                    raise ConversionJournalError("completed conversion receipt changed")
                return job
            prepared = job.prepared
            debit = receipt.amount_msat + receipt.routing_fee_msat
            if (
                job.state != "dispatched"
                or prepared is None
                or receipt.source_node != self._fence.authority.source_node
                or receipt.network != self._fence.authority.network
                or receipt.payment_hash != prepared.payment_hash
                or receipt.invoice_sha256 != prepared.invoice_sha256
                or receipt.amount_msat != prepared.invoice_amount_msat
                or receipt.routing_fee_msat > prepared.routing_fee_ceiling_msat
                or debit > job.request.max_source_debit_msat
                or receipt.destination_script != self._fence.authority.treasury_script
                or receipt.destination_value_sat < prepared.minimum_net_output_sat
                or receipt.confirmation_blocks < job.request.confirmation_blocks
                or debit - receipt.destination_value_sat * 1000 > job.request.max_fee_msat
            ):
                raise ConversionJournalError("independent conversion receipt refused")
            for (document,) in db.execute("SELECT job FROM jobs"):
                previous = parse_model_json(ConversionJob, document.encode()).receipt
                if previous is not None and (
                    previous.destination_txid,
                    previous.destination_vout,
                ) == (receipt.destination_txid, receipt.destination_vout):
                    raise ConversionJournalError("conversion destination counted twice")
            remaining = debit
            for item in job.request.allocations:
                consumed = min(remaining, item.amount_msat)
                db.execute(
                    "UPDATE credits SET consumed_msat=consumed_msat+? WHERE payment_hash=?",
                    (consumed, item.payment_hash),
                )
                remaining -= consumed
            if remaining:
                raise ConversionJournalError("conversion consumption exceeds allocations")
            db.execute("DELETE FROM holds WHERE kind='conversion' AND owner=?", (operation_id,))
            # Invalidate even RPCs begun before this completion but returned
            # afterward. Timestamp freshness cannot fence a released debit hold.
            db.execute("UPDATE metadata SET capacity_generation=capacity_generation+1 WHERE id=1")
            job = job.model_copy(update={"state": "complete", "receipt": receipt})
            self._put(db, job)
            return job
