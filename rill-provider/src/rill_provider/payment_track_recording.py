"""Explicit read-only LND reports appended to an existing payment journal.

Reports are diagnostics, not proof that the declared route was sent or that a
swap may claim, retry, cancel, settle, release risk, or advance its state.
No polling, startup work, backend action, or journal creation occurs here.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from rill_provider.lnd_payment_observation import (
    MAX_ATTEMPTS,
    MAX_UPDATES,
    HtlcAttemptSnapshot,
    PaymentSnapshot,
    RegtestLndPaymentObserver,
    TrackResult,
)
from rill_provider.payment_journal import (
    OutgoingPaymentIntent,
    OutgoingPaymentJournal,
    PaymentJournalError,
    PaymentObservation,
)

FORMAT = "rillswap-lnd-payment-report/v1"
ROW_DOMAIN = b"rillswap-lnd-payment-observation/v1\x00"


@dataclass(frozen=True, slots=True)
class RecordedTrack:
    """Portable sanitized evidence and its durable, non-authorizing reports."""

    evidence: bytes
    observations: tuple[PaymentObservation, ...]


def _snapshots(result: TrackResult, expected_hash: str) -> list[dict[str, object]]:
    if (
        not isinstance(result, TrackResult)
        or result.completion not in ("terminal", "update-limit")
        or not 0 < len(result.snapshots) <= MAX_UPDATES
    ):
        raise PaymentJournalError("incomplete or unsupported LND report")
    snapshots: list[dict[str, object]] = []
    for index, snap in enumerate(result.snapshots):
        if (
            not isinstance(snap, PaymentSnapshot)
            or snap.payment_hash != expected_hash
            or snap.status not in ("INITIATED", "IN_FLIGHT", "SUCCEEDED", "FAILED")
            or (snap.status in ("SUCCEEDED", "FAILED") and index != len(result.snapshots) - 1)
            or len(snap.htlc_attempts) > MAX_ATTEMPTS
        ):
            raise PaymentJournalError("LND report does not match the recorded intent")
        attempts: list[dict[str, object]] = []
        ids: set[int] = set()
        for attempt in snap.htlc_attempts:
            if (
                not isinstance(attempt, HtlcAttemptSnapshot)
                or type(attempt.lnd_attempt_id) is not int
                or attempt.lnd_attempt_id <= 0
                or attempt.lnd_attempt_id in ids
                or attempt.status not in ("IN_FLIGHT", "SUCCEEDED", "FAILED")
            ):
                raise PaymentJournalError("LND report has unsupported HTLC attempt evidence")
            ids.add(attempt.lnd_attempt_id)
            attempts.append({"lnd_attempt_id": attempt.lnd_attempt_id, "status": attempt.status})
        snapshots.append(
            {"payment_hash": snap.payment_hash, "status": snap.status, "htlcs": attempts}
        )
    terminal = result.snapshots[-1].status in ("SUCCEEDED", "FAILED")
    if terminal != (result.completion == "terminal") or (
        result.completion == "update-limit" and len(result.snapshots) != MAX_UPDATES
    ):
        raise PaymentJournalError("LND report completion does not match its snapshots")
    return snapshots


def record_payment_track(
    journal: OutgoingPaymentJournal,
    idempotency_key: str,
    observer: RegtestLndPaymentObserver,
    evidence_path: Path,
    *,
    deadline_seconds: float = 10,
) -> RecordedTrack:
    """Track a pre-existing intent by hash once and append its reported snapshots.

    The journal is assumed to have been opened with explicit network/backend
    identity. Its immutable intent is compared again inside the append transaction
    after the RPC. Evidence is durably written before the database append, to
    an exclusively reserved file in a private operator-controlled directory.
    It contains sensitive payment metadata, but no raw route or credentials.
    """
    if not isinstance(journal, OutgoingPaymentJournal) or not isinstance(
        observer, RegtestLndPaymentObserver
    ):
        raise PaymentJournalError("existing journal and read-only LND observer required")
    intent = journal.get_intent(idempotency_key)
    if intent is None:
        raise PaymentJournalError("payment intent missing; no absence claim")
    directory, descriptor = _reserve(evidence_path)
    try:
        result = observer.track(
            bytes.fromhex(intent.payment_hash), deadline_seconds=deadline_seconds
        )
        recorded = _project(journal, intent, result)
        _persist(directory, descriptor, recorded.evidence)
        journal.record_observed_track(intent, recorded.observations)
        return recorded
    finally:
        os.close(descriptor)
        os.close(directory)


def _reserve(evidence_path: Path) -> tuple[int, int]:
    if not isinstance(evidence_path, Path) or not evidence_path.name:
        raise PaymentJournalError("explicit new evidence path required")
    try:
        directory = os.open(evidence_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            details = os.fstat(directory)
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != os.getuid()
                or details.st_mode & 0o077
            ):
                raise PaymentJournalError(  # noqa: TRY301 - close directory below
                    "evidence directory must be private and owned"
                )
            descriptor = os.open(
                evidence_path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
        except BaseException:
            os.close(directory)
            raise
    except OSError as exc:
        raise PaymentJournalError("cannot reserve private payment evidence") from exc
    return directory, descriptor


def _persist(directory: int, descriptor: int, evidence: bytes) -> None:
    try:
        remaining = memoryview(evidence)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise PaymentJournalError("evidence write did not complete")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.fsync(directory)
    except OSError as exc:
        raise PaymentJournalError("cannot durably persist private payment evidence") from exc


def _project(
    journal: OutgoingPaymentJournal, intent: OutgoingPaymentIntent, result: TrackResult
) -> RecordedTrack:
    snapshots = _snapshots(result, intent.payment_hash)
    # Internal collaborators: the journal rechecks its configured network and
    # backend identity against the on-disk metadata for every connection.
    envelope = {
        "format": FORMAT,
        "network_identity": json.loads(journal._network),  # noqa: SLF001
        "backend_identity": journal._backend_identity,  # noqa: SLF001
        "intent": _intent_evidence(intent),
        "completion": result.completion,
        "snapshots": snapshots,
    }
    evidence = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(evidence).hexdigest()
    observations = tuple(
        PaymentObservation(
            observation_id=hashlib.sha256(
                ROW_DOMAIN + bytes.fromhex(digest) + index.to_bytes(4, "big") + snap.status.encode()
            ).hexdigest(),
            idempotency_key=intent.idempotency_key,
            backend_identity=journal._backend_identity,  # noqa: SLF001
            backend_attempt_id=None,  # LND HTLC IDs are not Rill attempt IDs.
            reported_status="UNKNOWN" if snap.status == "INITIATED" else snap.status,
            evidence_sha256=digest,
        )
        for index, snap in enumerate(result.snapshots)
    )
    return RecordedTrack(evidence, observations)


def _intent_evidence(intent: OutgoingPaymentIntent) -> dict[str, object]:
    return {
        "idempotency_key": intent.idempotency_key,
        "swap_id": intent.swap_id,
        "attempt_id": intent.attempt_id,
        "terms_digest": intent.terms_digest,
        "payment_hash": intent.payment_hash,
        "destination_amount_msat": intent.destination_amount_msat,
        "fee_cap_msat": intent.fee_cap_msat,
        "absolute_cltv_height": intent.absolute_cltv_height,
        "max_absolute_cltv_height": intent.max_absolute_cltv_height,
        "route_format": intent.route_format,
        "route_sha256": hashlib.sha256(intent.route).hexdigest(),
        "route_bytes": len(intent.route),
    }
