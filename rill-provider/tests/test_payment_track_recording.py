"""Read-only tracking facts do not establish execution of a declared route."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider import payment_track_recording
from rill_provider.lnd_payment_observation import (
    HtlcAttemptSnapshot,
    LndPaymentObserver,
    LndUnavailableError,
    PaymentSnapshot,
    TrackResult,
)
from rill_provider.payment_journal import (
    OutgoingPaymentIntent,
    OutgoingPaymentJournal,
    PaymentJournalConflictError,
    PaymentJournalError,
)
from rill_provider.payment_track_recording import record_payment_track
from scripts import record_lnd_payment_track as command

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

HASH = "14" * 32
KEY = "10" * 32


def _network() -> NetworkIdentity:
    return NetworkIdentity.model_validate(
        {
            "family": "bitcoin",
            "name": "regtest",
            "genesis_hash": "11" * 32,
            "signet_challenge": None,
            "consensus_profile": "bitcoin-core-v30.0-regtest-default",
            "deployment_namespace": "recording-a",
        }
    )


def _intent() -> OutgoingPaymentIntent:
    return OutgoingPaymentIntent(
        idempotency_key=KEY,
        swap_id="11" * 32,
        attempt_id="12" * 32,
        terms_digest="13" * 32,
        payment_hash=HASH,
        destination_amount_msat=100_000,
        fee_cap_msat=1_000,
        absolute_cltv_height=1050,
        max_absolute_cltv_height=1070,
        route_format="test-route/v1",
        route=b"SECRET ROUTE BYTES",
    )


def _journal(tmp_path: Path) -> OutgoingPaymentJournal:
    journal = OutgoingPaymentJournal.create(tmp_path / "payment.sqlite3", _network(), "node-alpha")
    journal.record_intent(_intent())
    return journal


def _snap(
    status: str = "FAILED", attempts: tuple[HtlcAttemptSnapshot, ...] = ()
) -> PaymentSnapshot:
    return PaymentSnapshot(HASH, status, attempts)  # type: ignore[arg-type]


class StubObserver(LndPaymentObserver):
    def __init__(
        self, result: TrackResult | Exception, during_track: Callable[[], None] | None = None
    ) -> None:
        self.result = result
        self.during_track = during_track
        self.calls: list[bytes] = []

    def track(self, payment_hash: bytes, *, deadline_seconds: float = 10) -> TrackResult:
        assert deadline_seconds == 10
        self.calls.append(payment_hash)
        if self.during_track:
            self.during_track()
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_durable_projection_replays_without_duplicating_and_keeps_conflicts(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    first = StubObserver(
        TrackResult(
            "terminal",
            (
                _snap("INITIATED"),
                _snap("IN_FLIGHT", (HtlcAttemptSnapshot(71, "IN_FLIGHT"),)),
                _snap("FAILED"),  # LND may have pruned failed attempt history.
            ),
        )
    )
    evidence_path = tmp_path / "evidence-1.json"
    recorded = record_payment_track(journal, KEY, first, evidence_path)
    assert evidence_path.read_bytes() == recorded.evidence
    assert evidence_path.stat().st_mode & 0o777 == 0o600
    assert first.calls == [bytes.fromhex(HASH)]
    assert [row.reported_status for row in recorded.observations] == [
        "UNKNOWN",
        "IN_FLIGHT",
        "FAILED",
    ]
    assert all(row.backend_attempt_id is None for row in recorded.observations)
    evidence = json.loads(recorded.evidence)
    assert evidence["network_identity"] == _network().model_dump(mode="json")
    assert evidence["intent"]["route_sha256"] == hashlib.sha256(_intent().route).hexdigest()
    assert evidence["snapshots"][1]["htlcs"] == [{"lnd_attempt_id": 71, "status": "IN_FLIGHT"}]
    assert b"SECRET ROUTE BYTES" not in recorded.evidence
    assert all(
        row.evidence_sha256 == hashlib.sha256(recorded.evidence).hexdigest()
        for row in recorded.observations
    )
    reopened = OutgoingPaymentJournal.open_existing(journal.path, _network(), "node-alpha")
    assert record_payment_track(reopened, KEY, first, tmp_path / "evidence-2.json") == recorded
    assert reopened.list_observations(KEY) == recorded.observations
    conflicting = StubObserver(TrackResult("terminal", (_snap("SUCCEEDED"),)))
    changed = record_payment_track(reopened, KEY, conflicting, tmp_path / "evidence-3.json")
    assert changed.observations[0].observation_id not in {
        row.observation_id for row in recorded.observations
    }
    assert reopened.list_observations(KEY) == (*recorded.observations, *changed.observations)


def test_missing_or_replaced_intent_never_records_external_report(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    observer = StubObserver(TrackResult("terminal", (_snap(),)))
    with pytest.raises(PaymentJournalError, match="intent missing"):
        record_payment_track(journal, "15" * 32, observer, tmp_path / "no-intent.json")
    assert observer.calls == []

    def replace_route() -> None:
        with sqlite3.connect(journal.path) as connection:
            connection.execute(
                "UPDATE intents SET route=? WHERE idempotency_key=?", (b"restored route", KEY)
            )

    observer.during_track = replace_route
    with pytest.raises(PaymentJournalConflictError, match="intent differs"):
        record_payment_track(journal, KEY, observer, tmp_path / "restored.json")
    assert (tmp_path / "restored.json").read_bytes()
    assert journal.list_observations(KEY) == ()


def test_malformed_or_failed_tracking_never_invents_evidence(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    cases: tuple[TrackResult | Exception, ...] = (
        LndUnavailableError("tracking unavailable; no absence claim"),
        TrackResult("terminal", (replace(_snap(), payment_hash="20" * 32),)),
        TrackResult("terminal", (_snap("INITIATED"),)),
        TrackResult("update-limit", (_snap("IN_FLIGHT"),)),
        TrackResult("terminal", ()),
    )
    for index, case in enumerate(cases):
        with pytest.raises((LndUnavailableError, PaymentJournalError)):
            record_payment_track(journal, KEY, StubObserver(case), tmp_path / f"bad-{index}.json")
        assert (tmp_path / f"bad-{index}.json").read_bytes() == b""
    assert journal.list_observations(KEY) == ()


def test_update_limit_is_incomplete_not_failed_or_permission(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    result = TrackResult("update-limit", tuple(_snap("IN_FLIGHT") for _ in range(16)))
    saved = record_payment_track(journal, KEY, StubObserver(result), tmp_path / "limit.json")
    assert len(saved.observations) == 16
    assert all(row.reported_status == "IN_FLIGHT" for row in saved.observations)
    assert json.loads(saved.evidence)["completion"] == "update-limit"


def test_evidence_reservation_refuses_existing_or_public_location_before_rpc(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path)
    observer = StubObserver(TrackResult("terminal", (_snap(),)))
    taken = tmp_path / "taken.json"
    taken.write_bytes(b"partial or unrelated")
    with pytest.raises(PaymentJournalError, match="reserve private payment evidence"):
        record_payment_track(journal, KEY, observer, taken)
    assert observer.calls == []
    assert taken.read_bytes() == b"partial or unrelated"
    unsafe = tmp_path / "public"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(PaymentJournalError, match="private and owned"):
        record_payment_track(journal, KEY, observer, unsafe / "report.json")
    assert observer.calls == []
    assert journal.list_observations(KEY) == ()


def test_evidence_sync_failure_blocks_append_and_retains_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = _journal(tmp_path)
    path = tmp_path / "failed-sync.json"

    def fail_sync(_descriptor: int) -> None:
        raise OSError("filesystem failure (never expose details)")

    monkeypatch.setattr(payment_track_recording.os, "fsync", fail_sync)
    with pytest.raises(
        PaymentJournalError, match="cannot durably persist private payment evidence"
    ):
        record_payment_track(journal, KEY, StubObserver(TrackResult("terminal", (_snap(),))), path)
    assert path.read_bytes()  # untrusted partial evidence remains for diagnosis
    assert journal.list_observations(KEY) == ()


def test_directory_sync_failure_blocks_append_and_keeps_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = _journal(tmp_path)
    original_fsync = payment_track_recording.os.fsync
    calls = 0

    def fail_second_sync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("do not expose filesystem details")
        original_fsync(descriptor)

    monkeypatch.setattr(payment_track_recording.os, "fsync", fail_second_sync)
    path = tmp_path / "directory-sync-failed.json"
    with pytest.raises(
        PaymentJournalError, match="cannot durably persist private payment evidence"
    ):
        record_payment_track(journal, KEY, StubObserver(TrackResult("terminal", (_snap(),))), path)
    assert calls == 2
    assert json.loads(path.read_bytes())["format"] == "rillswap-lnd-payment-report/v1"
    assert journal.list_observations(KEY) == ()


def test_evidence_symlinks_refused_before_observation(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    observer = StubObserver(TrackResult("terminal", (_snap(),)))
    target = tmp_path / "target.json"
    link = tmp_path / "linked.json"
    link.symlink_to(target)
    with pytest.raises(PaymentJournalError, match="reserve private payment evidence"):
        record_payment_track(journal, KEY, observer, link)
    linked_directory = tmp_path / "linked-dir"
    linked_directory.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(PaymentJournalError, match="reserve private payment evidence"):
        record_payment_track(journal, KEY, observer, linked_directory / "new.json")
    assert observer.calls == []
    assert not target.exists()
    assert journal.list_observations(KEY) == ()


def test_evidence_write_failure_blocks_append_and_retains_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = _journal(tmp_path)
    real_write = payment_track_recording.os.write
    writes = 0

    def fail_after_short_write(descriptor: int, content: memoryview) -> int:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("private bytes must not leak")
        return real_write(descriptor, content[:4])

    monkeypatch.setattr(payment_track_recording.os, "write", fail_after_short_write)
    path = tmp_path / "short.json"
    with pytest.raises(
        PaymentJournalError, match="cannot durably persist private payment evidence"
    ):
        record_payment_track(journal, KEY, StubObserver(TrackResult("terminal", (_snap(),))), path)
    assert len(path.read_bytes()) == 4
    assert journal.list_observations(KEY) == ()


def test_operator_command_requires_existing_journal_and_saves_private_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    network_file = tmp_path / "network.json"
    network_file.write_text(_network().model_dump_json())
    journal_file = tmp_path / "payment.sqlite3"
    evidence_file = tmp_path / "operator-report.json"
    arguments = [
        "--journal",
        str(journal_file),
        "--network-identity",
        str(network_file),
        "--backend-identity",
        "node-alpha",
        "--idempotency-key",
        KEY,
        "--lnd-host",
        "127.0.0.1",
        "--lnd-port",
        "10009",
        "--tls-cert",
        str(tmp_path / "cert"),
        "--read-macaroon",
        str(tmp_path / "read"),
        "--evidence-out",
        str(evidence_file),
    ]
    assert command.main(arguments) == 2
    assert not evidence_file.exists()
    assert capsys.readouterr().err == (
        "Payment observation unavailable or unrecorded; no action authority\n"
    )
    journal = _journal(tmp_path)
    observer = StubObserver(TrackResult("terminal", (_snap(),)))
    monkeypatch.setattr(command, "LndPaymentObserver", lambda **_config: observer)
    assert command.main(arguments) == 0
    output = capsys.readouterr()
    assert output.out == "Recorded 1 diagnostic observations; no action authority\n"
    assert output.err == ""
    assert hashlib.sha256(evidence_file.read_bytes()).hexdigest() == (
        journal.list_observations(KEY)[0].evidence_sha256
    )
    assert command.main(arguments) == 2  # exclusive evidence path, no second RPC
    assert observer.calls == [bytes.fromhex(HASH)]
