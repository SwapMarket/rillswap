"""Reservation-only issuance never grants receipt, signing, or session admission."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from multiprocessing import get_context
from pathlib import Path

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.types import NetworkIdentity

from rill_provider import issuance_reservation
from rill_provider.handshake_store import HandshakePolicy, PreparedHandshakeStore, UnknownPrepared
from rill_provider.issuance_reservation import (
    IssuanceConflictError,
    IssuanceReservationError,
    IssuanceReservationStore,
)

FIXTURE = Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json"
PROVIDER = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def _context() -> tuple[NetworkIdentity, HandshakePolicy, dict[str, object]]:
    manifest = json.loads((FIXTURE.parent / "manifest.json").read_bytes())
    data = FIXTURE.read_bytes()
    assert hashlib.sha256(data).hexdigest() == manifest["sha256"]
    package = json.loads(data)
    init = package["verification_context"]["handshake_init"]
    network = NetworkIdentity.model_validate(package["network_identity"])
    policy = HandshakePolicy(
        profile="btc-to-ln/v1",
        features=frozenset(),
        encryption_suites=frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
        capabilities=frozenset({"core/v1", "recovery/v1"}),
    )
    envelope: dict[str, object] = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": package["profile_id"],
        "network_identity": package["network_identity"],
        "session_id": init["session_id"],
        "message_id": "12" * 32,
        "sender_session_key": init["client_session_xonly_key"],
        "sequence": 0,
        "in_reply_to": None,
        "contract_hash": None,
        "message_type": "handshake_init",
        "payload": init,
        "required_features": [],
        "extensions": {},
        "signature": None,
    }
    return network, policy, envelope


def _open(tmp_path: Path) -> tuple[IssuanceReservationStore, bytes]:
    network, policy, envelope = _context()
    return (
        IssuanceReservationStore.create_new(
            tmp_path / "issuance.sqlite", network, PROVIDER, policy
        ),
        canonicalize(envelope),
    )


def test_explicit_create_reopen_stable_retry_and_unknown_never_admits(tmp_path: Path) -> None:
    network, policy, envelope = _context()
    location = tmp_path / "issuance.sqlite"
    with pytest.raises(IssuanceReservationError, match="unavailable"):
        IssuanceReservationStore.open_existing(location, network, PROVIDER, policy)
    assert not location.exists()
    store = IssuanceReservationStore.create_new(location, network, PROVIDER, policy)
    raw = canonicalize(envelope)
    assert location.stat().st_mode & 0o777 == 0o600
    assert store.lookup(envelope["session_id"]) is None
    reservation = store.reserve_init(raw)
    assert reservation.revision == 0
    assert reservation.session_id == envelope["session_id"]
    assert reservation.init_message_id == envelope["message_id"]
    assert reservation.provider_challenge not in (
        reservation.session_id,
        envelope["payload"]["client_challenge"],
    )
    assert len(reservation.provider_challenge) == 64
    reopened = IssuanceReservationStore.open_existing(location, network, PROVIDER, policy)
    assert reopened.lookup(reservation.session_id) == reservation
    assert reopened.reserve_init(raw) == reservation
    assert reopened.lookup("ff" * 32) is None  # A restored copy could still be older.
    with pytest.raises(FileExistsError):
        IssuanceReservationStore.create_new(location, network, PROVIDER, policy)
    # The original prepared store remains an independent offline registry.
    prepared = PreparedHandshakeStore.create_new(tmp_path / "prepared.sqlite", network, PROVIDER)
    assert prepared.lookup_prepared(reservation.session_id) is UnknownPrepared.UNKNOWN


def test_conflicting_canonical_init_marks_session_blocked_across_restart(tmp_path: Path) -> None:
    store, raw = _open(tmp_path)
    reservation = store.reserve_init(raw)
    _, _, envelope = _context()
    envelope["message_id"] = "13" * 32
    with pytest.raises(IssuanceConflictError, match="durable"):
        store.reserve_init(canonicalize(envelope))
    with pytest.raises(IssuanceConflictError, match="durable"):
        store.reserve_init(raw)
    network, policy, _ = _context()
    reopened = IssuanceReservationStore.open_existing(store.path, network, PROVIDER, policy)
    with pytest.raises(IssuanceConflictError, match="durable"):
        reopened.lookup(reservation.session_id)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT state, revision FROM reservations WHERE session_id=?", (reservation.session_id,)
        ).fetchone() == ("CONFLICT", 1)


def test_unsigned_foreign_sender_collision_can_poison_reservation(tmp_path: Path) -> None:
    """Conservative availability cost, not evidence of client equivocation."""
    store, raw = _open(tmp_path)
    reserved = store.reserve_init(raw)
    _, _, envelope = _context()
    fixture = json.loads(FIXTURE.read_bytes())
    foreign = fixture["verification_context"]["handshake_accept"]["provider_session_xonly_key"]
    envelope["sender_session_key"] = foreign
    payload = deepcopy(envelope["payload"])
    payload["client_session_xonly_key"] = foreign
    envelope["payload"] = payload
    with pytest.raises(IssuanceConflictError, match="durable"):
        store.reserve_init(canonicalize(envelope))
    with pytest.raises(IssuanceConflictError, match="durable"):
        store.lookup(reserved.session_id)


def test_malformed_foreign_or_unsupported_input_never_reserves(tmp_path: Path) -> None:
    store, raw = _open(tmp_path)
    _, _, envelope = _context()
    variants = [
        b" " + raw,
        canonicalize({**envelope, "message_type": "handshake_accept"}),
        canonicalize({**envelope, "sequence": 1}),
        canonicalize({**envelope, "sender_session_key": PROVIDER}),
        canonicalize({**envelope, "signature": "00" * 64}),
    ]
    foreign = deepcopy(envelope)
    foreign["payload"]["expected_provider_identity_xonly_key"] = "11" * 32
    variants.append(canonicalize(foreign))
    for variant in variants:
        with pytest.raises(IssuanceReservationError, match="refused"):
            store.reserve_init(variant)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT count(*) FROM reservations").fetchone() == (0,)


def test_exact_concurrent_reservation_has_one_challenge(tmp_path: Path) -> None:
    store, raw = _open(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(store.reserve_init, [raw] * 8))
    assert results == [results[0]] * 8
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT count(*) FROM reservations").fetchone() == (1,)


def test_challenge_reuse_is_refused_and_regenerated_within_one_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, raw = _open(tmp_path)
    first = store.reserve_init(raw)
    _, _, envelope = _context()
    envelope["session_id"] = "ab" * 32
    envelope["message_id"] = "13" * 32
    payload = deepcopy(envelope["payload"])
    payload["session_id"] = envelope["session_id"]
    envelope["payload"] = payload
    challenges = iter([first.provider_challenge, payload["client_challenge"], "30" * 32])
    monkeypatch.setattr(issuance_reservation.secrets, "token_hex", lambda _size: next(challenges))
    second = store.reserve_init(canonicalize(envelope))
    assert second.provider_challenge == "30" * 32
    assert second.provider_challenge != first.provider_challenge
    assert store.lookup(first.session_id) == first


def test_corrupted_reservation_is_refused_without_echoing_stored_bytes(tmp_path: Path) -> None:
    store, raw = _open(tmp_path)
    record = store.reserve_init(raw)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE reservations SET init_sender_key=? WHERE session_id=?",
            (PROVIDER, record.session_id),
        )
    with pytest.raises(IssuanceReservationError, match="issuance lookup unavailable"):
        store.lookup(record.session_id)
    with pytest.raises(IssuanceReservationError, match="issuance reservation refused"):
        store.reserve_init(raw)


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("provider_challenge", "30" * 32),
        ("state", "CONFLICT"),
    ],
)
def test_valid_looking_logical_corruption_is_rejected_by_record_checksum(
    tmp_path: Path, column: str, replacement: str
) -> None:
    store, raw = _open(tmp_path)
    reserved = store.reserve_init(raw)
    assert replacement != reserved.provider_challenge
    with sqlite3.connect(store.path) as connection:
        if column == "state":
            connection.execute(
                "UPDATE reservations SET state=?, revision=1 WHERE session_id=?",
                (replacement, reserved.session_id),
            )
        else:
            connection.execute(
                "UPDATE reservations SET provider_challenge=? WHERE session_id=?",
                (replacement, reserved.session_id),
            )
    with pytest.raises(IssuanceReservationError, match="issuance lookup unavailable"):
        store.lookup(reserved.session_id)
    with pytest.raises(IssuanceReservationError, match="issuance reservation refused"):
        store.reserve_init(raw)


def test_unsupported_partial_foreign_and_restored_files_fail_closed(tmp_path: Path) -> None:
    store, raw = _open(tmp_path)
    network, policy, envelope = _context()
    older_copy = tmp_path / "older.sqlite"
    with sqlite3.connect(store.path) as source, sqlite3.connect(older_copy) as backup:
        source.backup(backup)
    assert store.reserve_init(raw).session_id == envelope["session_id"]
    restored = IssuanceReservationStore.open_existing(older_copy, network, PROVIDER, policy)
    assert restored.lookup(envelope["session_id"]) is None  # NOT fresh/unused.
    with pytest.raises(IssuanceReservationError, match="mismatch"):
        IssuanceReservationStore.open_existing(
            store.path, network, envelope["payload"]["client_session_xonly_key"], policy
        )
    other_network = network.model_copy(update={"deployment_namespace": "foreign"})
    with pytest.raises(IssuanceReservationError, match="mismatch"):
        IssuanceReservationStore.open_existing(store.path, other_network, PROVIDER, policy)
    other_policy = HandshakePolicy(
        policy.profile, frozenset({"new/v1"}), policy.encryption_suites, policy.capabilities
    )
    with pytest.raises(IssuanceReservationError, match="mismatch"):
        IssuanceReservationStore.open_existing(store.path, network, PROVIDER, other_policy)
    with sqlite3.connect(store.path) as connection:
        connection.execute("PRAGMA user_version=2")
    with pytest.raises(IssuanceReservationError, match="version"):
        IssuanceReservationStore.open_existing(store.path, network, PROVIDER, policy)
    partial = tmp_path / "partial.sqlite"
    partial.write_bytes(b"not a database")
    with pytest.raises(IssuanceReservationError):
        IssuanceReservationStore.open_existing(partial, network, PROVIDER, policy)


def _die_on_commit(path: str, raw: bytes, phase: str) -> None:
    network, policy, _ = _context()
    store = IssuanceReservationStore.open_existing(path, network, PROVIDER, policy)
    if phase == "before":
        original = sqlite3.connect

        class DieBeforeCommit(sqlite3.Connection):
            def commit(self) -> None:
                if self.in_transaction:
                    os._exit(0)
                super().commit()

        def connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            return original(*args, factory=DieBeforeCommit, **kwargs)

        # A separate process never mutates the parent test's sqlite3 module.
        sqlite3.connect = connect
    store.reserve_init(raw)
    os._exit(0)


@pytest.mark.parametrize("phase", ["before", "after"])
def test_crash_at_commit_boundary_never_returns_partial_reservation(
    tmp_path: Path, phase: str
) -> None:
    store, raw = _open(tmp_path)
    process = get_context("spawn").Process(
        target=_die_on_commit, args=(str(store.path), raw, phase)
    )
    process.start()
    process.join(timeout=15)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
    assert process.exitcode == 0
    network, policy, envelope = _context()
    reopened = IssuanceReservationStore.open_existing(store.path, network, PROVIDER, policy)
    result = reopened.lookup(envelope["session_id"])
    if phase == "before":
        assert result is None  # Still not proof the initiation was never seen.
    else:
        assert result is not None
        assert result.revision == 0
