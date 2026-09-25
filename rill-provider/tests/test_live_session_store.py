"""Authoritative handshake session store: ownership, exposure order, admission."""

from __future__ import annotations

import copy
import json
import multiprocessing
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import handshake_accept_hash, unsigned_envelope_hash
from rill_core.wire.messages import Envelope, HandshakeAccept
from rill_core.wire.types import NetworkIdentity

from rill_provider import live_session_store as live
from rill_provider.handshake_store import HandshakePolicy
from rill_provider.live_session_store import (
    AuthorityDeclaration,
    LiveSessionStore,
    LiveSessionStoreError,
    SessionBlockedError,
    StaleOwnerError,
)

FIXTURE = Path(__file__).parent / "fixtures" / "initial-btc-to-ln-v1.json"
CONFIRM_SIGNATURE = (
    "d8a7339977e4673e215e61339386e8208b0c6d1ecbe01621e985fe3d6c1399"
    "384f7b321a32c9ddf5363cb484e78561b3fb6aa65e686a076fcf95c7263a13c3bb"
)
POLICY = HandshakePolicy(
    profile="btc-to-ln/v1",
    features=frozenset(),
    encryption_suites=frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
    capabilities=frozenset({"core/v1", "recovery/v1"}),
)
AUTHORITY = AuthorityDeclaration("test-volume", outside_restore_domain=True, single_host=True)


def _envelopes() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = json.loads(FIXTURE.read_text())
    context = source["verification_context"]
    init, accepted = context["handshake_init"], context["handshake_accept"]
    shared = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": source["profile_id"],
        "network_identity": source["network_identity"],
        "session_id": init["session_id"],
        "contract_hash": None,
        "required_features": [],
        "extensions": {},
    }
    return source, [
        {
            **shared,
            "message_type": "handshake_init",
            "message_id": "12" * 32,
            "sender_session_key": init["client_session_xonly_key"],
            "sequence": 0,
            "in_reply_to": None,
            "payload": init,
            "signature": None,
        },
        {
            **shared,
            "message_type": "handshake_accept",
            "message_id": "14" * 32,
            "sender_session_key": accepted["provider_session_xonly_key"],
            "sequence": 0,
            "in_reply_to": "12" * 32,
            "payload": {
                "accept": accepted,
                "provider_identity_signature": context["provider_identity_signature"],
            },
            "signature": None,
        },
        {
            **shared,
            "message_type": "handshake_confirm",
            "message_id": "13" * 32,
            "sender_session_key": init["client_session_xonly_key"],
            "sequence": 1,
            "in_reply_to": "14" * 32,
            "payload": {
                "handshake_hash": context["handshake_hash"],
                "session_id": init["session_id"],
                "client_session_xonly_key": init["client_session_xonly_key"],
                "provider_session_xonly_key": accepted["provider_session_xonly_key"],
            },
            "signature": CONFIRM_SIGNATURE,
        },
    ]


def _bytes(envelope: dict[str, Any]) -> bytes:
    return canonicalize(envelope)


class PinnedCrypto:
    """Accepts exactly the fixture signatures plus explicitly added ones."""

    def __init__(self, source: dict[str, Any], envelopes: list[dict[str, Any]]) -> None:
        context = source["verification_context"]
        selected = HandshakeAccept.model_validate_json(json.dumps(context["handshake_accept"]))
        self.permitted = {
            (
                bytes.fromhex(selected.provider_identity_xonly_key),
                handshake_accept_hash(selected),
                bytes.fromhex(context["provider_identity_signature"]),
            ),
        }
        self.permit_confirm(envelopes[2])

    def permit_confirm(self, confirm: dict[str, Any]) -> None:
        envelope = Envelope.model_validate_json(json.dumps(confirm))
        self.permitted.add(
            (
                bytes.fromhex(envelope.sender_session_key),
                unsigned_envelope_hash(envelope),
                bytes.fromhex(envelope.signature or ""),
            )
        )

    def schnorr_verify(self, key: bytes, digest: bytes, signature: bytes) -> None:
        if (key, digest, signature) not in self.permitted:
            raise ValueError("signature not permitted")


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.source, self.envelopes = _envelopes()
        self.crypto = PinnedCrypto(self.source, self.envelopes)
        init = self.source["verification_context"]["handshake_init"]
        self.network = NetworkIdentity.model_validate_json(json.dumps(init["network_identity"]))
        self.identity = init["expected_provider_identity_xonly_key"]
        self.path = tmp_path / "live.sqlite"
        challenge = self.source["verification_context"]["handshake_accept"]["provider_challenge"]
        monkeypatch.setattr(
            "rill_provider.live_session_store.secrets.token_hex", lambda _n: challenge
        )
        self.init, self.accept, self.confirm = (_bytes(e) for e in self.envelopes)

    def provision(self) -> None:
        LiveSessionStore.provision(self.path, self.network, self.identity, POLICY, AUTHORITY)

    def acquire(self) -> LiveSessionStore:
        return LiveSessionStore.acquire(
            self.path, self.network, self.identity, POLICY, crypto=self.crypto
        )


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


def test_absent_store_and_failed_attestation_never_create_state(harness: Harness) -> None:
    with pytest.raises(LiveSessionStoreError):
        harness.acquire()
    assert list(harness.path.parent.iterdir()) == []
    for bad in (
        AuthorityDeclaration("vol", outside_restore_domain=False, single_host=True),
        AuthorityDeclaration("vol", outside_restore_domain=True, single_host=False),
        AuthorityDeclaration("", outside_restore_domain=True, single_host=True),
    ):
        with pytest.raises(LiveSessionStoreError, match="attestation"):
            LiveSessionStore.provision(harness.path, harness.network, harness.identity, POLICY, bad)
    assert list(harness.path.parent.iterdir()) == []


def test_provision_is_exclusive_and_partial_files_refuse(harness: Harness) -> None:
    harness.provision()
    with pytest.raises(LiveSessionStoreError):
        harness.provision()
    other = harness.path.parent / "partial.sqlite"
    (harness.path.parent / ("partial.sqlite" + live.LOCK_SUFFIX)).write_bytes(b"")
    with pytest.raises(LiveSessionStoreError):
        LiveSessionStore.provision(other, harness.network, harness.identity, POLICY, AUTHORITY)
    other.write_bytes(b"")
    with pytest.raises(LiveSessionStoreError):
        LiveSessionStore.acquire(
            other, harness.network, harness.identity, POLICY, crypto=harness.crypto
        )


def test_full_handshake_commits_accept_before_exposure_and_admits_confirm(
    harness: Harness,
) -> None:
    harness.provision()
    with harness.acquire() as store:
        reserved = store.reserve(harness.init)
        expected = harness.source["verification_context"]["handshake_accept"]
        assert reserved.provider_challenge == expected["provider_challenge"]
        assert store.reserve(harness.init) == reserved
        assert store.pending_outbox() == ()
        with pytest.raises(LiveSessionStoreError, match="no committed accept"):
            store.admit_confirm(harness.confirm)
        committed = store.commit_accept(harness.accept)
        assert committed.canonical_bytes == harness.accept
        assert (
            committed.transcript_digest == harness.source["verification_context"]["handshake_hash"]
        )
        assert store.commit_accept(harness.accept) == committed
        assert [e.canonical_bytes for e in store.pending_outbox()] == [harness.accept]
        admitted = store.admit_confirm(harness.confirm)
        assert not admitted.replay
        assert admitted.revision == committed.revision + 1
        assert store.pending_outbox() == ()
        replay = store.admit_confirm(harness.confirm)
        assert replay.replay
        assert (replay.message_id, replay.revision) == (admitted.message_id, admitted.revision)
    with harness.acquire() as store:  # durable across owners
        assert store.admit_confirm(harness.confirm).replay


def test_accept_must_match_reserved_challenge_and_is_atomic(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        with pytest.raises(LiveSessionStoreError, match="no reservation"):
            store.commit_accept(harness.accept)
        store.reserve(harness.init)
        tampered = copy.deepcopy(harness.envelopes[1])
        tampered["payload"]["provider_identity_signature"] = "00" * 64
        with pytest.raises(LiveSessionStoreError, match="refused"):
            store.commit_accept(_bytes(tampered))
        with pytest.raises(LiveSessionStoreError, match="canonical"):
            store.commit_accept(json.dumps(harness.envelopes[1], indent=1).encode())
        assert store.pending_outbox() == ()
        store.commit_accept(harness.accept)
        different = copy.deepcopy(harness.envelopes[1])
        different["message_id"] = "15" * 32
        with pytest.raises(LiveSessionStoreError, match="already committed"):
            store.commit_accept(_bytes(different))
        assert len(store.pending_outbox()) == 1


def test_unverifiable_confirm_leaves_no_record(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        store.reserve(harness.init)
        store.commit_accept(harness.accept)
        forged = copy.deepcopy(harness.envelopes[2])
        forged["signature"] = "11" * 64
        with pytest.raises(LiveSessionStoreError, match="refused"):
            store.admit_confirm(_bytes(forged))
        assert len(store.pending_outbox()) == 1
        assert not store.admit_confirm(harness.confirm).replay


def test_signed_confirm_equivocation_blocks_session_durably(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        store.reserve(harness.init)
        store.commit_accept(harness.accept)
        store.admit_confirm(harness.confirm)
        second = copy.deepcopy(harness.envelopes[2])
        second["message_id"] = "16" * 32
        second["signature"] = "22" * 64
        harness.crypto.permit_confirm(second)
        with pytest.raises(SessionBlockedError):
            store.admit_confirm(_bytes(second))
        with pytest.raises(SessionBlockedError):
            store.admit_confirm(harness.confirm)
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("SELECT kind FROM conflicts").fetchall() == [("confirm",)]


def test_conflicting_unsigned_init_blocks_before_any_accept(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        store.reserve(harness.init)
        other = copy.deepcopy(harness.envelopes[0])
        other["message_id"] = "17" * 32
        with pytest.raises(SessionBlockedError):
            store.reserve(_bytes(other))
        with pytest.raises(SessionBlockedError):
            store.reserve(harness.init)
        with pytest.raises(SessionBlockedError):
            store.commit_accept(harness.accept)
        assert store.pending_outbox() == ()


def test_untrusted_init_is_refused_without_state(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        wrong = copy.deepcopy(harness.envelopes[0])
        wrong["sequence"] = 1
        with pytest.raises(LiveSessionStoreError, match="unsupported handshake initiation"):
            store.reserve(_bytes(wrong))
        store.reserve(harness.init)


def _child_acquire(path: str, network_json: str, identity: str, queue: Any) -> None:  # noqa: ANN401
    try:
        LiveSessionStore.acquire(
            path,
            NetworkIdentity.model_validate_json(network_json),
            identity,
            POLICY,
            crypto=object(),  # type: ignore[arg-type]
        ).close()
    except LiveSessionStoreError as error:
        queue.put(str(error))
    else:
        queue.put("acquired")


def test_single_owner_across_processes_and_no_takeover(harness: Harness) -> None:
    harness.provision()
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    arguments = (str(harness.path), harness.network.model_dump_json(), harness.identity, queue)
    with harness.acquire():
        child = context.Process(target=_child_acquire, args=arguments)
        child.start()
        child.join(30)
        assert queue.get(timeout=5) == "store owned by another process"
        with pytest.raises(LiveSessionStoreError, match="owned by another"):
            harness.acquire()
    child = context.Process(target=_child_acquire, args=arguments)
    child.start()
    child.join(30)
    assert queue.get(timeout=5) == "acquired"


def test_generation_advances_and_stale_or_closed_handle_cannot_write(harness: Harness) -> None:
    harness.provision()
    store = harness.acquire()
    first = store.generation
    store.close()
    with pytest.raises(StaleOwnerError):
        store.reserve(harness.init)
    store = harness.acquire()
    assert store.generation == first + 1
    with sqlite3.connect(harness.path) as connection:  # simulates a broken lock
        connection.execute("UPDATE meta SET generation=generation+1")
    with pytest.raises(StaleOwnerError):
        store.reserve(harness.init)
    with pytest.raises(StaleOwnerError):
        store.pending_outbox()
    store.close()
    with harness.acquire() as fresh, sqlite3.connect(harness.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone() == (0,)
        assert fresh.generation == first + 3


def test_copied_or_file_restored_store_is_not_authoritative(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        store.reserve(harness.init)
    copy_dir = harness.path.parent / "copy"
    copy_dir.mkdir()
    shutil.copy2(harness.path, copy_dir / harness.path.name)
    shutil.copy2(
        harness.path.with_name(harness.path.name + live.LOCK_SUFFIX),
        copy_dir / (harness.path.name + live.LOCK_SUFFIX),
    )
    with pytest.raises(LiveSessionStoreError, match="not the provisioned authoritative copy"):
        LiveSessionStore.acquire(
            copy_dir / harness.path.name,
            harness.network,
            harness.identity,
            POLICY,
            crypto=harness.crypto,
        )
    restored = harness.path.read_bytes()
    harness.path.rename(harness.path.with_name("original-kept-allocated"))
    harness.path.write_bytes(restored)  # distinct inode, as a file-level restore produces
    with pytest.raises(LiveSessionStoreError, match="not the provisioned authoritative copy"):
        harness.acquire()


def test_namespace_or_policy_mismatch_refuses(harness: Harness) -> None:
    harness.provision()
    other_policy = HandshakePolicy(
        profile="btc-to-ln/v1",
        features=frozenset(),
        encryption_suites=POLICY.encryption_suites,
        capabilities=frozenset({"core/v1"}),
    )
    with pytest.raises(LiveSessionStoreError, match="mismatch"):
        LiveSessionStore.acquire(
            harness.path, harness.network, harness.identity, other_policy, crypto=harness.crypto
        )
    with pytest.raises(LiveSessionStoreError, match="mismatch"):
        LiveSessionStore.acquire(
            harness.path, harness.network, "02" * 32, POLICY, crypto=harness.crypto
        )


def test_resigned_identical_confirm_is_replay_not_equivocation(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        store.reserve(harness.init)
        store.commit_accept(harness.accept)
        first = store.admit_confirm(harness.confirm)
        resigned = copy.deepcopy(harness.envelopes[2])
        resigned["signature"] = "33" * 64  # BIP340 permits many valid signatures
        harness.crypto.permit_confirm(resigned)
        replay = store.admit_confirm(_bytes(resigned))
        assert replay.replay
        assert (replay.message_id, replay.revision) == (first.message_id, first.revision)
        assert store.admit_confirm(harness.confirm).replay
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM conflicts").fetchone() == (0,)
        assert connection.execute("SELECT canonical_bytes FROM inbox").fetchall() == [
            (harness.confirm,)
        ]


def _forked_child(store: LiveSessionStore, init: bytes, queue: Any) -> None:  # noqa: ANN401
    try:
        store.reserve(init)
    except StaleOwnerError as error:
        queue.put(str(error))
    else:
        queue.put("wrote")
    store.close()


def test_handle_inherited_across_fork_cannot_act_or_release_parent(harness: Harness) -> None:
    harness.provision()
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    with harness.acquire() as store:
        child = context.Process(target=_forked_child, args=(store, harness.init, queue))
        child.start()
        child.join(30)
        assert queue.get(timeout=5) == "store handle inherited across fork; reacquire"
        with pytest.raises(LiveSessionStoreError, match="owned by another"):
            harness.acquire()  # the child's close did not release our lock
        assert store.reserve(harness.init).revision == 0


class _FailingCommit:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:  # noqa: ANN401
        if sql == "COMMIT":
            raise sqlite3.OperationalError("disk I/O error")
        return self._connection.execute(sql, *args)

    def close(self) -> None:
        self._connection.close()


def test_uncertain_commit_releases_ownership(harness: Harness) -> None:
    harness.provision()
    store = harness.acquire()
    store._connection = _FailingCommit(store._connection)  # type: ignore[assignment]  # noqa: SLF001
    with pytest.raises(StaleOwnerError, match="uncertain"):
        store.reserve(harness.init)
    with pytest.raises(StaleOwnerError):
        store.reserve(harness.init)
    with harness.acquire() as fresh:  # released; the truth is re-read by a new owner
        assert fresh.reserve(harness.init).revision == 0


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("store_uuid", "not-a-uuid"),
        (
            "authority_jcs",
            b'{"outside_restore_domain":false,"single_host":true,"volume_label":"v"}',
        ),
        ("authority_jcs", b"{}"),
    ],
)
def test_untrusted_provisioning_metadata_refuses(
    harness: Harness, column: str, value: object
) -> None:
    harness.provision()
    with sqlite3.connect(harness.path) as connection:
        connection.execute(f"UPDATE meta SET {column}=?", (value,))  # noqa: S608 - fixed names
    with pytest.raises(LiveSessionStoreError, match="provisioning metadata untrusted"):
        harness.acquire()


def test_foreign_sqlite_file_is_not_modified(harness: Harness) -> None:
    harness.provision()
    harness.path.rename(harness.path.with_name("provisioned-aside"))
    with sqlite3.connect(harness.path) as connection:
        connection.execute("CREATE TABLE unrelated (x)")
    connection.close()
    before = harness.path.read_bytes()
    with pytest.raises(LiveSessionStoreError, match="version unsupported"):
        harness.acquire()
    assert harness.path.read_bytes() == before
    assert not harness.path.with_name(harness.path.name + "-wal").exists()
