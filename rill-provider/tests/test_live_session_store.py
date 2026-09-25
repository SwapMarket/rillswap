"""Authoritative handshake session store: ownership, exposure order, admission."""

from __future__ import annotations

import copy
import json
import multiprocessing
import os
import shutil
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pyrage  # type: ignore[import-untyped]
import pytest
from pyrage import x25519
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

if TYPE_CHECKING:
    from rill_provider.provider_identity import ProviderIdentity

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
SESSION_SECRET = (3).to_bytes(32, "big")  # Fixture-only public scalar of the fixture session key.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


class PurePublicKeys:
    """Test-only affine secp256k1 derivation (not constant time, never deploy)."""

    def public_key(self, secret_key: bytes) -> bytes:
        scalar = int.from_bytes(secret_key, "big")
        if not 0 < scalar < N:
            raise ValueError("invalid scalar")
        result: tuple[int, int] | None = None
        addend: tuple[int, int] | None = G
        while scalar:
            if scalar & 1:
                result = _add(result, addend)
            addend = _add(addend, addend)
            scalar >>= 1
        assert result is not None
        return bytes([2 + (result[1] & 1)]) + result[0].to_bytes(32, "big")


def _add(a: tuple[int, int] | None, b: tuple[int, int] | None) -> tuple[int, int] | None:
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (slope * slope - a[0] - b[0]) % P
    return x, (slope * (a[0] - x) - a[1]) % P


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
        monkeypatch.setattr(live, "_new_challenge", lambda: challenge)
        self.scalar = SESSION_SECRET
        monkeypatch.setattr(live, "_new_session_scalar", lambda: self.scalar)
        self.custody = x25519.Identity.generate()
        self.init, self.accept, self.confirm = (_bytes(e) for e in self.envelopes)

    def provision(self) -> None:
        LiveSessionStore.provision(
            self.path,
            self.network,
            self.identity,
            POLICY,
            AUTHORITY,
            custody_recipient=str(self.custody.to_public()),
        )

    def acquire(self) -> LiveSessionStore:
        return self.acquire_at(self.path)

    def acquire_at(self, path: Path, **changed: Any) -> LiveSessionStore:  # noqa: ANN401
        arguments: dict[str, Any] = {
            "crypto": self.crypto,
            "custody_identity": str(self.custody),
            "public_keys": PurePublicKeys(),
        }
        arguments.update(changed)
        return LiveSessionStore.acquire(path, self.network, self.identity, POLICY, **arguments)


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
            LiveSessionStore.provision(
                harness.path,
                harness.network,
                harness.identity,
                POLICY,
                bad,
                custody_recipient=str(harness.custody.to_public()),
            )
    assert list(harness.path.parent.iterdir()) == []


def test_provision_is_exclusive_and_partial_files_refuse(harness: Harness) -> None:
    harness.provision()
    with pytest.raises(LiveSessionStoreError):
        harness.provision()
    other = harness.path.parent / "partial.sqlite"
    (harness.path.parent / ("partial.sqlite" + live.LOCK_SUFFIX)).write_bytes(b"")
    with pytest.raises(LiveSessionStoreError):
        LiveSessionStore.provision(
            other,
            harness.network,
            harness.identity,
            POLICY,
            AUTHORITY,
            custody_recipient=str(harness.custody.to_public()),
        )
    other.write_bytes(b"")
    with pytest.raises(LiveSessionStoreError):
        harness.acquire_at(other)


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


def _child_acquire(
    path: str,
    network_json: str,
    identity: str,
    custody: str,
    queue: Any,  # noqa: ANN401
) -> None:
    try:
        LiveSessionStore.acquire(
            path,
            NetworkIdentity.model_validate_json(network_json),
            identity,
            POLICY,
            crypto=object(),  # type: ignore[arg-type]
            custody_identity=custody,
            public_keys=PurePublicKeys(),
        ).close()
    except LiveSessionStoreError as error:
        queue.put(str(error))
    else:
        queue.put("acquired")


def test_single_owner_across_processes_and_no_takeover(harness: Harness) -> None:
    harness.provision()
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    arguments = (
        str(harness.path),
        harness.network.model_dump_json(),
        harness.identity,
        str(harness.custody),
        queue,
    )
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
        harness.acquire_at(copy_dir / harness.path.name)
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
            harness.path,
            harness.network,
            harness.identity,
            other_policy,
            crypto=harness.crypto,
            custody_identity=str(harness.custody),
            public_keys=PurePublicKeys(),
        )
    with pytest.raises(LiveSessionStoreError, match="mismatch"):
        LiveSessionStore.acquire(
            harness.path,
            harness.network,
            "02" * 32,
            POLICY,
            crypto=harness.crypto,
            custody_identity=str(harness.custody),
            public_keys=PurePublicKeys(),
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


def test_reservation_binds_encrypted_session_key_and_accept_must_use_it(
    harness: Harness,
) -> None:
    harness.provision()
    fixture_key = harness.source["verification_context"]["handshake_accept"][
        "provider_session_xonly_key"
    ]
    with harness.acquire() as store:
        reserved = store.reserve(harness.init)
        assert reserved.provider_session_key == fixture_key
        assert store.reserve(harness.init) == reserved
    stored = (
        harness.path.read_bytes() + harness.path.with_name(harness.path.name + "-wal").read_bytes()
        if harness.path.with_name(harness.path.name + "-wal").exists()
        else (harness.path.read_bytes())
    )
    assert SESSION_SECRET.hex().encode() not in stored
    with sqlite3.connect(harness.path) as connection:
        sealed = connection.execute("SELECT session_secret_age FROM sessions").fetchone()[0]
    record = json.loads(pyrage.decrypt(sealed, [harness.custody]))
    assert record["secret_scalar"] == SESSION_SECRET.hex()
    assert record["session_id"] == reserved.session_id
    assert record["provider_challenge"] == reserved.provider_challenge


def test_accept_for_a_different_session_key_is_refused(harness: Harness) -> None:
    harness.provision()
    harness.scalar = (5).to_bytes(32, "big")
    with harness.acquire() as store:
        reserved = store.reserve(harness.init)
        assert (
            reserved.provider_session_key
            != (
                harness.source["verification_context"]["handshake_accept"][
                    "provider_session_xonly_key"
                ]
            )
        )
        with pytest.raises(LiveSessionStoreError, match="not the reserved custody key"):
            store.commit_accept(harness.accept)
        assert store.pending_outbox() == ()


def test_wrong_custody_credential_refuses_ownership(harness: Harness) -> None:
    harness.provision()
    with pytest.raises(LiveSessionStoreError, match="custody identity does not match"):
        harness.acquire_at(harness.path, custody_identity=str(x25519.Identity.generate()))
    with pytest.raises(LiveSessionStoreError, match="custody identity malformed"):
        harness.acquire_at(harness.path, custody_identity="AGE-SECRET-KEY-NOPE")
    with harness.acquire():
        pass  # the refused attempts did not leave the lock held


def test_substituted_or_corrupt_custody_is_never_replaced(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        store.reserve(harness.init)
    with sqlite3.connect(harness.path) as connection:
        sealed = connection.execute("SELECT session_secret_age FROM sessions").fetchone()[0]
        record = json.loads(pyrage.decrypt(sealed, [harness.custody]))
        record["provider_challenge"] = "ab" * 32  # authentic age, wrong placement
        forged = pyrage.encrypt(canonicalize(record), [harness.custody.to_public()])
        connection.execute("UPDATE sessions SET session_secret_age=?", (forged,))
    with harness.acquire() as store:
        with pytest.raises(LiveSessionStoreError, match="custody unavailable"):
            store.reserve(harness.init)
        with pytest.raises(LiveSessionStoreError, match="custody unavailable"):
            store.commit_accept(harness.accept)
        assert store.pending_outbox() == ()
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("SELECT session_secret_age FROM sessions").fetchone() == (forged,)
        connection.execute("UPDATE sessions SET session_secret_age=?", (b"garbage",))
    with harness.acquire() as store, pytest.raises(LiveSessionStoreError, match="custody"):
        store.commit_accept(harness.accept)


def test_schema_v1_store_is_refused_unchanged(harness: Harness) -> None:
    harness.provision()
    harness.path.rename(harness.path.with_name("provisioned-aside"))
    with sqlite3.connect(harness.path) as connection:
        connection.execute(f"PRAGMA application_id={live.APPLICATION_ID}")
        connection.execute("PRAGMA user_version=1")
        connection.execute("CREATE TABLE meta (x)")
    connection.close()
    before = harness.path.read_bytes()
    with pytest.raises(LiveSessionStoreError, match="version unsupported"):
        harness.acquire()
    assert harness.path.read_bytes() == before


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_native_crypto_full_handshake_with_real_custody_derivation(harness: Harness) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
        reserved = store.reserve(harness.init)
        assert (
            reserved.provider_session_key == PurePublicKeys().public_key(SESSION_SECRET)[1:].hex()
        )
        committed = store.commit_accept(harness.accept)
        admitted = store.admit_confirm(harness.confirm)
        assert admitted.transcript_digest == committed.transcript_digest
        resigned = copy.deepcopy(harness.envelopes[2])
        resigned["signature"] = "00" * 64
        with pytest.raises(LiveSessionStoreError):
            store.admit_confirm(_bytes(resigned))  # real verification refuses


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_native_handshake_over_nip59_session_mailboxes(harness: Harness) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    from rill_provider._nip59_receive import _decode_gift_wrap_candidate  # noqa: PLC0415
    from rill_provider._nip59_send import _wrap_envelope  # noqa: PLC0415

    client_secret = (2).to_bytes(32, "big")  # Fixture-only public scalar of the client key.
    stranger_secret = (9).to_bytes(32, "big")
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
        reserved = store.reserve(harness.init)
        committed = store.commit_accept(harness.accept)
        client_key = crypto.public_key(client_secret)[1:].hex()
        wraps = [store.wrap_pending(committed.message_id, transport=crypto) for _ in range(2)]
        assert wraps[0] != wraps[1]  # fresh seal and wrapper per retransmission
        for wrap in wraps:
            received = _decode_gift_wrap_candidate(
                wrap,
                recipient_mailbox_secret=client_secret,
                expected_recipient_xonly_key=client_key,
                expected_network=harness.network,
                expected_profile_id="btc-to-ln/v1",
                crypto=crypto,
            )
            assert received.envelope_bytes == harness.accept
            assert received.seal_author_xonly_key == reserved.provider_session_key
        frame = _wrap_envelope(
            harness.confirm,
            sender_session_secret=client_secret,
            recipient_xonly_key=reserved.provider_session_key,
            crypto=crypto,
        )
        opened = store.open_mailbox_frame(frame, transport=crypto)
        assert opened == harness.confirm
        assert not store.admit_confirm(opened).replay
        with pytest.raises(LiveSessionStoreError, match="no pending outbox"):
            store.wrap_pending(committed.message_id, transport=crypto)
        stranger = copy.deepcopy(harness.envelopes[2])
        stranger["sender_session_key"] = crypto.public_key(stranger_secret)[1:].hex()
        forged = _wrap_envelope(
            _bytes(stranger),
            sender_session_secret=stranger_secret,
            recipient_xonly_key=reserved.provider_session_key,
            crypto=crypto,
        )
        with pytest.raises(LiveSessionStoreError, match="not bound to session"):
            store.open_mailbox_frame(forged, transport=crypto)
        elsewhere = _wrap_envelope(
            harness.confirm,
            sender_session_secret=client_secret,
            recipient_xonly_key=crypto.public_key(stranger_secret)[1:].hex(),
            crypto=crypto,
        )
        with pytest.raises(LiveSessionStoreError, match="unknown session"):
            store.open_mailbox_frame(elsewhere, transport=crypto)
        with pytest.raises(LiveSessionStoreError, match="refused"):
            store.open_mailbox_frame(frame[:-5] + b"0000}", transport=crypto)


def test_create_accept_refuses_without_reservation_or_foreign_identity(harness: Harness) -> None:
    class Foreign:
        xonly_public_key = "aa" * 32

    foreign = cast("ProviderIdentity", Foreign())
    harness.provision()
    with harness.acquire() as store:
        with pytest.raises(LiveSessionStoreError, match="no reservation"):
            store.create_accept("ab" * 32, identity=foreign, transport_endpoints=("wss://r/",))
        reserved = store.reserve(harness.init)
        with pytest.raises(LiveSessionStoreError, match="not this store's provider"):
            store.create_accept(
                reserved.session_id, identity=foreign, transport_endpoints=("wss://r/",)
            )
        assert store.pending_outbox() == ()


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_native_owner_built_accept_and_fresh_client_confirm(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    from rill_provider.provider_identity import ProviderIdentity  # noqa: PLC0415

    client_secret = (2).to_bytes(32, "big")  # Fixture-only public scalar of the client key.
    harness.provision()
    unlock = x25519.Identity.generate()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
        with monkeypatch.context() as patch:  # fixture identity scalar 1, provisioning only
            patch.setattr(
                "rill_provider.provider_identity.secrets.token_bytes",
                lambda _n: (1).to_bytes(32, "big"),
            )
            xonly = ProviderIdentity.provision(
                harness.path.parent / "id.age", recipient=str(unlock.to_public()), crypto=crypto
            )
        assert xonly == harness.identity
        signer = ProviderIdentity.load(
            harness.path.parent / "id.age",
            custody_identity=str(unlock),
            expected_xonly_public_key=xonly,
            crypto=crypto,
        )
        reserved = store.reserve(harness.init)
        committed = store.create_accept(
            reserved.session_id, identity=signer, transport_endpoints=("wss://relay.test/",)
        )
        assert (
            store.create_accept(
                reserved.session_id, identity=signer, transport_endpoints=("wss://other/",)
            )
            == committed
        )
        accept = json.loads(committed.canonical_bytes)
        assert accept["sender_session_key"] == reserved.provider_session_key
        assert accept["in_reply_to"] == harness.envelopes[0]["message_id"]
        confirm = copy.deepcopy(harness.envelopes[2])
        confirm["in_reply_to"] = committed.message_id
        confirm["payload"]["handshake_hash"] = committed.transcript_digest
        confirm["signature"] = None
        digest = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(confirm)))
        confirm["signature"] = crypto.schnorr_sign(client_secret, digest, b"\x55" * 32).hex()
        admitted = store.admit_confirm(_bytes(confirm))
        assert admitted.transcript_digest == committed.transcript_digest
        assert store.pending_outbox() == ()


def test_epoch_rotation_schedule_retention_and_cap(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        with pytest.raises(LiveSessionStoreError, match="schedule"):
            store.rotate_epochs(now=100, period=0, retention=0, advertise_for=0)
        first = store.rotate_epochs(now=1000, period=100, retention=250, advertise_for=0)
        assert len(first) == 1
        assert store.rotate_epochs(now=1099, period=100, retention=250, advertise_for=0) == first
        second = store.rotate_epochs(now=1100, period=100, retention=250, advertise_for=0)
        assert second[1:] == first
        assert len(second) == 2
        with pytest.raises(LiveSessionStoreError, match="clock is behind"):
            store.rotate_epochs(now=1050, period=100, retention=250, advertise_for=0)
        advertised = store.rotate_epochs(now=1349, period=100, retention=250, advertise_for=0)
        assert first[0] in advertised  # retire_after = 1000 + 100 + 250
        later = store.rotate_epochs(now=1350, period=100, retention=250, advertise_for=0)
        assert first[0] not in later
        for step in range(6):
            capped = store.rotate_epochs(
                now=1400 + 100 * step, period=100, retention=10_000, advertise_for=0
            )
        assert len(capped) == live.MAX_ADVERTISED_EPOCHS
        assert harness.identity not in capped
        with pytest.raises(LiveSessionStoreError, match="schedule"):
            store.rotate_epochs(now=2100, period=100, retention=10, advertise_for=11)
        newest = store.rotate_epochs(now=2100, period=100, retention=10_000, advertise_for=0)
        near = store.rotate_epochs(now=2100, period=100, retention=10_000, advertise_for=9_950)
        assert near == newest[:1]  # only the key decodable past the announcement
    for file in harness.path.parent.iterdir():
        assert b"secret_scalar" not in file.read_bytes()


def test_schema_v2_store_is_refused_unchanged(harness: Harness) -> None:
    harness.provision()
    harness.path.rename(harness.path.with_name("provisioned-aside"))
    with sqlite3.connect(harness.path) as connection:
        connection.execute(f"PRAGMA application_id={live.APPLICATION_ID}")
        connection.execute("PRAGMA user_version=2")
    connection.close()
    before = harness.path.read_bytes()
    with pytest.raises(LiveSessionStoreError, match="version unsupported"):
        harness.acquire()
    assert harness.path.read_bytes() == before


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_native_init_received_on_epoch_inbox(harness: Harness) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    from rill_provider._nip59_send import _wrap_envelope  # noqa: PLC0415

    client_secret = (2).to_bytes(32, "big")  # Fixture-only public scalar of the client key.
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
        (epoch,) = store.rotate_epochs(now=1000, period=100, retention=100, advertise_for=0)
        frame = _wrap_envelope(
            harness.init,
            sender_session_secret=client_secret,
            recipient_xonly_key=epoch,
            crypto=crypto,
        )
        opened = store.open_epoch_frame(frame, now=1150, transport=crypto)
        assert opened == live.EpochInit(harness.init, epoch)
        assert store.reserve(opened.init_document).session_id == harness.envelopes[0]["session_id"]
        with pytest.raises(LiveSessionStoreError, match="retired epoch"):
            store.open_epoch_frame(frame, now=1200, transport=crypto)
        not_init = _wrap_envelope(
            harness.confirm,
            sender_session_secret=client_secret,
            recipient_xonly_key=epoch,
            crypto=crypto,
        )
        with pytest.raises(LiveSessionStoreError, match="not a sender-bound init"):
            store.open_epoch_frame(not_init, now=1150, transport=crypto)
        with pytest.raises(LiveSessionStoreError, match="refused"):
            store.open_epoch_frame(frame[:-5] + b"0000}", now=1150, transport=crypto)


def _other_init(harness: Harness, index: int) -> bytes:
    envelope = copy.deepcopy(harness.envelopes[0])
    session = f"{index:064x}"
    envelope["session_id"] = envelope["payload"]["session_id"] = session
    envelope["message_id"] = f"{index + 0x100:064x}"
    return _bytes(envelope)


def test_capacity_counts_retained_and_expired_sessions(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secrets  # noqa: PLC0415

    monkeypatch.setattr(live, "_new_challenge", lambda: secrets.token_hex(32))
    monkeypatch.setattr(live, "_new_session_scalar", lambda: secrets.token_bytes(32))
    harness.provision()
    with pytest.raises(LiveSessionStoreError, match="capacity unsupported"):
        harness.acquire_at(harness.path, max_sessions=0)
    with harness.acquire_at(harness.path, max_sessions=2) as store:
        first = store.reserve(_other_init(harness, 1), now=1000)
        store.reserve(_other_init(harness, 2), now=1500)
        with pytest.raises(live.SessionCapacityError):
            store.reserve(_other_init(harness, 3), now=1500)
        assert store.reserve(_other_init(harness, 1), now=1600) == first  # replay unaffected
        with pytest.raises(LiveSessionStoreError, match="expiry schedule"):
            store.expire_idle(now=2000, idle_timeout=0)
        assert store.expire_idle(now=1999, idle_timeout=1000) == 0
        assert store.expire_idle(now=2000, idle_timeout=1000) == 1
        with pytest.raises(live.SessionExpiredError):
            store.reserve(_other_init(harness, 1), now=2000)  # recorded answer, no new accept
        assert store.expire_idle(now=10**9, idle_timeout=1) == 1
        with pytest.raises(live.SessionCapacityError):  # no epoch horizon: kept forever
            store.reserve(_other_init(harness, 3), now=10**9)
    with (
        harness.acquire_at(harness.path, max_sessions=2) as store,  # durable count
        pytest.raises(live.SessionCapacityError),
    ):
        store.reserve(_other_init(harness, 4), now=10**9)


def test_expired_record_is_kept_until_the_epoch_replay_horizon(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        (epoch,) = store.rotate_epochs(now=1000, period=100, retention=100, advertise_for=0)
        with pytest.raises(LiveSessionStoreError, match="unknown epoch"):
            store.reserve(harness.init, now=1000, via_epoch="ab" * 32)
        store.reserve(harness.init, now=1000, via_epoch=epoch)  # retire_after = 1200
        store.commit_accept(harness.accept)
        assert store.expire_idle(now=1100, idle_timeout=100) == 1
        assert store.pending_outbox() == ()
        assert store.awaiting_confirm_mailboxes() == ()
        with pytest.raises(live.SessionExpiredError):
            store.admit_confirm(harness.confirm)  # late confirm: recorded answer
        with pytest.raises(live.SessionExpiredError):
            store.reserve(harness.init, now=1150, via_epoch=epoch)
        assert store.receiving_epochs(now=1199) == (epoch,)
        store.expire_idle(now=1199, idle_timeout=100)
        with pytest.raises(live.SessionExpiredError):
            store.reserve(harness.init, now=1199)
        store.expire_idle(now=1200, idle_timeout=100)  # horizon passed: row deleted
        assert store.receiving_epochs(now=1200) == ()
        assert store.reserve(harness.init, now=1200).revision == 0


def test_idle_confirmed_sessions_expire_but_keep_their_record(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        store.reserve(harness.init, now=10)
        store.commit_accept(harness.accept)
        store.admit_confirm(harness.confirm, now=20)
        assert store.expire_idle(now=119, idle_timeout=100) == 0
        assert store.expire_idle(now=120, idle_timeout=100) == 1
        with pytest.raises(live.SessionExpiredError):
            store.admit_confirm(harness.confirm)
        with pytest.raises(live.SessionExpiredError):
            store.reserve(harness.init)
    for file in harness.path.parent.iterdir():
        assert b"secret_scalar" not in file.read_bytes()


def test_announcement_revisions_strictly_increase_across_owners(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        store.record_announcement(1000)
        with pytest.raises(LiveSessionStoreError, match="would not increase"):
            store.record_announcement(1000)
    with harness.acquire() as store:
        with pytest.raises(LiveSessionStoreError, match="would not increase"):
            store.record_announcement(999)
        store.record_announcement(1001)
