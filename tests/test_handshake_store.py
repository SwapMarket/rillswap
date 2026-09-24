"""Offline handshake preparation is durable bookkeeping, never admission."""

from __future__ import annotations

import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import handshake_accept_hash
from rill_core.wire.messages import HandshakeAccept
from rill_core.wire.types import NetworkIdentity

from rill_provider import handshake_store as store_module
from rill_provider.handshake_signing import SessionKeyRef
from rill_provider.handshake_store import (
    HandshakeConflictError,
    HandshakePolicy,
    HandshakeStoreError,
    PreparedHandshakeStore,
    UnknownPrepared,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

FIXTURE = Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json"
IDENTITY_KEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


class KnownFixtureVerifier:
    """Offline fixture-only verifier; native adapter separately tested."""

    def __init__(self, selection: dict[str, Any], signature: str) -> None:
        self.digest = handshake_accept_hash(
            HandshakeAccept.model_validate_json(json.dumps(selection)),
        )
        self.signature = bytes.fromhex(signature)
        self.calls = 0

    def schnorr_verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        self.calls += 1
        if (
            public_key != bytes.fromhex(IDENTITY_KEY)
            or message != self.digest
            or signature != self.signature
        ):
            raise ValueError("private fixture signer failure")


def _inputs() -> tuple[
    NetworkIdentity, HandshakePolicy, list[dict[str, Any]], SessionKeyRef, KnownFixtureVerifier
]:
    package = json.loads(FIXTURE.read_bytes())
    context = package["verification_context"]
    init, selection = context["handshake_init"], context["handshake_accept"]
    shared = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": package["profile_id"],
        "network_identity": package["network_identity"],
        "session_id": init["session_id"],
        "contract_hash": None,
        "required_features": [],
        "extensions": {},
    }
    envelopes = [
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
            "sender_session_key": selection["provider_session_xonly_key"],
            "sequence": 0,
            "in_reply_to": "12" * 32,
            "payload": {
                "accept": selection,
                "provider_identity_signature": context["provider_identity_signature"],
            },
            "signature": None,
        },
    ]
    network = NetworkIdentity.model_validate(package["network_identity"])
    policy = HandshakePolicy(
        profile="btc-to-ln/v1",
        features=frozenset(),
        encryption_suites=frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
        capabilities=frozenset({"core/v1", "recovery/v1"}),
    )
    ref = SessionKeyRef("test-only", "fixture-key-1", selection["provider_session_xonly_key"])
    return (
        network,
        policy,
        envelopes,
        ref,
        KnownFixtureVerifier(
            selection,
            context["provider_identity_signature"],
        ),
    )


def _record(
    store: PreparedHandshakeStore,
    envelopes: list[dict[str, Any]],
    ref: SessionKeyRef,
    policy: HandshakePolicy,
    crypto: KnownFixtureVerifier,
) -> object:
    return store.record_prepared(
        canonicalize(envelopes[0]),
        canonicalize(envelopes[1]),
        ref,
        policy=policy,
        crypto=crypto,
    )


def test_explicit_create_restart_exact_bytes_and_missing_rows_unknown(tmp_path: Path) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    location = tmp_path / "offline.sqlite"
    with pytest.raises(HandshakeStoreError):
        PreparedHandshakeStore.open_existing(location, network, IDENTITY_KEY)
    assert not location.exists()
    store = PreparedHandshakeStore.create_new(location, network, IDENTITY_KEY)
    assert location.stat().st_mode & 0o777 == 0o600
    assert store.lookup_prepared(envelopes[0]["session_id"]) is UnknownPrepared.UNKNOWN
    result = _record(store, envelopes, ref, policy, verifier)
    assert result.init_envelope_jcs == canonicalize(envelopes[0])
    assert result.accept_envelope_jcs == canonicalize(envelopes[1])
    reopened = PreparedHandshakeStore.open_existing(location, network, IDENTITY_KEY)
    assert reopened.lookup_prepared(result.session_id) == result
    assert _record(reopened, envelopes, ref, policy, verifier) == result
    assert verifier.calls == 2
    assert reopened.lookup_prepared("bb" * 32) is UnknownPrepared.UNKNOWN
    with pytest.raises((FileExistsError, HandshakeStoreError)):
        PreparedHandshakeStore.create_new(location, network, IDENTITY_KEY)
    assert reopened.lookup_prepared(result.session_id) == result


def test_concurrent_prepares_serialize_conflicts_and_accept_cross_sender_id(
    tmp_path: Path,
) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    store = PreparedHandshakeStore.create_new(tmp_path / "offline.sqlite", network, IDENTITY_KEY)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: _record(store, envelopes, ref, policy, verifier),
                range(24),
            )
        )
    assert len({item.init_unsigned_hash for item in results}) == 1
    assert all(item == results[0] for item in results)
    assert store.lookup_prepared(results[0].session_id) == results[0]
    for mutate in (
        lambda pair: pair[0].update(message_id="13" * 32),
        lambda pair: pair[1].update(message_id="13" * 32),
    ):
        changed = json.loads(json.dumps(envelopes))
        mutate(changed)
        if changed[0]["message_id"] == "13" * 32:
            changed[1]["in_reply_to"] = "13" * 32
        with pytest.raises(HandshakeConflictError):
            _record(store, changed, ref, policy, verifier)
    with pytest.raises(HandshakeConflictError):
        _record(
            store,
            envelopes,
            SessionKeyRef(ref.custody_id, "other", ref.xonly_public_key),
            policy,
            verifier,
        )
    assert store.lookup_prepared(results[0].session_id) == results[0]

    # RS-001 message IDs are sender-stream scoped; collision between opposite
    # session keys is not itself a conflict.
    other = PreparedHandshakeStore.create_new(
        tmp_path / "cross-stream.sqlite", network, IDENTITY_KEY
    )
    cross = json.loads(json.dumps(envelopes))
    cross[1]["message_id"] = cross[0]["message_id"]
    assert _record(other, cross, ref, policy, verifier).session_id == results[0].session_id


def test_two_valid_conflicting_concurrent_prepares_have_one_durable_winner(
    tmp_path: Path,
) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    store = PreparedHandshakeStore.create_new(tmp_path / "race.sqlite", network, IDENTITY_KEY)
    alternate = json.loads(json.dumps(envelopes))
    alternate[1]["message_id"] = "15" * 32

    def prepare(pair: list[dict[str, Any]]) -> object:
        try:
            return _record(store, pair, ref, policy, verifier)
        except HandshakeConflictError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(prepare, [envelopes, alternate] * 16))
    durable = store.lookup_prepared(envelopes[0]["session_id"])
    assert durable is not UnknownPrepared.UNKNOWN
    assert any(result == "conflict" for result in results)
    assert any(result == durable for result in results)
    assert all(result in (durable, "conflict") for result in results)


def test_canonical_envelope_over_eight_kib_is_supported_but_not_over_wire_limit(
    tmp_path: Path,
) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    store = PreparedHandshakeStore.create_new(tmp_path / "large.sqlite", network, IDENTITY_KEY)
    envelopes[1]["extensions"] = {"org.test/large": "x" * 9_000}
    assert 8_192 < len(canonicalize(envelopes[1])) < store_module.MAX_ENVELOPE_BYTES
    result = _record(store, envelopes, ref, policy, verifier)
    assert store.lookup_prepared(result.session_id) == result
    too_large = json.loads(json.dumps(envelopes))
    too_large[1]["extensions"] = {"org.test/large": "x" * store_module.MAX_ENVELOPE_BYTES}
    other = PreparedHandshakeStore.create_new(tmp_path / "too-large.sqlite", network, IDENTITY_KEY)
    with pytest.raises(HandshakeStoreError):
        _record(other, too_large, ref, policy, verifier)
    assert other.lookup_prepared(result.session_id) is UnknownPrepared.UNKNOWN


@pytest.mark.parametrize(
    "change",
    [
        "missing-key",
        "extra-column",
        "ignored-insert",
        "ignored-insert-like-internal",
    ],
)
def test_schema_constraint_changes_and_triggers_are_not_silently_accepted(
    tmp_path: Path,
    change: str,
) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    location = tmp_path / "altered.sqlite"
    store = PreparedHandshakeStore.create_new(location, network, IDENTITY_KEY)
    if change in {"ignored-insert", "ignored-insert-like-internal"}:
        name = "sqliteX_ignore" if change == "ignored-insert-like-internal" else "silent_ignore"
        with sqlite3.connect(location) as connection:
            connection.execute(
                f"CREATE TRIGGER {name} BEFORE INSERT ON prepared BEGIN SELECT RAISE(IGNORE); END"
            )
    else:
        with sqlite3.connect(location) as source:
            metadata = source.execute("SELECT * FROM metadata").fetchone()
        location.unlink()
        with sqlite3.connect(location) as connection:
            connection.execute(f"PRAGMA application_id={store_module.APPLICATION_ID}")
            connection.execute("PRAGMA user_version=1")
            connection.execute(store_module.SCHEMA[0])
            schema = store_module.SCHEMA[1]
            if change == "missing-key":
                schema = schema.replace("session_id TEXT PRIMARY KEY", "session_id TEXT")
            else:
                schema = schema.replace(
                    "row_hash TEXT NOT NULL)", "row_hash TEXT NOT NULL, added TEXT)"
                )
            connection.execute(schema)
            connection.execute("INSERT INTO metadata VALUES (?, ?, ?, ?, ?)", metadata)
    with pytest.raises(HandshakeStoreError):
        PreparedHandshakeStore.open_existing(location, network, IDENTITY_KEY)
    with pytest.raises(HandshakeStoreError):
        _record(store, envelopes, ref, policy, verifier)
    with sqlite3.connect(location) as connection:
        if change in {"ignored-insert", "ignored-insert-like-internal"}:
            assert connection.execute("SELECT count(*) FROM prepared").fetchone() == (0,)


@pytest.mark.parametrize(
    "name", ["question?.sqlite", "hash#.sqlite", "white space.sqlite", "unicodé.sqlite"]
)
def test_explicit_file_uri_handles_special_paths_and_refuses_symlink(
    tmp_path: Path,
    name: str,
) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    location = tmp_path / name
    store = PreparedHandshakeStore.create_new(location, network, IDENTITY_KEY)
    assert _record(store, envelopes, ref, policy, verifier).session_id == envelopes[0]["session_id"]
    assert PreparedHandshakeStore.open_existing(location, network, IDENTITY_KEY).lookup_prepared(
        envelopes[0]["session_id"]
    ) == store.lookup_prepared(envelopes[0]["session_id"])
    link = tmp_path / f"link-{name}"
    link.symlink_to(location)
    with pytest.raises(HandshakeStoreError):
        PreparedHandshakeStore.open_existing(link, network, IDENTITY_KEY)


@pytest.mark.parametrize("setting", ["journal_mode", "synchronous"])
def test_unconfirmed_sqlite_durability_pragma_never_returns_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    store = PreparedHandshakeStore.create_new(tmp_path / "pragma.sqlite", network, IDENTITY_KEY)
    real_connect = store_module.sqlite3.connect

    class UnexpectedSetting:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection

        def execute(self, statement: str, parameters: object = ()) -> object:
            if statement == "PRAGMA journal_mode=WAL" and setting == "journal_mode":
                return _Reply(("delete",))
            if statement == "PRAGMA synchronous" and setting == "synchronous":
                return _Reply((1,))
            return self.connection.execute(statement, parameters)

        def close(self) -> None:
            self.connection.close()

    class _Reply:
        def __init__(self, value: tuple[str] | tuple[int]) -> None:
            self.value = value

        def fetchone(self) -> tuple[str] | tuple[int]:
            return self.value

    monkeypatch.setattr(
        store_module.sqlite3, "connect", lambda *a, **k: UnexpectedSetting(real_connect(*a, **k))
    )
    with pytest.raises(HandshakeStoreError):
        _record(store, envelopes, ref, policy, verifier)
    monkeypatch.setattr(store_module.sqlite3, "connect", real_connect)
    assert store.lookup_prepared(envelopes[0]["session_id"]) is UnknownPrepared.UNKNOWN


@pytest.mark.parametrize(
    "mutation",
    [
        "init-signature",
        "accept-signature",
        "wrong-init-key",
        "wrong-accept-key",
        "accept-reply",
        "wrong-profile",
        "wrong-network",
        "wrong-identity",
        "wrong-init-hash",
        "wrong-identity-signature",
        "unsupported-suite",
        "unsupported-capabilities",
        "unknown-required-feature",
        "noncanonical",
        "duplicate-json",
        "bad-ref",
        "wrong-ref-key",
        "bad-accept-payload",
    ],
)
def test_invalid_preparation_has_no_row_or_authority(  # noqa: PLR0912 - negative matrix
    tmp_path: Path,
    mutation: str,
) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    store = PreparedHandshakeStore.create_new(tmp_path / "offline.sqlite", network, IDENTITY_KEY)
    altered = json.loads(json.dumps(envelopes))
    ref_changed = ref
    init_bytes: bytes | None = None
    if mutation == "init-signature":
        altered[0]["signature"] = "11" * 64
    elif mutation == "accept-signature":
        altered[1]["signature"] = "11" * 64
    elif mutation == "wrong-init-key":
        altered[0]["sender_session_key"] = IDENTITY_KEY
    elif mutation == "wrong-accept-key":
        altered[1]["sender_session_key"] = IDENTITY_KEY
    elif mutation == "accept-reply":
        altered[1]["in_reply_to"] = "ab" * 32
    elif mutation == "wrong-profile":
        altered[0]["profile_id"] = "ln-to-btc/v1"
    elif mutation == "wrong-network":
        altered[0]["network_identity"]["deployment_namespace"] = "other"
    elif mutation == "wrong-identity":
        altered[1]["payload"]["accept"]["provider_identity_xonly_key"] = ref.xonly_public_key
    elif mutation == "wrong-init-hash":
        altered[1]["payload"]["accept"]["handshake_init_hash"] = "bb" * 32
    elif mutation == "wrong-identity-signature":
        altered[1]["payload"]["provider_identity_signature"] = "00" * 64
    elif mutation == "unsupported-suite":
        policy = HandshakePolicy(policy.profile, policy.features, frozenset(), policy.capabilities)
    elif mutation == "unsupported-capabilities":
        policy = HandshakePolicy(
            policy.profile, policy.features, policy.encryption_suites, frozenset({"core/v1"})
        )
    elif mutation == "unknown-required-feature":
        altered[0]["required_features"] = ["org.test/unknown"]
    elif mutation == "noncanonical":
        init_bytes = json.dumps(altered[0]).encode()
    elif mutation == "duplicate-json":
        init_bytes = canonicalize(altered[0]).replace(
            b'"session_id":', b'"session_id":"00", "session_id":', 1
        )
    elif mutation == "bad-ref":
        ref_changed = SessionKeyRef("../../secret", ref.key_id, ref.xonly_public_key)
    elif mutation == "wrong-ref-key":
        ref_changed = SessionKeyRef(ref.custody_id, ref.key_id, IDENTITY_KEY)
    else:
        altered[1]["payload"]["provider_identity_signature"] = None
    with pytest.raises(HandshakeStoreError) as error:
        store.record_prepared(
            canonicalize(altered[0]) if init_bytes is None else init_bytes,
            canonicalize(altered[1]),
            ref_changed,
            policy=policy,
            crypto=verifier,
        )
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert store.lookup_prepared(envelopes[0]["session_id"]) is UnknownPrepared.UNKNOWN


def test_incompatible_or_partial_databases_never_bootstrap_or_migrate(tmp_path: Path) -> None:
    network, _, _, _, _ = _inputs()
    location = tmp_path / "offline.sqlite"
    location.write_bytes(b"partial, not sqlite")
    with pytest.raises((HandshakeStoreError, sqlite3.DatabaseError)):
        PreparedHandshakeStore.open_existing(location, network, IDENTITY_KEY)
    assert location.read_bytes() == b"partial, not sqlite"
    location.unlink()
    store = PreparedHandshakeStore.create_new(location, network, IDENTITY_KEY)
    mismatch = network.model_copy(update={"deployment_namespace": "other"})
    with pytest.raises(HandshakeStoreError):
        PreparedHandshakeStore.open_existing(location, mismatch, IDENTITY_KEY)
    with pytest.raises(HandshakeStoreError):
        PreparedHandshakeStore.open_existing(location, network, "02" * 32)
    for version in (0, 2):
        with sqlite3.connect(location) as connection:
            connection.execute(f"PRAGMA user_version={version}")
        with pytest.raises(HandshakeStoreError):
            PreparedHandshakeStore.open_existing(location, network, IDENTITY_KEY)
    with sqlite3.connect(location) as connection:
        connection.execute("PRAGMA user_version=1")
        connection.execute("UPDATE metadata SET store_id='not-a-store-id'")
    with pytest.raises(HandshakeStoreError):
        store.lookup_prepared("11" * 32)


def test_corrupted_prepared_row_and_restored_copy_are_not_safe_absence(tmp_path: Path) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    location = tmp_path / "offline.sqlite"
    store = PreparedHandshakeStore.create_new(location, network, IDENTITY_KEY)
    restored_path = tmp_path / "older-valid-copy.sqlite"
    with sqlite3.connect(location) as source, sqlite3.connect(restored_path) as target:
        source.backup(target)
    recorded = _record(store, envelopes, ref, policy, verifier)
    restored = PreparedHandshakeStore.open_existing(restored_path, network, IDENTITY_KEY)
    assert restored.lookup_prepared(recorded.session_id) is UnknownPrepared.UNKNOWN
    assert store.lookup_prepared(recorded.session_id) == recorded
    with sqlite3.connect(location) as connection:
        connection.execute(
            "UPDATE prepared SET row_hash='00' WHERE session_id=?", (recorded.session_id,)
        )
    with pytest.raises(HandshakeStoreError) as error:
        store.lookup_prepared(recorded.session_id)
    assert error.value.__context__ is None
    with pytest.raises(HandshakeStoreError):
        _record(store, envelopes, ref, policy, verifier)


def test_checksum_is_not_authentication_against_a_database_writer(tmp_path: Path) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    location = tmp_path / "local-trusted-only.sqlite"
    store = PreparedHandshakeStore.create_new(location, network, IDENTITY_KEY)
    recorded = _record(store, envelopes, ref, policy, verifier)
    with sqlite3.connect(location) as connection:
        store_id = connection.execute("SELECT store_id FROM metadata").fetchone()[0]
        ref_jcs = connection.execute(
            "SELECT ref_jcs FROM prepared WHERE session_id=?",
            (recorded.session_id,),
        ).fetchone()[0]
        altered = json.loads(recorded.accept_envelope_jcs)
        altered["message_id"] = "ab" * 32  # Outer ID is not identity-signed.
        forged = replace(recorded, accept_envelope_jcs=canonicalize(altered))
        connection.execute(
            "UPDATE prepared SET accept_jcs=?, row_hash=? WHERE session_id=?",
            (
                forged.accept_envelope_jcs,
                store_module._row_hash(store_id, forged, ref_jcs),  # noqa: SLF001 - tamper demonstration
                recorded.session_id,
            ),
        )
    assert store.lookup_prepared(recorded.session_id) == forged
    # A writer can also alter references, restore backups, or recompute the
    # checksum; only an operator-trusted local directory is supported.


def test_interruption_before_and_after_commit_has_no_retry_permission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network, policy, envelopes, ref, verifier = _inputs()
    store = PreparedHandshakeStore.create_new(tmp_path / "offline.sqlite", network, IDENTITY_KEY)
    original_hash = store_module._row_hash  # noqa: SLF001 - fault injection

    def fail_before_insert(*_args: object) -> str:
        raise OSError("simulated interruption before insert")

    monkeypatch.setattr(store_module, "_row_hash", fail_before_insert)
    with pytest.raises(HandshakeStoreError):
        _record(store, envelopes, ref, policy, verifier)
    monkeypatch.setattr(store_module, "_row_hash", original_hash)
    assert store.lookup_prepared(envelopes[0]["session_id"]) is UnknownPrepared.UNKNOWN

    original_connection = store._connection  # noqa: SLF001 - fault injection

    @contextmanager
    def fail_after_commit(
        *, check: bool = True, write: bool = False
    ) -> Iterator[sqlite3.Connection]:
        with original_connection(check=check, write=write) as connection:
            yield connection
        raise OSError("simulated interruption after commit")

    monkeypatch.setattr(store, "_connection", fail_after_commit)
    with pytest.raises(HandshakeStoreError):
        _record(store, envelopes, ref, policy, verifier)
    monkeypatch.setattr(store, "_connection", original_connection)
    recorded = store.lookup_prepared(envelopes[0]["session_id"])
    assert recorded is not UnknownPrepared.UNKNOWN
    assert recorded.accept_envelope_jcs == canonicalize(envelopes[1])
    assert _record(store, envelopes, ref, policy, verifier) == recorded


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_real_native_provider_identity_signature_is_verified_before_prepare(tmp_path: Path) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    network, policy, envelopes, ref, _ = _inputs()
    store = PreparedHandshakeStore.create_new(tmp_path / "native.sqlite", network, IDENTITY_KEY)
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        assert (
            store.record_prepared(
                canonicalize(envelopes[0]),
                canonicalize(envelopes[1]),
                ref,
                policy=policy,
                crypto=crypto,
            ).session_id
            == envelopes[0]["session_id"]
        )
        invalid = json.loads(json.dumps(envelopes))
        invalid[1]["payload"]["provider_identity_signature"] = "00" * 64
        separate = PreparedHandshakeStore.create_new(
            tmp_path / "bad-signature.sqlite",
            network,
            IDENTITY_KEY,
        )
        with pytest.raises(HandshakeStoreError) as error:
            _record(separate, invalid, ref, policy, crypto)
        assert error.value.__cause__ is None
        assert error.value.__context__ is None
        assert separate.lookup_prepared(envelopes[0]["session_id"]) is UnknownPrepared.UNKNOWN


@pytest.mark.parametrize("value", [False, True, "exception"])
def test_verifier_must_raise_or_return_none_before_any_row(tmp_path: Path, value: object) -> None:
    network, policy, envelopes, ref, _ = _inputs()
    store = PreparedHandshakeStore.create_new(
        tmp_path / "invalid-verifier.sqlite",
        network,
        IDENTITY_KEY,
    )

    class InvalidVerifier:
        def schnorr_verify(self, *_args: bytes) -> object:
            if value == "exception":
                raise OSError("secret-bearing verifier exception")
            return value

    with pytest.raises(HandshakeStoreError) as error:
        _record(store, envelopes, ref, policy, InvalidVerifier())  # type: ignore[arg-type]
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert store.lookup_prepared(envelopes[0]["session_id"]) is UnknownPrepared.UNKNOWN
