"""Epoch retirement is affirmative custody, not permission inferred from absence."""

from __future__ import annotations

import copy
import json
import os
import secrets
import sqlite3
from dataclasses import replace
from typing import TYPE_CHECKING

import pyrage  # type: ignore[import-untyped]
import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import (
    EPOCH_SESSION_EXTENSION,
    EPOCH_SESSION_FEATURE,
    epoch_bound_session_id,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import Envelope
from test_live_session_store import POLICY, Harness, PurePublicKeys, _forgeries

from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    assert EPOCH_SESSION_FEATURE in POLICY.features
    monkeypatch.setattr(live, "_new_challenge", lambda: secrets.token_hex(32))
    monkeypatch.setattr(live, "_new_session_scalar", lambda: secrets.token_bytes(32))
    return result


def _init(harness: Harness, epoch: str, client: int = 2) -> live.EpochInitiation:
    envelope = copy.deepcopy(harness.envelopes[0])
    key = PurePublicKeys().public_key(client.to_bytes(32, "big"))[1:].hex()
    session = epoch_bound_session_id(harness.network, harness.identity, epoch, key).hex()
    envelope.update(session_id=session, sender_session_key=key)
    envelope["payload"].update(
        session_id=session,
        client_session_xonly_key=key,
        required_features=[EPOCH_SESSION_FEATURE],
        extensions={EPOCH_SESSION_EXTENSION: {"epoch_inbox_xonly_key": epoch}},
    )
    return live.EpochInitiation(canonicalize(envelope), epoch)


def _unbound(harness: Harness, session: str, epoch: str) -> live.EpochInitiation:
    """An unbound init (no epoch feature) delivered with valid epoch provenance."""
    envelope = copy.deepcopy(harness.envelopes[0])
    envelope["session_id"] = session
    envelope["payload"].update(session_id=session, required_features=[], extensions={})
    return live.EpochInitiation(canonicalize(envelope), epoch)


def _epoch(store: live.LiveSessionStore, now: int = 1000) -> str:
    return store.rotate_epochs(now=now, period=100, retention=100, advertise_for=0)[0]


def test_epoch_binding_requires_provenance_and_refuses_unbound_ids(harness: Harness) -> None:
    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with harness.acquire() as store:
        epoch = _epoch(store)
        init = _init(harness, epoch)
        with pytest.raises(live.LiveSessionStoreError, match="provenance"):
            store.reserve(init.document, now=1000)
        with pytest.raises(live.LiveSessionStoreError, match="provenance"):
            store.reserve(replace(init, epoch_key=harness.identity), now=1000)
        with pytest.raises(live.LiveSessionStoreError, match="requires epoch-bound"):
            store.reserve(_unbound(harness, "10" * 32, epoch), now=1000)
        assert store._connection.execute("SELECT * FROM sessions").fetchall() == []  # noqa: SLF001
        reserved = store.reserve(init, now=1000)
        assert store.reserve(init, now=1000) == reserved


def test_tombstone_is_temporary_but_not_before_durable_epoch_retirement(harness: Harness) -> None:
    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with harness.acquire() as store:
        epoch = _epoch(store)
        init = _init(harness, epoch)
        session = store.reserve(init, now=1000).session_id
        assert store.expire_idle(now=1100, idle_timeout=100) == 1
        with pytest.raises(live.SessionExpiredError):
            store.reserve(init, now=1199)
        assert store._connection.execute(  # noqa: SLF001
            "SELECT expired FROM epoch_admissions WHERE session_id=?", (session,)
        ).fetchone() == (1,)
        assert store.expire_idle(now=1200, idle_timeout=100) == 0
        assert store._connection.execute("SELECT * FROM epoch_admissions").fetchall() == []  # noqa: SLF001
        assert store.receiving_epochs(now=1000) == ()
    with harness.acquire() as store:
        with pytest.raises(live.SessionExpiredError, match="epoch retired"):
            store.reserve(init, now=1000)
        with pytest.raises(live.LiveSessionStoreError, match="clock"):
            _epoch(store, now=1000)
        with pytest.raises(live.LiveSessionStoreError, match="clock"):
            store.expire_idle(now=1000, idle_timeout=100)
        new_epoch = _epoch(store, now=1200)
        with pytest.raises(live.LiveSessionStoreError, match="provenance"):
            store.reserve(replace(init, epoch_key=new_epoch), now=1200)
        with pytest.raises(live.LiveSessionStoreError, match="requires epoch-bound"):
            store.reserve(_unbound(harness, session, new_epoch), now=1200)
        store.reserve(_init(harness, new_epoch), now=1200)


def test_temporary_tombstone_capacity_recovers(harness: Harness) -> None:
    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with harness.acquire_at(harness.path, max_sessions=1, max_tombstones=1) as store:
        epoch = _epoch(store)
        store.reserve(_init(harness, epoch), now=1000)
        store.expire_idle(now=1100, idle_timeout=100)
        with pytest.raises(live.SessionCapacityError):
            store.reserve(_init(harness, epoch, client=4), now=1100)
        store.expire_idle(now=1200, idle_timeout=100)
        store.reserve(_init(harness, _epoch(store, now=1200)), now=1200)


def test_accepted_session_custody_survives_epoch_and_idle_expiry(harness: Harness) -> None:
    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with harness.acquire() as store:
        session = store.reserve(_init(harness, _epoch(store)), now=1000).session_id
        store._connection.execute(  # noqa: SLF001 - construct accepted retention boundary
            "UPDATE sessions SET phase='ACCEPTED' WHERE session_id=?", (session,)
        )
        before = store._connection.execute("SELECT * FROM sessions").fetchall()  # noqa: SLF001
        assert store.expire_idle(now=1300, idle_timeout=100) == 0
        assert store._connection.execute("SELECT * FROM sessions").fetchall() == before  # noqa: SLF001
        assert store._connection.execute("SELECT expired FROM epoch_admissions").fetchall() == [  # noqa: SLF001
            (0,)
        ]


def test_absent_epoch_retirement_marker_is_not_repaired(harness: Harness) -> None:
    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with sqlite3.connect(harness.path) as connection:
        connection.execute("DELETE FROM epoch_retirement")
    with pytest.raises(live.LiveSessionStoreError, match="retirement custody"):
        harness.acquire()
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("SELECT * FROM epoch_retirement").fetchall() == []


def test_missing_known_session_provenance_never_backfills_admission(harness: Harness) -> None:
    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with harness.acquire() as store:
        init = _init(harness, _epoch(store))
        store.reserve(init, now=1000)
        store._connection.execute("DELETE FROM epoch_admissions")  # noqa: SLF001
        with pytest.raises(live.LiveSessionStoreError, match="admission custody"):
            store.reserve(init, now=1001)


def test_repeated_epoch_scalar_cannot_reopen_pruned_id(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.provision(fixture_epoch=False)  # these tests own every epoch
    monkeypatch.setattr(live, "_new_epoch_scalar", lambda: (10).to_bytes(32, "big"))
    with harness.acquire() as store:
        epoch = _epoch(store)
        init = _init(harness, epoch)
        store.reserve(init, now=1000)
        store.expire_idle(now=1200, idle_timeout=100)
    with harness.acquire() as store:
        with pytest.raises(live.LiveSessionStoreError, match="rotation"):
            _epoch(store, now=1200)
        assert store.receiving_epochs(now=1200) == ()
        with pytest.raises(live.SessionExpiredError):
            store.reserve(init, now=1200)
        assert store._connection.execute("SELECT * FROM epoch_key_history").fetchall() == [(epoch,)]  # noqa: SLF001


def test_interrupted_retirement_never_leaves_pruned_history_with_reopened_epoch(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with harness.acquire() as store:
        epoch = _epoch(store)
        init = _init(harness, epoch)
        store.reserve(init, now=1000)
        retire = live._retire_epochs  # noqa: SLF001

        def interrupted(connection: sqlite3.Connection, now: int) -> None:
            retire(connection, now)
            raise OSError("process loss before commit")

        with monkeypatch.context() as patch:
            patch.setattr(live, "_retire_epochs", interrupted)
            with pytest.raises(live.LiveSessionStoreError, match="expiry refused"):
                store.expire_idle(now=1200, idle_timeout=100)
    with harness.acquire() as store:
        assert store.receiving_epochs(now=1000) == (epoch,)
        assert store.reserve(init, now=1000).session_id
        assert store.expire_idle(now=1200, idle_timeout=100) == 1
        assert store.receiving_epochs(now=1000) == ()
        with pytest.raises(live.SessionExpiredError):
            store.reserve(init, now=1000)


def test_partial_key_history_is_refused_instead_of_reconstructed(harness: Harness) -> None:
    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with harness.acquire() as store:
        _epoch(store)
    with sqlite3.connect(harness.path) as connection:
        connection.execute("DELETE FROM epoch_key_history")
    with pytest.raises(live.LiveSessionStoreError, match="key history unavailable"):
        harness.acquire()
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("SELECT * FROM epoch_key_history").fetchall() == []


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_native_epoch_ingress_accept_confirm_and_retirement(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    from rill_provider._nip59_send import _wrap_envelope  # noqa: PLC0415
    from rill_provider.provider_identity import ProviderIdentity  # noqa: PLC0415

    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
        with monkeypatch.context() as patch:
            patch.setattr(
                "rill_provider.provider_identity.secrets.token_bytes",
                lambda _n: (1).to_bytes(32, "big"),
            )
            ProviderIdentity.provision(
                harness.path.parent / "id.age",
                recipient=str(harness.custody.to_public()),
                crypto=crypto,
            )
        identity = ProviderIdentity.load(
            harness.path.parent / "id.age",
            custody_identity=str(harness.custody),
            expected_xonly_public_key=harness.identity,
            crypto=crypto,
        )
        epoch = _epoch(store)
        init = _init(harness, epoch)
        frame = _wrap_envelope(
            init.document,
            sender_session_secret=(2).to_bytes(32, "big"),
            recipient_xonly_key=epoch,
            crypto=crypto,
        )
        opened = store.open_epoch_frame(frame, now=1000, transport=crypto)
        assert opened == init
        reservation = store.reserve(opened, now=1000)
        accepted = store.create_accept(
            reservation.session_id, identity=identity, transport_endpoints=("wss://relay.test/",)
        )
        accept = json.loads(accepted.canonical_bytes)
        assert accept["payload"]["accept"]["required_features"] == [EPOCH_SESSION_FEATURE]
        confirm = copy.deepcopy(harness.envelopes[2])
        confirm.update(
            session_id=reservation.session_id, in_reply_to=accepted.message_id, signature=None
        )
        confirm["payload"].update(
            session_id=reservation.session_id,
            handshake_hash=accepted.transcript_digest,
            provider_session_xonly_key=reservation.provider_session_key,
        )
        confirm["signature"] = crypto.schnorr_sign(
            (2).to_bytes(32, "big"),
            unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(confirm))),
            b"\x55" * 32,
        ).hex()
        assert (
            store.admit_confirm(canonicalize(confirm), now=1010).session_id
            == reservation.session_id
        )
        assert store.expire_idle(now=1200, idle_timeout=100) == 1
        with pytest.raises(live.LiveSessionStoreError, match="retired epoch"):
            store.open_epoch_frame(frame, now=1000, transport=crypto)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_forged_epoch_frame_is_refused_before_custody_decryption(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    from rill_provider._nip59_send import _wrap_envelope  # noqa: PLC0415

    harness.provision(fixture_epoch=False)  # these tests own every epoch
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
        epoch = _epoch(store)
        init = _init(harness, epoch)
        frame = _wrap_envelope(
            init.document,
            sender_session_secret=(2).to_bytes(32, "big"),
            recipient_xonly_key=epoch,
            crypto=crypto,
        )
        decrypted: list[object] = []
        decrypt = pyrage.decrypt
        monkeypatch.setattr(pyrage, "decrypt", lambda *a: decrypted.append(a) or decrypt(*a))
        for forged in _forgeries(frame):
            with pytest.raises(live.LiveSessionStoreError, match="epoch frame refused"):
                store.open_epoch_frame(forged, now=1000, transport=crypto)
        assert decrypted == []  # the epoch secret was never unsealed
        assert store.open_epoch_frame(frame, now=1000, transport=crypto) == init
        assert decrypted  # the spy observes the authentic path
