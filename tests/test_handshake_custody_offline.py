"""Explicit encrypted offline custody proves availability only, never admission."""

from __future__ import annotations

import json
import os
import shutil
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pyrage import x25519
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import handshake_init_hash
from rill_core.wire.messages import HandshakeInit
from rill_core.wire.types import NetworkIdentity

from rill_provider import handshake_custody_offline as offline
from rill_provider.handshake_signing import SessionKeyRef, SessionReservation

FIXTURE = Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json"


def _network() -> NetworkIdentity:
    source = json.loads(FIXTURE.read_bytes())
    return NetworkIdentity.model_validate_json(json.dumps(source["network_identity"]))


def _reservation(network: NetworkIdentity, identity_key: str) -> SessionReservation:
    source = json.loads(FIXTURE.read_bytes())
    init = HandshakeInit.model_validate_json(
        json.dumps(source["verification_context"]["handshake_init"]),
    )
    return SessionReservation(
        init.session_id,
        handshake_init_hash(init).hex(),
        init.profile_id,
        canonicalize(network.model_dump(mode="json")),
        identity_key,
    )


def _store(tmp_path: Path) -> tuple[offline.OfflineHandshakeCustody, str, NetworkIdentity]:
    network = _network()
    protection = str(x25519.Identity.generate())
    root = tmp_path / "custody"
    with pytest.raises(offline.CustodyError):
        offline.OfflineHandshakeCustody.open_existing(
            root,
            protection_identity=protection,
            expected_network=network,
            expected_custody_id="00" * 32,
        )
    assert not root.exists()
    custody = offline.OfflineHandshakeCustody.create_new(
        root,
        protection_identity=protection,
        expected_network=network,
    )
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "manifest.json").stat().st_mode & 0o777 == 0o600
    return custody, protection, network


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 and RILL_CRYPTO_LIBRARY",
)
def test_explicit_encrypted_identity_and_session_survive_restart_without_admission(
    tmp_path: Path,
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        store, protection, network = _store(tmp_path)
        identity = store.provision_identity_new(crypto=crypto)
        assert store.custody_id == identity.custody_id
        store.require_identity_exact(identity, crypto=crypto)
        binding = _reservation(network, identity.xonly_public_key)
        session = store.provision_session_new(binding, identity, crypto=crypto)
        assert session.custody_id == identity.custody_id
        assert session.xonly_public_key != identity.xonly_public_key
        store.require_session_exact(binding, session, identity, crypto=crypto)
        for filename in ("identity.age", f"session-{binding.session_id}.age"):
            ciphertext = (tmp_path / "custody" / filename).read_bytes()
            assert ciphertext.startswith(b"age-encryption.org/v1\n-> X25519 ")
            assert (tmp_path / "custody" / filename).stat().st_mode & 0o777 == 0o600
            assert binding.handshake_init_hash.encode() not in ciphertext
        assert not any(path.suffix == ".sqlite" for path in (tmp_path / "custody").iterdir())
        restarted = offline.OfflineHandshakeCustody.open_existing(
            tmp_path / "custody",
            protection_identity=protection,
            expected_network=network,
            expected_custody_id=store.custody_id,
        )
        restarted.require_identity_exact(identity, crypto=crypto)
        restarted.require_session_exact(binding, session, identity, crypto=crypto)
        assert "secret_scalar" not in repr(identity) + repr(session)
        with pytest.raises(offline.CustodyError):
            restarted.provision_identity_new(crypto=crypto)
        with pytest.raises(offline.CustodyError):
            restarted.provision_session_new(binding, identity, crypto=crypto)
        restarted.require_session_exact(binding, session, identity, crypto=crypto)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 and RILL_CRYPTO_LIBRARY",
)
def test_absent_partial_wrong_root_and_restored_custody_never_auto_provisions(
    tmp_path: Path,
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        store, protection, network = _store(tmp_path)
        unknown = offline.IdentityRef(store.custody_id, "11" * 32, "22" * 32)
        with pytest.raises(offline.CustodyError):
            store.require_identity_exact(unknown, crypto=crypto)
        identity = store.provision_identity_new(crypto=crypto)
        binding = _reservation(network, identity.xonly_public_key)
        unknown_session = SessionKeyRef(store.custody_id, "11" * 32, "22" * 32)
        older = tmp_path / "restored-before-session"
        shutil.copytree(tmp_path / "custody", older)
        restored = offline.OfflineHandshakeCustody.open_existing(
            older,
            protection_identity=protection,
            expected_network=network,
            expected_custody_id=store.custody_id,
        )
        restored.require_identity_exact(identity, crypto=crypto)
        with pytest.raises(offline.CustodyError):
            restored.require_session_exact(binding, unknown_session, identity, crypto=crypto)
        session = store.provision_session_new(binding, identity, crypto=crypto)
        with pytest.raises(offline.CustodyError):
            restored.require_session_exact(binding, session, identity, crypto=crypto)
        full_copy = tmp_path / "restored-valid-copy"
        shutil.copytree(tmp_path / "custody", full_copy)
        historical = offline.OfflineHandshakeCustody.open_existing(
            full_copy,
            protection_identity=protection,
            expected_network=network,
            expected_custody_id=store.custody_id,
        )
        historical.require_session_exact(binding, session, identity, crypto=crypto)
        # A restored valid copy proves historical availability, not current
        # authority, freshness, or a right to send an acceptance.
        for wrong_identity in (
            offline.IdentityRef(identity.custody_id, "aa" * 32, identity.xonly_public_key),
            offline.IdentityRef(identity.custody_id, identity.key_id, session.xonly_public_key),
        ):
            with pytest.raises(offline.CustodyError):
                store.require_identity_exact(wrong_identity, crypto=crypto)
        changed = SessionReservation(
            binding.session_id,
            "aa" * 32,
            binding.profile_id,
            binding.network_identity_jcs,
            binding.provider_identity_key,
        )
        for wrong_binding, wrong_ref in (
            (changed, session),
            (binding, SessionKeyRef(session.custody_id, "aa" * 32, session.xonly_public_key)),
            (binding, SessionKeyRef(session.custody_id, session.key_id, identity.xonly_public_key)),
        ):
            with pytest.raises(offline.CustodyError):
                store.require_session_exact(wrong_binding, wrong_ref, identity, crypto=crypto)
        with pytest.raises(offline.CustodyError):
            offline.OfflineHandshakeCustody.open_existing(
                tmp_path / "custody",
                protection_identity=str(x25519.Identity.generate()),
                expected_network=network,
                expected_custody_id=store.custody_id,
            )
        with pytest.raises(offline.CustodyError):
            offline.OfflineHandshakeCustody.open_existing(
                tmp_path / "custody",
                protection_identity=protection,
                expected_network=network,
                expected_custody_id="ff" * 32,
            )
        damaged = tmp_path / "damaged"
        shutil.copytree(tmp_path / "custody", damaged)
        (damaged / "identity.age").write_bytes(b"partial")
        with pytest.raises(offline.CustodyError):
            offline.OfflineHandshakeCustody.open_existing(
                damaged,
                protection_identity=protection,
                expected_network=network,
                expected_custody_id=store.custody_id,
            ).require_identity_exact(identity, crypto=crypto)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 and RILL_CRYPTO_LIBRARY",
)
def test_concurrent_session_provisioning_has_one_immutable_winner(tmp_path: Path) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        store, _, network = _store(tmp_path)
        identity = store.provision_identity_new(crypto=crypto)
        binding = _reservation(network, identity.xonly_public_key)

    def attempt(_: int) -> SessionKeyRef | None:
        with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as worker_crypto:
            try:
                return store.provision_session_new(binding, identity, crypto=worker_crypto)
            except offline.CustodyError:
                return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(16)))
    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        store.require_session_exact(binding, winners[0], identity, crypto=crypto)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 and RILL_CRYPTO_LIBRARY",
)
def test_uncertain_publication_never_regenerates_or_returns_a_success_ref(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        store, _, _ = _store(tmp_path)
        original_fsync = offline.os.fsync

        def fail_directory_fsync(descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("secret-bearing durability failure")
            original_fsync(descriptor)

        with monkeypatch.context() as patch:
            patch.setattr(offline.os, "fsync", fail_directory_fsync)
            with pytest.raises(offline.CustodyPublicationUncertainError) as error:
                store.provision_identity_new(crypto=crypto)
            assert error.value.__context__ is None
            assert error.value.__cause__ is None
            assert "secret-bearing" not in repr(error.value)
        assert (tmp_path / "custody" / "identity.age").is_file()
        with pytest.raises(offline.CustodyError):
            store.provision_identity_new(crypto=crypto)
        # Never infer permission to provision a new identity on uncertainty.
        assert not any(
            path.name.startswith("session-") for path in (tmp_path / "custody").iterdir()
        )


@pytest.mark.parametrize("change", ["missing", "partial", "older", "newer", "symlink"])
def test_unsupported_or_missing_manifest_is_not_repaired(tmp_path: Path, change: str) -> None:
    network = _network()
    root = tmp_path / "partial-custody"
    root.mkdir(mode=0o700)
    protection = str(x25519.Identity.generate())
    valid_manifest = canonicalize(
        {
            "kind": "rillswap-offline-provider-custody/v1",
            "custody_id": "11" * 32,
            "network_identity": network.model_dump(mode="json"),
            "recipient": str(x25519.Identity.from_str(protection).to_public()),
        }
    )
    control = tmp_path / "valid-control"
    control.mkdir(mode=0o700)
    (control / "manifest.json").write_bytes(valid_manifest)
    (control / "manifest.json").chmod(0o600)
    assert (
        offline.OfflineHandshakeCustody.open_existing(
            control,
            protection_identity=protection,
            expected_network=network,
            expected_custody_id="11" * 32,
        ).custody_id
        == "11" * 32
    )
    if change == "partial":
        (root / "manifest.json").write_bytes(b"partial")
    elif change in {"older", "newer"}:
        (root / "manifest.json").write_bytes(
            valid_manifest.replace(
                b"custody/v1",
                b"custody/v0" if change == "older" else b"custody/v2",
            )
        )
    elif change == "symlink":
        (root / "manifest.json").symlink_to(FIXTURE)
    if change in {"partial", "older", "newer"}:
        (root / "manifest.json").chmod(0o600)
    before = tuple(
        (item.name, item.read_bytes() if item.is_file() else b"")
        for item in root.iterdir()
        if not item.is_symlink()
    )
    with pytest.raises(offline.CustodyError):
        offline.OfflineHandshakeCustody.open_existing(
            root,
            protection_identity=protection,
            expected_network=network,
            expected_custody_id="11" * 32,
        )
    assert (
        tuple(
            (item.name, item.read_bytes() if item.is_file() else b"")
            for item in root.iterdir()
            if not item.is_symlink()
        )
        == before
    )
    with pytest.raises(offline.CustodyError):
        offline.OfflineHandshakeCustody.create_new(
            root,
            protection_identity=protection,
            expected_network=network,
        )


@pytest.mark.parametrize("operation", ["create", "open"])
def test_sanitized_namespace_failure_does_not_retain_library_protection_root(
    tmp_path: Path,
    operation: str,
) -> None:
    network = _network()
    root = tmp_path / "unavailable"
    root.mkdir(mode=0o700)
    protection = str(x25519.Identity.generate())

    def invoke() -> object:
        if operation == "create":
            return offline.OfflineHandshakeCustody.create_new(
                root,
                protection_identity=protection,
                expected_network=network,
            )
        return offline.OfflineHandshakeCustody.open_existing(
            root,
            protection_identity=protection,
            expected_network=network,
            expected_custody_id="11" * 32,
        )

    with pytest.raises(offline.CustodyError) as failure:
        invoke()
    assert failure.value.__context__ is None
    assert failure.value.__cause__ is None
    assert protection not in repr(failure.value)
    frames = []
    traceback = failure.value.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename == offline.__file__:
            frames.append(frame)
        traceback = traceback.tb_next
    assert len(frames) == 1
    assert "protection_identity" not in frames[0].f_locals
    assert protection not in repr(frames[0].f_locals)
