"""Acceptance signing needs live key custody; no provider session is admitted."""

from __future__ import annotations

import json
import os
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.wire.hashes import handshake_accept_hash
from rill_core.wire.messages import HandshakeAccept
from rill_core.wire.types import NetworkIdentity

from rill_provider.handshake_signing import (
    HandshakeSigningError,
    SessionKeyRef,
    SessionReservation,
    session_reservation_for_init,
    sign_handshake_accept,
)

if TYPE_CHECKING:
    from rill_crypto import Context

FIXTURE = Path(__file__).parent / "fixtures" / "initial-btc-to-ln-v1.json"
IDENTITY_SECRET = (1).to_bytes(32, "big")  # Fixture-only public deterministic scalar.
SESSION_SECRET = (3).to_bytes(32, "big")  # Fixture-only public deterministic scalar.
IDENTITY_KEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


class TestOnlyEphemeralCustody:
    """Test fixture with no key persistence or restart recovery; never deploy."""

    __test__ = False

    def __init__(self, crypto: Context) -> None:
        self.crypto = crypto
        self._lock = threading.Lock()
        self._binding: SessionReservation | None = None
        self._ref: SessionKeyRef | None = None

    def identity_xonly_public_key(self) -> str:
        return self.crypto.public_key(IDENTITY_SECRET)[1:].hex()

    def reserve_session(self, binding: SessionReservation) -> SessionKeyRef:
        with self._lock:
            if self._binding is None:
                self._binding = binding
                self._ref = SessionKeyRef(
                    "test-only-memory",
                    secrets.token_hex(16),
                    self.crypto.public_key(SESSION_SECRET)[1:].hex(),
                )
            elif self._binding != binding:
                raise OSError("conflicting reservation must not allocate another key")
            assert self._ref is not None
            return self._ref

    def require_session(self, binding: SessionReservation, ref: SessionKeyRef) -> None:
        with self._lock:
            if self._binding != binding or self._ref != ref:
                raise OSError("test session key is not available after restart")
            if self.crypto.public_key(SESSION_SECRET)[1:].hex() != ref.xonly_public_key:
                raise OSError("test key public identity differs")

    def sign_handshake_accept_hash(self, digest: bytes) -> bytes:
        return self.crypto.schnorr_sign(IDENTITY_SECRET, digest, b"\x44" * 32)


def _fixture() -> tuple[dict[str, Any], bytes, bytes, NetworkIdentity]:
    package = json.loads(FIXTURE.read_text())
    context = package["verification_context"]
    init = context["handshake_init"]
    return (
        context,
        json.dumps(init).encode(),
        json.dumps(context["handshake_accept"]).encode(),
        NetworkIdentity.model_validate_json(json.dumps(package["network_identity"])),
    )


def _binding(init: bytes, network: NetworkIdentity, **overrides: object) -> SessionReservation:
    configured: dict[str, Any] = {
        "expected_network": network,
        "expected_profile": "btc-to-ln/v1",
        "expected_provider_identity": IDENTITY_KEY,
        "supported_features": frozenset(),
    }
    configured.update(overrides)
    return session_reservation_for_init(init, **configured)


def _sign(
    init: bytes,
    accept: bytes,
    network: NetworkIdentity,
    custody: TestOnlyEphemeralCustody,
    ref: SessionKeyRef,
    **overrides: object,
) -> str:
    configured: dict[str, Any] = {
        "expected_network": network,
        "expected_profile": "btc-to-ln/v1",
        "expected_provider_identity": IDENTITY_KEY,
        "supported_features": frozenset(),
        "supported_encryption_suites": frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
        "supported_capabilities": frozenset({"core/v1", "recovery/v1"}),
        "session_ref": ref,
        "custody": custody,
        "crypto": custody.crypto,
    }
    configured.update(overrides)
    return sign_handshake_accept(init, accept, **configured)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_real_identity_signature_and_test_only_live_session_reservation() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    context, init, accept, network = _fixture()
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        custody = TestOnlyEphemeralCustody(crypto)
        binding = _binding(init, network)
        ref = custody.reserve_session(binding)
        assert custody.reserve_session(binding) == ref
        assert ref.xonly_public_key == context["provider_session_xonly_key"]
        assert IDENTITY_SECRET.hex() not in repr(ref)
        signature = _sign(init, accept, network, custody, ref)
        accepted = HandshakeAccept.model_validate_json(accept)
        digest = handshake_accept_hash(accepted)
        crypto.schnorr_verify(
            bytes.fromhex(custody.identity_xonly_public_key()), digest, bytes.fromhex(signature)
        )
        assert _sign(init, accept, network, custody, ref) == signature
        with pytest.raises(HandshakeSigningError, match="signing unavailable") as error:
            _sign(init, accept, network, TestOnlyEphemeralCustody(crypto), ref)
        assert error.value.__context__ is None
        assert error.value.__cause__ is None


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_concurrent_identical_reservations_are_idempotent_and_conflict_refused() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    _, init, _, network = _fixture()
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        custody = TestOnlyEphemeralCustody(crypto)
        binding = _binding(init, network)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(custody.reserve_session, [binding] * 32))
        assert len({result.key_id for result in results}) == 1
        changed = SessionReservation(
            binding.session_id,
            "aa" * 32,
            binding.profile_id,
            binding.network_identity_jcs,
            binding.provider_identity_key,
        )
        with pytest.raises(OSError, match="conflicting reservation"):
            custody.reserve_session(changed)
        assert custody.reserve_session(binding) == results[0]


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize(
    "mutation",
    [
        "init-identity",
        "network",
        "profile",
        "features",
        "suite",
        "capabilities",
        "accept-key",
        "accept-init-hash",
        "accept-session",
        "bad-ref",
        "wrong-ref",
        "bad-signature",
        "boolean-verifier",
        "duplicate-init",
        "duplicate-accept",
    ],
)
def test_acceptance_signing_rejects_wrong_context_or_custody(  # noqa: PLR0912 - negative matrix
    mutation: str,
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    _, init, accept, network = _fixture()
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        custody = TestOnlyEphemeralCustody(crypto)
        ref = custody.reserve_session(_binding(init, network))
        changed_init = json.loads(init)
        changed_accept = json.loads(accept)
        overrides: dict[str, object] = {}
        if mutation == "init-identity":
            changed_init["expected_provider_identity_xonly_key"] = ref.xonly_public_key
        elif mutation == "network":
            configured = network.model_dump(mode="json")
            configured["deployment_namespace"] = "other"
            overrides["expected_network"] = NetworkIdentity.model_validate(configured)
        elif mutation == "profile":
            overrides["expected_profile"] = "ln-to-btc/v1"
        elif mutation == "features":
            changed_accept["required_features"] = ["org.test/unknown"]
        elif mutation == "suite":
            overrides["supported_encryption_suites"] = frozenset()
        elif mutation == "capabilities":
            overrides["supported_capabilities"] = frozenset({"core/v1"})
        elif mutation == "accept-key":
            changed_accept["provider_session_xonly_key"] = custody.identity_xonly_public_key()
        elif mutation == "accept-init-hash":
            changed_accept["handshake_init_hash"] = "00" * 32
        elif mutation == "accept-session":
            changed_accept["session_id"] = "00" * 32
        elif mutation == "bad-ref":
            overrides["session_ref"] = SessionKeyRef(ref.custody_id, "wrong", ref.xonly_public_key)
        elif mutation == "wrong-ref":
            overrides["session_ref"] = SessionKeyRef(
                ref.custody_id, ref.key_id, custody.identity_xonly_public_key()
            )
        elif mutation == "bad-signature":
            custody.sign_handshake_accept_hash = lambda _digest: b"\x00" * 64  # type: ignore[method-assign]
        elif mutation == "boolean-verifier":

            class InvalidVerifier:
                def schnorr_verify(self, *_args: bytes) -> bool:
                    return False

            overrides["crypto"] = InvalidVerifier()
        elif mutation == "duplicate-init":
            init = init.replace(b'"session_id":', b'"session_id":"00", "session_id":', 1)
        else:
            accept = accept.replace(b'"session_id":', b'"session_id":"00", "session_id":', 1)
        if mutation not in {"duplicate-init", "duplicate-accept"}:
            init, accept = json.dumps(changed_init).encode(), json.dumps(changed_accept).encode()
        with pytest.raises(HandshakeSigningError) as error:
            _sign(init, accept, network, custody, ref, **overrides)
        assert error.value.__cause__ is None
        assert error.value.__context__ is None


def test_invalid_init_fails_without_any_custody_lookup() -> None:
    _, _, _, network = _fixture()
    with pytest.raises(HandshakeSigningError, match="invalid handshake reservation") as error:
        _binding(b"{secret-bearing-invalid", network)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
