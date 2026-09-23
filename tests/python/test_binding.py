from __future__ import annotations

import copy
import json
import os
import pickle
import shutil
import subprocess
from pathlib import Path
from threading import Event, Thread
from typing import Any

import pytest
from rill_crypto import Context, CryptoError
from rill_crypto.binding import MusigAttempt

LIBRARY = os.environ.get("RILL_CRYPTO_LIBRARY")
pytestmark = pytest.mark.skipif(not LIBRARY, reason="native library path is not configured")


def scalar(value: int) -> bytes:
    return value.to_bytes(32, "big")


class BlockingLib:
    def __init__(self, delegate: Any, method: str, entered: Event, release: Event) -> None:
        self._delegate = delegate
        self._method = method
        self._entered = entered
        self._release = release

    def __getattr__(self, name: str) -> Any:
        original = getattr(self._delegate, name)
        if name != self._method:
            return original

        def blocked(*args: Any) -> Any:
            self._entered.set()
            if not self._release.wait(timeout=2):
                raise TimeoutError("test did not release blocked native call")
            return original(*args)

        return blocked


def test_schnorr_sign_and_verify() -> None:
    with Context(library_path=LIBRARY, context_random=b"\x11" * 32) as context:
        public_key = context.public_key(scalar(1))
        signature = context.schnorr_sign(scalar(1), b"\x22" * 32, b"\x33" * 32)
        context.schnorr_verify(public_key[1:], b"\x22" * 32, signature)
        with pytest.raises(CryptoError):
            context.schnorr_verify(public_key[1:], b"\x23" * 32, signature)


def test_pinned_bip340_verify_vectors_match_wasm_cases() -> None:
    """Native and WASM exercise the exact same official BIP340 fixtures."""
    fixtures = json.loads(
        (Path(__file__).parents[1] / "fixtures/bip340-verify-vectors.json").read_text()
    )
    with Context(library_path=LIBRARY, context_random=b"\x11" * 32) as context:
        for case in fixtures["cases"]:
            key = bytes.fromhex(case["key"])
            message = bytes.fromhex(case["message"])
            signature = bytes.fromhex(case["signature"])
            if case["expected"]:
                context.schnorr_verify(key, message, signature)
            else:
                with pytest.raises(CryptoError):
                    context.schnorr_verify(key, message, signature)


def test_musig_internal_key_uses_ordered_bip327_aggregation() -> None:
    # Independent BIP327 reference.py fixtures at acdce4d50c61f81d9ec6534a804b1fb14e84e565.
    with Context(library_path=LIBRARY, context_random=b"\x11" * 32) as context:
        user_key = context.public_key(scalar(1))
        provider_key = context.public_key(scalar(2))
        internal_key, parity = context.musig_internal_key(user_key, provider_key)
        assert internal_key.hex() == (
            "3b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63ec2ec"
        )
        assert parity == 0
        odd_key, odd_parity = context.musig_internal_key(
            user_key,
            context.public_key(scalar(3)),
        )
        assert odd_key.hex() == ("6e68b837de28101018371e7bf6e59b5852c9e39472794c28fd955c714b8174ba")
        assert odd_parity == 1
        reversed_key, _ = context.musig_internal_key(provider_key, user_key)
        assert reversed_key != internal_key
        with pytest.raises(CryptoError, match="duplicate public key"):
            context.musig_internal_key(user_key, user_key)


def test_new_binding_rejects_abi_v1_library_without_internal_key(
    tmp_path: Path,
) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler is unavailable")
    library = tmp_path / "librill_crypto_old.so"
    subprocess.run(  # noqa: S603
        [compiler, "-shared", "-fPIC", "-x", "c", "-o", str(library), "-"],
        input=("#include <stdint.h>\nuint32_t rill_crypto_abi_version(void) { return 1u; }\n"),
        text=True,
        check=True,
    )
    with pytest.raises(RuntimeError, match="missing required symbol") as error:
        Context(library_path=library, context_random=b"\x11" * 32)
    assert str(library) in str(error.value)
    assert "rill_musig_internal_key" in str(error.value)


def test_musig_attempt_is_one_shot_and_final_signature_verifies() -> None:
    with Context(library_path=LIBRARY, context_random=b"\x11" * 32) as context:
        user_key = context.public_key(scalar(1))
        provider_key = context.public_key(scalar(2))
        tweak = scalar(3)
        message = b"\x44" * 32
        cooperation_id = b"\x55" * 32
        output_key, parity = context.musig_output_key(user_key, provider_key, tweak)
        assert parity in (0, 1)

        user_attempt, user_nonce = context.musig_begin(
            secret_key=scalar(1),
            user_public_key=user_key,
            provider_public_key=provider_key,
            tap_tweak=tweak,
            message=message,
            cooperation_id=cooperation_id,
        )
        provider_attempt, provider_nonce = context.musig_begin(
            secret_key=scalar(2),
            user_public_key=user_key,
            provider_public_key=provider_key,
            tap_tweak=tweak,
            message=message,
            cooperation_id=cooperation_id,
        )
        with user_attempt, provider_attempt:
            context.musig_public_nonce_validate(user_nonce)
            with pytest.raises(CryptoError, match="invalid nonce"):
                context.musig_public_nonce_validate(b"\x00" * 66)
            user_partial = user_attempt.partial_sign_once(provider_nonce)
            with pytest.raises(CryptoError, match="attempt consumed"):
                user_attempt.partial_sign_once(provider_nonce)
            provider_partial = provider_attempt.partial_sign_once(user_nonce)

            context.musig_partial_verify(
                user_public_key=user_key,
                provider_public_key=provider_key,
                tap_tweak=tweak,
                message=message,
                user_public_nonce=user_nonce,
                provider_public_nonce=provider_nonce,
                signer_index=0,
                partial_signature=user_partial,
            )
            signature = context.musig_aggregate(
                user_public_key=user_key,
                provider_public_key=provider_key,
                tap_tweak=tweak,
                message=message,
                user_public_nonce=user_nonce,
                provider_public_nonce=provider_nonce,
                user_partial_signature=user_partial,
                provider_partial_signature=provider_partial,
            )
            context.schnorr_verify(output_key, message, signature)


def test_context_cannot_close_with_live_attempt() -> None:
    context = Context(library_path=LIBRARY, context_random=b"\x11" * 32)
    user_key = context.public_key(scalar(1))
    provider_key = context.public_key(scalar(2))
    attempt, _ = context.musig_begin(
        secret_key=scalar(1),
        user_public_key=user_key,
        provider_public_key=provider_key,
        tap_tweak=scalar(3),
        message=b"\x44" * 32,
        cooperation_id=b"\x55" * 32,
    )
    with pytest.raises(RuntimeError, match="live MuSig"):
        context.close()
    attempt.close()
    context.close()


def test_context_and_attempt_reject_copy_and_serialization() -> None:
    context = Context(library_path=LIBRARY, context_random=b"\x11" * 32)
    user_key = context.public_key(scalar(1))
    provider_key = context.public_key(scalar(2))
    attempt, _ = context.musig_begin(
        secret_key=scalar(1),
        user_public_key=user_key,
        provider_public_key=provider_key,
        tap_tweak=scalar(3),
        message=b"\x44" * 32,
        cooperation_id=b"\x55" * 32,
    )
    for value in (context, attempt):
        with pytest.raises(copy.Error):
            copy.copy(value)
        with pytest.raises(copy.Error):
            copy.deepcopy(value)
        with pytest.raises(TypeError):
            pickle.dumps(value)
    attempt.close()
    context.close()


def test_attempt_construction_requires_private_factory_token() -> None:
    context = Context(library_path=LIBRARY, context_random=b"\x11" * 32)
    with pytest.raises(TypeError, match="only be created"):
        MusigAttempt(context, object(), object())
    context.close()


def test_context_close_waits_for_native_operation() -> None:
    context = Context(library_path=LIBRARY, context_random=b"\x11" * 32)
    entered = Event()
    release = Event()
    close_done = Event()
    delegate = context._native.lib
    context._native.lib = BlockingLib(delegate, "rill_public_key_create", entered, release)

    operation = Thread(target=context.public_key, args=(scalar(1),))
    operation.start()
    assert entered.wait(timeout=1)

    def close_context() -> None:
        context.close()
        close_done.set()

    closing = Thread(target=close_context)
    closing.start()
    assert not close_done.wait(timeout=0.05)
    release.set()
    operation.join(timeout=1)
    closing.join(timeout=1)
    assert close_done.is_set()


def test_attempt_close_waits_for_partial_sign() -> None:
    context = Context(library_path=LIBRARY, context_random=b"\x11" * 32)
    user_key = context.public_key(scalar(1))
    provider_key = context.public_key(scalar(2))
    arguments = {
        "user_public_key": user_key,
        "provider_public_key": provider_key,
        "tap_tweak": scalar(3),
        "message": b"\x44" * 32,
        "cooperation_id": b"\x55" * 32,
    }
    user_attempt, user_nonce = context.musig_begin(secret_key=scalar(1), **arguments)
    provider_attempt, provider_nonce = context.musig_begin(secret_key=scalar(2), **arguments)
    entered = Event()
    release = Event()
    close_done = Event()
    delegate = context._native.lib
    context._native.lib = BlockingLib(
        delegate,
        "rill_musig_partial_sign_once",
        entered,
        release,
    )

    operation = Thread(target=user_attempt.partial_sign_once, args=(provider_nonce,))
    operation.start()
    assert entered.wait(timeout=1)

    def close_attempt() -> None:
        user_attempt.close()
        close_done.set()

    closing = Thread(target=close_attempt)
    closing.start()
    assert not close_done.wait(timeout=0.05)
    release.set()
    operation.join(timeout=1)
    closing.join(timeout=1)
    assert close_done.is_set()
    provider_attempt.close()
    context.close()
    assert len(user_nonce) == 66
