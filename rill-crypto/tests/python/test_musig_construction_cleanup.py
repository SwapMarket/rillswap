"""Successful native allocation always has an exception-safe Python owner."""

from __future__ import annotations

import asyncio
import gc
import os
import weakref
from typing import Any

import pytest
from rill_crypto import Context, CryptoError, binding

LIBRARY = os.environ.get("RILL_CRYPTO_LIBRARY")
pytestmark = pytest.mark.skipif(not LIBRARY, reason="native library path is not configured")


class CountingLib:
    def __init__(self, delegate: Any, *, failed_status: bool = False) -> None:
        self.delegate = delegate
        self.failed_status = failed_status
        self.allocated = 0
        self.destroyed = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.delegate, name)

    def rill_musig_begin(self, *args: Any) -> int:
        result = self.delegate.rill_musig_begin(*args)
        if result == 0:
            self.allocated += 1
            if self.failed_status:
                return 1  # A conservative failure with a published output pointer.
        return result

    def rill_musig_attempt_destroy(self, pointer: Any) -> None:
        self.destroyed += 1
        self.delegate.rill_musig_attempt_destroy(pointer)


@pytest.mark.parametrize(
    "failure",
    [
        "first wipe",
        "second wipe",
        "charge",
        "constructor before",
        "constructor after",
        "finalizer after",
        "nonce conversion",
        "status",
    ],
)
def test_post_allocation_failure_releases_once_even_with_retained_tracebacks(  # noqa: C901, PLR0915 - one ownership fault matrix
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    context = Context(library_path=LIBRARY, context_random=b"\x11" * 32)
    arguments = {
        "secret_key": (1).to_bytes(32, "big"),
        "user_public_key": context.public_key((1).to_bytes(32, "big")),
        "provider_public_key": context.public_key((2).to_bytes(32, "big")),
        "tap_tweak": (3).to_bytes(32, "big"),
        "message": b"\x44" * 32,
        "cooperation_id": b"\x55" * 32,
    }
    counted = CountingLib(context._native.lib, failed_status=failure == "status")
    context._native.lib = counted
    captured = []
    finalizers = []
    traces = []
    wipe_calls = []
    try:
        with monkeypatch.context() as patch:
            original_wipe = context._native.wipe

            def wipe(pointer: Any, size: int) -> None:
                wipe_calls.append(pointer)
                original_wipe(pointer, size)
                if failure == "first wipe" and len(wipe_calls) == 1:
                    raise MemoryError("injected first wipe failure")
                if failure == "second wipe" and len(wipe_calls) == 2:
                    raise MemoryError("injected second wipe failure")

            patch.setattr(context._native, "wipe", wipe)
            original_init = binding.MusigAttempt.__init__

            def initialize(self: binding.MusigAttempt, *args: Any) -> None:
                if failure == "constructor before":
                    raise MemoryError("injected wrapper failure")
                original_init(self, *args)
                captured.append(self)
                if failure == "constructor after":
                    raise MemoryError("injected owned-wrapper failure")

            patch.setattr(binding.MusigAttempt, "__init__", initialize)
            if failure == "finalizer after":
                original_finalize = binding.weakref.finalize

                def finalize(*args: Any, **kwargs: Any) -> Any:
                    registered = original_finalize(*args, **kwargs)
                    captured.append(args[0])
                    finalizers.append(registered)
                    raise MemoryError("injected after finalizer registration")

                patch.setattr(binding.weakref, "finalize", finalize)
            if failure == "nonce conversion":
                original_bytes = context._native.bytes

                def convert(pointer: Any, size: int) -> bytes:
                    if size == 66:
                        raise MemoryError("injected public nonce conversion failure")
                    return original_bytes(pointer, size)

                patch.setattr(context._native, "bytes", convert)
            if failure == "charge":

                class FailedIncrement(int):
                    def __add__(self, _other: object) -> int:
                        raise MemoryError("injected allocation-counter failure")

                context._active_attempts = FailedIncrement(0)
            with pytest.raises((MemoryError, CryptoError)) as error:
                context.musig_begin(**arguments)
            traces.append(error.value)  # Keep constructor frames and wrappers alive.
        assert counted.allocated == counted.destroyed == 1
        assert len(wipe_calls) == 2
        assert context._active_attempts == 0
        for wrapper in captured:
            assert wrapper._pointer == context._native.ffi.NULL
            with pytest.raises(RuntimeError, match="closed"):
                wrapper.partial_sign_once(b"\x02" * 66)
            finalizer = getattr(wrapper, "_finalizer", None)
            if finalizer is not None:
                finalizer()
        for finalizer in finalizers:
            finalizer()
        gc.collect()
        assert counted.destroyed == 1
        assert context._active_attempts == 0
        if failure == "charge":
            context._active_attempts = 0
        counted.failed_status = False
        fresh, nonce = context.musig_begin(**{**arguments, "cooperation_id": b"\x66" * 32})
        assert len(nonce) == 66
        assert context._active_attempts == 1
        fresh.close()
        assert counted.destroyed == 2
        assert context._active_attempts == 0
    finally:
        context.close()


def test_base_exception_during_wipe_releases_native_ownership_and_attempts_both_wipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with Context(library_path=LIBRARY, context_random=b"\x11" * 32) as context:
        arguments = {
            "secret_key": (1).to_bytes(32, "big"),
            "user_public_key": context.public_key((1).to_bytes(32, "big")),
            "provider_public_key": context.public_key((2).to_bytes(32, "big")),
            "tap_tweak": (3).to_bytes(32, "big"),
            "message": b"\x44" * 32,
            "cooperation_id": b"\x55" * 32,
        }
        counted = CountingLib(context._native.lib)
        context._native.lib = counted
        original = context._native.wipe
        calls = []

        def wipe(pointer: Any, size: int) -> None:
            original(pointer, size)
            calls.append(pointer)
            if len(calls) == 1:
                raise asyncio.CancelledError

        monkeypatch.setattr(context._native, "wipe", wipe)
        with pytest.raises(asyncio.CancelledError):
            context.musig_begin(**arguments)
        assert len(calls) == 2
        assert counted.allocated == counted.destroyed == 1
        assert context._active_attempts == 0


def test_input_preparation_failure_attempts_existing_secret_wipe_without_native_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with Context(library_path=LIBRARY, context_random=b"\x11" * 32) as context:
        arguments = {
            "secret_key": (1).to_bytes(32, "big"),
            "user_public_key": context.public_key((1).to_bytes(32, "big")),
            "provider_public_key": context.public_key((2).to_bytes(32, "big")),
            "tap_tweak": (3).to_bytes(32, "big"),
            "message": b"\x44" * 32,
            "cooperation_id": b"\x55" * 32,
        }
        counted = CountingLib(context._native.lib)
        context._native.lib = counted
        original_input = context._native.input
        original_wipe = context._native.wipe
        wiped = []

        def prepare(value: bytes, size: int, label: str) -> Any:
            if label == "session_random":
                raise MemoryError("injected random-input failure")
            return original_input(value, size, label)

        def wipe(pointer: Any, size: int) -> None:
            original_wipe(pointer, size)
            wiped.append(bytes(context._native.ffi.buffer(pointer, size)))

        monkeypatch.setattr(context._native, "input", prepare)
        monkeypatch.setattr(context._native, "wipe", wipe)
        with pytest.raises(MemoryError):
            context.musig_begin(**arguments)
        assert wiped == [b"\0" * 32]
        assert counted.allocated == counted.destroyed == 0
        assert context._active_attempts == 0


def test_successful_attempt_is_automatically_finalized_without_retaining_the_wrapper() -> None:
    context = Context(library_path=LIBRARY, context_random=b"\x11" * 32)
    counted = CountingLib(context._native.lib)
    context._native.lib = counted
    attempt, _nonce = context.musig_begin(
        secret_key=(1).to_bytes(32, "big"),
        user_public_key=context.public_key((1).to_bytes(32, "big")),
        provider_public_key=context.public_key((2).to_bytes(32, "big")),
        tap_tweak=(3).to_bytes(32, "big"),
        message=b"\x44" * 32,
        cooperation_id=b"\x55" * 32,
    )
    reference = weakref.ref(attempt)
    assert context._active_attempts == 1
    del attempt
    gc.collect()
    assert reference() is None
    assert counted.allocated == counted.destroyed == 1
    assert context._active_attempts == 0
    context.close()


def test_failed_constructor_automatic_finalization_never_destroys_a_second_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with Context(library_path=LIBRARY, context_random=b"\x11" * 32) as context:
        counted = CountingLib(context._native.lib)
        context._native.lib = counted
        references = []
        initialize = binding.MusigAttempt.__init__

        def fail_after_registration(self: binding.MusigAttempt, *args: Any) -> None:
            initialize(self, *args)
            references.append(weakref.ref(self))
            raise MemoryError("injected registered wrapper failure")

        with monkeypatch.context() as patch:
            patch.setattr(binding.MusigAttempt, "__init__", fail_after_registration)
            try:
                context.musig_begin(
                    secret_key=(1).to_bytes(32, "big"),
                    user_public_key=context.public_key((1).to_bytes(32, "big")),
                    provider_public_key=context.public_key((2).to_bytes(32, "big")),
                    tap_tweak=(3).to_bytes(32, "big"),
                    message=b"\x44" * 32,
                    cooperation_id=b"\x55" * 32,
                )
            except MemoryError as error:
                retained_traceback = error.__traceback__
                assert references[0]() is not None
                assert references[0]()._pointer == context._native.ffi.NULL
            else:
                pytest.fail("constructor injection did not execute")
        assert retained_traceback is not None
        assert counted.destroyed == 1
        del retained_traceback
        gc.collect()
        assert references[0]() is None
        assert counted.allocated == counted.destroyed == 1
        assert context._active_attempts == 0
