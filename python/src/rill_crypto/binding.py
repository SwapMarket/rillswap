"""CFFI ABI binding with explicit native context and MuSig handle ownership."""

from __future__ import annotations

import ctypes.util
import os
import weakref
from contextlib import contextmanager
from copy import Error as CopyError
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any, Final, Never, Protocol, Self, SupportsIndex, cast

from cffi import FFI

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

_ABI_VERSION: Final = 1
_OK: Final = 0
_ATTEMPT_TOKEN: Final = object()
_STATUS_NAMES: Final = {
    1: "invalid argument",
    2: "invalid secret key",
    3: "invalid public key",
    4: "duplicate public key",
    5: "invalid signature",
    6: "invalid nonce",
    7: "attempt consumed",
    8: "allocation failure",
    9: "internal error",
}

_CDEF = """
typedef struct rill_crypto_context rill_crypto_context;
typedef struct rill_musig_attempt rill_musig_attempt;
uint32_t rill_crypto_abi_version(void);
rill_crypto_context *rill_crypto_context_create(const unsigned char random32[32]);
void rill_crypto_context_destroy(rill_crypto_context *context);
int rill_public_key_create(
    const rill_crypto_context *, const unsigned char[32], unsigned char[33]
);
int rill_schnorr_sign(
    const rill_crypto_context *, const unsigned char[32],
    const unsigned char[32], const unsigned char[32], unsigned char[64]
);
int rill_schnorr_verify(
    const rill_crypto_context *, const unsigned char[32],
    const unsigned char[32], const unsigned char[64]
);
int rill_musig_internal_key(
    const rill_crypto_context *, const unsigned char[33],
    const unsigned char[33], unsigned char[32], int *
);
int rill_musig_output_key(
    const rill_crypto_context *, const unsigned char[33],
    const unsigned char[33], const unsigned char[32], unsigned char[32], int *
);
int rill_musig_begin(
    const rill_crypto_context *, const unsigned char[32],
    const unsigned char[33], const unsigned char[33], const unsigned char[32],
    const unsigned char[32], const unsigned char[32], const unsigned char[32],
    rill_musig_attempt **, unsigned char[66]
);
int rill_musig_public_nonce_validate(const rill_crypto_context *, const unsigned char[66]);
int rill_musig_partial_sign_once(
    const rill_crypto_context *, rill_musig_attempt *,
    const unsigned char[66], unsigned char[32]
);
int rill_musig_partial_verify(
    const rill_crypto_context *, const unsigned char[33],
    const unsigned char[33], const unsigned char[32], const unsigned char[32],
    const unsigned char[66], const unsigned char[66], size_t,
    const unsigned char[32]
);
int rill_musig_aggregate(
    const rill_crypto_context *, const unsigned char[33],
    const unsigned char[33], const unsigned char[32], const unsigned char[32],
    const unsigned char[66], const unsigned char[66], const unsigned char[32],
    const unsigned char[32], unsigned char[64]
);
void rill_musig_attempt_destroy(rill_musig_attempt *attempt);
"""


class _Lib(Protocol):
    def rill_crypto_abi_version(self) -> int: ...
    def rill_crypto_context_create(self, *args: Any) -> Any: ...
    def rill_crypto_context_destroy(self, *args: Any) -> None: ...
    def rill_public_key_create(self, *args: Any) -> int: ...
    def rill_schnorr_sign(self, *args: Any) -> int: ...
    def rill_schnorr_verify(self, *args: Any) -> int: ...
    def rill_musig_internal_key(self, *args: Any) -> int: ...
    def rill_musig_output_key(self, *args: Any) -> int: ...
    def rill_musig_begin(self, *args: Any) -> int: ...
    def rill_musig_public_nonce_validate(self, *args: Any) -> int: ...
    def rill_musig_partial_sign_once(self, *args: Any) -> int: ...
    def rill_musig_partial_verify(self, *args: Any) -> int: ...
    def rill_musig_aggregate(self, *args: Any) -> int: ...
    def rill_musig_attempt_destroy(self, *args: Any) -> None: ...


class CryptoError(RuntimeError):
    """Native cryptographic operation failed with a stable status code."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(_STATUS_NAMES.get(status, f"unknown native status {status}"))


def _require_size(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"{name} must contain exactly {size} bytes")
    return value


class _Native:
    def __init__(self, library_path: str | os.PathLike[str] | None) -> None:
        self.ffi = FFI()
        self.ffi.cdef(_CDEF)
        selected = self._select_library(library_path)
        self.lib = cast("_Lib", self.ffi.dlopen(selected))
        if self.lib.rill_crypto_abi_version() != _ABI_VERSION:
            raise RuntimeError("native rill-crypto ABI version mismatch")
        try:
            _ = self.lib.rill_musig_internal_key
        except AttributeError as error:
            raise RuntimeError(
                f"native rill-crypto library {selected!r} is missing required symbol "
                "rill_musig_internal_key",
            ) from error

    @staticmethod
    def _select_library(library_path: str | os.PathLike[str] | None) -> str:
        if library_path is not None:
            return os.fspath(library_path)
        configured = os.environ.get("RILL_CRYPTO_LIBRARY")
        if configured:
            return configured
        packaged = Path(__file__).parent / "_native" / "librill_crypto.so.1"
        if packaged.is_file():
            return str(packaged)
        discovered = ctypes.util.find_library("rill_crypto")
        if discovered:
            return discovered
        raise RuntimeError(
            "rill-crypto native library not found; set RILL_CRYPTO_LIBRARY",
        )

    def input(self, value: bytes, size: int, name: str) -> Any:
        return self.ffi.new(f"unsigned char[{size}]", _require_size(value, size, name))

    def output(self, size: int) -> Any:
        return self.ffi.new(f"unsigned char[{size}]")

    def bytes(self, value: Any, size: int) -> bytes:
        return bytes(self.ffi.buffer(value, size))

    def wipe(self, value: Any, size: int) -> None:
        self.ffi.buffer(value, size)[:] = b"\x00" * size


def _check(status: int) -> None:
    if status != _OK:
        raise CryptoError(status)


class Context:
    """Randomized native signing context that owns all attempts created from it."""

    def __init__(
        self,
        *,
        library_path: str | os.PathLike[str] | None = None,
        context_random: bytes | None = None,
    ) -> None:
        self._native = _Native(library_path)
        self._lock = RLock()
        self._active_attempts = 0
        random_value = os.urandom(32) if context_random is None else context_random
        random_input = self._native.input(random_value, 32, "context_random")
        try:
            self._pointer = self._native.lib.rill_crypto_context_create(random_input)
        finally:
            self._native.wipe(random_input, 32)
        if self._pointer == self._native.ffi.NULL:
            raise CryptoError(9)
        self._finalizer = weakref.finalize(
            self,
            self._native.lib.rill_crypto_context_destroy,
            self._pointer,
        )

    def _require_open(self) -> None:
        if self._pointer == self._native.ffi.NULL:
            raise RuntimeError("cryptographic context is closed")

    @contextmanager
    def _operation(self) -> Iterator[None]:
        with self._lock:
            self._require_open()
            yield

    def close(self) -> None:
        """Destroy the context after all child attempts are destroyed."""
        with self._lock:
            if self._active_attempts:
                raise RuntimeError("cannot close context with live MuSig attempts")
            if self._pointer != self._native.ffi.NULL:
                self._finalizer()
                self._pointer = self._native.ffi.NULL

    def __enter__(self) -> Self:
        with self._lock:
            self._require_open()
            return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __copy__(self) -> Never:
        raise CopyError("cryptographic contexts cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        raise CopyError("cryptographic contexts cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("cryptographic contexts cannot be serialized")

    def public_key(self, secret_key: bytes) -> bytes:
        """Return the compressed public key for a valid secret key."""
        with self._operation():
            secret = self._native.input(secret_key, 32, "secret_key")
            output = self._native.output(33)
            try:
                _check(self._native.lib.rill_public_key_create(self._pointer, secret, output))
                return self._native.bytes(output, 33)
            finally:
                self._native.wipe(secret, 32)

    def schnorr_sign(self, secret_key: bytes, message: bytes, auxiliary_random: bytes) -> bytes:
        """Create and internally verify a BIP340 signature."""
        with self._operation():
            secret = self._native.input(secret_key, 32, "secret_key")
            message_input = self._native.input(message, 32, "message")
            auxiliary = self._native.input(auxiliary_random, 32, "auxiliary_random")
            output = self._native.output(64)
            try:
                _check(
                    self._native.lib.rill_schnorr_sign(
                        self._pointer,
                        secret,
                        message_input,
                        auxiliary,
                        output,
                    ),
                )
                return self._native.bytes(output, 64)
            finally:
                self._native.wipe(secret, 32)
                self._native.wipe(auxiliary, 32)

    def schnorr_verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        """Verify a BIP340 signature or raise `CryptoError`."""
        with self._operation():
            _check(
                self._native.lib.rill_schnorr_verify(
                    self._pointer,
                    self._native.input(public_key, 32, "public_key"),
                    self._native.input(message, 32, "message"),
                    self._native.input(signature, 64, "signature"),
                ),
            )

    def musig_output_key(
        self,
        user_public_key: bytes,
        provider_public_key: bytes,
        tap_tweak: bytes,
    ) -> tuple[bytes, int]:
        """Aggregate user/provider keys in order and apply the x-only tweak."""
        with self._operation():
            output = self._native.output(32)
            parity = self._native.ffi.new("int *")
            _check(
                self._native.lib.rill_musig_output_key(
                    self._pointer,
                    self._native.input(user_public_key, 33, "user_public_key"),
                    self._native.input(provider_public_key, 33, "provider_public_key"),
                    self._native.input(tap_tweak, 32, "tap_tweak"),
                    output,
                    parity,
                ),
            )
            return self._native.bytes(output, 32), int(parity[0])

    def musig_internal_key(
        self,
        user_public_key: bytes,
        provider_public_key: bytes,
    ) -> tuple[bytes, int]:
        """Return the ordered untweaked BIP327 aggregate key and full-point parity."""
        with self._operation():
            output = self._native.output(32)
            parity = self._native.ffi.new("int *")
            _check(
                self._native.lib.rill_musig_internal_key(
                    self._pointer,
                    self._native.input(user_public_key, 33, "user_public_key"),
                    self._native.input(provider_public_key, 33, "provider_public_key"),
                    output,
                    parity,
                ),
            )
            return self._native.bytes(output, 32), int(parity[0])

    def musig_public_nonce_validate(self, public_nonce: bytes) -> None:
        """Validate one serialized MuSig public nonce or raise `CryptoError`."""
        with self._operation():
            _check(
                self._native.lib.rill_musig_public_nonce_validate(
                    self._pointer,
                    self._native.input(public_nonce, 66, "public_nonce"),
                ),
            )

    def musig_begin(
        self,
        *,
        secret_key: bytes,
        user_public_key: bytes,
        provider_public_key: bytes,
        tap_tweak: bytes,
        message: bytes,
        cooperation_id: bytes,
    ) -> tuple[MusigAttempt, bytes]:
        """Allocate an opaque one-shot native nonce handle."""
        with self._operation():
            secret = self._native.input(secret_key, 32, "secret_key")
            random_input = self._native.input(os.urandom(32), 32, "session_random")
            attempt_pointer = self._native.ffi.new("rill_musig_attempt **")
            public_nonce = self._native.output(66)
            try:
                _check(
                    self._native.lib.rill_musig_begin(
                        self._pointer,
                        secret,
                        self._native.input(user_public_key, 33, "user_public_key"),
                        self._native.input(provider_public_key, 33, "provider_public_key"),
                        self._native.input(tap_tweak, 32, "tap_tweak"),
                        self._native.input(message, 32, "message"),
                        self._native.input(cooperation_id, 32, "cooperation_id"),
                        random_input,
                        attempt_pointer,
                        public_nonce,
                    ),
                )
            finally:
                self._native.wipe(secret, 32)
                self._native.wipe(random_input, 32)
            self._active_attempts += 1
            return (
                MusigAttempt(self, attempt_pointer[0], _ATTEMPT_TOKEN),
                self._native.bytes(public_nonce, 66),
            )

    def musig_partial_verify(
        self,
        *,
        user_public_key: bytes,
        provider_public_key: bytes,
        tap_tweak: bytes,
        message: bytes,
        user_public_nonce: bytes,
        provider_public_nonce: bytes,
        signer_index: int,
        partial_signature: bytes,
    ) -> None:
        """Verify one participant's partial signature in the exact public session."""
        with self._operation():
            _check(
                self._native.lib.rill_musig_partial_verify(
                    self._pointer,
                    self._native.input(user_public_key, 33, "user_public_key"),
                    self._native.input(provider_public_key, 33, "provider_public_key"),
                    self._native.input(tap_tweak, 32, "tap_tweak"),
                    self._native.input(message, 32, "message"),
                    self._native.input(user_public_nonce, 66, "user_public_nonce"),
                    self._native.input(provider_public_nonce, 66, "provider_public_nonce"),
                    signer_index,
                    self._native.input(partial_signature, 32, "partial_signature"),
                ),
            )

    def musig_aggregate(
        self,
        *,
        user_public_key: bytes,
        provider_public_key: bytes,
        tap_tweak: bytes,
        message: bytes,
        user_public_nonce: bytes,
        provider_public_nonce: bytes,
        user_partial_signature: bytes,
        provider_partial_signature: bytes,
    ) -> bytes:
        """Verify both partials and return a verified final BIP340 signature."""
        with self._operation():
            output = self._native.output(64)
            _check(
                self._native.lib.rill_musig_aggregate(
                    self._pointer,
                    self._native.input(user_public_key, 33, "user_public_key"),
                    self._native.input(provider_public_key, 33, "provider_public_key"),
                    self._native.input(tap_tweak, 32, "tap_tweak"),
                    self._native.input(message, 32, "message"),
                    self._native.input(user_public_nonce, 66, "user_public_nonce"),
                    self._native.input(provider_public_nonce, 66, "provider_public_nonce"),
                    self._native.input(user_partial_signature, 32, "user_partial_signature"),
                    self._native.input(
                        provider_partial_signature,
                        32,
                        "provider_partial_signature",
                    ),
                    output,
                ),
            )
            return self._native.bytes(output, 64)


class MusigAttempt:
    """Nonserializable ownership token for exactly one native partial-sign call."""

    def __init__(self, context: Context, pointer: Any, token: object) -> None:
        if token is not _ATTEMPT_TOKEN:
            raise TypeError("MuSig attempts can only be created by Context.musig_begin")
        self._context = context
        self._pointer = pointer
        self._finalizer = weakref.finalize(self, self._destroy, context, pointer)

    @staticmethod
    def _destroy(context: Context, pointer: Any) -> None:
        context._native.lib.rill_musig_attempt_destroy(pointer)
        with context._lock:
            context._active_attempts -= 1

    def partial_sign_once(self, other_public_nonce: bytes) -> bytes:
        """Consume the native secret nonce and return one partial signature."""
        with self._context._operation():
            if self._pointer == self._context._native.ffi.NULL:
                raise RuntimeError("MuSig attempt is closed")
            output = self._context._native.output(32)
            _check(
                self._context._native.lib.rill_musig_partial_sign_once(
                    self._context._pointer,
                    self._pointer,
                    self._context._native.input(other_public_nonce, 66, "other_public_nonce"),
                    output,
                ),
            )
            return self._context._native.bytes(output, 32)

    def close(self) -> None:
        """Wipe and free the native attempt."""
        with self._context._lock:
            if self._pointer != self._context._native.ffi.NULL:
                self._finalizer()
                self._pointer = self._context._native.ffi.NULL

    def __enter__(self) -> Self:
        with self._context._lock:
            if self._pointer == self._context._native.ffi.NULL:
                raise RuntimeError("MuSig attempt is closed")
            return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __copy__(self) -> Never:
        raise CopyError("MuSig attempts cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        raise CopyError("MuSig attempts cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("MuSig attempts cannot be serialized")
