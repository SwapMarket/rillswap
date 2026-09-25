"""Explicit create-only publication of a validated, signed refund transaction.

No broadcast or success marker. The caller owns the trusted destination
directory and must reconcile a partial or interrupted publication manually.
"""

from __future__ import annotations

import os
import secrets
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

MAX_REFUND_BYTES = 100_000
MAX_INTENT_BYTES = 16 * 1024


class RefundPublicationError(OSError):
    """No validated durable output was established."""


class RefundPublicationUncertainError(RefundPublicationError):
    """Destination may exist but durability or readback cannot be claimed."""


def _require_readback_matches(stored: bytes, transaction: bytes) -> None:
    if stored != transaction:
        raise RefundPublicationError("signed refund readback mismatch")


def publish_new_signed_refund(
    destination: str | os.PathLike[str],
    transaction: bytes,
    *,
    verify_from_disk: Callable[[bytes], None],
) -> None:
    """Publish only exact locally verified bytes, never overwrite a path.

    `verify_from_disk` must fully revalidate the signed transaction against
    the previously checked binding and terms. This does not recheck the chain.
    """
    _publish_new_exact_file(
        destination,
        transaction,
        verify_from_disk=verify_from_disk,
        max_bytes=MAX_REFUND_BYTES,
    )


def publish_new_broadcast_intent(
    destination: str | os.PathLike[str],
    intent: bytes,
    *,
    verify_from_disk: Callable[[bytes], None],
) -> None:
    """Record the complete proposed send durably before any RPC submission.

    The content verifier must check the exact selected recovery, signed bytes,
    digest, and txid. Existence of a file is never permission to retry a send.
    """
    _publish_new_exact_file(
        destination,
        intent,
        verify_from_disk=verify_from_disk,
        max_bytes=MAX_INTENT_BYTES,
    )


def _publish_new_exact_file(
    destination: str | os.PathLike[str],
    transaction: bytes,
    *,
    verify_from_disk: Callable[[bytes], None],
    max_bytes: int,
) -> None:
    if type(transaction) is not bytes or not 0 < len(transaction) <= max_bytes:
        raise RefundPublicationError("signed refund bytes exceed resource limit")
    path = Path(destination).absolute()
    if path.name in ("", ".", ".."):
        raise RefundPublicationError("refund destination must be a file name")
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise RefundPublicationError("refund destination directory unavailable") from None
    temp_name = f".rill-refund-{secrets.token_hex(16)}.tmp"
    published = False
    temp_created = False
    try:
        temp_fd = os.open(
            temp_name,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        temp_created = True
        with os.fdopen(temp_fd, "wb", closefd=True) as stream:
            stream.write(transaction)
            stream.flush()
            os.fsync(stream.fileno())
        read_fd = os.open(temp_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(read_fd, "rb", closefd=True) as stream:
            stored = stream.read(max_bytes + 1)
        _require_readback_matches(stored, transaction)
        verify_from_disk(stored)
        os.link(
            temp_name,
            path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        published = True
        os.fsync(directory)
        os.unlink(temp_name, dir_fd=directory)
        temp_created = False
        os.fsync(directory)
    except Exception:  # noqa: BLE001 - no disk or verifier details may escape
        uncertain = published
        if temp_created and not published:
            with suppress(OSError):
                os.unlink(temp_name, dir_fd=directory)
    else:
        uncertain = False
        return
    finally:
        os.close(directory)
    if uncertain:
        raise RefundPublicationUncertainError("refund may be published; verify manually")
    raise RefundPublicationError("signed refund was not published")
