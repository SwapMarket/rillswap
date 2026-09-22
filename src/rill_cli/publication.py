"""Create-only ciphertext publication with disk readback and no-clobber semantics.

No persisted success marker or permission to fund is written. The destination
directory must be trusted local storage with working fsync/hardlink semantics.
Other writers, backups, and an interrupted rename require human reconciliation.
"""

from __future__ import annotations

import os
import secrets
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from rill_cli.age_container import MAX_CIPHERTEXT_BYTES, RecoveryContainerError

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.recovery import OfflineRecoveryInspection


class RecoveryPublicationError(OSError):
    """A recovery ciphertext was NOT successfully verified and published."""


class RecoveryPublicationUncertainError(RecoveryPublicationError):
    """Destination may exist, but publication durability was not confirmed."""


def publish_new_ciphertext(
    destination: str | os.PathLike[str],
    ciphertext: bytes,
    *,
    verify_from_disk: Callable[[bytes], OfflineRecoveryInspection],
) -> OfflineRecoveryInspection:
    """Publish only a verified encrypted file, never overwrite an existing path.

    `verify_from_disk` MUST decrypt, compare the complete original plaintext,
    and rerun static inspection with a real crypto implementation. It cannot
    substitute for restored-client state or fresh chain/backend evidence.
    """
    if not isinstance(ciphertext, bytes) or not 0 < len(ciphertext) <= MAX_CIPHERTEXT_BYTES:
        raise RecoveryPublicationError("recovery ciphertext exceeds size limit")
    path = Path(destination).absolute()
    if path.name in ("", ".", ".."):
        raise RecoveryPublicationError("destination must be a file name")
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise RecoveryPublicationError("recovery destination directory is not available") from None
    temp_name = f".rill-recovery-{secrets.token_hex(16)}.tmp"
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
            stream.write(ciphertext)
            stream.flush()
            os.fsync(stream.fileno())
        read_fd = os.open(temp_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(read_fd, "rb", closefd=True) as stream:
            stored = stream.read(MAX_CIPHERTEXT_BYTES + 1)
        if stored != ciphertext:
            raise RecoveryPublicationError("encrypted recovery readback did not match")
        report = verify_from_disk(stored)
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
    except (OSError, RecoveryContainerError, ValueError):
        if published:
            raise RecoveryPublicationUncertainError(
                "recovery file may be published; verify it manually before any action"
            ) from None
        if temp_created:
            # An orphaned temp contains ciphertext only, never a completed export.
            with suppress(OSError):
                os.unlink(temp_name, dir_fd=directory)
        raise RecoveryPublicationError("recovery file was not published") from None
    else:
        return report
    finally:
        os.close(directory)
