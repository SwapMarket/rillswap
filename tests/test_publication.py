from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import pytest

from rill_cli import publication
from rill_cli.age_container import RecoveryContainerError
from rill_cli.publication import (
    RecoveryPublicationError,
    RecoveryPublicationUncertainError,
    publish_new_ciphertext,
)

if TYPE_CHECKING:
    from pathlib import Path

ENCRYPTED = b"not actually age, but opaque ciphertext test bytes"


def _verify(plaintext: bytes) -> bytes:
    assert plaintext == ENCRYPTED
    return plaintext


def test_private_no_clobber_file_and_readback(tmp_path: Path) -> None:
    path = tmp_path / "recovery.age"
    result = publish_new_ciphertext(path, ENCRYPTED, verify_from_disk=_verify)  # type: ignore[arg-type]
    assert result == ENCRYPTED
    assert path.read_bytes() == ENCRYPTED
    assert path.stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["recovery.age"]
    with pytest.raises(RecoveryPublicationError, match="not published"):
        publish_new_ciphertext(path, b"different", verify_from_disk=lambda _data: None)  # type: ignore[arg-type]
    assert path.read_bytes() == ENCRYPTED


@pytest.mark.parametrize("kind", ["file", "symlink", "hardlink"])
def test_existing_destination_is_never_overwritten(tmp_path: Path, kind: str) -> None:
    existing = tmp_path / "existing"
    existing.write_bytes(b"already here")
    output = tmp_path / "recovery.age"
    if kind == "file":
        output.write_bytes(b"already here")
    elif kind == "symlink":
        output.symlink_to(existing)
    else:
        os.link(existing, output)
    with pytest.raises(RecoveryPublicationError):
        publish_new_ciphertext(output, ENCRYPTED, verify_from_disk=_verify)  # type: ignore[arg-type]
    assert output.read_bytes() == b"already here"
    assert existing.read_bytes() == b"already here"
    assert not list(tmp_path.glob(".rill-recovery-*.tmp"))


def test_trusted_directory_must_not_be_symlink(tmp_path: Path) -> None:
    direct = tmp_path / "direct"
    direct.mkdir()
    link = tmp_path / "link"
    link.symlink_to(direct, target_is_directory=True)
    with pytest.raises(RecoveryPublicationError, match="directory is not available"):
        publish_new_ciphertext(link / "x.age", ENCRYPTED, verify_from_disk=_verify)  # type: ignore[arg-type]
    assert list(direct.iterdir()) == []


def test_failed_validation_does_not_publish_or_leave_plaintext(tmp_path: Path) -> None:
    path = tmp_path / "recovery.age"
    for callback in (
        lambda _stored: (_ for _ in ()).throw(RecoveryContainerError("bad signature")),
        lambda stored: (
            (_ for _ in ()).throw(RecoveryPublicationError("mismatch"))
            if stored != b"wrong"
            else stored
        ),
    ):
        with pytest.raises(RecoveryPublicationError, match="not published"):
            publish_new_ciphertext(path, ENCRYPTED, verify_from_disk=callback)  # type: ignore[arg-type]
        assert list(tmp_path.iterdir()) == []


def test_concurrent_creations_admit_exactly_one(tmp_path: Path) -> None:
    output = tmp_path / "only-one.age"

    def attempt(data: bytes) -> bool:
        try:
            publish_new_ciphertext(output, data, verify_from_disk=lambda stored: stored)  # type: ignore[arg-type]
        except RecoveryPublicationError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(attempt, (b"encrypted-one", b"encrypted-two")))
    assert results.count(True) == 1
    assert output.read_bytes() in (b"encrypted-one", b"encrypted-two")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["only-one.age"]


def test_directory_fsync_failure_after_link_is_ambiguous_not_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = publication.os.fsync
    calls = 0

    def fail_directory(fd: int) -> None:
        nonlocal calls
        calls += 1
        if os.fstat(fd).st_mode & 0o170000 == 0o040000:
            raise OSError("simulated failed directory durability")
        original(fd)

    monkeypatch.setattr(publication.os, "fsync", fail_directory)
    output = tmp_path / "recovery.age"
    with pytest.raises(RecoveryPublicationUncertainError, match="verify it manually"):
        publish_new_ciphertext(output, ENCRYPTED, verify_from_disk=_verify)  # type: ignore[arg-type]
    assert output.read_bytes() == ENCRYPTED
    assert calls >= 2


def test_failure_before_link_cannot_create_successful_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_link(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated linking failure")

    monkeypatch.setattr(publication.os, "link", fail_link)
    output = tmp_path / "recovery.age"
    with pytest.raises(RecoveryPublicationError, match="not published"):
        publish_new_ciphertext(output, ENCRYPTED, verify_from_disk=_verify)  # type: ignore[arg-type]
    assert list(tmp_path.iterdir()) == []
