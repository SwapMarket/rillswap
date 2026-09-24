"""Signed refund artifact publication never overwrites or implies broadcast."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from rill_cli import refund_publication as publication

if TYPE_CHECKING:
    from pathlib import Path


def test_create_only_refund_is_private_exact_and_no_clobber(tmp_path: Path) -> None:
    transaction = b"\x02\x00\x00\x00signed test-only transaction"
    output = tmp_path / "refund.raw"
    verified: list[bytes] = []
    publication.publish_new_signed_refund(
        output,
        transaction,
        verify_from_disk=verified.append,
    )
    assert output.read_bytes() == transaction
    assert output.stat().st_mode & 0o777 == 0o600
    assert verified == [transaction]
    assert not list(tmp_path.glob(".rill-refund-*.tmp"))
    with pytest.raises(publication.RefundPublicationError) as error:
        publication.publish_new_signed_refund(
            output, b"different", verify_from_disk=verified.append
        )
    assert output.read_bytes() == transaction
    assert verified == [transaction, b"different"]
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


def test_invalid_verifier_failure_is_redacted_without_new_file(tmp_path: Path) -> None:
    output = tmp_path / "refund.raw"

    def fail(_stored: bytes) -> None:
        raise ValueError("sensitive native verifier error")

    with pytest.raises(publication.RefundPublicationError) as error:
        publication.publish_new_signed_refund(output, b"tx", verify_from_disk=fail)
    assert not output.exists()
    assert not list(tmp_path.glob(".rill-refund-*.tmp"))
    assert "sensitive" not in repr(error.value)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


def test_existing_symlink_and_bounded_bytes_never_publish(tmp_path: Path) -> None:
    original = tmp_path / "original"
    original.write_bytes(b"preserve")
    link = tmp_path / "refund.raw"
    link.symlink_to(original)
    with pytest.raises(publication.RefundPublicationError):
        publication.publish_new_signed_refund(link, b"tx", verify_from_disk=lambda _: None)
    assert original.read_bytes() == b"preserve"
    for invalid in (b"", b"x" * (publication.MAX_REFUND_BYTES + 1)):
        with pytest.raises(publication.RefundPublicationError):
            publication.publish_new_signed_refund(
                tmp_path / "fresh.raw",
                invalid,
                verify_from_disk=lambda _: None,
            )
    assert not (tmp_path / "fresh.raw").exists()


def test_failure_after_link_is_uncertain_not_permission_to_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "refund.raw"
    original_fsync = os.fsync
    calls: list[int] = []

    def fail_after_link(fd: int) -> None:
        calls.append(fd)
        if len(calls) == 2:
            raise OSError("test-only durability error")
        original_fsync(fd)

    monkeypatch.setattr(publication.os, "fsync", fail_after_link)
    with pytest.raises(publication.RefundPublicationUncertainError) as error:
        publication.publish_new_signed_refund(output, b"tx", verify_from_disk=lambda _: None)
    assert output.read_bytes() == b"tx"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
