"""Private tmpfs credential transfer never captures secrets or overwrites prior files."""

from __future__ import annotations

import subprocess
import traceback
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
import test_lnd_payment_pinned as pinned

if TYPE_CHECKING:
    from pathlib import Path
    from typing import BinaryIO

# ruff: noqa: SLF001 - secret-safe test infrastructure boundary


def test_cookie_transfer_streams_directly_to_an_exclusive_private_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "cookie"
    monkeypatch.setattr(pinned, "DOCKER", "/pinned/docker")

    def run(
        command: list[str], *, stdout: BinaryIO, stderr: int, timeout: int, check: bool
    ) -> subprocess.CompletedProcess[bytes]:
        assert command == [
            "/pinned/docker",
            "exec",
            "--user",
            "bitcoin:bitcoin",
            "owned-core",
            "cat",
            "/home/bitcoin/.bitcoin/.rill-preflight-cookie",
        ]
        assert stderr == subprocess.PIPE
        assert timeout == 10
        assert check is False
        stdout.write(b"__cookie__:disposable-test-credential\n")
        return subprocess.CompletedProcess(command, 0, stderr=b"")

    monkeypatch.setattr(pinned.subprocess, "run", run)
    pinned._copy_private_core_cookie("owned-core", destination)
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.read_bytes() == b"__cookie__:disposable-test-credential\n"


@pytest.mark.parametrize("failure", ["exit", "timeout", "malformed"])
def test_failed_private_transfer_removes_only_its_partial_file_and_redacts_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "cookie"
    monkeypatch.setattr(pinned, "DOCKER", "/pinned/docker")

    def run(
        command: list[str], *, stdout: BinaryIO, **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        stdout.write(b"private-fixture-credential")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 10, stderr=b"private-fixture-credential")
        return subprocess.CompletedProcess(
            command, 1 if failure == "exit" else 0, stderr=b"private-fixture-credential"
        )

    monkeypatch.setattr(pinned.subprocess, "run", run)
    with pytest.raises(AssertionError, match="private Core cookie transfer failed") as error:
        pinned._copy_private_core_cookie("owned-core", destination)
    assert "private-fixture-credential" not in str(error.value)
    assert error.value.__context__ is None
    formatted = "".join(traceback.format_exception(error.value))
    assert "private-fixture-credential" not in formatted
    captured = capsys.readouterr()
    assert "private-fixture-credential" not in captured.out + captured.err
    assert not destination.exists()


@pytest.mark.parametrize("symlink", [False, True])
def test_existing_destination_is_preserved_without_reading_or_transferring_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    symlink: bool,
) -> None:
    destination = tmp_path / "cookie"
    prior = tmp_path / "prior"
    prior.write_bytes(b"prior-private-state")
    if symlink:
        destination.symlink_to(prior)
    else:
        destination.write_bytes(b"prior-private-state")
    transfer = Mock(side_effect=AssertionError("must not execute"))
    monkeypatch.setattr(pinned, "DOCKER", "/pinned/docker")
    monkeypatch.setattr(pinned.subprocess, "run", transfer)
    with pytest.raises(AssertionError, match="private Core cookie transfer failed"):
        pinned._copy_private_core_cookie("owned-core", destination)
    transfer.assert_not_called()
    assert destination.read_bytes() == prior.read_bytes() == b"prior-private-state"
    assert destination.is_symlink() is symlink
