from __future__ import annotations

import getpass
import os
import sys
import termios
from pathlib import Path

import pytest

from rill_cli import main as cli


def test_missing_tty_never_reads_standard_input(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Path.open

    def refuse_tty(path: Path, *args: object, **kwargs: object) -> object:
        if str(path) == "/dev/tty":
            raise OSError("no terminal")
        return original(path, *args, **kwargs)  # type: ignore[arg-type]

    def forbidden_fallback(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("unprotected fallback was invoked")

    monkeypatch.setattr(Path, "open", refuse_tty)
    monkeypatch.setattr(getpass, "fallback_getpass", forbidden_fallback)
    with pytest.raises(OSError, match="no terminal"):
        cli._prompt()  # noqa: SLF001 - test the protected-input boundary directly


def test_failed_echo_suppression_never_falls_back_to_echoed_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    original_open = os.open
    original_path_open = Path.open

    def fake_os_open(path: str, *args: object, **kwargs: object) -> int:
        if path == "/dev/tty":
            return original_open(os.devnull, *args, **kwargs)  # type: ignore[arg-type]
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    def fake_path_open(path: Path, *args: object, **kwargs: object) -> object:
        if str(path) == "/dev/tty":
            return original_path_open(Path(os.devnull), *args, **kwargs)  # type: ignore[arg-type]
        return original_path_open(path, *args, **kwargs)  # type: ignore[arg-type]

    def deny_termios(_descriptor: int) -> object:
        raise termios.error("cannot disable echo")

    class ForbiddenStdin:
        def readline(self) -> str:
            raise AssertionError("unprotected input was read")

    monkeypatch.setattr(os, "open", fake_os_open)
    monkeypatch.setattr(Path, "open", fake_path_open)
    monkeypatch.setattr(termios, "tcgetattr", deny_termios)
    monkeypatch.setattr(sys, "stdin", ForbiddenStdin())
    with pytest.raises(getpass.GetPassWarning):
        cli._prompt()  # noqa: SLF001 - real getpass path, forced tty failure
    # The CLI catches the warning and presents only a fixed, redacted error.
    monkeypatch.setattr(cli, "_run", lambda _args: cli._prompt())  # noqa: SLF001
    assert (
        cli.main(
            [
                "recover",
                "inspect",
                "--network",
                "unused",
                "--crypto-library",
                "unused",
                "--passphrase-prompt",
                "unused.age",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Recovery operation failed; no payment or funding authority.\n"
