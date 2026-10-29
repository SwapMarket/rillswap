"""Host-side devctl command forwarding without Docker or backend access."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("args", [[], ["tools"], ["--no-cache", "--pull", "tools"]])
def test_build_includes_dependencies_and_preserves_arguments(tmp_path, monkeypatch, args):
    docker = tmp_path / "docker"
    docker.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$DOCKER_ARGS"\n')
    docker.chmod(0o755)
    arguments = tmp_path / "arguments"
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    monkeypatch.setenv("DOCKER_ARGS", str(arguments))

    subprocess.run([str(ROOT / "dev/devctl"), "build", *args], check=True, capture_output=True)

    assert arguments.read_text().splitlines() == [
        "compose",
        "-f",
        str(ROOT / "dev/compose.yaml"),
        "build",
        "--with-dependencies",
        *args,
    ]
