"""Historical integration replay must not silently repin or trust editable files."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from scripts import replay_provider_v2 as replay

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "rill-provider/integration-lock.json"


def test_historical_v2_verify_only_from_single_repository() -> None:
    assert not (ROOT / "rill-provider/.git").exists()
    assert hashlib.sha256(LOCK.read_bytes()).hexdigest() == replay.LOCK_SHA256
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/replay_provider_v2.py"),
            "--source-root",
            str(ROOT),
            "--verify-only",
        ],
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0
    assert result.stdout == (
        b"Pinned source commits and trees are available; no build or release authority\n"
    )
    assert result.stderr == b""


def test_bad_lock_refused_before_disposable_sources(tmp_path: Path) -> None:
    changed = tmp_path / "changed-lock.json"
    lock = json.loads(LOCK.read_bytes())
    lock["components"].pop("rill-core")
    changed.write_text(json.dumps(lock))
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/replay_provider_v2.py"),
            "--source-root",
            str(ROOT),
            "--lock",
            str(changed),
            "--verify-only",
        ],
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"no release authority" in result.stderr


@pytest.mark.parametrize("field", ["commit", "tree"])
def test_missing_or_wrong_historical_object_refused(field: str) -> None:
    components = deepcopy(replay._locked_components(LOCK))
    components["rill-core"][field] = "0" * 40
    with pytest.raises(replay.ReplayUnavailableError):
        replay._verify_pins(ROOT, components)


def test_failed_historical_child_never_returns_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_run = replay.subprocess.run
    prior = set((ROOT / "tmp").glob("provider-v2-replay-*"))

    def fail_child(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if str(command[1]).endswith("/scripts/check_integration_lock.py"):
            return subprocess.CompletedProcess(
                command, 2, b"PRIVATE-RECEIPT", b"PRIVATE-ERROR"
            )
        return real_run(command, **kwargs)

    monkeypatch.setattr(replay.subprocess, "run", fail_child)
    with pytest.raises(
        replay.ReplayUnavailableError, match="no release authority"
    ) as caught:
        replay.replay(ROOT, LOCK)
    assert "PRIVATE" not in str(caught.value)
    assert set((ROOT / "tmp").glob("provider-v2-replay-*")) == prior


def test_history_only_source_clone_not_editable_component_files(tmp_path: Path) -> None:
    clone = tmp_path / "monorepo"
    subprocess.run(
        ["git", "clone", "--shared", "--no-checkout", "--quiet", str(ROOT), str(clone)],
        check=True,
        capture_output=True,
        timeout=60,
    )
    assert not (clone / "rill-provider/integration-lock.json").exists()
    assert replay.replay(clone, LOCK, verify_only=True).startswith(
        "Pinned source commits"
    )


def test_timed_out_historical_child_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    real_run = replay.subprocess.run

    def time_out(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if str(command[1]).endswith("/scripts/check_integration_lock.py"):
            raise subprocess.TimeoutExpired(command + ["PRIVATE-DIAGNOSTIC"], 1)
        return real_run(command, **kwargs)

    monkeypatch.setattr(replay.subprocess, "run", time_out)
    monkeypatch.setattr(
        sys, "argv", ["replay_provider_v2.py", "--source-root", str(ROOT)]
    )
    assert replay.main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert (
        captured.err == "Historical v2 integration unavailable; no release authority\n"
    )
