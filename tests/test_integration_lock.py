"""Negative contract tests for the pinned source and consumed-artifact gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any
from xml.etree import ElementTree as ET

import pytest

if TYPE_CHECKING:
    from types import ModuleType

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_integration_lock.py"


def _runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rill_provider_integration_lock", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _committed_repos(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    runner = _runner()
    git_bin = shutil.which("git")
    assert git_bin is not None
    tmp_path.mkdir(parents=True, exist_ok=True)
    components = {}
    for name in runner.COMPONENTS:
        repo = tmp_path / name
        repo.mkdir()
        for args in (
            ("init", "-q"),
            ("add", "evidence"),
            (
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ),
        ):
            if args[0] == "add":
                (repo / "evidence").write_text(name)
            subprocess.run(  # noqa: S603 - fixed fixture args and resolved git binary
                [git_bin, *args],
                cwd=repo,
                check=True,
                capture_output=True,
            )

        def git(*args: str, repo_path: Path = repo) -> str:
            return subprocess.run(  # noqa: S603 - fixed fixture args and resolved git binary
                [git_bin, *args],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        components[name] = {
            "commit": git("rev-parse", "HEAD"),
            "tree": git("rev-parse", "HEAD^{tree}"),
        }
    lock = {
        "schema": "rillswap-provider-integration-lock/v1",
        "components": components,
        "python_wheels": dict.fromkeys(runner.WHEELS, "ab" * 32),
        "native_cases": json.loads((SCRIPT.parents[1] / "integration-lock.json").read_text())[
            "native_cases"
        ],
    }
    return tmp_path, lock


def test_pinned_sources_require_all_six_exact_commits_and_trees(tmp_path: Path) -> None:
    runner = _runner()
    root, lock = _committed_repos(tmp_path)
    manifest = tmp_path / "integration.json"
    manifest.write_text(json.dumps(lock))
    runner._verify_sources(runner._lock(manifest), root)  # noqa: SLF001 - gate contract
    for mutation in ("wrong-commit", "wrong-tree", "missing-source", "invalid-digest"):
        modified = json.loads(json.dumps(lock))
        name = "rill-crypto"
        if mutation == "wrong-commit":
            modified["components"][name]["commit"] = "00" * 20
        elif mutation == "wrong-tree":
            modified["components"][name]["tree"] = "00" * 20
        elif mutation == "missing-source":
            (root / name / ".git").rename(root / name / ".unavailable")
        else:
            modified["python_wheels"][next(iter(runner.WHEELS))] = "not-a-digest"
        manifest.write_text(json.dumps(modified))
        with pytest.raises(runner.IntegrationLockError):
            runner._verify_sources(runner._lock(manifest), root)  # noqa: SLF001
        if mutation == "missing-source":
            (root / name / ".unavailable").rename(root / name / ".git")
    assert not any((root / name / "evidence").read_text() != name for name in runner.COMPONENTS)


def test_missing_old_duplicate_and_partial_locks_refuse_without_build(tmp_path: Path) -> None:
    runner = _runner()
    _, lock = _committed_repos(tmp_path)
    manifest = tmp_path / "integration.json"
    for source in (
        b"",
        b"{",
        b'{"schema":"rillswap-provider-integration-lock/v0"}',
        json.dumps({**lock, "components": {}}).encode(),
        (json.dumps(lock)[:-1] + ',"native_cases":[]}').encode(),
    ):
        manifest.write_bytes(source)
        with pytest.raises((runner.IntegrationLockError, ValueError)):
            runner._lock(manifest)  # noqa: SLF001
    manifest.unlink()
    with pytest.raises(FileNotFoundError):
        runner._lock(manifest)  # noqa: SLF001


def test_modified_producer_wheel_is_refused_before_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    _, lock = _committed_repos(tmp_path / "repos")
    operations: list[str] = []
    artifacts = {name: name.encode() for name in runner.WHEELS}
    lock["python_wheels"] = {
        name: hashlib.sha256(data).hexdigest() for name, data in artifacts.items()
    }
    mutate = True

    def fake_archive(_repo: Path, _commit: str, destination: Path) -> None:
        destination.mkdir(parents=True)
        if destination.name == "rill-provider":
            (destination / "requirements-dev.txt").write_text("pytest==9.1.1\n")

    def fake_run(command: list[str], **_kwargs: object) -> bytes:
        operations.append(" ".join(command[:3]))
        if command[:2] == ["cmake", "--build"]:
            native = Path(command[2])
            native.mkdir(parents=True, exist_ok=True)
            (native / "librill_crypto.so").write_bytes(b"native")
        if command[:2] == ["uv", "build"]:
            folder = Path(command[command.index("--out-dir") + 1])
            folder.mkdir(exist_ok=True)
            for name, data in artifacts.items():
                (folder / name).write_bytes(
                    b"modified artifact" if mutate and name == min(artifacts) else data
                )
            (folder / "rill_provider-0.1.0.dev0-py3-none-any.whl").write_bytes(b"consumer")
        if command[:2] == ["uv", "pip"]:
            raise runner.IntegrationLockError("advanced beyond verified producer digests")
        return b""

    monkeypatch.setattr(runner, "_archive", fake_archive)
    monkeypatch.setattr(runner, "_run", fake_run)
    with pytest.raises(runner.IntegrationLockError, match=r"producer wheel.*digest"):
        runner._build(lock, tmp_path / "repos", tmp_path / "work")  # noqa: SLF001
    assert not any(operation.startswith("uv pip") for operation in operations)
    mutate = False
    with pytest.raises(runner.IntegrationLockError, match="advanced beyond verified"):
        runner._build(lock, tmp_path / "repos", tmp_path / "work-verified")  # noqa: SLF001
    assert any(operation.startswith("uv pip") for operation in operations)


def test_native_inventory_requires_exact_cases_with_no_skips_or_errors(tmp_path: Path) -> None:
    runner = _runner()
    expected = json.loads((SCRIPT.parents[1] / "integration-lock.json").read_text())["native_cases"]
    report = tmp_path / "results.xml"

    def write_report(names: list[str], bad_tag: str | None = None) -> None:
        root = ET.Element("testsuites")
        suite = ET.SubElement(root, "testsuite")
        for item in names:
            classname, name = item.split("::", 1)
            case = ET.SubElement(suite, "testcase", classname=classname, name=name)
            if bad_tag is not None and name == expected[0].split("::", 1)[1]:
                ET.SubElement(case, bad_tag)
        report.write_bytes(ET.tostring(root))

    write_report(expected)
    assert runner._check_native_report(report, expected) == 23  # noqa: SLF001
    for mutation in ("duplicate", "substitute", "missing", "substring"):
        altered = expected.copy()
        if mutation == "duplicate":
            altered[0] = altered[1]
        elif mutation == "substitute":
            altered[0] = "tests.test_handshake_signing::other_test"
        elif mutation == "missing":
            altered.pop()
        else:
            altered[0] += "_impostor"
        write_report(altered)
        with pytest.raises(runner.IntegrationLockError, match="inventory"):
            runner._check_native_report(report, expected)  # noqa: SLF001
    for marker in ("skipped", "failure", "error"):
        write_report(expected, marker)
        with pytest.raises(runner.IntegrationLockError, match="inventory"):
            runner._check_native_report(report, expected)  # noqa: SLF001


def test_runner_creates_missing_ignored_scratch_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = _runner()
    synthetic_script = tmp_path / "fresh-checkout" / "scripts" / "gate.py"
    synthetic_script.parent.mkdir(parents=True)
    monkeypatch.setattr(runner, "__file__", str(synthetic_script))
    monkeypatch.setattr(runner, "_lock", lambda _path: {"components": {}})
    monkeypatch.setattr(runner, "_verify_sources", lambda *_args: None)

    def fake_build(_lock: object, _root: Path, directory: Path) -> dict[str, str]:
        assert directory.is_dir()
        return {"authority": "none"}

    monkeypatch.setattr(runner, "_build", fake_build)
    monkeypatch.setattr(sys, "argv", ["gate.py", "--source-root", str(tmp_path)])
    assert not (synthetic_script.parent.parent / "tmp").exists()
    assert runner.main() == 0
    assert json.loads(capsys.readouterr().out) == {"authority": "none"}
    assert (synthetic_script.parent.parent / "tmp").is_dir()
