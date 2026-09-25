"""The local release check fails on absent or skipped independent evidence."""

from __future__ import annotations

import importlib.util
import io
import subprocess
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET

import pytest

if TYPE_CHECKING:
    from collections.abc import Sequence

GATE_PATH = Path(__file__).parents[1] / "scripts" / "check_age_interop.py"
SPEC = importlib.util.spec_from_file_location("check_age_interop", GATE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def _setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, symlink: bool = False
) -> tuple[Path, Path]:
    root = tmp_path / "rill-cli"
    (root / "tmp").mkdir(parents=True)
    pytest_path = root / ".venv" / "bin" / "pytest"
    pytest_path.parent.mkdir(parents=True)
    pytest_path.touch()
    native = tmp_path / "native.so"
    native.write_bytes(b"synthetic native library bytes")
    archive = tmp_path / "age.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        executable = tarfile.TarInfo("age/age")
        if symlink:
            executable.type = tarfile.SYMTYPE
            executable.linkname = "../../untrusted"
            bundle.addfile(executable)
        else:
            content = b"synthetic age executable"
            executable.size = len(content)
            bundle.addfile(executable, io.BytesIO(content))
    monkeypatch.setattr(gate, "ROOT", root)
    monkeypatch.setattr(gate.platform, "system", lambda: "Linux")
    monkeypatch.setattr(gate.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(gate, "_source_revision", lambda _path: "a" * 40 + " (clean)")
    monkeypatch.setattr(
        gate,
        "_sha256",
        lambda path: gate.AGE_ARCHIVE_SHA256 if path == archive else "b" * 64,
    )
    return archive, native


def test_gate_checks_actual_archive_checksum_before_extracting(tmp_path: Path) -> None:
    archive = tmp_path / "age.tar.gz"
    archive.write_bytes(b"not the pinned archive")
    with pytest.raises(gate.GateError, match="checksum differs"):
        gate._extract_verified_age(archive, tmp_path)  # noqa: SLF001 - direct checksum boundary


def test_gate_refuses_symlink_inside_even_verified_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, native = _setup(tmp_path, monkeypatch, symlink=True)
    with pytest.raises(gate.GateError, match="bounded regular"):
        gate.check_age_interop(archive, native, "b" * 64)


def test_gate_rejects_bad_native_digest_and_platform_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, native = _setup(tmp_path, monkeypatch)
    with pytest.raises(gate.GateError, match="native library differs"):
        gate.check_age_interop(archive, native, "c" * 64)
    monkeypatch.setattr(gate.platform, "machine", lambda: "aarch64")
    with pytest.raises(gate.GateError, match="Linux amd64"):
        gate.check_age_interop(archive, native, "b" * 64)


@pytest.mark.parametrize(
    ("scenario", "allowed"),
    [
        ("valid", True),
        ("missing-report", False),
        ("wrong-case", False),
        ("skipped-case", False),
        ("nonzero-exit", False),
    ],
)
def test_gate_requires_exact_three_executed_tests_and_closes_temp_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    allowed: bool,  # noqa: FBT001 - parametric outcome assertion
) -> None:
    archive, native = _setup(tmp_path, monkeypatch)
    calls: list[tuple[str, ...]] = []
    sentinel = gate.ROOT / "tmp" / "pytest-age-interop" / "preserve.txt"
    sentinel.parent.mkdir()
    sentinel.write_text("do not remove existing scratch data")
    for setting, value in (
        ("PYTEST_ADDOPTS", "--assert=plain"),
        ("PYTEST_PLUGINS", "evil.plugin"),
        ("PYTHONOPTIMIZE", "1"),
        ("PYTHONPATH", "/untrusted/source"),
        ("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "0"),
    ):
        monkeypatch.setenv(setting, value)

    def fake_run(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(command))
        if command[1] == "--version":
            return subprocess.CompletedProcess(command, 0, "v1.3.1\n", "")
        assert command[1] == "-q"
        assert tuple(command[2:4]) == gate.TEST_NODES
        environment = kwargs["env"]  # type: ignore[assignment]
        assert environment["RILL_CRYPTO_LIBRARY"] == str(native)
        assert Path(environment["AGE_BINARY"]).is_file()
        assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
        assert all(
            setting not in environment
            for setting in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONOPTIMIZE", "PYTHONPATH")
        )
        assert "--assert=rewrite" in command
        base = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--basetemp=")))
        report = Path(
            next(arg.split("=", 1)[1] for arg in command if arg.startswith("--junitxml="))
        )
        assert base.parent == report.parent
        assert base.parent.parent == gate.ROOT / "tmp"
        assert base.parent.name.startswith("age-interop-")
        if scenario != "missing-report":
            suite = ET.Element("testsuite")
            for classname, name in sorted(gate.EXPECTED_CASES):
                case = ET.SubElement(suite, "testcase", classname=classname, name=name)
                if scenario == "skipped-case" and name.endswith("[ln-to-btc]"):
                    ET.SubElement(case, "skipped")
            if scenario == "wrong-case":
                suite[0].set("name", "wrong-case")
            ET.ElementTree(suite).write(report, encoding="unicode")
        return subprocess.CompletedProcess(
            command, 1 if scenario == "nonzero-exit" else 0, "3 passed", ""
        )

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    if allowed:
        gate.check_age_interop(archive, native, "b" * 64)
    else:
        reason = "structured test report" if scenario == "missing-report" else "did not all pass"
        with pytest.raises(gate.GateError, match=reason):
            gate.check_age_interop(archive, native, "b" * 64)
    assert len(calls) == 2
    assert not list((gate.ROOT / "tmp").glob("age-interop-*"))
    assert sentinel.read_text() == "do not remove existing scratch data"


def test_gate_rejects_bad_version_and_missing_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, native = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "1.2.0", ""),
    )
    with pytest.raises(gate.GateError, match="version check"):
        gate.check_age_interop(archive, native, "b" * 64)
    monkeypatch.setattr(
        gate,
        "_source_revision",
        lambda _path: (_ for _ in ()).throw(
            gate.GateError("required sibling source checkout is unavailable")
        ),
    )
    with pytest.raises(gate.GateError, match="sibling source"):
        gate.check_age_interop(archive, native, "b" * 64)
