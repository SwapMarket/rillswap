"""Build a pinned local provider baseline from committed sources, not editable siblings.

This is an integration gate, NOT a release or authority to run a live swap.
It needs explicit local Git object sources, a trusted Python/uv/CMake toolchain,
and network access for pinned third-party build and Python dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

MAX_LOCK_BYTES = 8_192
MAX_JUNIT_BYTES = 2 * 1024 * 1024

COMPONENTS = frozenset(
    {
        "rill-docs",
        "rill-crypto",
        "rill-core",
        "rill-provider",
        "rill-cli",
        "rill-web",
    }
)
WHEELS = frozenset(
    {
        "rill_crypto-0.1.0.dev0-py3-none-any.whl",
        "rill_core-0.1.0.dev0-py3-none-any.whl",
    }
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MIN_NATIVE_CASES = 23


class IntegrationLockError(Exception):
    """Cannot attest this pinned local integration baseline."""


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
) -> bytes:
    result = subprocess.run(  # noqa: S603 - args constructed from strict pin/paths, no shell
        command,
        cwd=cwd,
        env=env,
        input=input_bytes,
        capture_output=True,
        timeout=240,
        check=False,
    )
    if result.returncode:
        raise IntegrationLockError(f"integration subprocess failed: {command[0]}")
    return result.stdout


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _lock(path: Path) -> dict[str, Any]:
    source = path.read_bytes()
    if not 0 < len(source) <= MAX_LOCK_BYTES:
        raise IntegrationLockError("integration lock is missing or oversized")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise IntegrationLockError("integration lock contains duplicate keys")
            result[key] = value
        return result

    lock: dict[str, Any] = json.loads(source, object_pairs_hook=unique_pairs)
    if (
        type(lock) is not dict
        or set(lock) != {"schema", "components", "python_wheels", "native_cases"}
        or lock["schema"] != "rillswap-provider-integration-lock/v1"
        or type(lock["components"]) is not dict
        or set(lock["components"]) != COMPONENTS
        or type(lock["python_wheels"]) is not dict
        or set(lock["python_wheels"]) != WHEELS
        or type(lock["native_cases"]) is not list
        or len(lock["native_cases"]) != MIN_NATIVE_CASES
        or any(
            type(case) is not str or not case.startswith("tests.test_") or case.count("::") != 1
            for case in lock["native_cases"]
        )
        or len(set(lock["native_cases"])) != MIN_NATIVE_CASES
    ):
        raise IntegrationLockError("unsupported or incomplete integration lock")
    for name in COMPONENTS:
        pin = lock["components"][name]
        if (
            type(pin) is not dict
            or set(pin) != {"commit", "tree"}
            or any(
                type(pin[field]) is not str or not HEX40.fullmatch(pin[field])
                for field in ("commit", "tree")
            )
        ):
            raise IntegrationLockError("invalid component reference")
    if any(
        type(digest) is not str or not HEX64.fullmatch(digest)
        for digest in lock["python_wheels"].values()
    ):
        raise IntegrationLockError("invalid artifact digest")
    return lock


def _verify_sources(lock: dict[str, Any], source_root: Path) -> None:
    for name, pin in lock["components"].items():
        repo = source_root / name
        if not (repo / ".git").is_dir():
            raise IntegrationLockError("required source repository unavailable")
        commit = pin["commit"]
        actual = _run(["git", "rev-parse", "--verify", f"{commit}^{{commit}}"], cwd=repo)
        tree = _run(["git", "rev-parse", "--verify", f"{commit}^{{tree}}"], cwd=repo)
        if actual.decode().strip() != commit or tree.decode().strip() != pin["tree"]:
            raise IntegrationLockError("committed source does not match pinned tree")


def _archive(repo: Path, commit: str, destination: Path) -> None:
    document = _run(["git", "archive", "--format=tar", commit], cwd=repo)
    destination.mkdir(mode=0o700)
    # Reject links and nonregular archive entries. Never extract into a trusted source path.
    with tarfile.open(fileobj=io.BytesIO(document)) as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not (member.isfile() or member.isdir())
                or member.issym()
                or member.islnk()
            ):
                raise IntegrationLockError("unsafe committed source archive")
        archive.extractall(destination, filter="data")


def _check_native_report(report: Path, expected: list[str]) -> int:
    if not 0 < report.stat().st_size <= MAX_JUNIT_BYTES:
        raise IntegrationLockError("native test report missing or oversized")
    suite = ET.fromstring(report.read_bytes())  # noqa: S314 - bounded local pytest output
    cases = list(suite.iter("testcase"))
    actual = [f"{case.get('classname')}::{case.get('name')}" for case in cases]
    if (
        len(actual) != len(expected)
        or sorted(actual) != sorted(expected)
        or any(list(case) for case in cases)
    ):
        raise IntegrationLockError("required real-native case inventory did not execute")
    return len(cases)


def _build(lock: dict[str, Any], source_root: Path, work: Path) -> dict[str, Any]:
    for name in ("rill-crypto", "rill-core", "rill-provider"):
        _archive(source_root / name, lock["components"][name]["commit"], work / name)
    crypto = work / "rill-crypto"
    core = work / "rill-core"
    provider = work / "rill-provider"
    native_build = work / "native"
    _run(
        [
            "cmake",
            "-S",
            str(crypto),
            "-B",
            str(native_build),
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBUILD_TESTING=ON",
        ]
    )
    _run(["cmake", "--build", str(native_build), "--parallel", "2"])
    _run(["ctest", "--test-dir", str(native_build), "--output-on-failure"])
    library = native_build / "librill_crypto.so"
    if not library.is_file():
        raise IntegrationLockError("required native shared library unavailable")
    artifact_dir = work / "artifacts"
    artifact_dir.mkdir()
    for path in (crypto / "python", core / "packages" / "core", provider):
        _run(["uv", "build", "--wheel", "--out-dir", str(artifact_dir), str(path)])
    for filename, expected in lock["python_wheels"].items():
        if _sha256(artifact_dir / filename) != expected:
            raise IntegrationLockError("producer wheel does not match pinned digest")
    provider_wheel = artifact_dir / "rill_provider-0.1.0.dev0-py3-none-any.whl"
    if not provider_wheel.is_file():
        raise IntegrationLockError("provider consumer artifact unavailable")
    virtualenv = work / "venv"
    _run(["uv", "venv", "--python", sys.executable, str(virtualenv)])
    python = virtualenv / "bin" / "python"
    pinned_requirements = work / "requirements-pinned.txt"
    pinned_requirements.write_text(
        "\n".join(
            line
            for line in (provider / "requirements-dev.txt").read_text().splitlines()
            if not line.startswith("-e ")
        )
        + "\n"
    )
    _run(["uv", "pip", "install", "--python", str(python), "-r", str(pinned_requirements)])
    _run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "--no-deps",
            *(str(artifact_dir / filename) for filename in sorted(WHEELS)),
            str(provider_wheel),
        ]
    )
    report = work / "native-tests.xml"
    env = os.environ.copy()
    for name in ("PYTHONPATH", "PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONOPTIMIZE"):
        env.pop(name, None)
    env.update(
        {
            "RILLSWAP_RUN_NATIVE_CRYPTO": "1",
            "RILL_CRYPTO_LIBRARY": str(library),
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        }
    )
    _run(
        [
            str(python),
            "-m",
            "pytest",
            "-q",
            "-m",
            "native_crypto",
            "--basetemp",
            str(work / "pytest"),
            f"--junitxml={report}",
        ],
        cwd=provider,
        env=env,
    )
    count = _check_native_report(report, lock["native_cases"])
    return {
        "kind": "local-pinned-provider-integration/v1",
        "components": lock["components"],
        "artifacts_sha256": {
            **{
                filename: _sha256(artifact_dir / filename)
                for filename in (*sorted(WHEELS), provider_wheel.name)
            },
            library.name: _sha256(library),
        },
        "native_cases_passed": count,
        "authority": "none (integration evidence, not production readiness)",
    }


def main() -> int:
    """Verify explicit pinned sources, then build/test disposable artifacts."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--lock", type=Path, default=Path(__file__).resolve().parents[1] / "integration-lock.json"
    )
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    try:
        lock = _lock(arguments.lock)
        _verify_sources(lock, arguments.source_root)
        if arguments.verify_only:
            sys.stdout.write(
                "Pinned source commits and trees are available; no build or release authority\n"
            )
            return 0
        scratch = Path(__file__).resolve().parents[1] / "tmp"
        scratch.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="integration-", dir=scratch) as temporary:
            result = _build(lock, arguments.source_root, Path(temporary))
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    except (IntegrationLockError, OSError, ValueError, KeyError, TypeError):
        sys.stderr.write("Pinned local integration unavailable or failed; no release authority\n")
        return 2
    else:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
