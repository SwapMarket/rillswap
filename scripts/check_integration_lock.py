"""Build a pinned local provider baseline from committed sources, not editable siblings.

This is an integration gate, NOT a release or authority to run a live swap.
It needs explicit local Git object sources, trusted Python/uv/CMake/Bun tools,
and network access for third-party build and test dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
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
WEB_NIP59_CASES = frozenset(
    {
        (
            "tests.test_nip59_web_interop::"
            "test_web_produced_wrap_native_provider_consumes_signed_rs001[0-btc-to-ln/v1]"
        ),
        (
            "tests.test_nip59_web_interop::"
            "test_web_produced_wrap_native_provider_consumes_signed_rs001[1-ln-to-btc/v1]"
        ),
    }
)
V1 = "rillswap-provider-integration-lock/v1"
V2 = "rillswap-provider-integration-lock/v2"
BUN_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")


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
    if type(lock) is not dict or lock.get("schema") not in {V1, V2}:
        raise IntegrationLockError("unsupported or incomplete integration lock")
    v2 = lock["schema"] == V2
    required = {"schema", "components", "python_wheels", "native_cases"}
    if v2:
        required.update({"web_nip59_cases", "bun_version"})
    if (
        set(lock) != required
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
    if v2 and (
        type(lock["bun_version"]) is not str
        or not BUN_VERSION.fullmatch(lock["bun_version"])
        or type(lock["web_nip59_cases"]) is not list
        or len(lock["web_nip59_cases"]) != len(WEB_NIP59_CASES)
        or any(type(case) is not str for case in lock["web_nip59_cases"])
        or set(lock["web_nip59_cases"]) != WEB_NIP59_CASES
    ):
        raise IntegrationLockError("unsupported or incomplete web integration inventory")
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


def _check_report(report: Path, expected: list[str]) -> int:
    if not 0 < report.stat().st_size <= MAX_JUNIT_BYTES:
        raise IntegrationLockError("integration test report missing or oversized")
    suite = ET.fromstring(report.read_bytes())  # noqa: S314 - bounded local pytest output
    cases = list(suite.iter("testcase"))
    actual = [f"{case.get('classname')}::{case.get('name')}" for case in cases]
    if (
        len(actual) != len(expected)
        or sorted(actual) != sorted(expected)
        or any(list(case) for case in cases)
    ):
        raise IntegrationLockError("required integration case inventory did not execute")
    return len(cases)


def _check_native_report(report: Path, expected: list[str]) -> int:
    """Keep the historical v1 inventory entry point."""
    return _check_report(report, expected)


def _bun(lock: dict[str, Any]) -> str:
    bun = shutil.which("bun")
    if bun is None:
        raise IntegrationLockError("locked Bun executable unavailable")
    if _run([bun, "--version"]).decode().strip() != lock["bun_version"]:
        raise IntegrationLockError("locked Bun version unavailable")
    return bun


def _install_web(bun: str, work: Path) -> None:
    web = work / "rill-web"
    original_lock_hash = _sha256(web / "bun.lock")
    bun_env = os.environ.copy()
    bun_env["BUN_INSTALL_CACHE_DIR"] = str(work / "bun-cache")
    _run([bun, "install", "--frozen-lockfile", "--ignore-scripts"], cwd=web, env=bun_env)
    if _sha256(web / "bun.lock") != original_lock_hash:
        raise IntegrationLockError("web dependency lock changed during frozen install")


def _build(lock: dict[str, Any], source_root: Path, work: Path) -> dict[str, Any]:
    v2 = lock["schema"] == V2
    bun = _bun(lock) if v2 else None  # Preflight before any archive or expensive build.
    archived = ["rill-crypto", "rill-core", "rill-provider"]
    if v2:
        archived.extend(["rill-docs", "rill-web"])
    for name in archived:
        _archive(source_root / name, lock["components"][name]["commit"], work / name)
    if v2:
        # The executing runner must itself be the pinned provider artifact.
        # Updating a local script without re-pinning cannot change the gate.
        if _sha256(work / "rill-provider/scripts/check_integration_lock.py") != _sha256(
            Path(__file__)
        ):
            raise IntegrationLockError("executing integration runner differs from pinned source")
        _install_web(bun, work)
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
    result = {
        "kind": "local-pinned-provider-integration/v2"
        if v2
        else "local-pinned-provider-integration/v1",
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
    if v2:
        web_report = work / "web-nip59-tests.xml"
        web_env = {**env, "RILLSWAP_RUN_WEB_NIP59": "1"}
        _run(
            [
                str(python),
                "-m",
                "pytest",
                "-q",
                "-m",
                "web_nip59_interop",
                "--basetemp",
                str(work / "pytest-web"),
                f"--junitxml={web_report}",
            ],
            cwd=provider,
            env=web_env,
        )
        result.update(
            {
                "bun_version": lock["bun_version"],
                "archived_components": archived,
                "web_nip59_cases_passed": _check_report(web_report, lock["web_nip59_cases"]),
            }
        )
    return result


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
        if lock.get("schema") == V2:
            result["integration_lock_sha256"] = _sha256(arguments.lock)
            result["executing_runner_sha256"] = _sha256(Path(__file__))
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    except (IntegrationLockError, OSError, ValueError, KeyError, TypeError):
        sys.stderr.write("Pinned local integration unavailable or failed; no release authority\n")
        return 2
    else:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
