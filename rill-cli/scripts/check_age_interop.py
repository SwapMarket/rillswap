"""Fail-closed local age/native recovery interop gate (not hosted CI).

Run with explicit official age archive and independently known native-library
digest. The script has no download or build step and never opens user backups.
"""

# ruff: noqa: INP001 - this is a standalone local verification executable

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
AGE_ARCHIVE_SHA256 = "bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377"
AGE_VERSION = "1.3.1"
MAX_AGE_BINARY_BYTES = 32 * 1024 * 1024
TEST_NODES = (
    "tests/test_recovery_cli.py::test_two_direction_independent_go_age_interoperability",
    "tests/test_age_container.py::test_independent_go_scrypt_fixture_decrypts_with_native_inspection",
)
EXPECTED_CASES = {
    (
        "tests.test_recovery_cli",
        "test_two_direction_independent_go_age_interoperability[btc-to-ln]",
    ),
    (
        "tests.test_recovery_cli",
        "test_two_direction_independent_go_age_interoperability[ln-to-btc]",
    ),
    (
        "tests.test_age_container",
        "test_independent_go_scrypt_fixture_decrypts_with_native_inspection",
    ),
}


class GateError(Exception):
    """Required interop evidence was not obtained."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_revision(path: Path) -> str:
    git = shutil.which("git")
    if git is None:
        raise GateError("Git is required to identify sibling source revisions")
    revision = subprocess.run(  # noqa: S603 - Git on fixed local sibling checkout
        [git, "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    state = subprocess.run(  # noqa: S603 - Git on fixed local sibling checkout
        [git, "-C", str(path), "status", "--porcelain"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if (
        revision.returncode
        or state.returncode
        or not re.fullmatch(r"[0-9a-f]{40}", revision.stdout.strip())
    ):
        raise GateError("required sibling source checkout is unavailable")
    return revision.stdout.strip() + (" (dirty)" if state.stdout else " (clean)")


def _extract_verified_age(archive: Path, destination: Path) -> Path:
    if _sha256(archive) != AGE_ARCHIVE_SHA256:
        raise GateError("age archive checksum differs from pinned v1.3.1 linux-amd64 asset")
    with tarfile.open(archive, mode="r:gz") as bundle:
        members = [member for member in bundle if member.name == "age/age"]
        if (
            len(members) != 1
            or not members[0].isfile()
            or not 0 < members[0].size <= MAX_AGE_BINARY_BYTES
        ):
            raise GateError("pinned age archive has no bounded regular age executable")
        stream = bundle.extractfile(members[0])
        if stream is None:
            raise GateError("pinned age executable cannot be read")
        binary = destination / "age"
        with stream, binary.open("xb") as output:
            remaining = members[0].size
            while remaining:
                block = stream.read(min(remaining, 1024 * 1024))
                if not block:
                    raise GateError("pinned age executable is truncated")
                output.write(block)
                remaining -= len(block)
        binary.chmod(stat.S_IRUSR | stat.S_IXUSR)
        return binary


def _require_exact_cases(report: Path) -> None:
    try:
        root = ET.parse(report).getroot()  # noqa: S314 - private generated test report
    except (OSError, ET.ParseError) as error:
        raise GateError("required structured test report is unavailable") from error
    cases = list(root.iter("testcase"))
    observed = {(case.get("classname"), case.get("name")) for case in cases}
    if (
        len(cases) != len(EXPECTED_CASES)
        or observed != EXPECTED_CASES
        or any(
            case.find(child) is not None
            for case in cases
            for child in ("failure", "error", "skipped")
        )
    ):
        raise GateError("required age/native interop tests did not all pass")


def check_age_interop(archive: Path, native_library: Path, expected_native_sha256: str) -> None:
    """Require both age directions plus independent scrypt fixture to pass."""
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise GateError("pinned age archive supports only Linux amd64")
    if not archive.is_absolute() or not native_library.is_absolute():
        raise GateError("both artifact paths must be absolute")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_native_sha256):
        raise GateError("native digest must be explicit lowercase SHA-256")
    if _sha256(native_library) != expected_native_sha256:
        raise GateError("native library differs from explicit expected digest")
    sources = (ROOT, ROOT.parent / "rill-core", ROOT.parent / "rill-crypto")
    revisions = [(source.name, _source_revision(source)) for source in sources]
    pytest = ROOT / ".venv" / "bin" / "pytest"
    if not pytest.is_file():
        raise GateError("locked development environment is missing")
    temp_root = ROOT / "tmp"
    temp_root.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="age-interop-", dir=temp_root) as directory:
        binary = _extract_verified_age(archive, Path(directory))
        version = subprocess.run(  # noqa: S603 - archive checksum verified before execution
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if version.returncode or version.stdout.strip() != f"v{AGE_VERSION}":
            raise GateError("pinned age executable version check failed")
        env = os.environ.copy()
        for setting in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONOPTIMIZE", "PYTHONPATH"):
            env.pop(setting, None)
        env.update(
            {
                "AGE_BINARY": str(binary),
                "RILL_CRYPTO_LIBRARY": str(native_library),
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            }
        )
        report = Path(directory) / "test-results.xml"
        result = subprocess.run(  # noqa: S603 - explicit local pytest and test nodes
            [
                str(pytest),
                "-q",
                *TEST_NODES,
                "--assert=rewrite",
                f"--basetemp={Path(directory) / 'pytest'}",
                f"--junitxml={report}",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if result.returncode:
            raise GateError("required age/native interop tests did not all pass")
        _require_exact_cases(report)
    for name, revision in revisions:
        sys.stdout.write(f"source {name}: {revision}\n")
    sys.stdout.write(f"native SHA-256: {expected_native_sha256}\n")
    sys.stdout.write(
        "local independent age interop: 3 passed (not hosted CI or recovery authority)\n"
    )


def main() -> int:
    """Run the explicit local verification gate and return a status code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--age-archive", type=Path, required=True)
    parser.add_argument("--native-library", type=Path, required=True)
    parser.add_argument("--native-sha256", required=True)
    args = parser.parse_args()
    try:
        check_age_interop(args.age_archive, args.native_library, args.native_sha256)
    except (GateError, OSError, subprocess.TimeoutExpired, tarfile.TarError):
        sys.stderr.write("local age interoperability gate failed; no release evidence\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
