"""Run the unmodified historical provider v2 gate from a monorepo checkout.

Only the exact committed v2 lock is supported. The component Git directories
are disposable, no-checkout views of already verified monorepo objects. This
wrapper does not repin a baseline or attest the current working tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

COMPONENTS = (
    "rill-docs",
    "rill-crypto",
    "rill-core",
    "rill-provider",
    "rill-cli",
    "rill-web",
)
LOCK_SHA256 = "61f33e58a71782ef189c349716e8e9ecd58f89772d0f4b1c729c39b100e06a74"
RUNNER_SHA256 = "a1cf4674c2566eb82d31126b8c4ccb6ad7f6f3cb2237e0417d405cfaf43cb4bf"
SCHEMA = "rillswap-provider-integration-lock/v2"


class ReplayUnavailableError(Exception):
    """The historical pinned baseline cannot be independently replayed."""


def _bounded_process(
    command: list[str], *, timeout: int
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command, capture_output=True, check=False, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise ReplayUnavailableError("historical replay subprocess timed out") from None


def _git(root: Path, *args: str, timeout: int = 60) -> bytes:
    completed = _bounded_process(["git", "-C", str(root), *args], timeout=timeout)
    if completed.returncode:
        raise ReplayUnavailableError("required historical Git object unavailable")
    return completed.stdout


def _locked_components(lock_path: Path) -> dict[str, dict[str, str]]:
    source = lock_path.read_bytes()
    if hashlib.sha256(source).hexdigest() != LOCK_SHA256:
        raise ReplayUnavailableError(
            "historical v2 integration lock differs from pinned bytes"
        )
    lock: Any = json.loads(source)
    if lock.get("schema") != SCHEMA or set(lock.get("components", {})) != set(
        COMPONENTS
    ):
        raise ReplayUnavailableError("historical v2 component inventory differs")
    return lock["components"]


def _verify_pins(root: Path, components: dict[str, dict[str, str]]) -> bytes:
    if (
        Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
        != root.resolve()
    ):
        raise ReplayUnavailableError("source must be the monorepo Git root")
    if _git(root, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise ReplayUnavailableError("historical replay requires the full Git history")
    for name in COMPONENTS:
        pin = components[name]
        commit, tree = pin["commit"], pin["tree"]
        if (
            type(commit) is not str
            or type(tree) is not str
            or len(commit) != 40
            or len(tree) != 40
            or any(char not in "0123456789abcdef" for char in commit + tree)
        ):
            raise ReplayUnavailableError("invalid historical component pin")
        if (
            _git(root, "rev-parse", "--verify", f"{commit}^{{commit}}").strip()
            != commit.encode()
        ):
            raise ReplayUnavailableError("historical commit differs")
        if (
            _git(root, "rev-parse", "--verify", f"{commit}^{{tree}}").strip()
            != tree.encode()
        ):
            raise ReplayUnavailableError("historical tree differs")
        _git(root, "merge-base", "--is-ancestor", commit, "HEAD")
    provider_commit = components["rill-provider"]["commit"]
    runner = _git(root, "show", f"{provider_commit}:scripts/check_integration_lock.py")
    if hashlib.sha256(runner).hexdigest() != RUNNER_SHA256:
        raise ReplayUnavailableError("historical runner differs from pinned bytes")
    return runner


def replay(root: Path, lock_path: Path, *, verify_only: bool = False) -> str:
    """Replay the original v2 runner with exactly pinned disposable source repositories."""
    components = _locked_components(lock_path)
    runner = _verify_pins(root, components)
    scratch = root / "tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="provider-v2-replay-", dir=scratch
    ) as temporary:
        work = Path(temporary)
        sources = work / "sources"
        sources.mkdir(mode=0o700)
        for name in COMPONENTS:
            subprocess_result = _bounded_process(
                [
                    "git",
                    "clone",
                    "--shared",
                    "--no-checkout",
                    "--quiet",
                    str(root),
                    str(sources / name),
                ],
                timeout=120,
            )
            if subprocess_result.returncode:
                raise ReplayUnavailableError("disposable Git source creation failed")
            pin = components[name]
            if (
                _git(sources / name, "rev-parse", f"{pin['commit']}^{{tree}}").strip()
                != pin["tree"].encode()
            ):
                raise ReplayUnavailableError(
                    "disposable source differs from historical tree"
                )
        historical = work / "rill-provider" / "scripts" / "check_integration_lock.py"
        historical.parent.mkdir(parents=True, mode=0o700)
        historical.write_bytes(runner)
        arguments = [
            sys.executable,
            str(historical),
            "--source-root",
            str(sources),
            "--lock",
            str(lock_path),
        ]
        if verify_only:
            arguments.append("--verify-only")
        result = _bounded_process(arguments, timeout=1800)
        if result.returncode:
            raise ReplayUnavailableError(
                "historical v2 runner refused or failed; no release authority"
            )
        return result.stdout.decode()


def main() -> int:
    """Replay only upon explicit invocation; never infer safety from missing state."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    root = args.source_root.resolve()
    lock_path = (
        args.lock or root / "rill-provider" / "integration-lock.json"
    ).resolve()
    try:
        sys.stdout.write(replay(root, lock_path, verify_only=args.verify_only))
    except (
        ReplayUnavailableError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
    ):
        sys.stderr.write(
            "Historical v2 integration unavailable; no release authority\n"
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
