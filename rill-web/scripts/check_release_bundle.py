"""Stage a deterministic static-site ZIP and verify it matches the one tested dist/.

This stages artifacts locally only. Deploying the exact staged bytes to Pages and
restricting release authorization remain separate release-gate work.
"""

from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path


def built_files(dist: Path) -> dict[str, bytes]:
    """Refuse symlinks and return the complete relative-path to bytes mapping."""
    if not dist.is_dir() or dist.is_symlink():
        raise ValueError("dist must be a real directory")
    files: dict[str, bytes] = {}
    for entry in sorted(dist.rglob("*")):
        if entry.is_symlink():
            raise ValueError(f"symlink in build: {entry}")
        if entry.is_file():
            files[entry.relative_to(dist).as_posix()] = entry.read_bytes()
        elif not entry.is_dir():
            raise ValueError(f"unexpected build entry: {entry}")
    if "index.html" not in files or "swap.html" not in files:
        raise ValueError("build is missing a page")
    return files


def check_bundle(files: dict[str, bytes], archive: Path) -> None:
    """Check ZIP membership, integrity, and every file byte against the built site."""
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if len(names) != len(files) or set(names) != set(files):
            raise ValueError("ZIP members differ from built site")
        if bundle.testzip() is not None:
            raise ValueError("ZIP member checksum failed")
        for name, contents in files.items():
            if bundle.read(name) != contents:
                raise ValueError(f"ZIP file differs from built site: {name}")


def stage_bundle(dist: Path, output: Path) -> None:
    """Create one ZIP and sorted hash manifest from the exact built dist bytes."""
    files = built_files(dist)
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "rill-web.zip"
    manifest = output / "SHA256SUMS"
    with zipfile.ZipFile(archive, "w") as bundle:
        for name, contents in files.items():
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, contents)
    check_bundle(files, archive)
    manifest.write_text(
        "".join(f"{hashlib.sha256(contents).hexdigest()}  {name}\n" for name, contents in files.items())
        + f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  rill-web.zip\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_release_bundle.py DIST OUTPUT")
    stage_bundle(Path(sys.argv[1]), Path(sys.argv[2]))
