"""Verify a deterministic ZIP and extracted Pages candidate against tested dist/.

These artifacts stay local. Publishing, destination-byte identity and release
authorization remain separate release-gate work.
"""

from __future__ import annotations

import hashlib
import stat
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
        entries = bundle.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(files) or set(names) != set(files):
            raise ValueError("ZIP members differ from built site")
        for entry in entries:
            path = Path(entry.filename)
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if (
                path.is_absolute()
                or any(part in ("", ".", "..") for part in entry.filename.split("/"))
                or "\\" in entry.filename
                or entry.is_dir()
                or mode not in (0, stat.S_IFREG)
            ):
                raise ValueError("ZIP contains an unsafe or non-file member")
        if bundle.testzip() is not None:
            raise ValueError("ZIP member checksum failed")
        for name, contents in files.items():
            if bundle.read(name) != contents:
                raise ValueError(f"ZIP file differs from built site: {name}")


def _manifest_bytes(files: dict[str, bytes], archive: Path) -> bytes:
    return (
        "".join(f"{hashlib.sha256(contents).hexdigest()}  {name}\n" for name, contents in files.items())
        + f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  rill-web.zip\n"
    ).encode()


def check_pages_payload(files: dict[str, bytes], pages: Path) -> None:
    """Refuse any Pages file not identical to the tested build."""
    if built_files(pages) != files:
        raise ValueError("Pages payload differs from tested build")


def extract_pages_payload(dist: Path, staged: Path, pages: Path) -> None:
    """Construct only a clean, verified Pages candidate from the staged ZIP."""
    files = built_files(dist)
    archive = staged / "rill-web.zip"
    check_bundle(files, archive)
    if (staged / "SHA256SUMS").read_bytes() != _manifest_bytes(files, archive):
        raise ValueError("release manifest differs from tested build and ZIP")
    if pages.exists() or pages.is_symlink():
        raise ValueError("Pages target must not exist before extraction")
    pages.mkdir(parents=True)
    with zipfile.ZipFile(archive) as bundle:
        for name in files:
            target = pages / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(name))
    check_pages_payload(files, pages)


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
    manifest.write_bytes(_manifest_bytes(files, archive))


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: check_release_bundle.py DIST OUTPUT [PAGES_TARGET]")
    stage_bundle(Path(sys.argv[1]), Path(sys.argv[2]))
    if len(sys.argv) == 4:
        extract_pages_payload(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
