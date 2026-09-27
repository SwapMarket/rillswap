"""Tests for release ZIP byte identity, without publishing or deploying."""

from __future__ import annotations

import tempfile
import stat
import unittest
import warnings
import zipfile
from pathlib import Path

from check_release_bundle import (
    built_files,
    check_bundle,
    check_pages_payload,
    extract_pages_payload,
    stage_bundle,
)


class ReleaseBundleTests(unittest.TestCase):
    def test_staged_bundle_contains_exact_built_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            (dist / "assets").mkdir(parents=True)
            (dist / "index.html").write_bytes(b"<html>preview</html>")
            (dist / "swap.html").write_bytes(b"<html>swap</html>")
            (dist / "assets" / "app.js").write_bytes(b"\x00\xff")
            output = root / "release"
            stage_bundle(dist, output)
            original_zip = (output / "rill-web.zip").read_bytes()
            stage_bundle(dist, output)
            self.assertEqual((output / "rill-web.zip").read_bytes(), original_zip)
            manifest = (output / "SHA256SUMS").read_text()
            self.assertIn("assets/app.js", manifest)
            pages = root / "pages"
            extract_pages_payload(dist, output, pages)
            self.assertEqual(built_files(pages), built_files(dist))
            with self.assertRaisesRegex(ValueError, "target must not exist"):
                extract_pages_payload(dist, output, pages)
            (pages / "extra.js").write_bytes(b"not in ZIP")
            with self.assertRaisesRegex(ValueError, "Pages payload differs"):
                check_pages_payload(built_files(dist), pages)
            (pages / "extra.js").unlink()
            (pages / "index.html").write_bytes(b"tampered after extraction")
            with self.assertRaisesRegex(ValueError, "Pages payload differs"):
                check_pages_payload(built_files(dist), pages)

            with zipfile.ZipFile(output / "rill-web.zip", "a") as bundle:
                bundle.writestr("unbuilt.js", "surprise")
            with self.assertRaisesRegex(ValueError, "members differ"):
                check_bundle(built_files(dist), output / "rill-web.zip")

    def test_manifest_and_archive_mutations_never_create_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            dist.mkdir()
            (dist / "index.html").write_bytes(b"index")
            (dist / "swap.html").write_bytes(b"swap")
            staged = root / "staged"
            stage_bundle(dist, staged)
            original_manifest = (staged / "SHA256SUMS").read_bytes()
            (staged / "SHA256SUMS").write_bytes(b"0" + original_manifest[1:])
            with self.assertRaisesRegex(ValueError, "manifest differs"):
                extract_pages_payload(dist, staged, root / "pages")
            self.assertFalse((root / "pages").exists())
            (staged / "SHA256SUMS").write_bytes(original_manifest)

            def replace_archive(entries: list[zipfile.ZipInfo], contents: dict[str, bytes]) -> None:
                with zipfile.ZipFile(staged / "rill-web.zip", "w") as bundle:
                    for entry in entries:
                        bundle.writestr(entry, contents[entry.filename])

            with zipfile.ZipFile(staged / "rill-web.zip") as bundle:
                entries = bundle.infolist()
                contents = {entry.filename: bundle.read(entry) for entry in entries}
            changed = dict(contents)
            changed["swap.html"] = b"tampered"
            replace_archive(entries, changed)
            with self.assertRaisesRegex(ValueError, "differs from built site"):
                extract_pages_payload(dist, staged, root / "pages")
            self.assertFalse((root / "pages").exists())

            replace_archive(entries[:1], contents)
            with self.assertRaisesRegex(ValueError, "members differ"):
                extract_pages_payload(dist, staged, root / "pages")
            self.assertFalse((root / "pages").exists())

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                replace_archive(entries + [entries[0]], contents)
            with self.assertRaisesRegex(ValueError, "members differ"):
                extract_pages_payload(dist, staged, root / "pages")
            self.assertFalse((root / "pages").exists())

            link = zipfile.ZipInfo("swap.html")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            replace_archive([entries[0], link], contents)
            with self.assertRaisesRegex(ValueError, "unsafe or non-file"):
                extract_pages_payload(dist, staged, root / "pages")
            self.assertFalse((root / "pages").exists())

    def test_unsafe_zip_paths_are_refused_even_when_a_build_matches_the_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            dist.mkdir()
            (dist / "index.html").write_bytes(b"index")
            (dist / "swap.html").write_bytes(b"swap")
            (dist / "unsafe\\name.js").write_bytes(b"unsafe")
            with self.assertRaisesRegex(ValueError, "unsafe or non-file"):
                stage_bundle(dist, root / "staged")
            self.assertFalse((root / "pages").exists())

    def test_symlinks_and_incomplete_build_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            dist.mkdir()
            (dist / "index.html").write_text("preview")
            with self.assertRaisesRegex(ValueError, "missing a page"):
                stage_bundle(dist, root / "release")
            (dist / "swap.html").symlink_to("index.html")
            with self.assertRaisesRegex(ValueError, "symlink in build"):
                stage_bundle(dist, root / "release")


if __name__ == "__main__":
    unittest.main()
