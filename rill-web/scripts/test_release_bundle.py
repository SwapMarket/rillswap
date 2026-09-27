"""Tests for release ZIP byte identity, without publishing or deploying."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from check_release_bundle import built_files, check_bundle, stage_bundle


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
            self.assertIn("assets/app.js", (output / "SHA256SUMS").read_text())

            with zipfile.ZipFile(output / "rill-web.zip", "a") as bundle:
                bundle.writestr("unbuilt.js", "surprise")
            with self.assertRaisesRegex(ValueError, "members differ"):
                check_bundle(built_files(dist), output / "rill-web.zip")

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
