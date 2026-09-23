"""Regenerate only pinned LND payment-observer protobuf messages.

Run from the repository root with dependencies from requirements-dev.txt.
Generated sources contain upstream message descriptors but no RouterStub with
send APIs; the observer uses only the pinned TrackPaymentV2 method path.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "proto/lnd-v0.21.0-beta"
DEST = ROOT / "src/rill_provider/_lnd_proto"
HASHES = {
    "lightning.proto": "9c0f9a8649312711bd849b82430bb5bcd17a3d85bb8c5627c3456214c2aa87b0",
    "routerrpc/router.proto": "3f47107905612218b78c006841f13ed88f45b6db101db910c1e5c5acceac489b",
    "LICENSE": "7ebd67c52a36357cb0c6c5e903ece047b195a6b8b04c6e7a8c820e01c884581c",
}


def main() -> None:
    """Verify the pinned sources and generate the package-local message types."""
    for package, expected in {
        "grpcio-tools": "1.84.0",
        "grpcio": "1.84.0",
        "protobuf": "7.36.2",
    }.items():
        if importlib.metadata.version(package) != expected:
            raise SystemExit("LND generation toolchain differs from pinned versions")
    for name, expected in HASHES.items():
        if hashlib.sha256((PROTO / name).read_bytes()).hexdigest() != expected:
            raise SystemExit("LND protobuf source differs from pinned upstream bytes")
    DEST.mkdir(parents=True, exist_ok=True)
    (DEST / "routerrpc").mkdir(exist_ok=True)
    shutil.copyfile(PROTO / "LICENSE", DEST / "LICENSE.lnd")
    subprocess.run(  # noqa: S603 - fixed interpreter and pinned local proto inputs
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            "-I",
            str(PROTO),
            f"--python_out={DEST}",
            f"--pyi_out={DEST}",
            str(PROTO / "lightning.proto"),
            str(PROTO / "routerrpc/router.proto"),
        ],
        check=True,
    )
    for directory in (DEST, DEST / "routerrpc"):
        (directory / "__init__.py").touch()
    for file, original, relative in (
        (
            "routerrpc/router_pb2.py",
            "import lightning_pb2 as lightning__pb2",
            "from .. import lightning_pb2 as lightning__pb2",
        ),
        (
            "routerrpc/router_pb2.pyi",
            "import lightning_pb2 as _lightning_pb2",
            "from .. import lightning_pb2 as _lightning_pb2",
        ),
    ):
        router = DEST / file
        generated = router.read_text()
        if generated.count(original) != 1:
            raise SystemExit("generated LND import shape changed")
        router.write_text(generated.replace(original, relative))


if __name__ == "__main__":
    main()
