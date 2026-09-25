"""Regenerate pinned LND read-only observer and invoice message types.

Run from the repository root with dependencies from requirements-dev.txt.
Generated sources contain upstream message descriptors but no gRPC service
stubs. Any future invoice actions require a separately reviewed adapter.
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
    "invoicesrpc/invoices.proto": (
        "1724f72aa2ed070c8978f5e8a40bc828a2859bbf5a56274ffa1577a65f3f05e7"
    ),
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
    (DEST / "invoicesrpc").mkdir(exist_ok=True)
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
            str(PROTO / "invoicesrpc/invoices.proto"),
        ],
        check=True,
    )
    for directory in (DEST, DEST / "routerrpc", DEST / "invoicesrpc"):
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
        (
            "invoicesrpc/invoices_pb2.py",
            "import lightning_pb2 as lightning__pb2",
            "from .. import lightning_pb2 as lightning__pb2",
        ),
        (
            "invoicesrpc/invoices_pb2.pyi",
            "import lightning_pb2 as _lightning_pb2",
            "from .. import lightning_pb2 as _lightning_pb2",
        ),
    ):
        generated_file = DEST / file
        generated = generated_file.read_text()
        if generated.count(original) != 1:
            raise SystemExit("generated LND import shape changed")
        generated_file.write_text(generated.replace(original, relative))


if __name__ == "__main__":
    main()
