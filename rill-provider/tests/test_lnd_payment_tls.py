"""Real loopback gRPC TLS and macaroon-metadata transport, fake read-only server.

This is not LND and cannot establish upstream retention or reconciliation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from typing import TYPE_CHECKING

import grpc
import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_payment_observation import (
    LndAuthError,
    LndPaymentObserver,
    LndUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

HASH = b"\x61" * 32
NETWORK = NetworkIdentity.model_validate(
    json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())[
        "contract_terms"
    ]["network_identity"]
)
OPENSSL = shutil.which("openssl")


def _certificate(directory: Path) -> tuple[Path, bytes]:
    assert OPENSSL is not None
    key = directory / "local.key"
    cert = directory / "local.crt"
    command = [
        OPENSSL,
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-noenc",
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=IP:127.0.0.1,DNS:localhost",
        "-batch",
    ]
    subprocess.run(  # noqa: S603 - local test-only synthetic TLS key, no shell
        command,
        capture_output=True,
        check=True,
        timeout=10,
    )
    return cert, key.read_bytes()


@contextmanager
def _server(
    cert: Path,
    key: bytes,
    *,
    macaroon_hex: str,
    mode: str = "normal",
    cancellation: Event | None = None,
) -> Iterator[tuple[int, list[bytes]]]:
    received: list[bytes] = []

    def track(
        request: router_pb2.TrackPaymentRequest,
        context: grpc.ServicerContext,
    ) -> Iterator[lightning_pb2.Payment]:
        if mode == "stall" and cancellation is not None:
            context.add_callback(cancellation.set)
        metadata = dict(context.invocation_metadata())
        if metadata.get("macaroon") != macaroon_hex:
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "synthetic restricted macaroon rejected"
            )
        received.append(request.payment_hash)
        yield lightning_pb2.Payment(payment_hash=request.payment_hash.hex(), status=4)
        if mode == "stall":
            assert cancellation is not None
            cancellation.wait(timeout=5)
            return
        yield lightning_pb2.Payment(
            payment_hash=request.payment_hash.hex(),
            status=2,
            payment_preimage=(
                "SENSITIVE-MOCK-PREIMAGE" if mode != "oversized" else "X" * (256 * 1024 + 4096)
            ),
            htlcs=[lightning_pb2.HTLCAttempt(attempt_id=5, status=1)],
        )

    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers(
        (
            grpc.method_handlers_generic_handler(
                "routerrpc.Router",
                {
                    "TrackPaymentV2": grpc.unary_stream_rpc_method_handler(
                        track,
                        request_deserializer=router_pb2.TrackPaymentRequest.FromString,
                        response_serializer=lightning_pb2.Payment.SerializeToString,
                    )
                },
            ),
        )
    )
    port = server.add_secure_port(
        "127.0.0.1:0", grpc.ssl_server_credentials(((key, cert.read_bytes()),))
    )
    assert port > 0
    server.start()
    try:
        yield port, received
    finally:
        assert server.stop(0).wait(timeout=3)


@pytest.mark.skipif(OPENSSL is None, reason="openssl required for synthetic TLS test")
def test_verified_loopback_tls_and_restricted_macaroon_metadata(tmp_path: Path) -> None:
    cert, key = _certificate(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    wrong_cert, _ = _certificate(other)
    macaroon = tmp_path / "restricted.macaroon"
    macaroon.write_bytes(b"synthetic-offchain-read-only")
    macaroon.chmod(0o600)
    with _server(cert, key, macaroon_hex=macaroon.read_bytes().hex()) as (port, received):
        observer = LndPaymentObserver(
            host="127.0.0.1",
            port=port,
            tls_certificate_path=cert,
            read_macaroon_path=macaroon,
            network=NETWORK,
        )
        result = observer.track(HASH, deadline_seconds=2)
        assert result.completion == "terminal"
        assert [item.status for item in result.snapshots] == ["INITIATED", "SUCCEEDED"]
        assert received == [HASH]
        assert "SENSITIVE-MOCK-PREIMAGE" not in repr(result)
        macaroon.write_bytes(b"wrong-macaroon")
        with pytest.raises(LndAuthError) as auth:
            observer.track(HASH, deadline_seconds=2)
        assert "synthetic" not in str(auth.value)
        wrong = LndPaymentObserver(
            host="127.0.0.1",
            port=port,
            tls_certificate_path=wrong_cert,
            read_macaroon_path=macaroon,
            network=NETWORK,
        )
        with pytest.raises(LndUnavailableError) as untrusted:
            wrong.track(HASH, deadline_seconds=2)
        assert "wrong-macaroon" not in str(untrusted.value)
        assert received == [HASH]


@pytest.mark.skipif(OPENSSL is None, reason="openssl required for synthetic TLS test")
@pytest.mark.parametrize("mode", ["stall", "oversized"])
def test_real_tls_deadline_and_receive_limit_never_yield_partial_success(
    tmp_path: Path,
    mode: str,
) -> None:
    cert, key = _certificate(tmp_path)
    macaroon = tmp_path / "restricted.macaroon"
    macaroon.write_bytes(b"synthetic-offchain-read-only")
    macaroon.chmod(0o600)
    cancellation = Event() if mode == "stall" else None
    with _server(
        cert, key, macaroon_hex=macaroon.read_bytes().hex(), mode=mode, cancellation=cancellation
    ) as (
        port,
        received,
    ):
        client = LndPaymentObserver(
            host="127.0.0.1",
            port=port,
            tls_certificate_path=cert,
            read_macaroon_path=macaroon,
            network=NETWORK,
        )
        started = time.monotonic()
        with pytest.raises(LndUnavailableError) as error:
            client.track(HASH, deadline_seconds=0.2 if mode == "stall" else 2)
        assert time.monotonic() - started < 2.5
        assert error.value.__context__ is None
        assert received == [HASH]
        if cancellation is not None:
            # Assert before stopping the server; only the client deadline or
            # cancellation can have signaled this callback so far.
            assert cancellation.wait(timeout=0.8)
