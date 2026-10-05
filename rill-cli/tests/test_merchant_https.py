"""Actual TLS with a synthetic merchant, not backend receipt or funding proof."""

from __future__ import annotations

import hashlib
import http.client
import shutil
import ssl
import subprocess
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.networks import REGTEST_CONSENSUS_PROFILE
from rill_core.wire.types import NetworkIdentity

from rill_cli import merchant_https as module
from rill_cli.merchant_credit import MerchantSourcePin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

NODE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
NETWORK = NetworkIdentity(
    family="bitcoin",
    name="regtest",
    genesis_hash="0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    signet_challenge=None,
    consensus_profile=REGTEST_CONSENSUS_PROFILE,
    deployment_namespace="merchant-https-test",
)
TOKEN = "SECRET_CANARY_status_capability_0001"  # noqa: S105 - synthetic test-only capability
INTENT = "merchant_intent_01"


def certificate(directory: Path, name: str, ip: str = "127.0.0.1") -> tuple[Path, Path]:
    cert, key = directory / f"{name}.cert", directory / f"{name}.key"
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl required for synthetic HTTPS tests")
    subprocess.run(  # noqa: S603 - fixed test-only local TLS generation
        [
            openssl,
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
            "/CN=synthetic",
            "-addext",
            f"subjectAltName=IP:{ip}",
            "-batch",
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )
    cert.chmod(0o600)
    key.chmod(0o600)
    return cert, key


def digest(cert: Path) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()


class SyntheticMerchant:
    def __init__(self, directory: Path, ip: str = "127.0.0.1") -> None:
        self.cert, self.key = certificate(directory, "merchant", ip)
        self.requests: list[tuple[str, str | None]] = []
        self.status = 200
        self.headers = {"Content-Type": "application/json", "Cache-Control": "no-store"}
        self.document = b'{"status":"unverified","private":"SECRET_CANARY"}'
        self.events = b"[]"
        self.chunked = False
        self.close_connection = True
        self.clock: list[float] | None = None
        self.header_delay = 0.0
        self.chunk_delay = 0.0
        self.events_status = 200
        self.truncated = False
        self.extra_headers: list[tuple[str, str]] = []
        self.missing_chunk_terminator = False
        self.omit_length = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle(self) -> None:
                with suppress(OSError, ssl.SSLError):
                    super().handle()

            def log_message(self, *_args: object) -> None:
                pass

            def do_GET(self) -> None:
                owner.requests.append((self.path, self.headers.get("Authorization")))
                if owner.clock is not None:
                    owner.clock[0] += owner.header_delay
                body = owner.events if self.path.endswith("/events") else owner.document
                self.send_response(
                    owner.events_status if self.path.endswith("/events") else owner.status
                )
                for name, value in owner.headers.items():
                    self.send_header(name, value)
                for name, value in owner.extra_headers:
                    self.send_header(name, value)
                self.send_header("Connection", "close" if owner.close_connection else "keep-alive")
                if owner.chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                elif not owner.omit_length:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if owner.truncated:
                    self.close_connection = True
                    return
                try:
                    if owner.chunked:
                        if owner.clock is not None:
                            owner.clock[0] += owner.chunk_delay
                        ending = (
                            b"\r\n0\r\n" if owner.missing_chunk_terminator else b"\r\n0\r\n\r\n"
                        )
                        self.wfile.write(f"{len(body):x}\r\n".encode() + body + ending)
                    else:
                        self.wfile.write(body)
                except (OSError, ssl.SSLError):
                    pass  # client intentionally refuses late/invalid evidence

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.pin = MerchantSourcePin(
            merchant_origin=f"https://127.0.0.1:{self.server.server_port}",
            event_public_key="a" * 64,
            source_node=NODE,
            network=NETWORK,
        )

    def reader(self, **updates: Any) -> module.MerchantHttpsReader:  # noqa: ANN401 - fixture keyword variations
        return module.MerchantHttpsReader(
            updates.get("pin", self.pin),
            updates.get("leaf", digest(self.cert)),
            updates.get("ca", self.cert),
        )

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive()


@pytest.fixture
def merchant(tmp_path: Path) -> Iterator[SyntheticMerchant]:
    server = SyntheticMerchant(tmp_path)
    try:
        yield server
    finally:
        server.stop()


def refused(action: Any) -> None:  # noqa: ANN401 - diagnostic callable with varied inputs
    with pytest.raises(module.MerchantHttpsError) as failure:
        action()
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert "SECRET_CANARY" not in str(failure.value)


def test_actual_leaf_verified_before_each_capability_read_and_close_body_supported(
    merchant: SyntheticMerchant,
) -> None:
    reader = merchant.reader()
    assert merchant.requests == []
    batch = reader.read(INTENT, TOKEN)
    assert merchant.requests == [
        (f"/v1/intents/{INTENT}", f"Bearer {TOKEN}"),
        (f"/v1/intents/{INTENT}/events", f"Bearer {TOKEN}"),
    ]
    assert batch.view.document == merchant.document
    assert batch.events_document == b"[]"
    assert batch.view.origin == merchant.pin.merchant_origin
    assert batch.view.acquisition.started_at <= batch.events_acquisition.started_at
    assert batch.events_acquisition.completed_at <= batch.view.acquisition.completed_at
    assert not hasattr(batch, "status_token")
    assert not hasattr(batch, "credit")


@pytest.mark.parametrize(
    "fault", ["leaf", "root", "malformed_root", "public_root", "missing_root", "symlink_root"]
)
def test_failed_peer_or_trust_configuration_never_sends_bearer(
    merchant: SyntheticMerchant, tmp_path: Path, fault: str
) -> None:
    leaf, ca = digest(merchant.cert), merchant.cert
    if fault == "leaf":
        leaf = "b" * 64
    elif fault == "root":
        ca, _key = certificate(tmp_path, "other")
    elif fault == "malformed_root":
        ca = tmp_path / "invalid.cert"
        ca.write_text("SECRET_CANARY")
        ca.chmod(0o600)
    elif fault == "public_root":
        ca.chmod(0o644)
    elif fault == "missing_root":
        ca = tmp_path / "absent.cert"
    else:
        ca = tmp_path / "symlink.cert"
        ca.symlink_to(merchant.cert)
    refused(lambda: merchant.reader(leaf=leaf, ca=ca).read(INTENT, TOKEN))
    assert merchant.requests == []


def test_trusted_replacement_leaf_does_not_learn_new_identity(
    merchant: SyntheticMerchant, tmp_path: Path
) -> None:
    original_pin = digest(merchant.cert)
    (tmp_path / "other").mkdir(mode=0o700)
    other = SyntheticMerchant(tmp_path / "other")
    try:
        refused(lambda: other.reader(leaf=original_pin).read(INTENT, TOKEN))
        assert other.requests == []
    finally:
        other.stop()


def test_wrong_hostname_refuses_even_with_matching_leaf_and_trusted_root(tmp_path: Path) -> None:
    server = SyntheticMerchant(tmp_path, "127.0.0.2")
    try:
        refused(lambda: server.reader().read(INTENT, TOKEN))
        assert server.requests == []
    finally:
        server.stop()


@pytest.mark.parametrize(
    "fault",
    [
        "redirect",
        "age",
        "public_cache",
        "missing_no_store",
        "duplicate_directive",
        "no_store_value",
        "no_store_empty_assignment",
        "missing_length",
        "encoding",
        "non_json",
        "oversized",
        "empty",
        "denied",
    ],
)
def test_nonfresh_or_unsupported_response_never_returns_batch_or_follows_redirect(  # noqa: PLR0912 - one response refusal matrix
    merchant: SyntheticMerchant, fault: str
) -> None:
    if fault == "redirect":
        merchant.status = 302
        merchant.headers["Location"] = "/secret-destination"
    elif fault == "age":
        merchant.headers["Age"] = "0"
    elif fault == "public_cache":
        merchant.headers["Cache-Control"] = "no-store, public, max-age=0"
    elif fault == "missing_no_store":
        merchant.headers["Cache-Control"] = "no-cache"
    elif fault == "duplicate_directive":
        merchant.headers["Cache-Control"] = "no-store, no-store"
    elif fault == "no_store_value":
        merchant.headers["Cache-Control"] = "no-store=1"
    elif fault == "no_store_empty_assignment":
        merchant.headers["Cache-Control"] = "no-store="
    elif fault == "missing_length":
        merchant.omit_length = True
    elif fault == "encoding":
        merchant.headers["Content-Encoding"] = "gzip"
    elif fault == "non_json":
        merchant.headers["Content-Type"] = "text/plain"
    elif fault == "oversized":
        merchant.document = b"x" * 16385
    elif fault == "empty":
        merchant.document = b""
    elif fault == "denied":
        merchant.status = 404
    refused(lambda: merchant.reader().read(INTENT, TOKEN))
    assert len(merchant.requests) == 1


def test_supported_cache_directives_do_not_promote_documents_to_paid_proof(
    merchant: SyntheticMerchant,
) -> None:
    merchant.headers["Cache-Control"] = "private, no-store, no-cache, must-revalidate"
    assert merchant.reader().read(INTENT, TOKEN).view.document == merchant.document


@pytest.mark.parametrize("missing_terminator", [False, True])
def test_chunked_body_is_unsupported_even_after_nonempty_payload_and_zero_chunk(
    merchant: SyntheticMerchant,
    *,
    missing_terminator: bool,
) -> None:
    merchant.chunked, merchant.missing_chunk_terminator = True, missing_terminator
    refused(lambda: merchant.reader().read(INTENT, TOKEN))
    assert len(merchant.requests) == 1


@pytest.mark.parametrize("chunked", [False, True])
def test_truncated_document_never_returns_batch(
    merchant: SyntheticMerchant, *, chunked: bool
) -> None:
    merchant.chunked, merchant.truncated = chunked, True
    refused(lambda: merchant.reader().read(INTENT, TOKEN))
    assert len(merchant.requests) == 1


@pytest.mark.parametrize(
    "header",
    [
        ("Content-Length", "1"),
        ("Content-Type", "application/json"),
        ("Transfer-Encoding", "chunked"),
        ("Transfer-Encoding", "gzip"),
    ],
)
def test_ambiguous_framing_never_returns_document(
    merchant: SyntheticMerchant, header: tuple[str, str]
) -> None:
    merchant.extra_headers = [header]
    refused(lambda: merchant.reader().read(INTENT, TOKEN))
    assert len(merchant.requests) == 1


def test_failed_events_read_does_not_release_partial_view(merchant: SyntheticMerchant) -> None:
    merchant.events_status = 404
    refused(lambda: merchant.reader().read(INTENT, TOKEN))
    assert len(merchant.requests) == 2


def test_invalid_intent_or_header_injection_never_connects(merchant: SyntheticMerchant) -> None:
    for identifier, token in (("../secret", TOKEN), (INTENT, TOKEN + "\r\nInjected: value")):
        refused(
            lambda identifier=identifier, token=token: merchant.reader().read(identifier, token)
        )
    assert merchant.requests == []


def test_clock_rollback_refuses_acquisition(
    merchant: SyntheticMerchant, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = iter((100, 100, 99))
    monkeypatch.setattr(time, "time", lambda: next(clock))
    refused(lambda: merchant.reader().read(INTENT, TOKEN))


def test_cleanup_failure_discards_upstream_error_context(
    merchant: SyntheticMerchant, monkeypatch: pytest.MonkeyPatch
) -> None:
    close = http.client.HTTPSConnection.close

    def failing_close(connection: http.client.HTTPSConnection) -> None:
        close(connection)
        raise RuntimeError("SECRET_CANARY")

    monkeypatch.setattr(http.client.HTTPSConnection, "close", failing_close)
    refused(lambda: merchant.reader().read(INTENT, TOKEN))


def test_modified_pin_cannot_bypass_canonical_https_origin(merchant: SyntheticMerchant) -> None:
    pin = merchant.pin.model_copy(
        update={"merchant_origin": f"http://127.0.0.1:{merchant.server.server_port}"}
    )
    refused(lambda: merchant.reader(pin=pin))
    assert merchant.requests == []


@pytest.mark.parametrize("phase", ["headers", "chunks", "setup", "cleanup"])
def test_entire_batch_rejects_late_evidence_after_setup_parsing_or_cleanup(
    merchant: SyntheticMerchant, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    clock = [100.0]
    merchant.clock = clock
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    if phase == "headers":
        merchant.header_delay = 11
    elif phase == "chunks":
        merchant.chunked = True
        merchant.chunk_delay = 11
    elif phase == "setup":
        original = module._context  # noqa: SLF001 - entire setup acceptance budget

        def slow(path: Path) -> ssl.SSLContext:
            result = original(path)
            clock[0] += 11
            return result

        monkeypatch.setattr(module, "_context", slow)
    else:
        close = http.client.HTTPSConnection.close

        def slow_close(connection: http.client.HTTPSConnection) -> None:
            close(connection)
            clock[0] += 11

        monkeypatch.setattr(http.client.HTTPSConnection, "close", slow_close)
    refused(lambda: merchant.reader().read(INTENT, TOKEN))
    assert len(merchant.requests) <= 1


def test_implicit_connection_open_is_disabled_before_any_authorization(
    merchant: SyntheticMerchant, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = http.client.HTTPSConnection.connect

    def drop(connection: http.client.HTTPSConnection) -> None:
        assert connection.auto_open == 0
        original(connection)
        verified = connection.sock
        assert verified is not None
        # After the client pins, simulate a detached connection during send.
        send = connection.send

        def detached(data: Any) -> None:  # noqa: ANN401 - preserve the stdlib send input union in this test double
            connection.sock = None
            try:
                send(data)
            finally:
                verified.close()

        connection.send = detached  # type: ignore[method-assign]

    monkeypatch.setattr(http.client.HTTPSConnection, "connect", drop)
    refused(lambda: merchant.reader().read(INTENT, TOKEN))
    assert merchant.requests == []


@pytest.mark.parametrize("duration", [0, -1, 11, 10**400, True, float("nan"), float("inf")])
def test_invalid_batch_lifetime_is_inert(merchant: SyntheticMerchant, duration: float) -> None:
    refused(lambda: merchant.reader().read(INTENT, TOKEN, deadline_seconds=duration))
    assert merchant.requests == []


def test_nonprofile_origin_or_bad_leaf_refuses_without_connecting(
    merchant: SyntheticMerchant,
) -> None:
    foreign = merchant.pin.model_copy(update={"merchant_origin": "https://merchant.invalid"})
    refused(lambda: merchant.reader(pin=foreign))
    refused(lambda: merchant.reader(leaf="SECRET_CANARY"))
    assert merchant.requests == []
