"""Synthetic gRPC transport tests: no actual payment or pinned live-LND claim."""

from __future__ import annotations

import json
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any

import grpc
import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider import lnd_payment_observation as observer
from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

HASH = b"\xab" * 32
NETWORK = NetworkIdentity.model_validate(
    json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())[
        "contract_terms"
    ]["network_identity"]
)


def _payment(
    status: int, *, hash_hex: str = HASH.hex(), attempts: tuple[tuple[int, int], ...] = ()
) -> lightning_pb2.Payment:
    return lightning_pb2.Payment(
        payment_hash=hash_hex,
        status=status,
        payment_preimage="private-preimage-must-never-escape",
        htlcs=[
            lightning_pb2.HTLCAttempt(attempt_id=identifier, status=state)
            for identifier, state in attempts
        ],
    )


class FakeStream:
    def __init__(self, responses: list[lightning_pb2.Payment | grpc.RpcError]) -> None:
        self.responses = responses
        self.cancelled = False
        self.consumed = 0

    def __iter__(self) -> FakeStream:
        return self

    def __next__(self) -> lightning_pb2.Payment:
        if self.consumed == len(self.responses):
            raise StopIteration
        value = self.responses[self.consumed]
        self.consumed += 1
        if isinstance(value, grpc.RpcError):
            raise value
        return value

    def cancel(self) -> None:
        self.cancelled = True


class FakeChannel:
    def __init__(self, stream: FakeStream) -> None:
        self.stream = stream
        self.closed = False
        self.calls: list[tuple[router_pb2.TrackPaymentRequest, dict[str, Any]]] = []
        self.methods: list[str] = []

    def unary_stream(
        self,
        method: str,
        *,
        request_serializer: Callable[[router_pb2.TrackPaymentRequest], bytes],
        response_deserializer: Callable[[bytes], lightning_pb2.Payment],
    ) -> Callable[..., FakeStream]:
        self.methods.append(method)

        def call(request: router_pb2.TrackPaymentRequest, **kwargs: object) -> FakeStream:
            # Exercise the generated protobuf serialization, not only fake objects.
            assert router_pb2.TrackPaymentRequest.FromString(request_serializer(request)) == request
            assert isinstance(
                response_deserializer(_payment(4).SerializeToString()), lightning_pb2.Payment
            )
            self.calls.append((request, kwargs))
            return self.stream

        return call

    def close(self) -> None:
        self.closed = True


def _client(tmp_path: Path) -> observer.LndPaymentObserver:
    cert = tmp_path / "tls.cert"
    cert.write_bytes(b"FAKE-PINNED-TLS-CERT")
    macaroon = tmp_path / "readonly.macaroon"
    macaroon.write_bytes(b"restricted-test-macaroon")
    macaroon.chmod(0o600)
    return observer.LndPaymentObserver(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=cert,
        read_macaroon_path=macaroon,
        network=NETWORK,
    )


def _transport(
    monkeypatch: pytest.MonkeyPatch, stream: FakeStream
) -> tuple[FakeChannel, list[Any]]:
    channel = FakeChannel(stream)
    details: list[Any] = []

    def fake_secure(target: str, credentials: object, *, options: object) -> FakeChannel:
        details.append((target, credentials, options))
        return channel

    def fake_ssl(*, root_certificates: bytes) -> str:
        details.append(root_certificates)
        return "TLS-WITH-PINNED-ROOT"

    monkeypatch.setattr(observer.grpc, "ssl_channel_credentials", fake_ssl)
    monkeypatch.setattr(observer.grpc, "secure_channel", fake_secure)
    return channel, details


def test_construction_and_invalid_requests_are_inert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        observer, "_read_file", lambda *_args, **_kw: pytest.fail("unexpected credential read")
    )
    monkeypatch.setattr(
        observer.grpc, "secure_channel", lambda *_args, **_kw: pytest.fail("unexpected RPC")
    )
    diagnostic = observer.LndPaymentObserver(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=tmp_path / "absent-cert",
        read_macaroon_path=tmp_path / "absent-key",
        network=NETWORK,
    )
    for invalid in (b"", b"a", b"a" * 33):
        with pytest.raises(ValueError, match="32 bytes"):
            diagnostic.track(invalid)
    for invalid in (-1, 0, 31, float("nan"), True):
        with pytest.raises(ValueError, match="deadline"):
            diagnostic.track(HASH, deadline_seconds=invalid)


def test_typed_statuses_and_attempts_are_not_journal_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshots = [
        _payment(4),
        _payment(1, attempts=((1, 0), (2, 2))),
        _payment(2, attempts=((1, 1), (2, 2))),
    ]
    stream = FakeStream(snapshots)
    channel, details = _transport(monkeypatch, stream)
    result = _client(tmp_path).track(HASH, deadline_seconds=3.0)
    assert result.completion == "terminal"
    assert [snapshot.status for snapshot in result.snapshots] == [
        "INITIATED",
        "IN_FLIGHT",
        "SUCCEEDED",
    ]
    assert result.snapshots[0].htlc_attempts == ()
    assert [
        (attempt.lnd_attempt_id, attempt.status) for attempt in result.snapshots[1].htlc_attempts
    ] == [
        (1, "IN_FLIGHT"),
        (2, "FAILED"),
    ]
    assert channel.methods == ["/routerrpc.Router/TrackPaymentV2"]
    request, arguments = channel.calls[0]
    assert request.payment_hash == HASH
    assert request.no_inflight_updates is False
    assert arguments["metadata"] == (("macaroon", b"restricted-test-macaroon".hex()),)
    assert arguments["timeout"] == 3.0
    assert details[0] == b"FAKE-PINNED-TLS-CERT"
    assert details[1][0] == "127.0.0.1:10009"
    assert ("grpc.max_receive_message_length", observer.MAX_MESSAGE_BYTES) in details[1][2]
    assert ("grpc.enable_retries", 0) in details[1][2]
    assert stream.cancelled
    assert channel.closed
    assert "private-preimage" not in repr(result)
    assert "restricted-test-macaroon" not in repr(result)


def test_terminal_failed_is_a_reported_payment_status_not_retry_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stream = FakeStream([_payment(3, attempts=((91, 2),))])
    channel, _ = _transport(monkeypatch, stream)
    result = _client(tmp_path).track(HASH)
    assert result.snapshots[0].status == "FAILED"
    assert result.snapshots[0].htlc_attempts[0].status == "FAILED"
    assert result.completion == "terminal"
    assert channel.methods == [observer.TRACK_METHOD]


def test_terminal_failed_without_attempt_history_is_not_absence_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = FakeStream([_payment(3)])
    channel, _ = _transport(monkeypatch, stream)
    result = _client(tmp_path).track(HASH)
    assert result.completion == "terminal"
    assert result.snapshots[-1].status == "FAILED"
    assert result.snapshots[-1].htlc_attempts == ()
    assert channel.methods == [observer.TRACK_METHOD]
    assert stream.cancelled
    assert channel.closed


def test_bounded_nonterminal_stream_cancels_without_claiming_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stream = FakeStream([_payment(1) for _ in range(observer.MAX_UPDATES + 1)])
    channel, _ = _transport(monkeypatch, stream)
    result = _client(tmp_path).track(HASH)
    assert result.completion == "update-limit"
    assert len(result.snapshots) == observer.MAX_UPDATES
    assert stream.consumed == observer.MAX_UPDATES
    assert stream.cancelled
    assert channel.closed


@pytest.mark.parametrize(
    "invalid",
    [
        _payment(0),
        _payment(999),
        _payment(2, hash_hex="ee" * 32),
        _payment(1, attempts=((0, 0),)),
        _payment(1, attempts=((2, 999),)),
        _payment(1, attempts=((2, 0), (2, 1))),
        _payment(1, attempts=tuple((index, 0) for index in range(1, observer.MAX_ATTEMPTS + 2))),
    ],
)
def test_malformed_or_conflicting_snapshot_rejected_and_stream_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: lightning_pb2.Payment
) -> None:
    stream = FakeStream([invalid])
    channel, _ = _transport(monkeypatch, stream)
    with pytest.raises(observer.LndProtocolError) as error:
        _client(tmp_path).track(HASH)
    assert "private-preimage" not in str(error.value)
    assert stream.cancelled
    assert channel.closed


class FakeRpcError(grpc.RpcError):
    def __init__(self, code: grpc.StatusCode) -> None:
        self._code = code

    def code(self) -> grpc.StatusCode:
        return self._code

    def __str__(self) -> str:
        return "SENTINEL-SECRET-FROM-UNTRUSTED-GRPC"


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (grpc.StatusCode.NOT_FOUND, observer.LndUnavailableError),
        (grpc.StatusCode.DEADLINE_EXCEEDED, observer.LndUnavailableError),
        (grpc.StatusCode.UNAVAILABLE, observer.LndUnavailableError),
        (grpc.StatusCode.UNAUTHENTICATED, observer.LndAuthError),
        (grpc.StatusCode.PERMISSION_DENIED, observer.LndAuthError),
    ],
)
def test_transport_failure_is_unknown_without_retry_or_secret_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: grpc.StatusCode,
    error_type: type[Exception],
) -> None:
    stream = FakeStream([_payment(1), FakeRpcError(status)])
    channel, _ = _transport(monkeypatch, stream)
    with pytest.raises(error_type) as error:
        _client(tmp_path).track(HASH)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "SENTINEL-SECRET" not in "".join(traceback.format_exception(error.value))
    assert channel.methods == [observer.TRACK_METHOD]
    assert stream.cancelled
    assert channel.closed


def test_empty_stream_and_missing_or_insecure_malformed_credentials_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stream = FakeStream([])
    channel, _ = _transport(monkeypatch, stream)
    client = _client(tmp_path)
    with pytest.raises(observer.LndUnavailableError):
        client.track(HASH)
    assert channel.closed
    assert stream.cancelled
    (tmp_path / "readonly.macaroon").chmod(0o644)
    with pytest.raises(observer.LndAuthError):
        client.track(HASH)
    assert len(channel.calls) == 1
    (tmp_path / "readonly.macaroon").unlink()
    (tmp_path / "readonly.macaroon").symlink_to(tmp_path / "tls.cert")
    with pytest.raises(observer.LndAuthError):
        client.track(HASH)
    assert len(channel.calls) == 1


def test_sensitive_credential_read_errors_do_not_survive_in_exception_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)
    original_open = observer.os.open

    def broken_open(path: str | Path, *args: object, **kwargs: object) -> int:
        if str(path).endswith("readonly.macaroon"):
            raise OSError("SENTINEL-SECRET-FROM-FILE-ERROR")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(observer.os, "open", broken_open)
    with pytest.raises(observer.LndAuthError) as error:
        client.track(HASH)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "SENTINEL-SECRET" not in "".join(traceback.format_exception(error.value))
