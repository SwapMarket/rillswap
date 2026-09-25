"""LND SendPaymentV2/TrackPaymentV2: one intent, never two payments."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import grpc
import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider import lnd_payment_send as sender
from rill_provider._lnd_proto import lightning_pb2
from rill_provider.lnd_payment_observation import LndProtocolError, LndUnavailableError

NETWORK = NetworkIdentity.model_validate(
    json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())[
        "contract_terms"
    ]["network_identity"]
)
PREIMAGE = "42" * 32
HASH = hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest()


class FakeRpcError(grpc.RpcError):
    def __init__(self, status: grpc.StatusCode) -> None:
        self.status = status

    def code(self) -> grpc.StatusCode:
        return self.status


class FakeChannel:
    def __init__(self, responses: list[Any] | BaseException) -> None:
        self.responses = responses
        self.calls: list[tuple[str, Any]] = []

    def unary_stream(self, method: str, **_kwargs: object) -> Any:  # noqa: ANN401
        def call(request: Any, **_kw: object) -> Any:  # noqa: ANN401
            self.calls.append((method, request))
            if isinstance(self.responses, BaseException):
                raise self.responses
            return iter(self.responses)

        return call

    def close(self) -> None:
        return


def _sender(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, responses: list[Any] | BaseException
) -> tuple[sender.RegtestLndPaymentSender, FakeChannel]:
    (tmp_path / "tls.cert").write_bytes(b"ROOT")
    macaroon = tmp_path / "pay.macaroon"
    macaroon.write_bytes(b"PAY")
    macaroon.chmod(0o600)
    channel = FakeChannel(responses)
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda **_: "TLS")
    monkeypatch.setattr(grpc, "secure_channel", lambda *_a, **_k: channel)
    return (
        sender.RegtestLndPaymentSender(
            host="127.0.0.1",
            port=10009,
            tls_certificate_path=tmp_path / "tls.cert",
            macaroon_path=macaroon,
            network=NETWORK,
        ),
        channel,
    )


def _payment(status: int, preimage: str = "") -> lightning_pb2.Payment:
    return lightning_pb2.Payment(
        payment_hash=HASH,
        status=status,  # type: ignore[arg-type]
        payment_preimage=preimage,
    )


def test_send_bounds_the_payment_and_returns_the_checked_preimage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [_payment(1), _payment(2, PREIMAGE)])
    outcome = client.send("lnbcrt1x", payment_hash=HASH, fee_limit_sat=10, cltv_limit=144)
    assert outcome == sender.PaymentOutcome("SUCCEEDED", PREIMAGE)
    ((method, request),) = channel.calls
    assert method == sender.SEND_METHOD
    assert (request.payment_request, request.fee_limit_sat, request.cltv_limit) == (
        "lnbcrt1x",
        10,
        144,
    )


def test_wrong_preimage_or_hash_is_a_protocol_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = _sender(tmp_path, monkeypatch, [_payment(2, "43" * 32)])
    with pytest.raises(LndProtocolError):
        client.track(HASH)
    other = lightning_pb2.Payment(payment_hash="00" * 32, status="FAILED")
    client, _ = _sender(tmp_path, monkeypatch, [other])
    with pytest.raises(LndProtocolError):
        client.track(HASH)


@pytest.mark.parametrize(
    ("method", "status", "expected"),
    [
        ("track", grpc.StatusCode.NOT_FOUND, sender.PaymentOutcome("UNKNOWN")),
        ("send", grpc.StatusCode.DEADLINE_EXCEEDED, sender.PaymentOutcome("IN_FLIGHT")),
        ("send", grpc.StatusCode.UNAVAILABLE, LndUnavailableError),
        ("track", grpc.StatusCode.DEADLINE_EXCEEDED, LndUnavailableError),
    ],
)
def test_errors_never_claim_absence_except_track_not_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    status: grpc.StatusCode,
    expected: object,
) -> None:
    client, _ = _sender(tmp_path, monkeypatch, FakeRpcError(status))

    def call() -> sender.PaymentOutcome:
        if method == "track":
            return client.track(HASH)
        return client.send("lnbcrt1x", payment_hash=HASH, fee_limit_sat=1, cltv_limit=40)

    if isinstance(expected, sender.PaymentOutcome):
        assert call() == expected
    else:
        with pytest.raises(expected):  # type: ignore[call-overload]
            call()


def test_failed_payment_is_terminal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _ = _sender(tmp_path, monkeypatch, [_payment(3)])
    assert client.track(HASH) == sender.PaymentOutcome("FAILED")
