"""LND DecodePayReq mapped onto RS-001 invoice bindings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import grpc
import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider import lnd_invoice_decode as decode
from rill_provider._lnd_proto import lightning_pb2
from rill_provider.lnd_payment_observation import (
    LndAuthError,
    LndProtocolError,
    LndUnavailableError,
)

NETWORK = NetworkIdentity.model_validate(
    json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())[
        "contract_terms"
    ]["network_identity"]
)
PAYEE = "02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
INVOICE = "lnbcrt500u1pexample"


def _payreq(**changes: Any) -> lightning_pb2.PayReq:  # noqa: ANN401
    fields: dict[str, Any] = {
        "destination": PAYEE,
        "payment_hash": "ab" * 32,
        "num_msat": 50_000_000,
        "timestamp": 1_700_000_000,
        "expiry": 3600,
        "cltv_expiry": 40,
        "payment_addr": b"s" * 32,
        "features": {8: {}, 14: {}, 17: {}, 25: {}},
    }
    return lightning_pb2.PayReq(**(fields | changes))


class FakeRpcError(grpc.RpcError):
    def __init__(self, status: grpc.StatusCode) -> None:
        self.status = status

    def code(self) -> grpc.StatusCode:
        return self.status


class FakeChannel:
    def __init__(self, response: object) -> None:
        self.response = response
        self.requests: list[lightning_pb2.PayReqString] = []
        self.closed = False

    def unary_unary(self, method: str, **_kwargs: object) -> Any:  # noqa: ANN401
        assert method == decode.DECODE_METHOD

        def call(request: lightning_pb2.PayReqString, **kwargs: object) -> object:
            assert kwargs["metadata"] == (("macaroon", b"READ".hex()),)
            self.requests.append(request)
            if isinstance(self.response, BaseException):
                raise self.response
            return self.response

        return call

    def close(self) -> None:
        self.closed = True


def _decoder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response: object) -> FakeChannel:
    (tmp_path / "tls.cert").write_bytes(b"ROOT")
    macaroon = tmp_path / "read.macaroon"
    macaroon.write_bytes(b"READ")
    macaroon.chmod(0o600)
    channel = FakeChannel(response)
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda **_: "TLS")
    monkeypatch.setattr(grpc, "secure_channel", lambda *_a, **_k: channel)
    decoder = decode.RegtestLndInvoiceDecoder(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=tmp_path / "tls.cert",
        macaroon_path=macaroon,
        network=NETWORK,
    )
    channel.decoder = decoder  # type: ignore[attr-defined]
    return channel


def test_decoded_invoice_becomes_exact_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    channel = _decoder(tmp_path, monkeypatch, _payreq())
    binding = channel.decoder.decode(INVOICE)  # type: ignore[attr-defined]
    assert binding.bolt11_sha256 == hashlib.sha256(INVOICE.encode()).hexdigest()
    assert binding.payment_hash == "ab" * 32
    assert binding.amount_msat == "50000000"
    assert binding.payee_compressed_pubkey == PAYEE
    assert (binding.created_at, binding.expires_at) == (1_700_000_000, 1_700_003_600)
    assert binding.min_final_cltv_delta == 40
    assert channel.requests[0].pay_req == INVOICE
    assert channel.closed


@pytest.mark.parametrize(
    "payreq",
    [
        _payreq(num_msat=0),
        _payreq(num_msat=50_000_001),
        _payreq(expiry=0),
        _payreq(cltv_expiry=0),
        _payreq(destination="02" + "11" * 32),
        _payreq(payment_hash="ab"),
        _payreq(payment_addr=b""),
        _payreq(payment_addr=b"s" * 31),
        _payreq(features={}),
        _payreq(features={8: {}, 9: {}, 14: {}}),
        _payreq(features={8: {}, 14: {}, 15: {}}),
        _payreq(features={8: {}, 14: {}, 16: {}}),
        _payreq(features={8: {}, 14: {}, 30: {}}),
        _payreq(features={8: {}, 14: {}, 31: {}}),
        _payreq(features={8: {}, 14: {}, 48: {}}),
        _payreq(features={8: {}, 14: {}, 49: {}}),
        _payreq(features={8: {}, 14: {}, 100: {}}),
        _payreq(features={8: {}, 14: {}, 101: {}}),
        _payreq(blinded_paths=[{}]),
    ],
)
def test_unbindable_invoices_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payreq: lightning_pb2.PayReq
) -> None:
    channel = _decoder(tmp_path, monkeypatch, payreq)
    with pytest.raises(decode.InvoiceRejectedError):
        channel.decoder.decode(INVOICE)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (grpc.StatusCode.UNKNOWN, decode.InvoiceRejectedError),
        (grpc.StatusCode.INVALID_ARGUMENT, decode.InvoiceRejectedError),
        (grpc.StatusCode.UNAVAILABLE, LndUnavailableError),
        (grpc.StatusCode.DEADLINE_EXCEEDED, LndUnavailableError),
        (grpc.StatusCode.PERMISSION_DENIED, LndAuthError),
        (grpc.StatusCode.INTERNAL, LndProtocolError),
        (grpc.StatusCode.UNIMPLEMENTED, LndProtocolError),
    ],
)
def test_rpc_failures_distinguish_rejection_from_unavailability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: grpc.StatusCode, error: type
) -> None:
    channel = _decoder(tmp_path, monkeypatch, FakeRpcError(status))
    with pytest.raises(error):
        channel.decoder.decode(INVOICE)  # type: ignore[attr-defined]
    assert channel.closed


def test_only_loopback_regtest_is_configurable(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="loopback"):
        decode.RegtestLndInvoiceDecoder(
            host="10.0.0.1",
            port=10009,
            tls_certificate_path=tmp_path,
            macaroon_path=tmp_path,
            network=NETWORK,
        )
    with pytest.raises(ValueError, match="regtest"):
        decode.RegtestLndInvoiceDecoder(
            host="127.0.0.1",
            port=10009,
            tls_certificate_path=tmp_path,
            macaroon_path=tmp_path,
            network=NETWORK.model_copy(update={"name": "mainnet"}),
        )


@pytest.mark.parametrize("invoice", ["lnbc500u1pexample", "lntb500u1pexample", "lnbcrt", ""])
def test_invoices_for_other_networks_never_reach_lnd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invoice: str
) -> None:
    channel = _decoder(tmp_path, monkeypatch, _payreq())
    with pytest.raises(decode.InvoiceRejectedError):
        channel.decoder.decode(invoice)  # type: ignore[attr-defined]
    assert channel.requests == []
