"""Hold invoice adapter: exact requests, accepted-part summaries, redacted errors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import grpc
import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider import lnd_hold_invoice as hold
from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2
from rill_provider.lnd_payment_observation import LndAuthError, LndProtocolError

NETWORK = NetworkIdentity.model_validate(
    json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())[
        "contract_terms"
    ]["network_identity"]
)
HASH = "ab" * 32


class FakeRpcError(grpc.RpcError):
    def __init__(self, status: grpc.StatusCode) -> None:
        self.status = status

    def code(self) -> grpc.StatusCode:
        return self.status


class FakeChannel:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[tuple[str, Any]] = []
        self.closed = False

    def unary_unary(self, method: str, **_kwargs: object) -> Any:  # noqa: ANN401
        def call(request: Any, **kwargs: object) -> object:  # noqa: ANN401
            assert kwargs["metadata"] == (("macaroon", b"INVOICES".hex()),)
            self.calls.append((method, request))
            if isinstance(self.response, BaseException):
                raise self.response
            return self.response

        return call

    def close(self) -> None:
        self.closed = True


def _client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response: object
) -> tuple[hold.LndHoldInvoices, FakeChannel]:
    (tmp_path / "tls.cert").write_bytes(b"ROOT")
    macaroon = tmp_path / "invoices.macaroon"
    macaroon.write_bytes(b"INVOICES")
    macaroon.chmod(0o600)
    channel = FakeChannel(response)
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda **_: "TLS")
    monkeypatch.setattr(grpc, "secure_channel", lambda *_a, **_k: channel)
    client = hold.LndHoldInvoices(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=tmp_path / "tls.cert",
        macaroon_path=macaroon,
        network=NETWORK,
    )
    return client, channel


def test_add_sends_exact_hold_parameters_and_returns_the_invoice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _client(
        tmp_path, monkeypatch, invoices_pb2.AddHoldInvoiceResp(payment_request="lnbcrt1")
    )
    bolt11 = client.add(HASH, value_msat=102_000_000, expiry_seconds=1800, cltv_expiry_delta=150)
    assert bolt11 == "lnbcrt1"
    method, request = channel.calls[0]
    assert method == hold.ADD_METHOD
    assert request == invoices_pb2.AddHoldInvoiceRequest(
        hash=bytes.fromhex(HASH), value_msat=102_000_000, expiry=1800, cltv_expiry=150
    )
    assert channel.closed
    for bad in (
        {"value_msat": 1500},
        {"value_msat": 0},
        {"expiry_seconds": 0},
        {"cltv_expiry_delta": hold.MAX_CLTV_DELTA + 1},
    ):
        params: dict[str, Any] = {
            "value_msat": 1000,
            "expiry_seconds": 60,
            "cltv_expiry_delta": 10,
            **bad,
        }
        with pytest.raises(ValueError, match="unsupported"):
            client.add(HASH, **params)
    with pytest.raises(ValueError, match="32 bytes"):
        client.add("zz", value_msat=1000, expiry_seconds=60, cltv_expiry_delta=10)


def test_lookup_summarizes_only_accepted_parts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invoice = lightning_pb2.Invoice(
        state=lightning_pb2.Invoice.ACCEPTED,
        htlcs=[
            lightning_pb2.InvoiceHTLC(
                amt_msat=60_000_000, expiry_height=1180, state=lightning_pb2.ACCEPTED
            ),
            lightning_pb2.InvoiceHTLC(
                amt_msat=42_000_000, expiry_height=1150, state=lightning_pb2.ACCEPTED
            ),
            lightning_pb2.InvoiceHTLC(
                amt_msat=5_000_000, expiry_height=1100, state=lightning_pb2.CANCELED
            ),
        ],
    )
    client, channel = _client(tmp_path, monkeypatch, invoice)
    status = client.lookup(HASH)
    assert channel.calls[0] == (
        hold.LOOKUP_METHOD,
        invoices_pb2.LookupInvoiceMsg(payment_hash=bytes.fromhex(HASH)),
    )
    assert status.state == "ACCEPTED"
    assert status.held_msat == 102_000_000
    assert status.earliest_expiry_height == 1150
    open_status = hold.HoldInvoiceStatus(state="OPEN", htlcs=())
    assert open_status.held_msat == 0
    assert open_status.earliest_expiry_height is None


def test_settle_and_cancel_send_exact_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _client(tmp_path, monkeypatch, invoices_pb2.SettleInvoiceResp())
    client.settle("cd" * 32)
    client.cancel(HASH)
    assert channel.calls == [
        (hold.SETTLE_METHOD, invoices_pb2.SettleInvoiceMsg(preimage=bytes.fromhex("cd" * 32))),
        (hold.CANCEL_METHOD, invoices_pb2.CancelInvoiceMsg(payment_hash=bytes.fromhex(HASH))),
    ]


def test_failures_are_redacted_and_classified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = _client(tmp_path, monkeypatch, FakeRpcError(grpc.StatusCode.PERMISSION_DENIED))
    with pytest.raises(LndAuthError):
        client.cancel(HASH)
    client, _ = _client(tmp_path, monkeypatch, invoices_pb2.AddHoldInvoiceResp())
    with pytest.raises(LndProtocolError, match="no hold invoice"):
        client.add(HASH, value_msat=1000, expiry_seconds=60, cltv_expiry_delta=10)
    odd = lightning_pb2.Invoice(state=7)  # type: ignore[arg-type]
    client, _ = _client(tmp_path, monkeypatch, odd)
    with pytest.raises(LndProtocolError, match="unknown invoice state"):
        client.lookup(HASH)
    with pytest.raises(ValueError, match="loopback"):
        hold.LndHoldInvoices(
            host="10.0.0.1",
            port=1,
            tls_certificate_path=tmp_path,
            macaroon_path=tmp_path,
            network=NETWORK,
        )
