"""Read-only synthetic LND invoice observations, never funding policy."""

from __future__ import annotations

import json
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

import grpc
import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider import lnd_invoice_observation as observer
from rill_provider._lnd_proto import lightning_pb2
from rill_provider.lnd_payment_observation import (
    LndAuthError,
    LndProtocolError,
    LndUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

HASH = b"\xaa" * 32
NETWORK = NetworkIdentity.model_validate(
    json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())[
        "contract_terms"
    ]["network_identity"]
)


def _invoice(state: int = 3) -> lightning_pb2.Invoice:
    return lightning_pb2.Invoice(
        r_hash=HASH,
        state=state,
        value_msat=3000,
        amt_paid_msat=3000,
        creation_date=123,
        expiry=3600,
        cltv_expiry=40,
        htlcs=[
            lightning_pb2.InvoiceHTLC(
                chan_id=1,
                htlc_index=0,
                state=0,
                amt_msat=1000,
                accept_height=120,
                expiry_height=160,
                mpp_total_amt_msat=3000,
            ),
            lightning_pb2.InvoiceHTLC(
                chan_id=2,
                htlc_index=0,
                state=0,
                amt_msat=2000,
                accept_height=121,
                expiry_height=150,
                mpp_total_amt_msat=3000,
                custom_records={9: b"PRIVATE-RECORD"},
            ),
        ],
    )


class FakeChannel:
    def __init__(self, response: object) -> None:
        self.response = response
        self.methods: list[str] = []
        self.calls: list[tuple[lightning_pb2.PaymentHash, dict[str, object]]] = []
        self.closed = False

    def unary_unary(
        self,
        method: str,
        *,
        request_serializer: Callable[[lightning_pb2.PaymentHash], bytes],
        response_deserializer: Callable[[bytes], lightning_pb2.Invoice],
    ) -> Callable[..., object]:
        self.methods.append(method)

        def call(request: lightning_pb2.PaymentHash, **kwargs: object) -> object:
            assert lightning_pb2.PaymentHash.FromString(request_serializer(request)) == request
            assert isinstance(
                response_deserializer(_invoice().SerializeToString()),
                lightning_pb2.Invoice,
            )
            self.calls.append((request, kwargs))
            if isinstance(self.response, BaseException):
                raise self.response
            return self.response

        return call

    def close(self) -> None:
        self.closed = True


class FakeRpcError(grpc.RpcError):
    def __init__(self, status: grpc.StatusCode) -> None:
        self.status = status

    def code(self) -> grpc.StatusCode:
        return self.status

    def __str__(self) -> str:
        return "PRIVATE-INVOICE-PREIMAGE"


def _client(tmp_path: Path) -> observer.LndInvoiceObserver:
    (tmp_path / "tls.cert").write_bytes(b"FAKE-ROOT")
    macaroon = tmp_path / "invoice.macaroon"
    macaroon.write_bytes(b"INVOICE-READ-SECRET")
    macaroon.chmod(0o600)
    return observer.LndInvoiceObserver(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=tmp_path / "tls.cert",
        invoice_macaroon_path=macaroon,
        network=NETWORK,
    )


def _transport(
    monkeypatch: pytest.MonkeyPatch,
    response: object,
) -> tuple[FakeChannel, list[object]]:
    channel = FakeChannel(response)
    evidence: list[object] = []

    def ssl(*, root_certificates: bytes) -> str:
        evidence.append(root_certificates)
        return "TLS-ROOT"

    def secure(target: str, credentials: object, *, options: object) -> FakeChannel:
        evidence.append((target, credentials, options))
        return channel

    monkeypatch.setattr(observer.grpc, "ssl_channel_credentials", ssl)
    monkeypatch.setattr(observer.grpc, "secure_channel", secure)
    return channel, evidence


def test_construction_and_invalid_request_are_inert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(observer, "_read_file", lambda *_args, **_kw: pytest.fail("read"))
    monkeypatch.setattr(observer.grpc, "secure_channel", lambda *_args, **_kw: pytest.fail("dial"))
    client = observer.LndInvoiceObserver(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=tmp_path / "absent",
        invoice_macaroon_path=tmp_path / "missing",
        network=NETWORK,
    )
    for invalid in (b"", b"a" * 31, b"a" * 33, bytearray(HASH)):
        with pytest.raises(ValueError, match="32 bytes"):
            client.lookup(invalid)  # type: ignore[arg-type]
    for invalid in (0, -1, 31, float("nan"), True):
        with pytest.raises(ValueError, match="deadline"):
            client.lookup(HASH, deadline_seconds=invalid)


def test_full_mpp_and_history_are_reported_but_not_authorizing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _invoice()
    response.r_preimage = b"PRIVATE-INVOICE-PREIMAGE"
    response.htlcs[0].state = lightning_pb2.InvoiceHTLCState.CANCELED
    response.htlcs[0].amt_msat = 0
    response.htlcs[1].expiry_height = 0
    channel, evidence = _transport(monkeypatch, response)
    result = _client(tmp_path).lookup(HASH, deadline_seconds=3)
    assert result.payment_hash == HASH.hex()
    assert result.state == "ACCEPTED"
    assert result.value_msat == result.amount_paid_msat == 3000
    assert result.invoice_expiry_seconds == 3600
    assert [(p.channel_id, p.htlc_index) for p in result.htlcs] == [(1, 0), (2, 0)]
    assert [p.state for p in result.htlcs] == ["CANCELED", "ACCEPTED"]
    assert [p.amount_msat for p in result.htlcs] == [0, 2000]
    assert [p.expiry_height for p in result.htlcs] == [160, 0]
    assert [p.mpp_total_msat for p in result.htlcs] == [3000, 3000]
    assert channel.methods == [observer.LOOKUP_METHOD]
    assert channel.calls[0][0].r_hash == HASH
    assert not channel.calls[0][0].r_hash_str
    assert channel.calls[0][1] == {
        "timeout": 3,
        "metadata": (("macaroon", b"INVOICE-READ-SECRET".hex()),),
        "wait_for_ready": False,
    }
    assert evidence[0] == b"FAKE-ROOT"
    assert ("grpc.enable_retries", 0) in evidence[1][2]
    assert channel.closed
    assert "PRIVATE" not in repr(result)


@pytest.mark.parametrize("state", [0, 1, 2, 3])
def test_invoice_status_never_becomes_permission_to_fund(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: int,
) -> None:
    channel, _ = _transport(monkeypatch, _invoice(state))
    result = _client(tmp_path).lookup(HASH)
    assert result.state == observer.INVOICE_STATES[state]
    assert result.htlcs[0].htlc_index == 0
    assert channel.closed


def test_default_partial_and_inconsistent_observations_are_not_normalized_to_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = lightning_pb2.Invoice(r_hash=HASH)
    channel, _ = _transport(monkeypatch, response)
    empty = _client(tmp_path).lookup(HASH)
    assert empty.state == "OPEN"
    assert empty.value_sat == empty.value_msat == empty.amount_paid_msat == 0
    assert empty.creation_time == empty.invoice_expiry_seconds == empty.final_cltv_delta == 0
    assert empty.htlcs == ()
    assert channel.closed

    response = _invoice()
    response.value = 2
    response.value_msat = 3000  # Deliberately inconsistent backend fields.
    response.amt_paid_msat = 4000
    response.htlcs[0].mpp_total_amt_msat = 0
    response.htlcs[0].accept_height = -5
    response.htlcs[0].expiry_height = -1
    response.htlcs[1].state = lightning_pb2.InvoiceHTLCState.SETTLED
    channel, _ = _transport(monkeypatch, response)
    observed = _client(tmp_path).lookup(HASH)
    assert (observed.value_sat, observed.value_msat, observed.amount_paid_msat) == (2, 3000, 4000)
    assert (observed.htlcs[0].mpp_total_msat, observed.htlcs[1].mpp_total_msat) == (0, 3000)
    assert (observed.htlcs[0].accepted_height, observed.htlcs[0].expiry_height) == (-5, -1)
    assert observed.htlcs[1].state == "SETTLED"
    assert channel.closed


@pytest.mark.parametrize(
    "change",
    [
        "wrong-hash",
        "unknown-state",
        "too-many-parts",
        "duplicate-pair",
        "unknown-part",
        "amp-invoice",
        "amp-part",
        "keysend",
        "blinded",
        "custom-channel",
        "amp-state-map",
    ],
)
def test_malformed_or_unsupported_invoice_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    response = _invoice()
    if change == "wrong-hash":
        response.r_hash = b"\xbb" * 32
    elif change == "unknown-state":
        response.state = 9
    elif change == "too-many-parts":
        for index in range(observer.MAX_HTLCS):
            response.htlcs.add(chan_id=3, htlc_index=index)
    elif change == "duplicate-pair":
        response.htlcs[1].chan_id = 1
    elif change == "unknown-part":
        response.htlcs[1].state = 99
    elif change == "amp-invoice":
        response.is_amp = True
    elif change == "amp-part":
        response.htlcs[1].amp.set_id = b"a" * 32
    elif change == "blinded":
        response.is_blinded = True
    elif change == "custom-channel":
        response.htlcs[1].custom_channel_data = b"unsupported"
    elif change == "amp-state-map":
        response.amp_invoice_state["part"].amt_paid_msat = 1
    else:
        response.is_keysend = True
    channel, _ = _transport(monkeypatch, response)
    with pytest.raises(LndProtocolError) as caught:
        _client(tmp_path).lookup(HASH)
    assert caught.value.__context__ is None
    assert channel.closed


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (grpc.StatusCode.NOT_FOUND, LndUnavailableError),
        (grpc.StatusCode.DEADLINE_EXCEEDED, LndUnavailableError),
        (grpc.StatusCode.UNKNOWN, LndUnavailableError),
        (grpc.StatusCode.UNAUTHENTICATED, LndAuthError),
        (grpc.StatusCode.PERMISSION_DENIED, LndAuthError),
    ],
)
def test_missing_unavailable_and_denied_are_not_absence_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: grpc.StatusCode,
    error_type: type[Exception],
) -> None:
    channel, _ = _transport(monkeypatch, FakeRpcError(status))
    with pytest.raises(error_type) as caught:
        _client(tmp_path).lookup(HASH)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert "PRIVATE" not in "".join(traceback.format_exception(caught.value))
    assert len(channel.calls) == 1
    assert channel.closed


def test_missing_or_insecure_macaroon_does_not_call_lnd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel, _ = _transport(monkeypatch, _invoice())
    client = _client(tmp_path)
    secret = tmp_path / "invoice.macaroon"
    secret.chmod(0o644)
    with pytest.raises(LndAuthError):
        client.lookup(HASH)
    secret.unlink()
    secret.symlink_to(tmp_path / "tls.cert")
    with pytest.raises(LndAuthError):
        client.lookup(HASH)
    assert channel.methods == []
