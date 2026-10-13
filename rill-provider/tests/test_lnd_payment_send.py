"""Exact absolute-expiry routes, one-shot dispatch, and hash reconciliation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import grpc
import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider import lnd_payment_send as sender
from rill_provider._lnd_proto import lightning_pb2
from rill_provider.lnd_invoice_decode import binding_from_payreq
from rill_provider.lnd_payment_observation import LndProtocolError, LndUnavailableError

NETWORK = NetworkIdentity.model_validate(
    json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())[
        "contract_terms"
    ]["network_identity"]
)
PREIMAGE = "42" * 32
HASH = hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest()
INVOICE = "lnbcrt500u1pexample"
PAYEE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
NOW = 1_700_000_010
PAYER = "03" + "ab" * 32
AMOUNT_MSAT = 50_000_000


def _payreq() -> lightning_pb2.PayReq:
    return lightning_pb2.PayReq(
        destination=PAYEE,
        payment_hash=HASH,
        num_msat=AMOUNT_MSAT,
        timestamp=NOW - 10,
        expiry=3600,
        cltv_expiry=40,
        payment_addr=b"s" * 32,
        features={8: {}, 14: {}, 17: {}, 25: {}},
        route_hints=[{"hop_hints": [{"node_id": PAYEE, "chan_id": 123}]}],
    )


def _info(height: int = 1000) -> lightning_pb2.GetInfoResponse:
    return lightning_pb2.GetInfoResponse(
        block_height=height,
        synced_to_chain=True,
        chains=[{"chain": "bitcoin", "network": "regtest"}],
        identity_pubkey=PAYER,
    )


def _route() -> lightning_pb2.Route:
    return lightning_pb2.Route(
        total_time_lock=1050,
        total_fees_msat=1000,
        total_amt_msat=AMOUNT_MSAT + 1000,
        hops=[
            {
                "pub_key": PAYEE,
                "amt_to_forward_msat": AMOUNT_MSAT,
                "fee_msat": 1000,
                "expiry": 1043,
            },
            {"pub_key": PAYEE, "amt_to_forward_msat": AMOUNT_MSAT, "expiry": 1043},
        ],
    )


class FakeRpcError(grpc.RpcError):
    def __init__(self, status: grpc.StatusCode) -> None:
        self.status = status

    def code(self) -> grpc.StatusCode:
        return self.status


class FakeChannel:
    def __init__(self, responses: list[Any] | BaseException) -> None:
        self.responses = responses
        self.calls: list[tuple[str, Any]] = []
        self.unary_responses: dict[str, object] = {
            sender.DECODE_METHOD: _payreq(),
            sender.INFO_METHOD: _info(),
            sender.QUERY_METHOD: lightning_pb2.QueryRoutesResponse(routes=[_route()]),
            sender.SEND_METHOD: lightning_pb2.HTLCAttempt(
                status="SUCCEEDED", preimage=bytes.fromhex(PREIMAGE)
            ),
        }
        self.closed = False

    def unary_unary(self, method: str, **_kwargs: object) -> Any:  # noqa: ANN401
        def call(request: Any, **kwargs: Any) -> object:  # noqa: ANN401
            assert kwargs["wait_for_ready"] is False
            assert 0 < kwargs["timeout"] <= 60
            self.calls.append((method, request))
            response = self.unary_responses[method]
            if callable(response):
                response = response()
            if isinstance(response, BaseException):
                raise response
            return response

        return call

    def unary_stream(self, method: str, **_kwargs: object) -> Any:  # noqa: ANN401
        def call(request: Any, **_kw: object) -> Any:  # noqa: ANN401
            self.calls.append((method, request))
            if isinstance(self.responses, BaseException):
                raise self.responses
            return iter(self.responses)

        return call

    def close(self) -> None:
        self.closed = True


def _sender(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, responses: list[Any] | BaseException
) -> tuple[sender.LndPaymentSender, FakeChannel]:
    (tmp_path / "tls.cert").write_bytes(b"ROOT")
    macaroon = tmp_path / "pay.macaroon"
    macaroon.write_bytes(b"PAY")
    macaroon.chmod(0o600)
    channel = FakeChannel(responses)
    monkeypatch.setattr(sender.time, "time", lambda: NOW)
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda **_: "TLS")
    monkeypatch.setattr(grpc, "secure_channel", lambda *_a, **_k: channel)
    return (
        sender.LndPaymentSender(
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
    invoice = binding_from_payreq(INVOICE, _payreq())
    payment = client.prepare(
        INVOICE, invoice_binding=invoice, fee_limit_sat=10, max_expiry_height=1070
    )
    assert not any(method == sender.SEND_METHOD for method, _ in channel.calls)
    outcome = client.send(payment)
    assert outcome == sender.PaymentOutcome("SUCCEEDED", PREIMAGE)
    (query,) = [r for m, r in channel.calls if m == sender.QUERY_METHOD]
    assert query.amt_msat == AMOUNT_MSAT
    assert query.fee_limit.fixed_msat == 10_000
    assert query.final_cltv_delta == 43
    assert query.cltv_limit == 70
    assert query.route_hints == _payreq().route_hints
    assert set(query.dest_features) == {8, 14, 17, 25}
    (request,) = [r for m, r in channel.calls if m == sender.SEND_METHOD]
    assert request.SerializeToString() == payment.request
    assert request.payment_hash.hex() == HASH
    assert request.route.total_time_lock == 1050
    assert not request.skip_temp_err
    assert request.route.hops[-1].mpp_record.payment_addr == b"s" * 32
    assert request.route.hops[-1].mpp_record.total_amt_msat == AMOUNT_MSAT
    assert all(hop.tlv_payload for hop in request.route.hops)
    assert not request.route.hops[0].HasField("mpp_record")


def test_post_submit_sync_failure_is_not_a_retryable_pre_submit_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = client.prepare(
        INVOICE,
        invoice_binding=binding_from_payreq(INVOICE, _payreq()),
        fee_limit_sat=10,
        max_expiry_height=1070,
    )
    channel.unary_responses[sender.SEND_METHOD] = lightning_pb2.HTLCAttempt(status="FAILED")
    infos = iter(
        [
            _info(),
            lightning_pb2.GetInfoResponse(
                block_height=1000,
                synced_to_chain=False,
                chains=[{"chain": "bitcoin", "network": "regtest"}],
                identity_pubkey=PAYER,
            ),
        ]
    )
    channel.unary_responses[sender.INFO_METHOD] = lambda: next(infos)
    with pytest.raises(LndUnavailableError, match="after submission"):
        client.send(payment)
    assert sum(method == sender.SEND_METHOD for method, _ in channel.calls) == 1


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
        ("send", grpc.StatusCode.DEADLINE_EXCEEDED, LndUnavailableError),
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
    client, channel = _sender(tmp_path, monkeypatch, FakeRpcError(status))
    payment = client.prepare(
        INVOICE,
        invoice_binding=binding_from_payreq(INVOICE, _payreq()),
        fee_limit_sat=1,
        max_expiry_height=1070,
    )
    channel.unary_responses[sender.SEND_METHOD] = FakeRpcError(status)

    def call() -> sender.PaymentOutcome:
        if method == "track":
            return client.track(HASH)
        return client.send(payment)

    if isinstance(expected, sender.PaymentOutcome):
        assert call() == expected
    else:
        with pytest.raises(expected):  # type: ignore[call-overload]
            call()


def test_failed_payment_is_terminal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _ = _sender(tmp_path, monkeypatch, [_payment(3)])
    assert client.track(HASH) == sender.PaymentOutcome("FAILED")


def _prepare(client: sender.LndPaymentSender) -> sender.PreparedPayment:
    return client.prepare(
        INVOICE,
        invoice_binding=binding_from_payreq(INVOICE, _payreq()),
        fee_limit_sat=10,
        max_expiry_height=1070,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("total_time_lock", 1071),
        ("total_time_lock", 1000),
        ("total_fees_msat", 10_001),
        ("total_fees_msat", -1),
        ("total_amt_msat", AMOUNT_MSAT),
        ("first_hop_amount_msat", AMOUNT_MSAT + 10_001),
    ],
)
def test_route_bounds_are_checked_not_just_requested(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    route = _route()
    setattr(route, field, value)
    channel.unary_responses[sender.QUERY_METHOD] = lightning_pb2.QueryRoutesResponse(routes=[route])
    with pytest.raises(LndProtocolError):
        _prepare(client)
    assert all(method != sender.SEND_METHOD for method, _ in channel.calls)


@pytest.mark.parametrize(
    "case",
    [
        "empty",
        "many",
        "amount",
        "destination",
        "expiry",
        "amp",
        "mpp",
        "custom",
        "metadata",
        "blinded",
    ],
)
def test_unsupported_route_payloads_never_get_a_dispatch_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    route = _route()
    if case == "empty":
        route.ClearField("hops")
    elif case == "many":
        for _ in range(20):
            route.hops.add().CopyFrom(route.hops[-1])
    elif case == "amount":
        route.hops[-1].amt_to_forward_msat += 1
    elif case == "destination":
        route.hops[-1].pub_key = "03" + "11" * 32
    elif case == "expiry":
        route.hops[-1].expiry = 1051
    elif case == "amp":
        route.hops[-1].amp_record.root_share = b"x" * 32
    elif case == "mpp":
        route.hops[0].mpp_record.payment_addr = b"x" * 32
    elif case == "custom":
        route.hops[-1].custom_records[100_000] = b"x"
    elif case == "metadata":
        route.hops[-1].metadata = b"x"
    else:
        route.hops[-1].blinding_point = b"x" * 33
    channel.unary_responses[sender.QUERY_METHOD] = lightning_pb2.QueryRoutesResponse(routes=[route])
    with pytest.raises(LndProtocolError):
        _prepare(client)
    assert all(method != sender.SEND_METHOD for method, _ in channel.calls)


def test_new_blocks_and_core_lnd_height_mismatch_cannot_raise_absolute_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    # Core's caller used height 1000. LND is ahead, then advances during query.
    channel.unary_responses[sender.INFO_METHOD] = _info(1005)
    route = _route()
    route.total_time_lock = 1070
    for hop in route.hops:
        hop.expiry = 1048
    channel.unary_responses[sender.QUERY_METHOD] = lightning_pb2.QueryRoutesResponse(routes=[route])
    payment = _prepare(client)
    channel.unary_responses[sender.INFO_METHOD] = _info(1006)
    assert client.send(payment).status == "SUCCEEDED"
    (query,) = [r for m, r in channel.calls if m == sender.QUERY_METHOD]
    (request,) = [r for m, r in channel.calls if m == sender.SEND_METHOD]
    assert query.cltv_limit == 65
    assert request.route.total_time_lock == 1070
    assert request.SerializeToString() == payment.request


@pytest.mark.parametrize("case", ["invoice", "route", "final_cltv", "sync", "network", "chain"])
def test_submission_rechecks_expiry_sync_and_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    info = _info()
    if case == "invoice":
        monkeypatch.setattr(sender.time, "time", lambda: payment.expires_at)
    elif case == "route":
        info.block_height = 1050
    elif case == "final_cltv":
        info.block_height = 1042
    elif case == "sync":
        info.synced_to_chain = False
    elif case == "network":
        info.chains[0].network = "mainnet"
    else:
        info.chains[0].chain = "litecoin"
    channel.unary_responses[sender.INFO_METHOD] = info
    with pytest.raises(LndProtocolError):
        client.send(payment)
    assert all(method != sender.SEND_METHOD for method, _ in channel.calls)


def test_expiry_during_final_rpc_setup_prevents_submission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    original = channel.unary_unary

    def delayed_setup(method: str, **kwargs: object) -> Any:  # noqa: ANN401
        if method == sender.SEND_METHOD:
            monkeypatch.setattr(sender.time, "time", lambda: payment.expires_at)
        return original(method, **kwargs)

    monkeypatch.setattr(channel, "unary_unary", delayed_setup)
    with pytest.raises(LndUnavailableError, match="deadline elapsed"):
        client.send(payment)
    assert all(method != sender.SEND_METHOD for method, _ in channel.calls)


def test_query_must_match_signed_invoice_before_preparing_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payreq = _payreq()
    payreq.num_msat += 1000
    channel.unary_responses[sender.DECODE_METHOD] = payreq
    with pytest.raises(LndProtocolError, match="signed binding"):
        _prepare(client)
    assert all(
        method not in (sender.QUERY_METHOD, sender.SEND_METHOD) for method, _ in channel.calls
    )


def test_prepared_bytes_cannot_bypass_expiry_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    with pytest.raises(LndProtocolError):
        client.send(replace(payment, max_expiry_height=1049))
    assert all(method != sender.SEND_METHOD for method, _ in channel.calls)


@pytest.mark.parametrize(
    "status",
    [grpc.StatusCode.NOT_FOUND, grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED],
)
def test_ambiguous_submission_is_not_absence_and_never_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: grpc.StatusCode,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    channel.unary_responses[sender.SEND_METHOD] = FakeRpcError(status)
    with pytest.raises(LndUnavailableError):
        client.send(payment)
    assert len([1 for method, _ in channel.calls if method == sender.SEND_METHOD]) == 1
    assert channel.closed


def test_failed_attempt_reconciles_payment_level_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [_payment(1)])
    payment = _prepare(client)
    channel.unary_responses[sender.SEND_METHOD] = lightning_pb2.HTLCAttempt(status="FAILED")
    assert client.send(payment) == sender.PaymentOutcome("IN_FLIGHT", payer=PAYER)
    assert channel.calls[-1][0] == sender.TRACK_METHOD


def test_successful_attempt_still_requires_hash_preimage_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    channel.unary_responses[sender.SEND_METHOD] = lightning_pb2.HTLCAttempt(
        status="SUCCEEDED", preimage=b"x" * 32
    )
    with pytest.raises(LndProtocolError, match="preimage"):
        client.send(payment)


def test_current_tracking_reports_a_held_payment_in_flight_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [_payment(1), _payment(2, PREIMAGE)])
    assert client.track(HASH, current=True) == sender.PaymentOutcome("IN_FLIGHT")
    method, request = channel.calls[-1][:2]
    assert method == sender.TRACK_METHOD
    assert request.no_inflight_updates is False
    client, channel = _sender(tmp_path, monkeypatch, [_payment(1), _payment(2, PREIMAGE)])
    assert client.track(HASH) == sender.PaymentOutcome("SUCCEEDED", PREIMAGE)
    assert channel.calls[-1][1].no_inflight_updates is True
