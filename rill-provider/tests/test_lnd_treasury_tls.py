"""Actual loopback TLS/gRPC codec, synthetic server (not LND macaroon conformance)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import grpc
import pytest
from test_lnd_payment_tls import OPENSSL, _certificate
from test_lnd_treasury_observation import HASH, NETWORK, NODE, channel, info, payment

from rill_provider._lnd_proto import lightning_pb2 as pb
from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_treasury_observation import LndTreasuryObservationError, LndTreasuryObserver

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.mark.skipif(OPENSSL is None, reason="openssl required for synthetic TLS test")
@pytest.mark.parametrize(
    "fault", ["none", "wrong_root", "wrong_metadata", "wrong_node", "oversized_response"]
)
def test_real_tls_source_identity_metadata_and_private_projection(
    tmp_path: Path, fault: str
) -> None:
    certificate, key = _certificate(tmp_path)
    macaroon = tmp_path / "test-read.mac"
    macaroon.write_bytes(b"synthetic-secret-credential")
    macaroon.chmod(0o600)
    events: list[str] = []

    def authorize(context: grpc.ServicerContext, method: str) -> None:
        if (
            dict(context.invocation_metadata()).get("macaroon")
            != b"synthetic-secret-credential".hex()
        ):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "SECRET_CANARY")
        events.append(method)

    def get_info(_request: pb.GetInfoRequest, context: grpc.ServicerContext) -> pb.GetInfoResponse:
        authorize(context, "info")
        result = info()
        if fault == "wrong_node":
            result.identity_pubkey = "03" + NODE[2:]
        return result

    def list_channels(
        _request: pb.ListChannelsRequest, context: grpc.ServicerContext
    ) -> pb.ListChannelsResponse:
        authorize(context, "channels")
        if fault == "oversized_response":
            return pb.ListChannelsResponse(channels=[channel(custom_channel_data=b"x" * 262144)])
        return pb.ListChannelsResponse(channels=[channel()])

    def track(
        request: router_pb2.TrackPaymentRequest, context: grpc.ServicerContext
    ) -> Iterator[pb.Payment]:
        authorize(context, "track")
        assert request.payment_hash.hex() == HASH
        yield payment()

    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers(
        (
            grpc.method_handlers_generic_handler(
                "lnrpc.Lightning",
                {
                    "GetInfo": grpc.unary_unary_rpc_method_handler(
                        get_info,
                        request_deserializer=pb.GetInfoRequest.FromString,
                        response_serializer=pb.GetInfoResponse.SerializeToString,
                    ),
                    "ListChannels": grpc.unary_unary_rpc_method_handler(
                        list_channels,
                        request_deserializer=pb.ListChannelsRequest.FromString,
                        response_serializer=pb.ListChannelsResponse.SerializeToString,
                    ),
                },
            ),
            grpc.method_handlers_generic_handler(
                "routerrpc.Router",
                {
                    "TrackPaymentV2": grpc.unary_stream_rpc_method_handler(
                        track,
                        request_deserializer=router_pb2.TrackPaymentRequest.FromString,
                        response_serializer=pb.Payment.SerializeToString,
                    ),
                },
            ),
        )
    )
    port = server.add_secure_port(
        "127.0.0.1:0", grpc.ssl_server_credentials(((key, certificate.read_bytes()),))
    )
    assert port > 0
    server.start()
    try:
        if fault == "wrong_root":
            other = tmp_path / "other"
            other.mkdir(mode=0o700)
            certificate, _unused_key = _certificate(other)
        if fault == "wrong_metadata":
            macaroon.write_bytes(b"invalid-test-credential")
        observer = LndTreasuryObserver(
            host="127.0.0.1",
            port=port,
            tls_certificate_path=certificate,
            read_macaroon_path=macaroon,
            network=NETWORK,
            expected_node_pubkey=NODE,
        )
        if fault == "none":
            result = observer.observe_accounting(deadline_seconds=2)
            paid = observer.observe_completed_payment(HASH, 20000000, deadline_seconds=2)
            assert result.coverage_complete
            assert paid.routing_fee_msat == 1234
            assert "SECRET_CANARY" not in repr(result) + repr(paid)
            assert events == ["info", "channels", "info", "info", "track", "info"]
        else:
            with pytest.raises(LndTreasuryObservationError) as error:
                observer.observe_accounting(deadline_seconds=0.5)
            assert error.value.__context__ is None
            assert error.value.__cause__ is None
            assert "SECRET_CANARY" not in str(error.value)
    finally:
        assert server.stop(0).wait(timeout=3)
