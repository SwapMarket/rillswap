"""Synthetic least-privilege GetInfo boundary, not LND network attestation."""

from __future__ import annotations

import json
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

import grpc
import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider import lnd_payment_observation as observer
from rill_provider._lnd_proto import lightning_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

KEY = "02" + "ab" * 32  # Syntactically compressed; never used for cryptography.
NETWORK = NetworkIdentity.model_validate(
    json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())[
        "contract_terms"
    ]["network_identity"]
)


class FakeChannel:
    def __init__(self, response: object) -> None:
        self.response = response
        self.closed = False
        self.methods: list[str] = []
        self.calls: list[tuple[object, dict[str, object]]] = []

    def unary_unary(
        self,
        method: str,
        *,
        request_serializer: Callable[[lightning_pb2.GetInfoRequest], bytes],
        response_deserializer: Callable[[bytes], lightning_pb2.GetInfoResponse],
    ) -> Callable[..., object]:
        self.methods.append(method)

        def call(request: lightning_pb2.GetInfoRequest, **kwargs: object) -> object:
            assert isinstance(request, lightning_pb2.GetInfoRequest)
            assert lightning_pb2.GetInfoRequest.FromString(request_serializer(request)) == request
            assert isinstance(
                response_deserializer(lightning_pb2.GetInfoResponse().SerializeToString()),
                lightning_pb2.GetInfoResponse,
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
        return "PRIVATE-ENDPOINT-ERROR-DO-NOT-LEAK"


def _info() -> lightning_pb2.GetInfoResponse:
    return lightning_pb2.GetInfoResponse(
        identity_pubkey=KEY,
        chains=[lightning_pb2.Chain(chain="bitcoin", network="regtest")],
        block_height=0,
        synced_to_chain=False,
        synced_to_graph=False,
    )


def _client(tmp_path: Path, *, key: str = KEY) -> observer.RegtestLndInfoObserver:
    (tmp_path / "tls.cert").write_bytes(b"FAKE-TLS-ROOT")
    macaroon = tmp_path / "info.macaroon"
    macaroon.write_bytes(b"info-read-only-secret")
    macaroon.chmod(0o600)
    return observer.RegtestLndInfoObserver(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=tmp_path / "tls.cert",
        info_macaroon_path=macaroon,
        network=NETWORK,
        expected_node_pubkey=key,
    )


def _transport(
    monkeypatch: pytest.MonkeyPatch, response: object
) -> tuple[FakeChannel, list[object]]:
    channel = FakeChannel(response)
    evidence: list[object] = []

    def ssl(*, root_certificates: bytes) -> str:
        evidence.append(root_certificates)
        return "TRUSTED-ROOT"

    def secure(target: str, credentials: object, *, options: object) -> FakeChannel:
        evidence.append((target, credentials, options))
        return channel

    monkeypatch.setattr(observer.grpc, "ssl_channel_credentials", ssl)
    monkeypatch.setattr(observer.grpc, "secure_channel", secure)
    return channel, evidence


def test_construction_and_invalid_deadlines_do_not_read_credentials_or_dial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(observer, "_read_file", lambda *_args, **_kw: pytest.fail("read"))
    monkeypatch.setattr(observer.grpc, "secure_channel", lambda *_args, **_kw: pytest.fail("dial"))
    diagnostic = observer.RegtestLndInfoObserver(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=tmp_path / "absent-cert",
        info_macaroon_path=tmp_path / "absent-info",
        network=NETWORK,
        expected_node_pubkey=KEY,
    )
    for deadline in (0, -1, 31, float("nan"), True):
        with pytest.raises(ValueError, match="deadline"):
            diagnostic.get_info(deadline_seconds=deadline)
    for key in ("", "04" + "ab" * 32, "02" + "gg" * 32, KEY.upper(), KEY + "00"):
        with pytest.raises(ValueError, match="node key"):
            observer.RegtestLndInfoObserver(
                host="127.0.0.1",
                port=10009,
                tls_certificate_path="absent",
                info_macaroon_path="absent",
                network=NETWORK,
                expected_node_pubkey=key,
            )


@pytest.mark.parametrize(
    ("chain", "graph"), [(False, False), (True, False), (False, True), (True, True)]
)
def test_exact_endpoint_claims_are_inert_even_if_synced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    chain: bool,  # noqa: FBT001 - pytest parametrized diagnostic flags
    graph: bool,  # noqa: FBT001 - pytest parametrized diagnostic flags
) -> None:
    info = _info()
    info.block_height = 123
    info.synced_to_chain = chain
    info.synced_to_graph = graph
    channel, evidence = _transport(monkeypatch, info)
    actual = _client(tmp_path).get_info(deadline_seconds=3)
    assert actual == observer.LndInfoSnapshot(KEY, 123, chain, graph)
    assert channel.methods == [observer.INFO_METHOD]
    assert channel.calls[0][1] == {
        "timeout": 3,
        "metadata": (("macaroon", b"info-read-only-secret".hex()),),
        "wait_for_ready": False,
    }
    assert evidence[0] == b"FAKE-TLS-ROOT"
    assert evidence[1][0] == "127.0.0.1:10009"
    assert ("grpc.enable_retries", 0) in evidence[1][2]
    assert channel.closed
    assert "secret" not in repr(actual)


@pytest.mark.parametrize(
    "bad",
    [
        lightning_pb2.GetInfoResponse(),
        lightning_pb2.GetInfoResponse(identity_pubkey="03" + "ab" * 32),
        lightning_pb2.GetInfoResponse(identity_pubkey="private-error"),
        lightning_pb2.GetInfoResponse(identity_pubkey=KEY),
        lightning_pb2.GetInfoResponse(
            identity_pubkey=KEY, chains=[lightning_pb2.Chain(chain="bitcoin", network="mainnet")]
        ),
        lightning_pb2.GetInfoResponse(
            identity_pubkey=KEY,
            chains=[
                lightning_pb2.Chain(chain="bitcoin", network="regtest"),
                lightning_pb2.Chain(chain="bitcoin", network="regtest"),
            ],
        ),
        lightning_pb2.GetInfoResponse(
            identity_pubkey=KEY.upper(),
            chains=[lightning_pb2.Chain(chain="bitcoin", network="regtest")],
        ),
    ],
)
def test_mismatched_partial_or_extra_chain_response_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bad: lightning_pb2.GetInfoResponse,
) -> None:
    channel, _ = _transport(monkeypatch, bad)
    with pytest.raises(observer.LndProtocolError) as error:
        _client(tmp_path).get_info()
    assert "private-error" not in str(error.value)
    assert channel.closed


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (grpc.StatusCode.UNAUTHENTICATED, observer.LndAuthError),
        (grpc.StatusCode.PERMISSION_DENIED, observer.LndAuthError),
        (grpc.StatusCode.UNKNOWN, observer.LndUnavailableError),
        (grpc.StatusCode.DEADLINE_EXCEEDED, observer.LndUnavailableError),
        (grpc.StatusCode.UNAVAILABLE, observer.LndUnavailableError),
    ],
)
def test_rpc_failure_is_sanitized_without_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: grpc.StatusCode,
    error_type: type[Exception],
) -> None:
    channel, _ = _transport(monkeypatch, FakeRpcError(status))
    with pytest.raises(error_type) as caught:
        _client(tmp_path).get_info()
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert "PRIVATE-ENDPOINT" not in "".join(traceback.format_exception(caught.value))
    assert len(channel.calls) == 1
    assert channel.closed


def test_private_credential_absence_and_symlink_refuse_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel, _ = _transport(monkeypatch, _info())
    client = _client(tmp_path)
    macaroon = tmp_path / "info.macaroon"
    macaroon.chmod(0o644)
    with pytest.raises(observer.LndAuthError):
        client.get_info()
    macaroon.unlink()
    macaroon.symlink_to(tmp_path / "tls.cert")
    with pytest.raises(observer.LndAuthError):
        client.get_info()
    assert channel.methods == []


def test_missing_sync_scalars_are_only_unsynced_endpoint_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = lightning_pb2.GetInfoResponse(
        identity_pubkey=KEY,
        chains=[lightning_pb2.Chain(chain="bitcoin", network="regtest")],
    )
    channel, _ = _transport(monkeypatch, response)
    assert _client(tmp_path).get_info() == observer.LndInfoSnapshot(
        node_pubkey=KEY,
        block_height=0,
        synced_to_chain=False,
        synced_to_graph=False,
    )
    assert channel.closed


def test_malformed_identity_and_deserializer_error_cannot_echo_upstream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _info()
    response.identity_pubkey = "private-error-invalid-hex"
    channel, _ = _transport(monkeypatch, response)
    with pytest.raises(observer.LndProtocolError) as caught:
        _client(tmp_path).get_info()
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert channel.closed

    class BadChannel(FakeChannel):
        def unary_unary(
            self,
            method: str,
            *,
            request_serializer: Callable[[lightning_pb2.GetInfoRequest], bytes],  # noqa: ARG002
            response_deserializer: Callable[[bytes], lightning_pb2.GetInfoResponse],
        ) -> Callable[..., object]:
            self.methods.append(method)

            def call(_request: object, **_kwargs: object) -> object:
                return response_deserializer(b"\xffPRIVATE-ENDPOINT-ERROR-DO-NOT-LEAK")

            return call

    malformed = BadChannel(response)
    monkeypatch.setattr(observer.grpc, "secure_channel", lambda *_args, **_kw: malformed)
    with pytest.raises(observer.LndUnavailableError) as caught:
        _client(tmp_path).get_info()
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert "PRIVATE-ENDPOINT" not in "".join(traceback.format_exception(caught.value))
    assert malformed.closed
