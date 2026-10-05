"""Real protobuf codec boundaries with fake TLS/RPC, no funds or live daemon."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.networks import REGTEST_CONSENSUS_PROFILE
from rill_core.wire.types import NetworkIdentity
from test_lnd_payment_pinned import HELD_HTLC_PAYMENT

from rill_provider import lnd_treasury_observation as module
from rill_provider._lnd_proto import lightning_pb2 as pb

if TYPE_CHECKING:
    from pathlib import Path

NODE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
HASH = "b" * 64
NETWORK = NetworkIdentity(
    family="bitcoin",
    name="regtest",
    genesis_hash="0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    signet_challenge=None,
    consensus_profile=REGTEST_CONSENSUS_PROFILE,
    deployment_namespace="treasury-observation-test",
)


def info(**updates: Any) -> pb.GetInfoResponse:  # noqa: ANN401 - protobuf fixture fields
    return pb.GetInfoResponse(
        identity_pubkey=NODE,
        block_height=100,
        block_hash="a" * 64,
        synced_to_chain=True,
        chains=[pb.Chain(chain="bitcoin", network="regtest")],
        **updates,
    )


def channel(**updates: Any) -> pb.Channel:  # noqa: ANN401 - protobuf fixture fields
    values = {
        "active": True,
        "local_balance": 50000,
        "capacity": 1500000,
        "private": True,
        "commitment_type": pb.ANCHORS,
        "local_constraints": pb.ChannelConstraints(
            chan_reserve_sat=15000, max_pending_amt_msat=1000000000, max_accepted_htlcs=483
        ),
        "remote_constraints": pb.ChannelConstraints(
            chan_reserve_sat=15000, max_pending_amt_msat=1000000000, max_accepted_htlcs=483
        ),
    }
    return pb.Channel(**(values | updates))


def payment(**updates: Any) -> pb.Payment:  # noqa: ANN401 - protobuf fixture fields
    route = pb.Route(
        total_amt_msat=20001234,
        total_fees_msat=1234,
        first_hop_amount_msat=20001234,
        hops=[pb.Hop(amt_to_forward_msat=20000000, pub_key="SECRET_CANARY")],
    )
    values = {
        "payment_hash": HASH,
        "value_msat": 20000000,
        "fee_msat": 1234,
        "status": pb.Payment.SUCCEEDED,
        "payment_preimage": "SECRET_CANARY",
        "htlcs": [
            pb.HTLCAttempt(
                attempt_id=1,
                status=pb.HTLCAttempt.SUCCEEDED,
                route=route,
                preimage=b"SECRET_CANARY",
            )
        ],
    }
    return pb.Payment(**(values | updates))


class Stream:
    def __init__(self, owner: Transport, values: list[pb.Payment]) -> None:
        self.owner, self.values = owner, iter(values)
        self.count = 0

    def __iter__(self) -> Stream:
        return self

    def __next__(self) -> pb.Payment:
        self.count += 1
        self.owner.clock += self.owner.response_delay
        return next(self.values)

    def cancel(self) -> None:
        self.owner.events.append("cancel")
        self.owner.clock += self.owner.cancel_delay
        if self.owner.cancel_failure:
            raise RuntimeError("SECRET_CANARY")


class Transport:
    def __init__(self) -> None:
        self.infos = [info(), info()]
        self.channels = pb.ListChannelsResponse(channels=[channel()])
        self.payments = [payment()]
        self.events: list[str] = []
        self.calls: list[dict[str, Any]] = []
        self.clock = 100.0
        self.response_delay = self.cancel_delay = self.close_delay = 0.0
        self.cancel_failure = self.close_failure = False
        self.rpc_failure = False
        self.details: list[object] = []

    def unary_unary(self, method: str, **codec: Any):  # noqa: ANN201, ANN401 - fake generated RPC codec
        def call(request: Any, **kwargs: Any) -> Any:  # noqa: ANN401 - protobuf boundary
            self.events.append(method)
            self.calls.append(kwargs)
            self.clock += self.response_delay
            if self.rpc_failure:
                raise RuntimeError("SECRET_CANARY")
            assert codec["request_serializer"](request) == request.SerializeToString()
            result = self.infos.pop(0) if method.endswith("GetInfo") else self.channels
            return codec["response_deserializer"](result.SerializeToString())

        return call

    def unary_stream(self, method: str, **codec: Any):  # noqa: ANN201, ANN401 - fake generated RPC codec
        def call(request: Any, **kwargs: Any) -> Stream:  # noqa: ANN401 - protobuf boundary
            self.events.append(method)
            self.calls.append(kwargs)
            assert request.payment_hash.hex() == HASH
            assert codec["request_serializer"](request) == request.SerializeToString()
            values = [
                codec["response_deserializer"](value.SerializeToString()) for value in self.payments
            ]
            return Stream(self, values)

        return call

    def close(self) -> None:
        self.events.append("close")
        self.clock += self.close_delay
        if self.close_failure:
            raise RuntimeError("SECRET_CANARY")


@pytest.fixture
def transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[module.LndTreasuryObserver, Transport]:
    certificate = tmp_path / "tls.cert"
    certificate.write_bytes(b"configured-trust-anchor")
    macaroon = tmp_path / "read.macaroon"
    macaroon.write_bytes(b"SECRET_CANARY")
    macaroon.chmod(0o600)
    client = module.LndTreasuryObserver(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=certificate,
        read_macaroon_path=macaroon,
        network=NETWORK,
        expected_node_pubkey=NODE,
    )
    backend = Transport()
    monkeypatch.setattr(module.time, "monotonic", lambda: backend.clock)

    def secure(target: str, credentials: object, **kwargs: object) -> Transport:
        backend.details.append((target, credentials, kwargs))
        return backend

    monkeypatch.setattr(module.grpc, "secure_channel", secure)
    monkeypatch.setattr(module.grpc, "ssl_channel_credentials", lambda **kwargs: kwargs)
    return client, backend


def refused(action: Any) -> None:  # noqa: ANN401 - callable fixture includes both result kinds
    with pytest.raises(module.LndTreasuryObservationError) as failure:
        action()
    assert failure.value.__context__ is None
    assert failure.value.__cause__ is None
    assert "SECRET_CANARY" not in str(failure.value)


def test_accounting_returns_claims_not_complete_network_or_spendability(
    transport: tuple[module.LndTreasuryObserver, Transport],
) -> None:
    client, backend = transport
    result = client.observe_accounting()
    assert result.context.configured_network == NETWORK
    assert result.context.observed_network_label == "regtest"
    assert result.context.observed_node_pubkey == NODE
    assert result.context.before_tip == result.context.after_tip
    assert result.coverage_complete
    assert result.classified_channel_count == 1
    assert result.classified_local_commitment_floor_msat == 50000000
    assert result.classified_local_reserve_msat == 15000000
    assert "budget" not in json.dumps(asdict(result), default=str)
    assert "SECRET_CANARY" not in repr(result)
    assert backend.events == [
        "/lnrpc.Lightning/GetInfo",
        "/lnrpc.Lightning/ListChannels",
        "/lnrpc.Lightning/GetInfo",
        "close",
    ]
    assert all(call["wait_for_ready"] is False for call in backend.calls)
    target, credentials, options = backend.details[0]
    assert target == "127.0.0.1:10009"
    assert credentials == {"root_certificates": b"configured-trust-anchor"}
    assert options["options"][-1] == ("grpc.enable_retries", 0)


def test_empty_is_known_zero_and_missing_constraints_are_not_known_zero(
    transport: tuple[module.LndTreasuryObserver, Transport],
) -> None:
    client, backend = transport
    backend.channels = pb.ListChannelsResponse()
    zero = client.observe_accounting()
    assert zero.coverage_complete
    assert zero.channel_count == 0
    backend.infos = [info(), info()]
    unknown = channel()
    unknown.ClearField("local_constraints")
    backend.channels = pb.ListChannelsResponse(channels=[unknown])
    result = client.observe_accounting()
    assert not result.coverage_complete
    assert result.channel_count == 1
    assert result.classified_channel_count == 0


def test_mixed_custom_inactive_and_private_accounting_coverage_is_explicit(
    transport: tuple[module.LndTreasuryObserver, Transport],
) -> None:
    client, backend = transport
    backend.channels = pb.ListChannelsResponse(
        channels=[channel(), channel(active=False), channel(custom_channel_data=b"SECRET_CANARY")]
    )
    result = client.observe_accounting()
    assert result.channel_count == 3
    assert result.classified_channel_count == 2
    assert not result.coverage_complete
    assert result.classified_local_commitment_floor_msat == 100000000
    assert result.active_classified_local_commitment_floor_msat == 50000000


def test_pending_incoming_is_separate_and_outgoing_not_double_subtracted(
    transport: tuple[module.LndTreasuryObserver, Transport],
) -> None:
    client, backend = transport
    backend.channels = pb.ListChannelsResponse(
        channels=[
            channel(
                pending_htlcs=[
                    pb.HTLC(incoming=True, amount=20000),
                    pb.HTLC(incoming=False, amount=10000),
                ]
            )
        ]
    )
    result = client.observe_accounting()
    assert result.classified_local_commitment_floor_msat == 50000000
    assert result.classified_pending_incoming_floor_msat == 20000000
    assert result.classified_pending_outgoing_floor_msat == 10000000


@pytest.mark.parametrize("accountability", [False, True])
def test_exact_successful_payment_excludes_preimages_routes_and_failed_attempt_fees(
    transport: tuple[module.LndTreasuryObserver, Transport],
    *,
    accountability: bool,
) -> None:
    client, backend = transport
    paid = payment()
    if accountability:
        paid.first_hop_custom_records[106823] = b"\x00"
    paid.htlcs.add(
        attempt_id=2,
        status=pb.HTLCAttempt.FAILED,
        route=pb.Route(total_amt_msat=999999, total_fees_msat=999999),
        preimage=b"SECRET_CANARY",
    )
    backend.payments = [payment(status=pb.Payment.IN_FLIGHT), paid]
    receipt = client.observe_completed_payment(HASH, 20000000)
    assert receipt.amount_msat == 20000000
    assert receipt.routing_fee_msat == 1234
    assert "SECRET_CANARY" not in repr(receipt)
    assert set(asdict(receipt)) == {"context", "payment_hash", "amount_msat", "routing_fee_msat"}
    assert backend.events == [
        "/lnrpc.Lightning/GetInfo",
        "/routerrpc.Router/TrackPaymentV2",
        "cancel",
        "/lnrpc.Lightning/GetInfo",
        "close",
    ]


@pytest.mark.parametrize("mismatch", [False, True])
def test_mpp_success_requires_sum_of_recipient_and_settled_fee_amounts(
    transport: tuple[module.LndTreasuryObserver, Transport],
    *,
    mismatch: bool,
) -> None:
    client, backend = transport
    paid = payment()
    paid.htlcs.clear()
    for index in range(2):
        paid.htlcs.add(
            attempt_id=index + 1,
            status=pb.HTLCAttempt.SUCCEEDED,
            route=pb.Route(
                total_amt_msat=10000617,
                total_fees_msat=617,
                first_hop_amount_msat=10000617,
                hops=[pb.Hop(amt_to_forward_msat=10000000)],
            ),
        )
    backend.payments = [paid]
    if mismatch:
        paid.htlcs[-1].route.first_hop_amount_msat -= 1
        refused(lambda: client.observe_completed_payment(HASH, 20000000))
    else:
        assert client.observe_completed_payment(HASH, 20000000).routing_fee_msat == 1234


@pytest.mark.parametrize(
    "kind",
    [
        "value",
        "fee",
        "hash",
        "no_attempt",
        "inflight_attempt",
        "unknown_attempt",
        "duplicate_attempt",
        "no_route",
        "no_hops",
        "route_recipient",
        "sum_recipient",
        "sum_fee",
        "too_many_attempts",
        "too_many_hops",
        "failed_payment",
        "unknown_payment",
        "update_limit",
        "ended",
        "custom_records",
        "custom_route",
        "different_source_debit",
        "missing_source_debit",
        "negative_source_debit",
        "wrong_accountability_value",
        "unknown_record_with_accountability",
    ],
)
def test_unknown_or_inconsistent_payment_never_proves_debit(  # noqa: PLR0912, PLR0915 - one malformed-field matrix
    transport: tuple[module.LndTreasuryObserver, Transport], kind: str
) -> None:
    client, backend = transport
    paid = payment()
    if kind == "value":
        paid.value_msat = 19999999
    elif kind == "fee":
        paid.fee_msat = -1
    elif kind == "hash":
        paid.payment_hash = "c" * 64
    elif kind == "no_attempt":
        paid.htlcs.clear()
    elif kind == "inflight_attempt":
        paid.htlcs[0].status = pb.HTLCAttempt.IN_FLIGHT
    elif kind == "unknown_attempt":
        paid.htlcs[0].status = 999
    elif kind == "duplicate_attempt":
        paid.htlcs.add().CopyFrom(paid.htlcs[0])
    elif kind == "no_route":
        paid.htlcs[0].ClearField("route")
    elif kind == "no_hops":
        paid.htlcs[0].route.hops.clear()
    elif kind == "route_recipient":
        paid.htlcs[0].route.hops[-1].amt_to_forward_msat -= 1
    elif kind == "sum_recipient":
        paid.htlcs[0].route.hops[-1].amt_to_forward_msat -= 1
        paid.htlcs[0].route.total_amt_msat -= 1
        paid.htlcs[0].route.first_hop_amount_msat -= 1
    elif kind == "sum_fee":
        paid.fee_msat += 1
    elif kind == "too_many_attempts":
        for index in range(257):
            paid.htlcs.add(attempt_id=index + 2, status=pb.HTLCAttempt.FAILED)
    elif kind == "too_many_hops":
        for _ in range(20):
            paid.htlcs[0].route.hops.add(amt_to_forward_msat=20000000)
    elif kind == "failed_payment":
        paid.status = pb.Payment.FAILED
    elif kind == "unknown_payment":
        paid.status = 999
    elif kind == "custom_records":
        paid.first_hop_custom_records[65536] = b"SECRET_CANARY"
    elif kind == "custom_route":
        paid.htlcs[0].route.custom_channel_data = b"SECRET_CANARY"
    elif kind == "different_source_debit":
        paid.htlcs[0].route.first_hop_amount_msat = 1
    elif kind == "missing_source_debit":
        paid.htlcs[0].route.first_hop_amount_msat = 0
    elif kind == "negative_source_debit":
        paid.htlcs[0].route.first_hop_amount_msat = -1
    elif kind == "wrong_accountability_value":
        paid.first_hop_custom_records[106823] = b"\x01"
    elif kind == "unknown_record_with_accountability":
        paid.first_hop_custom_records[106823] = b"\x00"
        paid.first_hop_custom_records[65536] = b"SECRET_CANARY"
    backend.payments = (
        [paid]
        if kind not in {"update_limit", "ended"}
        else ([payment(status=pb.Payment.IN_FLIGHT)] * 17 if kind == "update_limit" else [])
    )
    refused(lambda: client.observe_completed_payment(HASH, 20000000))
    assert "cancel" in backend.events
    assert backend.events[-1] == "close"
    assert backend.events.count("/lnrpc.Lightning/GetInfo") == 1


@pytest.mark.parametrize(
    "kind",
    [
        "node",
        "network",
        "not_synced",
        "no_hash",
        "rollback",
        "same_height_fork",
        "final_node",
        "final_network",
    ],
)
@pytest.mark.parametrize("method", ["accounting", "payment"])
def test_same_channel_identity_and_tip_correspondence(
    transport: tuple[module.LndTreasuryObserver, Transport], kind: str, method: str
) -> None:
    client, backend = transport
    first, last = backend.infos
    if kind in {"node", "final_node"}:
        (last if kind == "final_node" else first).identity_pubkey = "03" + NODE[2:]
    elif kind in {"network", "final_network"}:
        (last if kind == "final_network" else first).chains[0].network = "mainnet"
    elif kind == "not_synced":
        first.synced_to_chain = False
    elif kind == "no_hash":
        first.block_hash = ""
    elif kind == "rollback":
        last.block_height = 99
    elif kind == "same_height_fork":
        last.block_hash = "c" * 64
    refused(
        client.observe_accounting
        if method == "accounting"
        else lambda: client.observe_completed_payment(HASH, 20000000)
    )
    assert backend.events[-1] == "close"


@pytest.mark.parametrize(
    "kind", ["rpc", "close", "cancel", "rpc_delay", "cancel_delay", "close_delay"]
)
def test_upstream_errors_and_cleanup_expiry_are_private(
    transport: tuple[module.LndTreasuryObserver, Transport], kind: str
) -> None:
    client, backend = transport
    if kind == "rpc":
        backend.rpc_failure = True
    elif kind == "close":
        backend.close_failure = True
    elif kind == "cancel":
        backend.cancel_failure = True
    elif kind == "rpc_delay":
        backend.response_delay = 6
    elif kind == "cancel_delay":
        backend.cancel_delay = 11
    elif kind == "close_delay":
        backend.close_delay = 11
    refused(lambda: client.observe_completed_payment(HASH, 20000000))
    assert backend.events[-1] == "close"


def test_setup_time_consumes_deadline_before_any_rpc(
    transport: tuple[module.LndTreasuryObserver, Transport], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, backend = transport
    original = module._read_file  # noqa: SLF001 - exact setup lifetime seam

    def slow(*args: Any, **kwargs: Any) -> bytes:  # noqa: ANN401 - preserve helper signature
        value = original(*args, **kwargs)
        backend.clock += 11
        return value

    monkeypatch.setattr(module, "_read_file", slow)
    refused(client.observe_accounting)
    assert not backend.events
    assert not backend.details


def test_one_absolute_deadline_never_renews_between_reads(
    transport: tuple[module.LndTreasuryObserver, Transport],
) -> None:
    client, backend = transport
    backend.response_delay = 1
    client.observe_accounting()
    assert [call["timeout"] for call in backend.calls] == [10, 9, 8]


@pytest.mark.parametrize(
    "kind",
    [
        "negative_balance",
        "overflow_balance",
        "too_many_channels",
        "too_many_htlcs",
        "unknown_commitment",
    ],
)
def test_bounded_channel_accounting_and_unknown_coverage(
    transport: tuple[module.LndTreasuryObserver, Transport], kind: str
) -> None:
    client, backend = transport
    observed = channel()
    if kind == "negative_balance":
        observed.local_balance = -1
    elif kind == "overflow_balance":
        observed.local_balance = 2100000000000001
    elif kind == "too_many_channels":
        backend.channels.channels.extend([observed] * 256)
    elif kind == "too_many_htlcs":
        observed.pending_htlcs.extend([pb.HTLC(amount=1)] * 484)
    elif kind == "unknown_commitment":
        observed.commitment_type = 999
    if kind != "too_many_channels":
        backend.channels = pb.ListChannelsResponse(channels=[observed])
    if kind == "unknown_commitment":
        assert not client.observe_accounting().coverage_complete
    else:
        refused(client.observe_accounting)
    assert backend.events[-1] == "close"


@pytest.mark.parametrize("duration", [-1, 0, 31, 10**400, float("nan"), float("inf"), True])
def test_invalid_lifetimes_are_inert(
    transport: tuple[module.LndTreasuryObserver, Transport], duration: float
) -> None:
    client, backend = transport
    refused(lambda: client.observe_accounting(deadline_seconds=duration))
    refused(lambda: client.observe_completed_payment(HASH, 20000000, deadline_seconds=duration))
    assert not backend.events
    assert not backend.details


@pytest.mark.parametrize(
    "fault", ["missing_macaroon", "public_macaroon", "symlink_macaroon", "missing_certificate"]
)
def test_credentials_refuse_before_transport(
    transport: tuple[module.LndTreasuryObserver, Transport], tmp_path: Path, fault: str
) -> None:
    client, backend = transport
    macaroon = tmp_path / "read.macaroon"
    if fault == "missing_macaroon":
        macaroon.unlink()
    elif fault == "public_macaroon":
        macaroon.chmod(0o644)
    elif fault == "symlink_macaroon":
        target = tmp_path / "real.macaroon"
        macaroon.rename(target)
        macaroon.symlink_to(target)
    else:
        (tmp_path / "tls.cert").unlink()
    refused(client.observe_accounting)
    assert not backend.events
    assert not backend.details


@pytest.mark.parametrize("fault", ["host", "bool_port", "unsupported_network", "secret_key"])
def test_constructor_is_inert_and_source_failures_do_not_echo_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(
        module, "_read_file", lambda *_args, **_kwargs: pytest.fail("inert constructor read a file")
    )
    values = {
        "host": "127.0.0.1",
        "port": 10009,
        "tls_certificate_path": tmp_path / "absent.crt",
        "read_macaroon_path": tmp_path / "absent.mac",
        "network": NETWORK,
        "expected_node_pubkey": NODE,
    }
    values.update(
        {"host": "elsewhere.invalid"}
        if fault == "host"
        else {"port": True}
        if fault == "bool_port"
        else {"network": NETWORK.model_copy(update={"consensus_profile": "unknown/1"})}
        if fault == "unsupported_network"
        else {"expected_node_pubkey": "SECRET_CANARY"}
    )
    refused(lambda: module.LndTreasuryObserver(**values))


def test_aggregate_htlc_count_is_bounded_even_with_small_messages(
    transport: tuple[module.LndTreasuryObserver, Transport],
) -> None:
    client, backend = transport
    backend.channels = pb.ListChannelsResponse(
        channels=[channel(pending_htlcs=[pb.HTLC(amount=1)] * 483)] * 9
    )
    refused(client.observe_accounting)


def test_forward_tip_is_only_observed_context_not_atomicity(
    transport: tuple[module.LndTreasuryObserver, Transport],
) -> None:
    client, backend = transport
    backend.infos[-1].block_height = 101
    backend.infos[-1].block_hash = "c" * 64
    result = client.observe_accounting()
    assert result.context.before_tip.height == 100
    assert result.context.after_tip.height == 101
    assert "atomic" not in asdict(result)


def test_zero_satoshi_htlc_floor_is_not_proof_of_malformed_payment(
    transport: tuple[module.LndTreasuryObserver, Transport],
) -> None:
    client, backend = transport
    backend.channels = pb.ListChannelsResponse(
        channels=[channel(pending_htlcs=[pb.HTLC(amount=0)])]
    )
    result = client.observe_accounting()
    assert result.coverage_complete
    assert result.classified_pending_outgoing_floor_msat == 0


def test_pinned_treasury_diagnostic_program_is_valid_without_execution() -> None:
    assert "\x00" not in HELD_HTLC_PAYMENT
    compile(HELD_HTLC_PAYMENT, "<owned-treasury-diagnostic>", "exec")
