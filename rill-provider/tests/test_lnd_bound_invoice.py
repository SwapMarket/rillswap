"""Bound Own-LND observations assert correspondence, not settlement authority."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core import networks
from rill_core.wire.messages import InvoiceBinding
from rill_core.wire.types import NetworkIdentity
from test_lnd_hold_invoice import NETWORK, FakeChannel, FakeRpcError, _client

from rill_provider import lnd_hold_invoice as hold
from rill_provider._lnd_proto import lightning_pb2
from rill_provider.lnd_payment_observation import (
    LndAuthError,
    LndProtocolError,
    LndUnavailableError,
)

if TYPE_CHECKING:
    from pathlib import Path

# ruff: noqa: SLF001 - supported-network and transport test seams
NODE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
HASH = "ab" * 32


@dataclass
class BoundCase:
    client: hold.LndHoldInvoices
    channel: FakeChannel
    expected: InvoiceBinding
    responses: list[object]
    budgets: list[float]


def _bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, network: NetworkIdentity = NETWORK
) -> BoundCase:
    _, channel = _client(tmp_path, monkeypatch, None)
    client = hold.LndHoldInvoices(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=tmp_path / "tls.cert",
        macaroon_path=tmp_path / "invoices.macaroon",
        network=network,
    )
    names = networks.backend_names(network)
    bolt11 = names.invoice_prefix + "1original"
    expected = InvoiceBinding(
        payment_hash=HASH,
        bolt11_sha256=hashlib.sha256(bolt11.encode("ascii")).hexdigest(),
        amount_msat="1000",
        payee_compressed_pubkey=NODE,
        created_at=1_700_000_000,
        expires_at=1_700_000_600,
        min_final_cltv_delta=40,
    )
    info = lightning_pb2.GetInfoResponse(
        identity_pubkey=NODE,
        synced_to_chain=True,
        synced_to_graph=False,
        block_height=100,
        block_hash="22" * 32,
        chains=[lightning_pb2.Chain(chain="bitcoin", network=names.lnd_network)],
    )
    last_info = lightning_pb2.GetInfoResponse()
    last_info.CopyFrom(info)
    invoice = lightning_pb2.Invoice(
        r_hash=bytes.fromhex(HASH),
        payment_request=bolt11,
        value_msat=1000,
        creation_date=expected.created_at,
        expiry=600,
        cltv_expiry=40,
        state=lightning_pb2.Invoice.ACCEPTED,
        htlcs=[
            lightning_pb2.InvoiceHTLC(
                amt_msat=1000, expiry_height=160, state=lightning_pb2.ACCEPTED
            )
        ],
    )
    case = BoundCase(client, channel, expected, [info, invoice, last_info], [])
    original = channel.unary_unary

    def setup(method: str, **kwargs: object) -> object:
        rpc = original(method, **kwargs)

        def call(request: object, **options: object) -> object:
            assert options["wait_for_ready"] is False
            case.budgets.append(options["timeout"])
            response = case.responses.pop(0)
            channel.response = response() if callable(response) else response
            return rpc(request, **options)

        return call

    monkeypatch.setattr(channel, "unary_unary", setup)
    return case


@pytest.mark.parametrize("name", ["regtest", "mainnet", "signet", "testnet4"])
def test_exact_original_correspondence_on_all_supported_networks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    fields = NETWORK.model_dump()
    if name != "regtest":
        fields.update(
            name=name,
            genesis_hash=networks._GENESIS[name],
            consensus_profile=networks.PUBLIC_CONSENSUS_PROFILE,
            deployment_namespace=None,
            signet_challenge=networks.DEFAULT_SIGNET_CHALLENGE if name == "signet" else None,
        )
    network = NetworkIdentity.model_validate(fields)
    case = _bound(tmp_path, monkeypatch, network)
    monkeypatch.setattr(hold.time, "monotonic", lambda: 100.0)
    result = case.client.observe_bound_invoice(case.expected)
    assert result == hold.BoundHoldInvoiceObservation(
        HASH,
        case.expected.bolt11_sha256,
        NODE,
        network,
        hold.HoldInvoiceStatus("ACCEPTED", (hold.HeldHtlc(1000, 160),)),
        100,
        "22" * 32,
    )
    assert [method for method, _ in case.channel.calls] == [
        hold.INFO_METHOD,
        hold.LOOKUP_METHOD,
        hold.INFO_METHOD,
    ]
    assert case.channel.calls[1][1].payment_hash == bytes.fromhex(HASH)
    assert case.budgets == [10.0] * 3
    assert case.channel.closed


@pytest.mark.parametrize(
    "fault",
    [
        "hash",
        "invoice",
        "unicode",
        "prefix",
        "amount",
        "creation",
        "expiry",
        "expiration",
        "cltv",
        "type",
        "state",
        "part",
    ],
)
def test_invoice_mismatch_never_returns_an_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = _bound(tmp_path, monkeypatch)
    invoice = case.responses[1]
    if fault == "hash":
        invoice.r_hash = b"\x01" * 32
    elif fault == "invoice":
        invoice.payment_request += "changed"
    elif fault == "unicode":
        invoice.payment_request += "\u00e9"
    elif fault == "prefix":
        invoice.payment_request = "lntb1original"
        case.expected = case.expected.model_copy(
            update={
                "bolt11_sha256": hashlib.sha256(
                    invoice.payment_request.encode("ascii")
                ).hexdigest(),
            }
        )
    elif fault == "amount":
        invoice.value_msat = 2000
    elif fault == "creation":
        invoice.creation_date += 1
    elif fault == "expiry":
        invoice.expiry = 0
    elif fault == "expiration":
        invoice.expiry = 601
    elif fault == "cltv":
        invoice.cltv_expiry += 1
    elif fault == "state":
        invoice.state = 7
    elif fault == "part":
        invoice.htlcs[0].amt_msat = 0
    else:
        case.responses[1] = object()
    with pytest.raises(LndProtocolError) as error:
        case.client.observe_bound_invoice(case.expected)
    assert case.expected.bolt11_sha256 not in str(error.value)
    assert [method for method, _ in case.channel.calls] == [hold.INFO_METHOD, hold.LOOKUP_METHOD]
    assert case.channel.closed


@pytest.mark.parametrize("position", [0, 2])
@pytest.mark.parametrize(
    "fault",
    [
        "identity",
        "identity case",
        "network",
        "chain",
        "multiple",
        "sync",
        "height",
        "hash",
        "hash case",
        "type",
    ],
)
def test_both_identity_observations_must_match_the_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, position: int, fault: str
) -> None:
    case = _bound(tmp_path, monkeypatch)
    info = case.responses[position]
    if fault == "identity":
        info.identity_pubkey = "03" + "33" * 32
    elif fault == "identity case":
        info.identity_pubkey = NODE.upper()
    elif fault == "network":
        info.chains[0].network = "testnet"
    elif fault == "chain":
        info.chains[0].chain = "litecoin"
    elif fault == "multiple":
        info.chains.add(chain="bitcoin", network="regtest")
    elif fault == "sync":
        info.synced_to_chain = False
    elif fault == "height":
        info.block_height = 0
    elif fault == "hash":
        info.block_hash = "not-a-hash"
    elif fault == "hash case":
        info.block_hash = "AA" * 32
    else:
        case.responses[position] = object()
    with pytest.raises(LndProtocolError):
        case.client.observe_bound_invoice(case.expected)
    assert len(case.channel.calls) == position + 1
    assert case.channel.closed


@pytest.mark.parametrize("change", ["advance", "rollback", "reorg"])
def test_final_tip_is_reported_not_promoted_to_atomic_chain_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    case = _bound(tmp_path, monkeypatch)
    last = case.responses[2]
    last.block_hash = "33" * 32
    last.block_height = {"advance": 101, "rollback": 99, "reorg": 100}[change]
    if change == "advance":
        result = case.client.observe_bound_invoice(case.expected)
        assert (result.last_lnd_height, result.last_lnd_block_hash) == (101, "33" * 32)
    else:
        with pytest.raises(LndProtocolError, match="tip changed"):
            case.client.observe_bound_invoice(case.expected)
    assert len(case.channel.calls) == 3
    assert case.channel.closed


@pytest.mark.parametrize(
    "deadline",
    [100.0, 99, True, float("nan"), float("inf"), 10**1000],
    ids=["due", "past", "bool", "nan", "infinite", "huge"],
)
def test_invalid_or_due_budget_does_not_read_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, deadline: object
) -> None:
    case = _bound(tmp_path, monkeypatch)
    monkeypatch.setattr(hold.time, "monotonic", lambda: 100.0)
    credentials = Mock(side_effect=AssertionError("must not read credentials"))
    monkeypatch.setattr(hold, "_read_file", credentials)
    with pytest.raises(LndUnavailableError):
        case.client.observe_bound_invoice(case.expected, deadline=deadline)
    credentials.assert_not_called()
    assert case.channel.calls == []


@pytest.mark.parametrize("answer", [False, None, 1, "raises"])
def test_refused_predicate_is_redacted_before_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object
) -> None:
    case = _bound(tmp_path, monkeypatch)
    allowed = Mock(return_value=answer)
    if answer == "raises":
        allowed.side_effect = RuntimeError("private invoice details")
    credentials = Mock(side_effect=AssertionError("must not read credentials"))
    monkeypatch.setattr(hold, "_read_file", credentials)
    with pytest.raises(LndUnavailableError, match="authority unavailable") as error:
        case.client.observe_bound_invoice(case.expected, submission_allowed=allowed)
    assert "private" not in str(error.value)
    credentials.assert_not_called()
    assert case.channel.calls == []


def test_untyped_original_binding_refuses_before_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _bound(tmp_path, monkeypatch)
    credentials = Mock(side_effect=AssertionError("must not read credentials"))
    monkeypatch.setattr(hold, "_read_file", credentials)
    with pytest.raises(LndProtocolError, match="original invoice binding"):
        case.client.observe_bound_invoice(object())
    credentials.assert_not_called()
    assert case.channel.calls == []


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("failure", ["expiry", "revocation"])
def test_unary_setup_cannot_authorize_the_next_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, position: int, failure: str
) -> None:
    case = _bound(tmp_path, monkeypatch)
    clock = {"mono": 100.0}
    enabled = True
    count = 0
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    original = case.channel.unary_unary

    def setup(method: str, **kwargs: object) -> object:
        nonlocal enabled, count
        rpc = original(method, **kwargs)
        if count == position:
            if failure == "expiry":
                clock["mono"] = 110.0
            else:
                enabled = False
        count += 1
        return rpc

    monkeypatch.setattr(case.channel, "unary_unary", setup)
    with pytest.raises(LndUnavailableError):
        case.client.observe_bound_invoice(
            case.expected,
            deadline=110.0,
            submission_allowed=lambda: enabled,
        )
    assert len(case.channel.calls) == position
    assert case.channel.closed


@pytest.mark.parametrize("outer_budget", [5.0, 600.0])
def test_setup_is_charged_to_one_fixed_batch_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outer_budget: float
) -> None:
    case = _bound(tmp_path, monkeypatch)
    clock = {"mono": 100.0}
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    connect = case.client._connect
    original = case.channel.unary_unary

    def delayed_connect() -> object:
        clock["mono"] += 1.0
        return connect()

    def setup(method: str, **kwargs: object) -> object:
        clock["mono"] += 1.0
        return original(method, **kwargs)

    monkeypatch.setattr(case.client, "_connect", delayed_connect)
    monkeypatch.setattr(case.channel, "unary_unary", setup)
    allowed = Mock(return_value=True)
    case.client.observe_bound_invoice(
        case.expected, deadline=100.0 + outer_budget, submission_allowed=allowed
    )
    limit = min(10.0, outer_budget)
    assert case.budgets == [limit - 2.0, limit - 3.0, limit - 4.0]
    assert allowed.call_count == 4


@pytest.mark.parametrize("position", [0, 1, 2])
def test_late_response_never_renews_dispatch_but_final_knowledge_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, position: int
) -> None:
    case = _bound(tmp_path, monkeypatch)
    clock = {"mono": 100.0}
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    original = case.responses[position]

    def late() -> object:
        clock["mono"] = 200.0
        return original

    case.responses[position] = late
    if position == 2:
        assert case.client.observe_bound_invoice(case.expected, deadline=110.0).payment_hash == HASH
    else:
        with pytest.raises(LndUnavailableError):
            case.client.observe_bound_invoice(case.expected, deadline=110.0)
    assert len(case.channel.calls) == position + 1
    assert case.channel.closed


def test_missing_info_permission_never_falls_back_or_queries_an_invoice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import grpc  # noqa: PLC0415 - explicit auth failure fixture

    case = _bound(tmp_path, monkeypatch)
    case.responses[0] = FakeRpcError(grpc.StatusCode.PERMISSION_DENIED)
    with pytest.raises(LndAuthError):
        case.client.observe_bound_invoice(case.expected)
    assert [method for method, _ in case.channel.calls] == [hold.INFO_METHOD]
    assert case.channel.closed
