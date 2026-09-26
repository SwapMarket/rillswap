"""New dispatches bind their original LND payer; nothing else gains authority."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import grpc
import pytest
from rill_core.wire.canonical import canonicalize
from test_live_session_store import Harness
from test_lnd_payment_send import HASH, NETWORK, PAYER, _info, _payment, _prepare, _sender
from test_payment_dispatch_store import _hash
from test_payment_reconciliation import Signer, _financial_rows, _paying
from test_settlement_failure_authority import _binding

from rill_provider import lnd_payment_send as sender
from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_payment_observation import LndProtocolError
from rill_provider.lnd_payment_send import PaymentOutcome
from rill_provider.payment_dispatch_record import PaymentAuthority, bound_payer, encode_dispatch
from rill_provider.settlement_engine import SettlementEngine

if TYPE_CHECKING:
    from pathlib import Path

OTHER = "02" + "cd" * 32


def _request(payment_hash: str = HASH) -> bytes:
    return router_pb2.SendToRouteRequest(
        payment_hash=bytes.fromhex(payment_hash)
    ).SerializeToString()


def test_version_one_record_round_trips_its_payer() -> None:
    payer = PaymentAuthority(PAYER, NETWORK)
    record = encode_dispatch(_request(), payer)
    assert bound_payer(record, payment_hash=HASH, network=NETWORK) == payer


def _mutations() -> list[bytes | None]:
    good = {
        "version": 1,
        "method": "SendToRouteV2",
        "request_hex": _request().hex(),
        "payer": {"node_pubkey": PAYER, "network": NETWORK.model_dump(mode="json")},
    }
    other_network = NETWORK.model_dump(mode="json") | {"name": "signet"}
    return [
        None,
        b"",
        b"not json",
        canonicalize({"method": "SendToRouteV2", "request_hex": _request().hex()}),  # legacy
        canonicalize(good | {"version": 2}),
        canonicalize(good | {"version": True}),
        canonicalize(good | {"method": "SendPaymentV2"}),
        canonicalize(good | {"extra": 1}),
        canonicalize(good | {"request_hex": _request("00" * 32).hex()}),
        canonicalize(good | {"request_hex": "zz"}),
        canonicalize(
            good | {"payer": {"node_pubkey": "04" + "ab" * 32, "network": good["payer"]["network"]}}
        ),
        canonicalize(good | {"payer": {"node_pubkey": PAYER, "network": other_network}}),
        canonicalize(good | {"payer": {"node_pubkey": PAYER}}),
        canonicalize(good).replace(b"{", b"{ ", 1),  # non-canonical bytes
    ]


@pytest.mark.parametrize("record", _mutations())
def test_absent_legacy_or_malformed_records_never_bind_a_payer(record: bytes | None) -> None:
    assert bound_payer(record, payment_hash=HASH, network=NETWORK) is None


def _count_channels(monkeypatch: pytest.MonkeyPatch, channel: Any) -> list[int]:  # noqa: ANN401
    opened: list[int] = []

    def secure_channel(*_args: object, **_kwargs: object) -> object:
        opened.append(len(channel.calls))
        return channel

    monkeypatch.setattr(grpc, "secure_channel", secure_channel)
    return opened


def test_prepare_captures_the_attested_identity_on_one_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    opened = _count_channels(monkeypatch, channel)
    payment = _prepare(client)
    assert payment.payer == PaymentAuthority(PAYER, NETWORK)
    assert opened == [0]
    assert bound_payer(payment.dispatch_record, payment_hash=HASH, network=NETWORK) == payment.payer


@pytest.mark.parametrize("identity", ["", "not a key", "04" + "ab" * 32])
def test_prepare_refuses_an_unattestable_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, identity: str
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    info = _info()
    info.identity_pubkey = identity
    channel.unary_responses[sender.INFO_METHOD] = info
    with pytest.raises(LndProtocolError, match="identity"):
        _prepare(client)
    assert not any(method == sender.QUERY_METHOD for method, _ in channel.calls)


def test_endpoint_drift_before_submission_refuses_to_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    info = _info()
    info.identity_pubkey = OTHER
    channel.unary_responses[sender.INFO_METHOD] = info
    with pytest.raises(LndProtocolError, match="bound dispatch"):
        client.send(payment)
    assert not any(method == sender.SEND_METHOD for method, _ in channel.calls)


def test_submission_attests_and_sends_on_the_same_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    opened = _count_channels(monkeypatch, channel)
    start = len(channel.calls)
    assert client.send(payment).status == "SUCCEEDED"
    assert opened == [start]
    assert [method for method, _ in channel.calls[start:]] == [
        sender.INFO_METHOD,
        sender.SEND_METHOD,
    ]


def test_failed_attempt_fallback_is_bound_and_refuses_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [_payment(3)])
    payment = _prepare(client)
    other = _info()
    other.identity_pubkey = OTHER
    infos = iter([_info(), other])
    channel.unary_responses[sender.INFO_METHOD] = lambda: next(infos)
    channel.unary_responses[sender.SEND_METHOD] = sender.lightning_pb2.HTLCAttempt(status="FAILED")
    with pytest.raises(LndProtocolError, match="bound dispatch"):
        client.send(payment)
    assert not any(method == sender.TRACK_METHOD for method, _ in channel.calls)


def test_bound_tracking_attests_first_on_the_same_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [_payment(3)])
    opened = _count_channels(monkeypatch, channel)
    payer = PaymentAuthority(PAYER, NETWORK)
    assert client.track(HASH, payer=payer) == PaymentOutcome("FAILED", payer=PAYER)
    assert opened == [0]
    assert [method for method, _ in channel.calls] == [sender.INFO_METHOD, sender.TRACK_METHOD]
    with pytest.raises(LndProtocolError, match="bound dispatch"):
        client.track(HASH, payer=PaymentAuthority(OTHER, NETWORK))
    assert [method for method, _ in channel.calls].count(sender.TRACK_METHOD) == 1


def test_unbound_tracking_keeps_its_raw_single_call_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [_payment(3)])
    assert client.track(HASH) == PaymentOutcome("FAILED")
    assert [method for method, _ in channel.calls] == [sender.TRACK_METHOD]


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def _submit(store: Any, harness: Harness, record: bytes) -> str:  # noqa: ANN401
    session = _paying(store, harness, "UNSENT")
    _binding(store, harness)
    assert store.commit_payment_dispatch(session, _hash(harness), record)
    return session


def test_store_exposes_payer_only_for_a_valid_submitted_record(harness: Harness) -> None:
    payer = PaymentAuthority(PAYER, harness.network)
    with harness.acquire() as store:
        session = _submit(store, harness, encode_dispatch(_request(_hash(harness)), payer))
        assert store.settlement_work(session_id=session)[0].payment_payer == payer
    with harness.acquire() as store:
        assert store.settlement_work(session_id=session)[0].payment_payer == payer
        store._connection.execute(  # noqa: SLF001 - an older relative-send custody record
            "UPDATE payment_dispatch SET request=?", (b'{"method":"SendPaymentV2"}',)
        )
        assert store.settlement_work(session_id=session)[0].payment_payer is None


def _engine(
    store: Any,  # noqa: ANN401 - the real store under test
    harness: Harness,
    outcome: PaymentOutcome | Exception,
) -> tuple[SettlementEngine, Mock]:
    lightning = Mock(spec=["track", "prepare", "send"])
    if isinstance(outcome, Exception):
        lightning.track.side_effect = outcome
    else:
        lightning.track.return_value = outcome
    return SettlementEngine(store, Mock(), lightning, Signer(harness)), lightning


def test_bound_payer_failure_terminates_without_another_send(harness: Harness) -> None:
    payer = PaymentAuthority(PAYER, harness.network)
    with harness.acquire() as store:
        session = _submit(store, harness, encode_dispatch(_request(_hash(harness)), payer))
        engine, lightning = _engine(store, harness, PaymentOutcome("FAILED"))
        assert asyncio.run(engine.tick(now=1002)) == {session: "FAILED"}
        lightning.track.assert_called_once_with(_hash(harness), payer=payer)
        lightning.prepare.assert_not_called()
        lightning.send.assert_not_called()
        dispatch = store._connection.execute("SELECT state FROM payment_dispatch")  # noqa: SLF001
        assert dispatch.fetchone() == ("SUBMITTED",)


@pytest.mark.parametrize(
    "record",
    [b"legacy opaque request", canonicalize({"method": "SendToRouteV2", "request_hex": "00"})],
)
def test_unbound_submitted_failure_is_still_deferred(harness: Harness, record: bytes) -> None:
    with harness.acquire() as store:
        session = _submit(store, harness, record)
        before = _financial_rows(store)
        engine, lightning = _engine(store, harness, PaymentOutcome("FAILED"))
        assert asyncio.run(engine.tick(now=1002)) == {}
        lightning.track.assert_called_once_with(_hash(harness))
        assert _financial_rows(store) == before
        assert store.settlement_work(session_id=session)[0].state == "PAYING"


def test_payer_attestation_failure_preserves_all_custody(harness: Harness) -> None:
    payer = PaymentAuthority(PAYER, harness.network)
    with harness.acquire() as store:
        session = _submit(store, harness, encode_dispatch(_request(_hash(harness)), payer))
        before = _financial_rows(store)
        engine, lightning = _engine(
            store, harness, LndProtocolError("LND payer differs from the bound dispatch")
        )
        assert asyncio.run(engine.tick(now=1002)) == {}
        assert _financial_rows(store) == before
        assert store.settlement_work(session_id=session)[0].state == "PAYING"
        lightning.send.assert_not_called()


def _reservation(store: Any) -> tuple[str, bytes | None]:  # noqa: ANN401
    return store._connection.execute(  # noqa: SLF001
        "SELECT state, release_evidence FROM economic_reservations"
    ).fetchone()


@pytest.mark.parametrize(
    ("attested_by", "state"),
    [(PAYER, "RELEASED"), (None, "DISPATCHED")],
)
def test_only_a_failure_attested_by_the_bound_payer_releases_capacity(
    harness: Harness, attested_by: str | None, state: str
) -> None:
    payer = PaymentAuthority(PAYER, harness.network)
    with harness.acquire() as store:
        session = _submit(store, harness, encode_dispatch(_request(_hash(harness)), payer))
        engine, _lightning = _engine(store, harness, PaymentOutcome("FAILED", payer=attested_by))
        assert asyncio.run(engine.tick(now=1002)) == {session: "FAILED"}
        reserved, evidence = _reservation(store)
        assert reserved == state
        if evidence is not None:
            assert b'"reason":"failed-after-dispatch"' in evidence
        # The grant stays consumed and the hash stays reserved forever.
        dispatch = store._connection.execute("SELECT state FROM payment_dispatch")  # noqa: SLF001
        assert dispatch.fetchone() == ("SUBMITTED",)


def test_a_failure_attributed_to_another_node_is_refused(harness: Harness) -> None:
    payer = PaymentAuthority(PAYER, harness.network)
    with harness.acquire() as store:
        session = _submit(store, harness, encode_dispatch(_request(_hash(harness)), payer))
        engine, _lightning = _engine(store, harness, PaymentOutcome("FAILED", payer=OTHER))
        assert asyncio.run(engine.tick(now=1002)) == {}
        assert store.settlement_work(session_id=session)[0].state == "PAYING"
        assert _reservation(store)[0] == "DISPATCHED"
