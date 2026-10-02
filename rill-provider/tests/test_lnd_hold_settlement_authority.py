"""Hold settlement transport respects caller authority without inventing it."""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING
from unittest.mock import Mock

import grpc
import pytest
from test_lnd_hold_invoice import FakeRpcError, _client

from rill_provider import lnd_hold_invoice as hold
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2
from rill_provider.lnd_payment_observation import LndAuthError, LndUnavailableError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

PREIMAGE = "cd" * 32


@pytest.mark.parametrize("explicit_none", [False, True])
def test_unguarded_settlement_keeps_exact_post_connect_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, explicit_none: bool
) -> None:
    client, _ = _client(tmp_path, monkeypatch, invoices_pb2.SettleInvoiceResp())
    clock = {"mono": 100.0}
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    calls = Mock()

    @contextmanager
    def delayed_connect() -> Iterator[Mock]:
        clock["mono"] = 200.0
        yield calls

    monkeypatch.setattr(client, "_connect", delayed_connect)
    if explicit_none:
        assert client.settle(PREIMAGE, deadline=None, submission_allowed=None) is None
    else:
        assert client.settle(PREIMAGE) is None
    calls.unary.assert_called_once_with(
        request=invoices_pb2.SettleInvoiceMsg(preimage=bytes.fromhex(PREIMAGE)),
        method=hold.SETTLE_METHOD,
        response_type=invoices_pb2.SettleInvoiceResp,
        deadline=210.0,
    )


@pytest.mark.parametrize(
    "deadline",
    [float("nan"), float("inf"), float("-inf"), True, False, "200", 10**1000, 100.0, 99],
    ids=["nan", "infinity", "negative-infinity", "true", "false", "string", "huge", "due", "past"],
)
def test_invalid_or_due_deadline_refuses_before_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, deadline: object
) -> None:
    client, channel = _client(tmp_path, monkeypatch, invoices_pb2.SettleInvoiceResp())
    monkeypatch.setattr(hold.time, "monotonic", lambda: 100.0)
    credentials = Mock(side_effect=AssertionError("must not read credentials"))
    monkeypatch.setattr(hold, "_read_file", credentials)
    with pytest.raises(LndUnavailableError, match="submission"):
        client.settle(PREIMAGE, deadline=deadline)
    credentials.assert_not_called()
    assert channel.calls == []


@pytest.mark.parametrize("answer", [False, None, 1, "true", "raises", "noncallable"])
def test_predicate_requires_exact_true_before_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object
) -> None:
    client, channel = _client(tmp_path, monkeypatch, invoices_pb2.SettleInvoiceResp())
    allowed = Mock(return_value=answer)
    if answer == "raises":
        allowed.side_effect = RuntimeError("private preimage and credential details")
    credentials = Mock(side_effect=AssertionError("must not read credentials"))
    monkeypatch.setattr(hold, "_read_file", credentials)
    predicate = "private noncallable" if answer == "noncallable" else allowed
    with pytest.raises(LndUnavailableError, match="authority unavailable") as error:
        client.settle(PREIMAGE, submission_allowed=predicate)
    assert "private" not in str(error.value)
    credentials.assert_not_called()
    assert channel.calls == []


@pytest.mark.parametrize(
    "boundary",
    [
        "connection expiry",
        "connection revocation",
        "setup expiry",
        "setup revocation",
        "predicate expiry",
    ],
)
def test_expiry_and_revocation_after_setup_prevent_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    client, channel = _client(tmp_path, monkeypatch, invoices_pb2.SettleInvoiceResp())
    clock = {"mono": 100.0}
    enabled = True
    setup_done = False
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])

    def connect(*_args: object, **_kwargs: object) -> object:
        nonlocal enabled
        if boundary == "connection expiry":
            clock["mono"] = 110.0
        elif boundary == "connection revocation":
            enabled = False
        return channel

    monkeypatch.setattr(grpc, "secure_channel", connect)
    original = channel.unary_unary

    def setup(method: str, **kwargs: object) -> object:
        nonlocal enabled, setup_done
        rpc = original(method, **kwargs)
        setup_done = True
        if boundary == "setup expiry":
            clock["mono"] = 110.0
        elif boundary == "setup revocation":
            enabled = False
        return rpc

    monkeypatch.setattr(channel, "unary_unary", setup)

    def allowed() -> bool:
        if setup_done and boundary == "predicate expiry":
            clock["mono"] = 110.0
        return enabled

    with pytest.raises(LndUnavailableError):
        client.settle(PREIMAGE, deadline=110.0, submission_allowed=allowed)
    assert channel.calls == []
    assert channel.closed


@pytest.mark.parametrize("mode", ["deadline", "predicate", "both"])
@pytest.mark.parametrize("outer_budget", [5.0, 600.0])
def test_guards_charge_setup_and_preserve_exact_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, outer_budget: float
) -> None:
    client, channel = _client(tmp_path, monkeypatch, invoices_pb2.SettleInvoiceResp())
    clock = {"mono": 100.0}
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    original = channel.unary_unary
    budgets: list[float] = []
    predicate_calls: list[float] = []

    def connect(*_args: object, **_kwargs: object) -> object:
        clock["mono"] += 1.0
        return channel

    monkeypatch.setattr(grpc, "secure_channel", connect)

    def setup(method: str, **kwargs: object) -> object:
        rpc = original(method, **kwargs)
        clock["mono"] += 1.0

        def call(request: object, **options: object) -> object:
            assert options["wait_for_ready"] is False
            budgets.append(options["timeout"])
            return rpc(request, **options)

        return call

    monkeypatch.setattr(channel, "unary_unary", setup)

    def allowed() -> bool:
        predicate_calls.append(clock["mono"])
        clock["mono"] += 0.5
        return True

    deadline = None if mode == "predicate" else 100.0 + outer_budget
    predicate = None if mode == "deadline" else allowed
    assert client.settle(PREIMAGE, deadline=deadline, submission_allowed=predicate) is None
    limit = 10.0 if deadline is None else min(10.0, outer_budget)
    assert budgets == [limit - (3.0 if predicate is not None else 2.0)]
    assert predicate_calls == ([] if predicate is None else [100.0, 102.5])
    assert channel.calls == [
        (hold.SETTLE_METHOD, invoices_pb2.SettleInvoiceMsg(preimage=bytes.fromhex(PREIMAGE))),
    ]
    assert channel.closed


@pytest.mark.parametrize("mode", ["deadline", "predicate", "both"])
def test_guarded_setup_cannot_renew_local_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    client, channel = _client(tmp_path, monkeypatch, invoices_pb2.SettleInvoiceResp())
    clock = {"mono": 100.0}
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])

    def connect(*_args: object, **_kwargs: object) -> object:
        clock["mono"] = 110.0
        return channel

    monkeypatch.setattr(grpc, "secure_channel", connect)
    with pytest.raises(LndUnavailableError):
        client.settle(
            PREIMAGE,
            deadline=None if mode == "predicate" else 700.0,
            submission_allowed=None if mode == "deadline" else lambda: True,
        )
    assert channel.calls == []
    assert channel.closed


@pytest.mark.parametrize("outcome", ["success", "unknown", "auth"])
@pytest.mark.parametrize("boundary", ["expiry", "revocation"])
def test_late_inflight_outcome_is_retained_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str, boundary: str
) -> None:
    response: object = invoices_pb2.SettleInvoiceResp()
    if outcome == "unknown":
        response = RuntimeError("private invoice and preimage details")
    elif outcome == "auth":
        response = FakeRpcError(grpc.StatusCode.PERMISSION_DENIED)
    client, channel = _client(tmp_path, monkeypatch, response)
    clock = {"mono": 100.0}
    enabled = True
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    original = channel.unary_unary

    def setup(method: str, **kwargs: object) -> object:
        rpc = original(method, **kwargs)

        def call(request: object, **options: object) -> object:
            nonlocal enabled
            if boundary == "expiry":
                clock["mono"] = 200.0
            else:
                enabled = False
            return rpc(request, **options)

        return call

    monkeypatch.setattr(channel, "unary_unary", setup)
    if outcome == "success":
        assert client.settle(PREIMAGE, deadline=110.0, submission_allowed=lambda: enabled) is None
    else:
        expected = LndAuthError if outcome == "auth" else LndUnavailableError
        with pytest.raises(expected) as error:
            client.settle(PREIMAGE, deadline=110.0, submission_allowed=lambda: enabled)
        assert "private" not in str(error.value)
    assert channel.calls == [
        (hold.SETTLE_METHOD, invoices_pb2.SettleInvoiceMsg(preimage=bytes.fromhex(PREIMAGE))),
    ]
    assert channel.closed
