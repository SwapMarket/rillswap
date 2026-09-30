"""Payment submission cannot outlive the original caller's authority."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from test_lnd_payment_send import NOW, PREIMAGE, _info, _prepare, _sender

from rill_provider import lnd_payment_send as sender
from rill_provider.lnd_payment_observation import LndUnavailableError

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    "deadline", [float("nan"), float("inf"), float("-inf"), True, "200", 100.0, 99.0]
)
def test_invalid_or_due_authority_never_connects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    deadline: object,
) -> None:
    client, _ = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    monkeypatch.setattr(sender.time, "monotonic", lambda: 100.0)
    connect = Mock(side_effect=AssertionError("no connection for invalid authority"))
    monkeypatch.setattr(client, "_connect", connect)
    with pytest.raises(LndUnavailableError, match="submission"):
        client.send(payment, deadline=deadline)
    connect.assert_not_called()


@pytest.mark.parametrize("answer", [False, None, 1, "true", "raises"])
def test_predicate_requires_affirmative_boolean_and_redacts_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    answer: object,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    allowed = Mock(return_value=answer)
    if answer == "raises":
        allowed.side_effect = RuntimeError("private invoice details")
    with pytest.raises(LndUnavailableError, match="authority unavailable") as error:
        client.send(payment, submission_allowed=allowed)
    assert "private invoice details" not in str(error.value)
    assert all(method != sender.SEND_METHOD for method, _ in channel.calls)


@pytest.mark.parametrize(
    "boundary",
    [
        "attestation expiry",
        "attestation revocation",
        "rpc setup expiry",
        "rpc setup revocation",
        "predicate expiry",
        "predicate invoice expiry",
    ],
)
def test_expiry_and_revocation_are_fenced_at_actual_rpc_submission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    clock = {"mono": 100.0, "wall": float(NOW)}
    enabled = True
    monkeypatch.setattr(sender.time, "monotonic", lambda: clock["mono"])
    monkeypatch.setattr(sender.time, "time", lambda: clock["wall"])

    def delayed_info() -> object:
        nonlocal enabled
        if boundary == "attestation expiry":
            clock["mono"] = 110.0
        elif boundary == "attestation revocation":
            enabled = False
        return _info()

    channel.unary_responses[sender.INFO_METHOD] = delayed_info
    original = channel.unary_unary
    setup_done = False

    def setup(method: str, **kwargs: object) -> object:
        nonlocal enabled, setup_done
        rpc = original(method, **kwargs)
        if method == sender.SEND_METHOD:
            setup_done = True
            if boundary == "rpc setup expiry":
                clock["mono"] = 110.0
            elif boundary == "rpc setup revocation":
                enabled = False
        return rpc

    monkeypatch.setattr(channel, "unary_unary", setup)

    def allowed() -> bool:
        if setup_done:
            if boundary == "predicate expiry":
                clock["mono"] = 110.0
            elif boundary == "predicate invoice expiry":
                clock["wall"] = float(payment.expires_at)
        return enabled

    with pytest.raises(LndUnavailableError):
        client.send(payment, deadline=110.0, submission_allowed=allowed)
    assert all(method != sender.SEND_METHOD for method, _ in channel.calls)
    assert channel.closed


@pytest.mark.parametrize("outer_budget", [5.0, 600.0])
def test_positive_authority_caps_rpc_budget_without_changing_payment_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outer_budget: float,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    monkeypatch.setattr(sender.time, "monotonic", lambda: 100.0)
    original = channel.unary_unary
    budgets: list[float] = []

    def setup(method: str, **kwargs: object) -> object:
        rpc = original(method, **kwargs)

        def call(request: object, **options: object) -> object:
            if method == sender.SEND_METHOD:
                budgets.append(options["timeout"])
            return rpc(request, **options)

        return call

    monkeypatch.setattr(channel, "unary_unary", setup)
    outcome = client.send(payment, deadline=100.0 + outer_budget, submission_allowed=lambda: True)
    assert outcome == sender.PaymentOutcome("SUCCEEDED", PREIMAGE)
    assert budgets == [min(60.0, outer_budget)]
    (request,) = [request for method, request in channel.calls if method == sender.SEND_METHOD]
    assert request.SerializeToString() == payment.request


def test_successful_inflight_rpc_is_not_reclassified_or_resubmitted_after_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, channel = _sender(tmp_path, monkeypatch, [])
    payment = _prepare(client)
    clock = {"mono": 100.0}
    monkeypatch.setattr(sender.time, "monotonic", lambda: clock["mono"])
    attempt = channel.unary_responses[sender.SEND_METHOD]

    def late_result() -> object:
        clock["mono"] = 200.0
        return attempt

    channel.unary_responses[sender.SEND_METHOD] = late_result
    assert client.send(payment, deadline=110.0) == sender.PaymentOutcome("SUCCEEDED", PREIMAGE)
    assert sum(method == sender.SEND_METHOD for method, _ in channel.calls) == 1
