"""Hold submission shares the original budget without losing payment knowledge."""

from __future__ import annotations

import threading
from unittest.mock import Mock

import pytest
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndUnavailableError
from rill_provider.lnd_payment_send import PaymentOutcome
from test_hold_payment import _payer

from rill_cli import hold_payment
from rill_cli.hold_payment import HoldPaymentError, LndHoldPayer


def _pay(payer: LndHoldPayer, **guards: object) -> str:
    return payer.pay(
        "lnbcrt1hold",
        invoice_binding=Mock(),
        min_final_expiry_height=1035,
        max_expiry_height=1300,
        fee_limit_sat=100,
        **guards,
    )


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), True, "110", 99.0, 100.0])
def test_invalid_or_due_deadline_never_plans_or_submits(
    monkeypatch: pytest.MonkeyPatch,
    deadline: object,
) -> None:
    payer, sender = _payer(1035)
    monkeypatch.setattr(hold_payment.time, "monotonic", lambda: 100.0)
    with pytest.raises((HoldPaymentError, LndUnavailableError)):
        _pay(payer, deadline=deadline)
    sender.prepare.assert_not_called()
    sender.send.assert_not_called()


@pytest.mark.parametrize("reason", ["expired", "revoked", "callback error"])
def test_successful_planning_cannot_renew_submission_authority(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    payer, sender = _payer(1035)
    payment = sender.prepare.return_value
    clock = {"mono": 100.0}
    enabled = True
    monkeypatch.setattr(hold_payment.time, "monotonic", lambda: clock["mono"])

    def prepare(*_args: object, **_kwargs: object) -> object:
        nonlocal enabled
        if reason == "expired":
            clock["mono"] = 110.0
        else:
            enabled = False
        return payment

    def allowed() -> bool:
        if not enabled and reason == "callback error":
            raise RuntimeError("private invoice data")
        return enabled

    sender.prepare.side_effect = prepare
    thread = Mock(side_effect=AssertionError("no expired queued submission"))
    monkeypatch.setattr(hold_payment.threading, "Thread", thread)
    with pytest.raises(LndUnavailableError, match="submission authority") as error:
        _pay(payer, deadline=110.0, submission_allowed=allowed)
    assert "private invoice data" not in str(error.value)
    sender.send.assert_not_called()
    thread.assert_not_called()


@pytest.mark.parametrize("budget", [10.0, 600.0])
def test_guarded_daemon_forwards_one_capped_absolute_deadline_and_original_predicate(
    monkeypatch: pytest.MonkeyPatch,
    budget: float,
) -> None:
    payer, sender = _payer(1035)
    monkeypatch.setattr(hold_payment.time, "monotonic", lambda: 100.0)

    def allowed() -> bool:
        return True

    assert _pay(payer, deadline=100.0 + budget, submission_allowed=allowed) == "IN_FLIGHT"
    sender.send.assert_called_once_with(
        sender.prepare.return_value,
        deadline=100.0 + min(60.0, budget),
        submission_allowed=allowed,
    )
    assert "deadline" not in sender.prepare.call_args.kwargs


@pytest.mark.parametrize("reason", ["expired", "revoked"])
def test_scheduled_daemon_rechecks_authority_before_calling_sender(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    payer, sender = _payer(1035)
    sender.track.return_value = PaymentOutcome("UNKNOWN")
    clock = {"mono": 100.0}
    enabled = True
    monkeypatch.setattr(hold_payment.time, "monotonic", lambda: clock["mono"])

    def thread(*, target: object, **_kwargs: object) -> Mock:
        def start() -> None:
            nonlocal enabled
            if reason == "expired":
                clock["mono"] = 110.0
            else:
                enabled = False
            target()

        return Mock(start=start)

    monkeypatch.setattr(hold_payment.threading, "Thread", thread)
    with pytest.raises(LndUnavailableError, match="submission authority"):
        _pay(payer, deadline=110.0, submission_allowed=lambda: enabled)
    sender.send.assert_not_called()


def test_retry_sleep_cannot_restart_submission_after_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payer, sender = _payer(1035)
    sender.send.side_effect = LndNotSyncedError("unsynced before submission")
    clock = {"mono": 100.0}
    monkeypatch.setattr(hold_payment.time, "monotonic", lambda: clock["mono"])
    monkeypatch.setattr(hold_payment.time, "sleep", lambda _duration: clock.update(mono=110.0))
    with pytest.raises(LndUnavailableError, match="submission authority"):
        _pay(payer, deadline=110.0)
    sender.send.assert_called_once()


@pytest.mark.parametrize("status", ["IN_FLIGHT", "SUCCEEDED", "UNKNOWN", "unavailable"])
def test_inflight_submission_remains_observable_after_caller_expiry(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    payer, sender = _payer(1035)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    clock = {"mono": 100.0}
    monkeypatch.setattr(hold_payment.time, "monotonic", lambda: clock["mono"])
    monkeypatch.setattr(hold_payment, "POLL_SECONDS", 0.01)

    def send(_payment: object, **_guards: object) -> PaymentOutcome:
        try:
            entered.set()
            assert release.wait(2)
            return PaymentOutcome("SUCCEEDED")
        finally:
            finished.set()

    def track(*_args: object, **_kwargs: object) -> PaymentOutcome:
        assert entered.wait(1)
        clock["mono"] = 110.0
        if status == "unavailable":
            raise LndUnavailableError("private tracking data")
        return PaymentOutcome(status)

    sender.send.side_effect = send
    sender.track.side_effect = track
    try:
        if status in {"IN_FLIGHT", "SUCCEEDED"}:
            assert _pay(payer, deadline=110.0) == "IN_FLIGHT"
        else:
            with pytest.raises(HoldPaymentError, match="outcome unknown") as error:
                _pay(payer, deadline=110.0)
            assert "do not retry payment" in str(error.value)
            assert "private tracking data" not in str(error.value)
    finally:
        release.set()
        assert finished.wait(1)
    sender.send.assert_called_once()
