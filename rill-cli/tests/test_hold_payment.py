"""The client refuses a hold payment whose final hop expires before the provider's minimum."""

from __future__ import annotations

import threading
from unittest.mock import Mock

import pytest
from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndUnavailableError
from rill_provider.lnd_payment_send import PaymentOutcome

from rill_cli import hold_payment
from rill_cli.hold_payment import HoldPaymentError, LndHoldPayer
from rill_cli.live_swap import SwapError


def _payer(final_expiry: int) -> tuple[LndHoldPayer, Mock]:
    payer = LndHoldPayer.__new__(LndHoldPayer)
    sender = Mock()
    route = lightning_pb2.Route(
        hops=[lightning_pb2.Hop(expiry=final_expiry + 40), lightning_pb2.Hop(expiry=final_expiry)]
    )
    sender.prepare.return_value = Mock(
        request=router_pb2.SendToRouteRequest(route=route).SerializeToString()
    )
    sender.send.return_value = PaymentOutcome("IN_FLIGHT")
    payer._sender = sender  # noqa: SLF001
    return payer, sender


def _pay(payer: LndHoldPayer) -> str:
    return payer.pay(
        "lnbcrt1hold",
        invoice_binding=Mock(),
        min_final_expiry_height=1035,
        max_expiry_height=1300,
        fee_limit_sat=100,
    )


def test_a_final_expiry_at_the_minimum_is_sent() -> None:
    payer, sender = _payer(1035)
    assert _pay(payer) == "IN_FLIGHT"
    sender.send.assert_called_once()
    assert sender.prepare.call_args.kwargs == {
        "invoice_binding": sender.prepare.call_args.kwargs["invoice_binding"],
        "fee_limit_sat": 100,
        "max_expiry_height": 1300,
    }


def test_an_earlier_final_expiry_is_never_sent() -> None:
    payer, sender = _payer(1034)
    with pytest.raises(HoldPaymentError, match="expires before"):
        _pay(payer)
    sender.send.assert_not_called()
    assert issubclass(HoldPaymentError, SwapError)  # reported as a stopped swap, nothing at risk


def test_a_briefly_unsynced_lnd_is_retried_before_planning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hold_payment, "POLL_SECONDS", 0.01)
    payer, sender = _payer(1035)
    planned = sender.prepare.return_value
    sender.prepare.side_effect = [LndNotSyncedError("catching up"), planned]
    assert _pay(payer) == "IN_FLIGHT"
    assert sender.prepare.call_count == 2
    sender.send.assert_called_once()


def test_a_blocking_hold_send_returns_once_lnd_tracks_it_in_flight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hold_payment, "POLL_SECONDS", 0.01)
    payer, sender = _payer(1035)
    release = threading.Event()
    sender.send.side_effect = lambda _payment: release.wait(5) and PaymentOutcome("SUCCEEDED")
    sender.track.return_value = PaymentOutcome("IN_FLIGHT")
    try:
        assert _pay(payer) == "IN_FLIGHT"  # SendToRouteV2 is still waiting on the hold
    finally:
        release.set()
    sender.send.assert_called_once()


def test_a_failed_send_without_a_record_is_still_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hold_payment, "POLL_SECONDS", 0.01)
    payer, sender = _payer(1035)
    sender.send.side_effect = LndUnavailableError("connection refused")
    sender.track.return_value = PaymentOutcome("UNKNOWN")
    with pytest.raises(HoldPaymentError, match="outcome unknown"):
        _pay(payer)
    sender.send.assert_called_once()


@pytest.mark.parametrize("failure", [RuntimeError("private invoice"), ValueError("private key")])
def test_unexpected_worker_failure_preserves_unknown_guidance(failure: Exception) -> None:
    payer, sender = _payer(1035)
    sender.send.side_effect = failure
    sender.track.return_value = PaymentOutcome("UNKNOWN")
    with pytest.raises(HoldPaymentError, match="do not retry payment") as error:
        _pay(payer)
    assert "private" not in str(error.value)
    sender.send.assert_called_once()


def test_unknown_send_result_cannot_claim_nothing_was_sent() -> None:
    payer, sender = _payer(1035)
    sender.send.return_value = PaymentOutcome("UNKNOWN")
    with pytest.raises(HoldPaymentError, match="outcome unknown"):
        _pay(payer)
    sender.send.assert_called_once()


def test_an_untrackable_failed_send_is_ambiguous(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hold_payment, "POLL_SECONDS", 0.01)
    payer, sender = _payer(1035)
    sender.send.side_effect = LndUnavailableError("deadline")
    sender.track.side_effect = LndUnavailableError("down")
    with pytest.raises(HoldPaymentError, match="outcome unknown"):
        _pay(payer)
