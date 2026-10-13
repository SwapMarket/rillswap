"""Configured payer authority binds planning, sending and separate tracking channels."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.networks import REGTEST_CONSENSUS_PROFILE
from rill_provider import lnd_payment_send as sender_module
from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndProtocolError
from rill_provider.lnd_payment_send import PaymentOutcome, PreparedPayment
from rill_provider.payment_dispatch_record import PaymentAuthority
from test_hold_payment import _pay, _payer
from test_merchant_credit import NETWORK as FIXTURE_NETWORK
from test_merchant_credit import NODE

from rill_cli import hold_payment as module

if TYPE_CHECKING:
    from pathlib import Path

NETWORK = FIXTURE_NETWORK.model_copy(update={"consensus_profile": REGTEST_CONSENSUS_PROFILE})
EXPECTED = PaymentAuthority(NODE, NETWORK)
WRONG = PaymentAuthority("03" + NODE[2:], NETWORK)


def planned(sender: Mock, authority: PaymentAuthority = EXPECTED) -> PreparedPayment:
    request = sender.prepare.return_value.request
    return PreparedPayment(
        request=request,
        payment_hash="a" * 64,
        expires_at=2_000_000_000,
        max_expiry_height=1300,
        min_final_cltv_delta=40,
        payer=authority,
    )


def test_pinned_matching_source_uses_existing_sender_bound_request_once() -> None:
    payer, sender = _payer(1035)
    payer._expected_payer = EXPECTED  # noqa: SLF001 - constructor-free legacy fixture
    payment = planned(sender)
    sender.prepare.return_value = payment
    assert _pay(payer) == "IN_FLIGHT"
    sender.send.assert_called_once_with(payment)
    assert sender.prepare.call_args.kwargs.keys() == {
        "invoice_binding",
        "fee_limit_sat",
        "max_expiry_height",
    }


def test_real_sender_post_send_sync_failure_cannot_redispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payer, stub = _payer(1043)
    payment = planned(stub)
    request = router_pb2.SendToRouteRequest.FromString(payment.request)
    request.payment_hash = bytes.fromhex(payment.payment_hash)
    request.route.total_time_lock = 1100
    payment = replace(payment, request=request.SerializeToString())
    real = sender_module.LndPaymentSender(
        host="127.0.0.1",
        port=10009,
        network=NETWORK,
        tls_certificate_path=tmp_path / "unused.cert",
        macaroon_path=tmp_path / "unused.macaroon",
    )
    calls = Mock()
    counts = {"info": 0, "send": 0}

    def unary(method: str, *_args: object, **_kwargs: object) -> object:
        if method == sender_module.INFO_METHOD:
            counts["info"] += 1
            return lightning_pb2.GetInfoResponse(
                block_height=1000,
                synced_to_chain=counts["info"] != 2,
                chains=[{"chain": "bitcoin", "network": "regtest"}],
                identity_pubkey=NODE,
            )
        assert method == sender_module.SEND_METHOD
        counts["send"] += 1
        return lightning_pb2.HTLCAttempt(status="FAILED" if counts["send"] == 1 else "IN_FLIGHT")

    calls.unary.side_effect = unary
    calls.track.return_value = PaymentOutcome("UNKNOWN")
    monkeypatch.setattr(real, "_connect", lambda: nullcontext(calls))
    monkeypatch.setattr(real, "prepare", Mock(return_value=payment))
    payer._sender = real  # noqa: SLF001 - integrate the real send/track boundary
    payer._expected_payer = EXPECTED  # noqa: SLF001
    with pytest.raises(module.HoldPaymentError, match="do not retry payment"):
        _pay(payer)
    assert counts["send"] == 1


def test_wrong_prepared_source_never_sends_or_tracks() -> None:
    payer, sender = _payer(1035)
    payer._expected_payer = EXPECTED  # noqa: SLF001
    sender.prepare.return_value = planned(sender, WRONG)
    with pytest.raises(module.HoldPaymentError, match="source differs"):
        _pay(payer)
    sender.send.assert_not_called()
    sender.track.assert_not_called()


def test_unsynced_preparation_retry_does_not_learn_new_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payer, sender = _payer(1035)
    payer._expected_payer = EXPECTED  # noqa: SLF001
    monkeypatch.setattr(module, "POLL_SECONDS", 0.001)
    sender.prepare.side_effect = [LndNotSyncedError("catching up"), planned(sender, WRONG)]
    with pytest.raises(module.HoldPaymentError, match="source differs"):
        _pay(payer)
    assert sender.prepare.call_count == 2
    sender.send.assert_not_called()


def test_submission_drift_cannot_fall_back_to_another_nodes_failed_status() -> None:
    payer, sender = _payer(1035)
    payer._expected_payer = EXPECTED  # noqa: SLF001
    sender.prepare.return_value = planned(sender)
    sender.send.side_effect = LndProtocolError("submission payer changed")

    def bound_track(payment_hash: str, *, payer: PaymentAuthority) -> PaymentOutcome:
        assert payment_hash == "a" * 64
        assert payer == EXPECTED
        raise LndProtocolError("tracking payer changed")

    sender.track.side_effect = bound_track
    with pytest.raises(module.HoldPaymentError, match="outcome unknown"):
        _pay(payer)
    sender.track.assert_called_once_with("a" * 64, payer=EXPECTED)
    sender.send.assert_called_once()


def test_pinned_polling_and_status_use_same_authority() -> None:
    payer, sender = _payer(1035)
    payer._expected_payer = EXPECTED  # noqa: SLF001
    sender.track.return_value = PaymentOutcome("IN_FLIGHT", payer=NODE)
    assert payer._polled("a" * 64) == "IN_FLIGHT"  # noqa: SLF001
    sender.track.assert_called_with("a" * 64, current=True, payer=EXPECTED)
    assert payer.status("a" * 64) == "IN_FLIGHT"
    sender.track.assert_called_with("a" * 64, payer=EXPECTED)
    sender.track.side_effect = LndProtocolError("another tracking node")
    assert payer._polled("a" * 64) is None  # noqa: SLF001
    with pytest.raises(LndProtocolError):
        payer.status("a" * 64)


def test_inert_constructor_validates_network_without_reading_credentials(tmp_path: Path) -> None:
    payer = module.LndHoldPayer(
        port=10009,
        tls_certificate_path=tmp_path / "missing-tls",
        macaroon_path=tmp_path / "missing-mac",
        network=NETWORK,
        expected_payer=EXPECTED,
    )
    assert payer._expected_payer == EXPECTED  # noqa: SLF001
    wrong_network = NETWORK.model_copy(update={"deployment_namespace": "another-source"})
    with pytest.raises(module.HoldPaymentError, match="network differs"):
        module.LndHoldPayer(
            port=10009,
            tls_certificate_path=tmp_path / "missing-tls",
            macaroon_path=tmp_path / "missing-mac",
            network=NETWORK,
            expected_payer=PaymentAuthority(NODE, wrong_network),
        )
    assert not list(tmp_path.iterdir())
