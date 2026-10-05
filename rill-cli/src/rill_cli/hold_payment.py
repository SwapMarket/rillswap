"""Pay an LN to BTC hold invoice from the user's LND (RS-004, client side).

The provider funds only after the hold is accepted, and it checks that every
accepted HTLC expires at or after ``min_incoming_htlc_expiry_height``; a
payment whose final hop expires earlier would be refused and fail back, so
the client checks the planned final expiry itself before submitting.
"""

from __future__ import annotations

import math
import threading
import time
from typing import TYPE_CHECKING, Literal

from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_payment_observation import (
    LndNotSyncedError,
    LndObservationError,
    LndUnavailableError,
)
from rill_provider.lnd_payment_send import LndPaymentSender
from rill_provider.payment_dispatch_record import PaymentAuthority

from rill_cli.live_swap import SwapError

if TYPE_CHECKING:
    import os
    from collections.abc import Callable

    from rill_core.wire.messages import InvoiceBinding
    from rill_core.wire.types import NetworkIdentity
    from rill_provider.lnd_payment_send import PreparedPayment

type HoldStatus = Literal["IN_FLIGHT", "SUCCEEDED", "FAILED", "UNKNOWN"]

# LND reports itself unsynced for a moment after every block; planning and
# the pre-submission attestation are retried within this budget.
SYNC_BUDGET_SECONDS = 30.0
# SendToRouteV2 returns only when the HTLC resolves, which for a hold is after
# our own claim. The submission therefore runs aside, and pay() returns once
# LND tracks the payment as in flight.
SUBMIT_BUDGET_SECONDS = 60.0
POLL_SECONDS = 0.5


_AMBIGUOUS = (
    "hold invoice payment outcome unknown; keep the recovery file. If the payment "
    "is held, the provider funds and you claim with rill recover, or it is "
    "canceled and fails back after the provider's funding window; "
    "check `lncli listpayments` and do not retry payment"
)


class HoldPaymentError(SwapError):
    """The hold stopped; unresolved submissions require payment inspection."""


class LndHoldPayer:
    """Explicit-route submission of one hold invoice with a checked final expiry."""

    _expected_payer: PaymentAuthority | None = None

    def __init__(
        self,
        *,
        port: int,
        tls_certificate_path: str | os.PathLike[str],
        macaroon_path: str | os.PathLike[str],
        network: NetworkIdentity,
        expected_payer: PaymentAuthority | None = None,
    ) -> None:
        """Configure only; no credential read or network dial."""
        if expected_payer is not None:
            if not isinstance(expected_payer, PaymentAuthority):
                raise HoldPaymentError("explicit source payer authority required")
            expected_payer = PaymentAuthority(expected_payer.node_pubkey, expected_payer.network)
            if expected_payer.network != network:
                raise HoldPaymentError("source payer network differs from configuration")
        self._expected_payer = expected_payer
        self._sender = LndPaymentSender(
            host="127.0.0.1",
            port=port,
            tls_certificate_path=tls_certificate_path,
            macaroon_path=macaroon_path,
            network=network,
        )

    def pay(  # noqa: PLR0913 - signed route bounds and independent submission authority
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        min_final_expiry_height: int,
        max_expiry_height: int,
        fee_limit_sat: int,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> HoldStatus:
        """Submit one payment whose final hop expires at or after the minimum.

        Returns LND's status: ``IN_FLIGHT`` is the expected answer for an
        accepted hold; the client then waits for the provider's funding.
        Optional original-lifetime authority caps planning and submission,
        including queued daemon work and the sender's actual RPC boundary.
        The predicate must be thread-safe, nonconsuming, and independent of
        crypto-context lifetime. Already-started RPCs may outlive this method;
        late tracked statuses are knowledge, not renewed signing authority.
        """
        if deadline is not None and (
            type(deadline) not in (int, float) or not math.isfinite(deadline)
        ):
            raise HoldPaymentError("hold payment submission deadline invalid")
        planning_deadline = time.monotonic() + SYNC_BUDGET_SECONDS
        if deadline is not None:
            planning_deadline = min(planning_deadline, deadline)
        while True:
            _require_submission(planning_deadline, submission_allowed)
            try:
                payment = self._sender.prepare(
                    bolt11,
                    invoice_binding=invoice_binding,
                    fee_limit_sat=fee_limit_sat,
                    max_expiry_height=max_expiry_height,
                )
                break
            except LndNotSyncedError:  # planning only; nothing was sent
                if time.monotonic() >= planning_deadline:
                    raise
                time.sleep(min(POLL_SECONDS, max(0, planning_deadline - time.monotonic())))
        _require_submission(planning_deadline, submission_allowed)
        if self._expected_payer is not None and payment.payer != self._expected_payer:
            raise HoldPaymentError("planned payment source differs from pinned payer")
        request = router_pb2.SendToRouteRequest.FromString(payment.request)
        if not request.route.hops or request.route.hops[-1].expiry < min_final_expiry_height:
            raise HoldPaymentError("planned route expires before the provider's minimum")
        _require_submission(planning_deadline, submission_allowed)
        return self._submit(payment, deadline=deadline, submission_allowed=submission_allowed)

    def _submit(
        self,
        payment: PreparedPayment,
        *,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> HoldStatus:
        """Send aside; return when LND tracks it, or when the send itself ends."""
        submission_deadline = time.monotonic() + SUBMIT_BUDGET_SECONDS
        if deadline is not None:
            submission_deadline = min(submission_deadline, deadline)
        while True:
            _require_submission(submission_deadline, submission_allowed)
            box: list[HoldStatus | LndObservationError] = []
            done = threading.Event()

            def send(
                box: list[HoldStatus | LndObservationError] = box, done: threading.Event = done
            ) -> None:
                try:
                    _require_submission(submission_deadline, submission_allowed)
                    if deadline is None and submission_allowed is None:
                        outcome = self._sender.send(payment)
                    else:
                        outcome = self._sender.send(
                            payment,
                            deadline=submission_deadline,
                            submission_allowed=submission_allowed,
                        )
                    box.append(outcome.status)
                except LndObservationError as error:
                    box.append(error)
                finally:
                    done.set()

            threading.Thread(target=send, name="hold-payment", daemon=True).start()
            while not done.wait(min(POLL_SECONDS, max(0, submission_deadline - time.monotonic()))):
                if self._polled(payment.payment_hash) in ("IN_FLIGHT", "SUCCEEDED"):
                    return "IN_FLIGHT"
                if time.monotonic() >= submission_deadline:
                    raise HoldPaymentError(_AMBIGUOUS)
            (outcome,) = box
            if not isinstance(outcome, LndObservationError):
                return outcome
            # Unsynced is raised by the attestation before anything is sent.
            if isinstance(outcome, LndNotSyncedError) and time.monotonic() < submission_deadline:
                time.sleep(min(POLL_SECONDS, max(0, submission_deadline - time.monotonic())))
                continue
            try:
                status = self.status(payment.payment_hash)
            except LndObservationError:
                raise HoldPaymentError(_AMBIGUOUS) from None
            if status == "UNKNOWN":  # the call ended and LND has no payment
                raise outcome
            return status

    def _polled(self, payment_hash: str) -> HoldStatus | None:
        try:  # an accepted hold never reaches a final state before our claim
            if self._expected_payer is not None:
                return self._sender.track(
                    payment_hash, current=True, payer=self._expected_payer
                ).status
            return self._sender.track(payment_hash, current=True).status
        except LndObservationError:
            return None  # not yet known; the send is still running

    def status(self, payment_hash: str) -> HoldStatus:
        """Return the tracked status of the payment (``UNKNOWN`` when LND has none)."""
        if self._expected_payer is not None:
            return self._sender.track(payment_hash, payer=self._expected_payer).status
        return self._sender.track(payment_hash).status


def _require_submission(deadline: float, submission_allowed: Callable[[], bool] | None) -> None:
    """Fence both sides of nonconsuming permission checks before new work."""
    allowed = time.monotonic() < deadline
    if allowed and submission_allowed is not None:
        try:
            allowed = submission_allowed() is True
        except Exception:  # noqa: BLE001 - callback details may contain secrets
            allowed = False
    if not allowed or time.monotonic() >= deadline:
        raise LndUnavailableError(
            "hold payment submission authority expired or unavailable; keep the recovery file, "
            "check `lncli listpayments`, and do not retry payment"
        )
