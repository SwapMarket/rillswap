"""Pay an LN to BTC hold invoice from the user's LND (RS-004, client side).

The provider funds only after the hold is accepted, and it checks that every
accepted HTLC expires at or after ``min_incoming_htlc_expiry_height``; a
payment whose final hop expires earlier would be refused and fail back, so
the client checks the planned final expiry itself before submitting.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Literal

from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndObservationError
from rill_provider.lnd_payment_send import LndPaymentSender

from rill_cli.live_swap import SwapError

if TYPE_CHECKING:
    import os

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
    "canceled and fails back after the provider's funding window"
)


class HoldPaymentError(SwapError):
    """The hold could not be paid as the terms require; nothing was sent."""


class LndHoldPayer:
    """Explicit-route submission of one hold invoice with a checked final expiry."""

    def __init__(
        self,
        *,
        port: int,
        tls_certificate_path: str | os.PathLike[str],
        macaroon_path: str | os.PathLike[str],
        network: NetworkIdentity,
    ) -> None:
        """Configure only; no credential read or network dial."""
        self._sender = LndPaymentSender(
            host="127.0.0.1",
            port=port,
            tls_certificate_path=tls_certificate_path,
            macaroon_path=macaroon_path,
            network=network,
        )

    def pay(
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        min_final_expiry_height: int,
        max_expiry_height: int,
        fee_limit_sat: int,
    ) -> HoldStatus:
        """Submit one payment whose final hop expires at or after the minimum.

        Returns LND's status: ``IN_FLIGHT`` is the expected answer for an
        accepted hold; the client then waits for the provider's funding.
        """
        deadline = time.monotonic() + SYNC_BUDGET_SECONDS
        while True:
            try:
                payment = self._sender.prepare(
                    bolt11,
                    invoice_binding=invoice_binding,
                    fee_limit_sat=fee_limit_sat,
                    max_expiry_height=max_expiry_height,
                )
                break
            except LndNotSyncedError:  # planning only; nothing was sent
                if time.monotonic() >= deadline:
                    raise
                time.sleep(POLL_SECONDS)
        request = router_pb2.SendToRouteRequest.FromString(payment.request)
        if not request.route.hops or request.route.hops[-1].expiry < min_final_expiry_height:
            raise HoldPaymentError("planned route expires before the provider's minimum")
        return self._submit(payment)

    def _submit(self, payment: PreparedPayment) -> HoldStatus:
        """Send aside; return when LND tracks it, or when the send itself ends."""
        deadline = time.monotonic() + SUBMIT_BUDGET_SECONDS
        while True:
            box: list[HoldStatus | LndObservationError] = []
            done = threading.Event()

            def send(
                box: list[HoldStatus | LndObservationError] = box, done: threading.Event = done
            ) -> None:
                try:
                    box.append(self._sender.send(payment).status)
                except LndObservationError as error:
                    box.append(error)
                finally:
                    done.set()

            threading.Thread(target=send, name="hold-payment", daemon=True).start()
            while not done.wait(POLL_SECONDS):
                if self._polled(payment.payment_hash) in ("IN_FLIGHT", "SUCCEEDED"):
                    return "IN_FLIGHT"
                if time.monotonic() >= deadline:
                    raise HoldPaymentError(_AMBIGUOUS)
            (outcome,) = box
            if not isinstance(outcome, LndObservationError):
                return outcome
            # Unsynced is raised by the attestation before anything is sent.
            if isinstance(outcome, LndNotSyncedError) and time.monotonic() < deadline:
                time.sleep(POLL_SECONDS)
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
            return self._sender.track(payment_hash, current=True).status
        except LndObservationError:
            return None  # not yet known; the send is still running

    def status(self, payment_hash: str) -> HoldStatus:
        """Return the tracked status of the payment (``UNKNOWN`` when LND has none)."""
        return self._sender.track(payment_hash).status
