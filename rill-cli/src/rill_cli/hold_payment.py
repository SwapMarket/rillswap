"""Pay an LN to BTC hold invoice from the user's LND (RS-004, client side).

The provider funds only after the hold is accepted, and it checks that every
accepted HTLC expires at or after ``min_incoming_htlc_expiry_height``; a
payment whose final hop expires earlier would be refused and fail back, so
the client checks the planned final expiry itself before submitting.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_payment_send import LndPaymentSender

from rill_cli.live_swap import SwapError

if TYPE_CHECKING:
    import os

    from rill_core.wire.messages import InvoiceBinding
    from rill_core.wire.types import NetworkIdentity

type HoldStatus = Literal["IN_FLIGHT", "SUCCEEDED", "FAILED", "UNKNOWN"]


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
        payment = self._sender.prepare(
            bolt11,
            invoice_binding=invoice_binding,
            fee_limit_sat=fee_limit_sat,
            max_expiry_height=max_expiry_height,
        )
        request = router_pb2.SendToRouteRequest.FromString(payment.request)
        if not request.route.hops or request.route.hops[-1].expiry < min_final_expiry_height:
            raise HoldPaymentError("planned route expires before the provider's minimum")
        return self._sender.send(payment).status

    def status(self, payment_hash: str) -> HoldStatus:
        """Return the tracked status of the payment (``UNKNOWN`` when LND has none)."""
        return self._sender.track(payment_hash).status
