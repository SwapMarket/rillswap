"""Pay an LN to BTC hold invoice from a Lightning wallet the CLI does not control.

The provider funds the on-chain contract only after its node holds the
payment (RS-004), and the payment then stays held until the claim reveals the
preimage. Wallets without hold invoice support may show it as failed after a
timeout although the HTLC is still held; paying again would be refused. The
invoice is decoded offline (``rill_core.wire.bolt11``), so no LND is needed.
"""

from __future__ import annotations

import io
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, Literal

import segno
from rill_core.errors import ValidationError
from rill_core.wire.bolt11 import invoice_binding

from rill_cli.live_swap import SwapError

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.wire.bolt11 import EcdsaAuthenticator
    from rill_core.wire.messages import InvoiceBinding
    from rill_core.wire.types import NetworkIdentity

DO_NOT_PAY_AGAIN: Final = (
    "Until the claim settles it, your wallet may show the payment as pending, or as failed "
    "after a timeout; this is normal. Do not pay again."
)


def offline_invoice_decoder(
    network: NetworkIdentity, crypto: EcdsaAuthenticator
) -> Callable[[str], InvoiceBinding]:
    """Decode the provider's hold invoice without a Lightning node."""

    def decode(bolt11: str) -> InvoiceBinding:
        try:
            return invoice_binding(bolt11, network, crypto=crypto)
        except ValidationError as error:
            raise SwapError(f"{error}; nothing was paid") from None

    return decode


def invoice_qr(bolt11: str) -> str:
    """Return a terminal QR code of the ``lightning:`` URI (upper case, as BOLT 11 advises)."""
    out = io.StringIO()
    segno.make(f"lightning:{bolt11}".upper(), error="l", micro=False).terminal(
        out=out, compact=True
    )
    return out.getvalue().rstrip("\n")


class ExternalWalletPayer:
    """Show the hold invoice once; the user's own wallet pays it.

    ``pay`` returns ``"SHOWN"``: whether and how the wallet paid is not
    observable here, so the swap waits for the provider's funding, which
    proves the payment is held.
    """

    def __init__(self, *, write: Callable[[str], None], qr: bool = True) -> None:
        """Configure only; nothing is shown until ``pay``."""
        self._write = write
        self._qr = qr

    def pay(  # noqa: PLR0913 - the HoldPayer contract
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        min_final_expiry_height: int,
        max_expiry_height: int,
        fee_limit_sat: int,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> Literal["SHOWN"]:
        """Print amount, deadline, QR code, invoice text and guidance."""
        del max_expiry_height, fee_limit_sat  # the external wallet chooses its route
        if not _allowed(deadline, submission_allowed):
            raise SwapError("the swap's payment window closed before the invoice was shown")
        expires = datetime.fromtimestamp(invoice_binding.expires_at, UTC)
        lines = [
            (
                f"Pay {int(invoice_binding.amount_msat) // 1000} sat from your Lightning wallet "
                f"before {expires:%Y-%m-%d %H:%M:%S} UTC:"
            ),
            *([invoice_qr(bolt11)] if self._qr else []),
            bolt11,
            f"payment hash {invoice_binding.payment_hash}",
            "The provider funds the on-chain contract only after your payment is held. "
            + DO_NOT_PAY_AGAIN,
            (
                "Your wallet chooses the route, its fee and its expiry (--max-routing-fee-sat "
                "does not apply); the provider refuses a payment that expires before block "
                f"{min_final_expiry_height}."
            ),
        ]
        self._write("\n".join(lines))
        return "SHOWN"


def _allowed(deadline: float | None, submission_allowed: Callable[[], bool] | None) -> bool:
    if deadline is not None and time.monotonic() >= deadline:
        return False
    if submission_allowed is None:
        return True
    try:
        return submission_allowed() is True
    except Exception:  # noqa: BLE001 - callback details may contain secrets
        return False
