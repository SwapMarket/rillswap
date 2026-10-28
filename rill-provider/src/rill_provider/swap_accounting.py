"""Durable per-swap accounting: the ledger vocabulary and each swap's economics.

From store schema v18 the live session store appends ledger rows in the same
transaction as the swap event they describe: a firm offer, an acceptance, a
terminal outcome (with the revenue or loss it realized), and every realized
cost an engine measured (LN routing fee, BTC claim, funding and refund fees,
EVM gas). Swaps accepted before the upgrade have no ``accepted`` row, so a
report can tell them apart instead of treating a missing cost as zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from rill_core.wire.messages import (
    BtcToLnEconomics,
    Erc20ToLnEconomics,
    LnToBtcEconomics,
    LnToErc20Economics,
)

if TYPE_CHECKING:
    from rill_core.wire.messages import AnyContractTerms

SATS_PER_BTC = 100_000_000
# Events. ``completed`` carries the revenue in sat, ``lost`` the principal lost.
OFFERED = "offered"
ACCEPTED = "accepted"
COMPLETED = "completed"
FAILED = "failed"
LOST = "lost"
REFUNDED = "refunded"
ABORTED = "aborted"
# Realized costs, in the unit the engine measured.
ROUTING_FEE = "routing_fee"  # msat
CLAIM_FEE = "claim_fee"  # sat
FUNDING_FEE = "funding_fee"  # sat
REFUND_FEE = "refund_fee"  # sat
GAS = "gas"  # wei of the EVM chain's native coin, never converted to sat
LEDGER_KINDS = (
    OFFERED,
    ACCEPTED,
    COMPLETED,
    FAILED,
    LOST,
    REFUNDED,
    ABORTED,
    ROUTING_FEE,
    CLAIM_FEE,
    FUNDING_FEE,
    REFUND_FEE,
    GAS,
)
LEDGER_UNITS = ("sat", "msat", "wei")
TERMINAL_KINDS = frozenset({COMPLETED, FAILED, LOST, REFUNDED, ABORTED})
TERMINAL_KIND_BY_STATE = {
    "CLAIMED": COMPLETED,
    "SETTLED": COMPLETED,
    "FAILED": FAILED,
    "LOST": LOST,
    "REFUNDED": REFUNDED,
    "ABORTED": ABORTED,
}
MAX_LEDGER_AMOUNT = 2**63 - 1  # SQLite INTEGER


@dataclass(frozen=True)
class LedgerEntry:
    """One appended ledger row; ``amount`` is None when it was not measured."""

    entry_id: int
    session_id: str
    recorded_at: int
    kind: str
    amount: int | None
    unit: str | None


@dataclass(frozen=True)
class SwapEconomics:
    """What one swap's signed terms commit to, in sat.

    ``volume_sat`` is the swapped amount (LN principal, on-chain payout, or the
    payout's quoted sat value), ``revenue_sat`` what the provider keeps on
    success before realized costs, and ``principal_sat`` the LN amount a
    forward swap pays out (what a LOST swap loses).
    """

    volume_sat: int
    revenue_sat: int
    principal_sat: int | None


def swap_economics(terms: AnyContractTerms) -> SwapEconomics | None:
    """Return the committed amounts of validated terms; None for an unknown kind."""
    economics = terms.economics
    if isinstance(economics, BtcToLnEconomics):
        principal = int(economics.lightning_principal_sat)
        return SwapEconomics(principal, int(economics.success_fee_sat), principal)
    if isinstance(economics, LnToBtcEconomics):
        # The hold invoice pays for the contract output; the rest is kept.
        revenue = int(economics.hold_invoice_sat) - int(economics.contract_amount_sat)
        return SwapEconomics(int(economics.nominal_payout_sat), revenue, None)
    if isinstance(economics, Erc20ToLnEconomics):
        principal = int(economics.lightning_principal_sat)
        fee = int(economics.success_fee_token_base) * SATS_PER_BTC
        revenue = fee // int(economics.rate_token_base_per_btc)  # at the quoted rate
        return SwapEconomics(principal, revenue, principal)
    if isinstance(economics, LnToErc20Economics):
        return SwapEconomics(
            int(economics.payout_sat_equivalent), int(economics.success_fee_sat), None
        )
    return None


def ledger_amount(value: object) -> int | None:
    """Return a storable amount, or None (unknown) for anything else.

    The ledger insert shares its transaction with a swap transition, so an
    unexpected value must never fail it: it is recorded as unmeasured.
    """
    if type(value) is not int or not 0 <= value <= MAX_LEDGER_AMOUNT:
        return None
    return value
