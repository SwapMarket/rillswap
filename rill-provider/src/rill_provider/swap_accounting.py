"""Durable per-swap accounting: the ledger vocabulary and each swap's economics.

The live session store appends ledger rows in the same transaction as the
swap event they describe: a firm offer, an acceptance, a terminal outcome
(with the revenue or loss it realized), and every realized cost an engine
measured (LN routing fee, BTC claim, funding and refund fees, EVM gas). A swap
without an ``accepted`` row is reported as inexact instead of treating a
missing cost as zero.
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
    from collections.abc import Iterable, Sequence

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
MSAT_PER_SAT = 1000
# The costs every swap of a profile records on its way to an outcome. One
# missing or unmeasured makes the swap's net inexact, never zero-cost. Gas is
# reported apart, in wei, so it never takes part here.
EXPECTED_COSTS: dict[tuple[str, str], tuple[str, ...]] = {
    ("btc-to-ln/v1", COMPLETED): (ROUTING_FEE, CLAIM_FEE),
    ("btc-to-ln/v1", LOST): (ROUTING_FEE,),
    ("erc20-to-ln/v1", COMPLETED): (ROUTING_FEE,),
    ("erc20-to-ln/v1", LOST): (ROUTING_FEE,),
    ("ln-to-btc/v1", COMPLETED): (FUNDING_FEE,),
    ("ln-to-btc/v1", REFUNDED): (FUNDING_FEE, REFUND_FEE),
}


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


@dataclass(frozen=True)
class SwapResult:
    """One closed swap's realized economics, from its ledger entries.

    ``exact`` is False when the swap has no ``accepted`` row or an expected
    cost (or the outcome amount) was not measured; ``net_msat``
    is then an upper bound, since every missing cost is non-negative.
    """

    session_id: str
    outcome: str
    closed_at: int
    revenue_sat: int
    routing_fee_msat: int
    mining_fee_sat: int
    lost_sat: int
    gas_wei: int
    exact: bool
    gas_measured: bool

    @property
    def costs_msat(self) -> int:
        """Return the measured routing and mining costs."""
        return self.routing_fee_msat + MSAT_PER_SAT * self.mining_fee_sat

    @property
    def net_msat(self) -> int:
        """Return revenue less measured costs and losses (gas excluded)."""
        return MSAT_PER_SAT * (self.revenue_sat - self.lost_sat) - self.costs_msat


def swap_result(entries: Sequence[LedgerEntry], profile: str) -> SwapResult | None:
    """Return one swap's result from all its entries; None while it is open."""
    terminal = [entry for entry in entries if entry.kind in TERMINAL_KINDS]
    if not terminal:
        return None
    closed = terminal[-1]
    outcome = closed.kind
    measured: dict[str, int] = {}
    unmeasured: set[str] = set()
    for entry in entries:
        if entry.kind == REFUND_FEE and outcome != REFUNDED:
            continue  # the client's claim won the race: the refund never confirmed
        if entry.amount is None:
            unmeasured.add(entry.kind)
        else:
            measured[entry.kind] = measured.get(entry.kind, 0) + entry.amount
    expected = EXPECTED_COSTS.get((profile, outcome), ())
    exact = (
        any(entry.kind == ACCEPTED for entry in entries)
        and not unmeasured & {COMPLETED, LOST}  # the revenue or loss itself
        and all(kind in measured and kind not in unmeasured for kind in expected)
        and not unmeasured & {ROUTING_FEE, CLAIM_FEE, FUNDING_FEE, REFUND_FEE}
    )
    return SwapResult(
        session_id=closed.session_id,
        outcome=outcome,
        closed_at=closed.recorded_at,
        revenue_sat=measured.get(COMPLETED, 0),
        routing_fee_msat=measured.get(ROUTING_FEE, 0),
        mining_fee_sat=sum(measured.get(kind, 0) for kind in (CLAIM_FEE, FUNDING_FEE, REFUND_FEE)),
        lost_sat=measured.get(LOST, 0),
        gas_wei=measured.get(GAS, 0),
        exact=exact,
        gas_measured=GAS not in unmeasured,
    )


@dataclass(frozen=True)
class LedgerSummary:
    """Activity in ``[since, until)`` and the swaps that closed in it."""

    since: int
    until: int
    offered: int
    accepted: int
    accepted_sat: int
    outcomes: dict[str, int]  # terminal kind -> swaps closed in the window
    revenue_sat: int
    costs_msat: int
    lost_sat: int
    net_msat: int
    gas_wei: int
    inexact: int  # closed swaps whose costs were not all recorded
    gas_unmeasured: int

    @property
    def closed(self) -> int:
        """Return the number of swaps that closed in the window."""
        return sum(self.outcomes.values())

    @property
    def success_percent(self) -> float | None:
        """Return completed over closed swaps, None when none closed."""
        return None if not self.closed else 100 * self.outcomes.get(COMPLETED, 0) / self.closed


def summarize(
    entries: Iterable[LedgerEntry], profile: str, since: int, until: int
) -> LedgerSummary:
    """Summarize ``LiveSessionStore.ledger_window(since, until)`` for one profile."""
    sessions: dict[str, list[LedgerEntry]] = {}
    offered = accepted = accepted_sat = 0
    for entry in entries:
        sessions.setdefault(entry.session_id, []).append(entry)
        if since <= entry.recorded_at < until and entry.kind in (OFFERED, ACCEPTED):
            if entry.kind == OFFERED:
                offered += 1
            else:
                accepted += 1
                accepted_sat += entry.amount or 0
    results = [
        result
        for session in sessions.values()
        if (result := swap_result(session, profile)) is not None
        and since <= result.closed_at < until
    ]
    outcomes: dict[str, int] = {}
    for result in results:
        outcomes[result.outcome] = outcomes.get(result.outcome, 0) + 1
    return LedgerSummary(
        since=since,
        until=until,
        offered=offered,
        accepted=accepted,
        accepted_sat=accepted_sat,
        outcomes=outcomes,
        revenue_sat=sum(result.revenue_sat for result in results),
        costs_msat=sum(result.costs_msat for result in results),
        lost_sat=sum(result.lost_sat for result in results),
        net_msat=sum(result.net_msat for result in results),
        gas_wei=sum(result.gas_wei for result in results),
        inexact=sum(not result.exact for result in results),
        gas_unmeasured=sum(not result.gas_measured for result in results),
    )
