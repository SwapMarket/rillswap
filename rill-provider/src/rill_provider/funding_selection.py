"""Privacy-first funding coin selection: fewest inputs, then the least excess.

Pure arithmetic over the funding wallet's own listed coins. Core still builds,
locks, and signs the transaction and makes the final change decision. Input
weights are upper bounds (72-byte ECDSA signatures), so a chosen set always
covers the fee Core computes for it at the same rate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

BASE_WEIGHT = 42  # version, locktime, segwit marker and flag, one-byte counts
CHANGE_OUTPUT_WEIGHT = 172  # 8-byte value, script length, 34-byte P2TR script
MIN_CHANGE_SAT = 330  # P2TR dust at Core's default dust relay rate
MAX_SEARCH_NODES = 200_000
MAX_SEARCH_DEPTH = 64  # larger sets keep the largest-coins seed
EXTRA_INPUT_COUNTS = 2  # larger sets tried only when no smaller one fits the cap
MAX_ONE_BYTE_COUNT = 252
WEIGHT_PER_KVB = 4000  # fee(sat) = rate(sat/kvB) * weight / 4000
# Signed input weight upper bounds by descriptor kind.
INPUT_WEIGHTS = {"tr": 230, "wpkh": 272, "sh-wpkh": 364, "pkh": 592}


@dataclass(frozen=True, slots=True)
class Coin:
    """One spendable wallet output and its signed input weight bound."""

    txid: str
    vout: int
    value_sat: int
    weight: int
    confirmed: bool


@dataclass(frozen=True, slots=True)
class FundingSelection:
    """Chosen inputs and the predicted outcome at the selection rate.

    ``excess_sat`` is what remains after the payment and the changeless fee;
    it becomes change when worth keeping, otherwise extra fee.
    """

    coins: tuple[Coin, ...]
    changeless_fee_sat: int
    excess_sat: int
    change: bool
    fee_sat: int  # predicted total fee, change output included when made


def input_kind(script_hex: str, descriptor: str) -> str | None:
    """Classify a single-key output whose signed size is known, else ``None``.

    Script trees, multisig, and anything else Core might spend differently
    stay out of explicit selection.
    """
    script = script_hex.lower()
    if len(script) == 68 and script.startswith("5120"):  # noqa: PLR2004
        return "tr" if descriptor.startswith("tr(") and "," not in descriptor else None
    if len(script) == 44 and script.startswith("0014"):  # noqa: PLR2004
        return "wpkh" if descriptor.startswith("wpkh(") else None
    if len(script) == 46 and script.startswith("a914") and script.endswith("87"):  # noqa: PLR2004
        return "sh-wpkh" if descriptor.startswith("sh(wpkh(") else None
    if len(script) == 50 and script.startswith("76a914") and script.endswith("88ac"):  # noqa: PLR2004
        return "pkh" if descriptor.startswith("pkh(") else None
    return None


def fee_for_weight(weight: int, rate_sat_kvb: int) -> int:
    """Core's fee for a transaction weight: vsize rounded up, then sats rounded up."""
    vsize = (weight + 3) // 4
    return -(-rate_sat_kvb * vsize // 1000)


def select_funding_inputs(
    coins: Sequence[Coin],
    *,
    value_sat: int,
    script_len: int,
    rate_sat_kvb: int,
    max_fee_sat: int,
) -> FundingSelection | None:
    """Pick the fewest inputs, then the least excess, confirmed coins first.

    Sets whose predicted fee fits ``max_fee_sat`` win. When none does, the
    best uncapped set is returned so the builder's signed-maximum check
    refuses it (and releases its inputs) exactly as before. ``None`` means
    these coins cannot pay ``value_sat`` at this rate at all.
    """
    if not (0 < script_len <= MAX_ONE_BYTE_COUNT and value_sat > 0 and rate_sat_kvb > 0):
        raise ValueError("funding selection request unsupported")
    request = _Request(value_sat, 4 * (9 + script_len), rate_sat_kvb, max_fee_sat)
    confirmed = [coin for coin in coins if coin.confirmed]
    pools = [confirmed] if len(confirmed) == len(coins) else [confirmed, list(coins)]
    budget = [MAX_SEARCH_NODES]
    for capped in (True, False):
        for pool in pools:
            found = _search(pool, request, capped=capped, budget=budget)
            if found is not None:
                return found
    return None


@dataclass(frozen=True, slots=True)
class _Request:
    value_sat: int
    output_weight: int
    rate_sat_kvb: int
    max_fee_sat: int

    def weight(self, count: int) -> int:
        """Weight of everything but the inputs themselves (no change output)."""
        return BASE_WEIGHT + self.output_weight + (8 if count > MAX_ONE_BYTE_COUNT else 0)

    def outcome(self, coins: Sequence[Coin], *, capped: bool) -> FundingSelection | None:
        weight = self.weight(len(coins)) + sum(coin.weight for coin in coins)
        changeless = fee_for_weight(weight, self.rate_sat_kvb)
        excess = sum(coin.value_sat for coin in coins) - self.value_sat - changeless
        if excess < 0:
            return None
        with_change = fee_for_weight(weight + CHANGE_OUTPUT_WEIGHT, self.rate_sat_kvb)
        change = excess - (with_change - changeless) >= MIN_CHANGE_SAT
        fee = with_change if change else changeless + excess
        if capped and fee > self.max_fee_sat:
            return None
        return FundingSelection(tuple(coins), changeless, excess, change, fee)


def _search(
    pool: Sequence[Coin], request: _Request, *, capped: bool, budget: list[int]
) -> FundingSelection | None:
    rate = request.rate_sat_kvb
    # Effective values scaled by WEIGHT_PER_KVB keep the bounds exact integers.
    scored = [(coin.value_sat * WEIGHT_PER_KVB - rate * coin.weight, coin) for coin in pool]
    scored = sorted(
        (item for item in scored if item[0] > 0),  # never spend a coin worth less than its fee
        key=lambda item: (-item[0], item[1].txid, item[1].vout),
    )
    effs = [eff for eff, _ in scored]
    items = [coin for _, coin in scored]
    prefix = [0]
    for eff in effs:
        prefix.append(prefix[-1] + eff)
    smallest = next(
        (
            count
            for count in range(1, len(items) + 1)
            if prefix[count] >= request.value_sat * WEIGHT_PER_KVB + rate * request.weight(count)
            and request.outcome(items[:count], capped=False) is not None
        ),
        None,
    )
    if smallest is None:
        return None
    for count in range(smallest, min(smallest + EXTRA_INPUT_COUNTS, len(items)) + 1):
        best = _best_of_size(items, effs, prefix, count, request, capped=capped, budget=budget)
        if best is not None:
            return best
    return None


def _best_of_size(  # noqa: PLR0913 - private search state
    items: list[Coin],
    effs: list[int],
    prefix: list[int],
    count: int,
    request: _Request,
    *,
    capped: bool,
    budget: list[int],
) -> FundingSelection | None:
    """Least-excess set of exactly ``count`` coins: bounded depth-first search.

    Seeded with the largest coins. An exhausted node budget keeps the best
    set found so far.
    """
    best = request.outcome(items[:count], capped=capped)
    if count > MAX_SEARCH_DEPTH:
        return best
    total_items = len(items)
    need = request.value_sat * WEIGHT_PER_KVB + request.rate_sat_kvb * request.weight(count)
    # Exact excess exceeds the scaled bound minus this rounding slack.
    slack = WEIGHT_PER_KVB + 3 * request.rate_sat_kvb
    chosen: list[int] = []

    def visit(start: int, total: int) -> None:
        nonlocal best
        remaining = count - len(chosen)
        if remaining == 0:
            found = request.outcome([items[index] for index in chosen], capped=capped)
            if found is not None and (best is None or found.excess_sat < best.excess_sat):
                best = found
            return
        for index in range(start, total_items - remaining + 1):
            if budget[0] <= 0:
                return
            budget[0] -= 1
            if total + prefix[index + remaining] - prefix[index] < need:
                return  # every later coin is smaller
            lowest = (
                total
                + effs[index]
                + prefix[total_items]
                - prefix[total_items - remaining + 1]
                - need
            )
            if best is not None and lowest >= WEIGHT_PER_KVB * best.excess_sat + slack:
                continue
            chosen.append(index)
            visit(index + 1, total + effs[index])
            chosen.pop()

    visit(0, 0)
    return best
