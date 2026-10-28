"""Privacy-first funding selection: fewest inputs, then the least excess."""

from __future__ import annotations

import itertools
import random

import pytest

from rill_provider.funding_selection import (
    INPUT_WEIGHTS,
    Coin,
    fee_for_weight,
    input_kind,
    select_funding_inputs,
)

P2TR = INPUT_WEIGHTS["tr"]


def _coins(*values: int, confirmed: bool = True, weight: int = P2TR) -> list[Coin]:
    return [
        Coin(f"{index:064x}", index, value, weight, confirmed) for index, value in enumerate(values)
    ]


def _select(coins: list[Coin], value: int = 101_000, rate: int = 1_000, cap: int = 5_000):  # noqa: ANN202
    return select_funding_inputs(
        coins, value_sat=value, script_len=34, rate_sat_kvb=rate, max_fee_sat=cap
    )


def test_reported_signet_wallet_spends_the_one_coin_that_suffices() -> None:
    # bd9f7ed6...: Core consolidated all five coins at 2 sat/vB for a 101,000-sat contract.
    coins = _coins(99_840_846, 9_826, 830, 5_830, 7_870)
    selection = _select(coins)
    assert selection is not None
    assert [coin.value_sat for coin in selection.coins] == [99_840_846]
    assert selection.change
    # 1 P2TR input, contract and change outputs: 154 vB at 1 sat/vB.
    assert selection.fee_sat == 154


def test_least_excess_single_coin_goes_changeless() -> None:
    coins = _coins(150_000, 101_200, 400_000, 101_400)
    selection = _select(coins)
    assert selection is not None
    assert [coin.value_sat for coin in selection.coins] == [101_200]
    # 111 vB changeless; the 89-sat remainder is not worth a change output.
    assert (selection.changeless_fee_sat, selection.excess_sat) == (111, 89)
    assert not selection.change
    assert selection.fee_sat == 200


def test_fewest_inputs_win_over_a_tighter_multi_coin_fit() -> None:
    coins = _coins(60_000, 41_200, 900_000)
    selection = _select(coins)
    assert selection is not None
    assert [coin.value_sat for coin in selection.coins] == [900_000]


def test_least_excess_among_the_fewest_inputs() -> None:
    coins = _coins(60_000, 60_000, 45_000, 41_300, 70_000)
    selection = _select(coins)
    assert selection is not None
    # 60,000 + 41,300 leaves the least over the 101,000 payment and 2-input fee.
    assert sorted(coin.value_sat for coin in selection.coins) == [41_300, 60_000]
    assert not selection.change


def test_confirmed_coins_first_then_safe_unconfirmed_ones() -> None:
    confirmed = _coins(60_000, 60_000)
    pending = [Coin("ff" * 32, 0, 500_000, P2TR, confirmed=False)]
    selection = _select(confirmed + pending)
    assert selection is not None
    assert all(coin.confirmed for coin in selection.coins)
    assert len(selection.coins) == 2
    selection = _select(confirmed[:1] + pending)
    assert selection is not None
    assert selection.coins == tuple(pending)


def test_fee_cap_prefers_a_set_that_fits_then_leaves_refusal_to_the_builder() -> None:
    # Changeless 101,400 would pay 400 sats; 160,000 with change pays 154.
    coins = _coins(101_400, 160_000)
    selection = _select(coins, cap=300)
    assert selection is not None
    assert [coin.value_sat for coin in selection.coins] == [160_000]
    # Nothing fits a 1-sat cap: the best set still goes to Core, whose fee
    # check then refuses and releases exactly these inputs.
    selection = _select(coins, cap=1)
    assert selection is not None
    assert [coin.value_sat for coin in selection.coins] == [101_400]
    assert selection.fee_sat == 400


def test_uneconomic_and_insufficient_coins() -> None:
    # A 100-sat coin costs more than it is worth at 1 sat/vB... at 2 sat/vB.
    assert _select(_coins(100), value=1, rate=2_000) is None
    assert _select(_coins(50_000, 50_000)) is None
    assert _select([]) is None


def test_input_weights_set_the_fee() -> None:
    legacy = _coins(200_000, weight=INPUT_WEIGHTS["pkh"])
    selection = _select(legacy)
    assert selection is not None
    # 42 + 172 + 592 + 172 (change) = 978 WU: 245 vB.
    assert selection.fee_sat == 245


@pytest.mark.parametrize(
    ("weight", "rate", "fee"),
    [(396, 1_000, 99), (397, 1_000, 100), (396, 1_001, 100), (444, 100, 12), (1, 1, 1)],
)
def test_fee_rounds_vsize_then_sats_up_like_core(weight: int, rate: int, fee: int) -> None:
    assert fee_for_weight(weight, rate) == fee


@pytest.mark.parametrize(
    ("script", "descriptor", "kind"),
    [
        ("5120" + "11" * 32, "tr([d34db33f/86h]" + "22" * 32 + ")#x", "tr"),
        ("5120" + "11" * 32, "tr(" + "22" * 32 + ",pk(" + "33" * 32 + "))#x", None),
        ("0014" + "11" * 20, "wpkh(02" + "22" * 32 + ")#x", "wpkh"),
        ("a914" + "11" * 20 + "87", "sh(wpkh(02" + "22" * 32 + "))#x", "sh-wpkh"),
        ("a914" + "11" * 20 + "87", "sh(multi(1,02" + "22" * 32 + "))#x", None),
        ("76a914" + "11" * 20 + "88ac", "pkh(02" + "22" * 32 + ")#x", "pkh"),
        ("0020" + "11" * 32, "wsh(pk(02" + "22" * 32 + "))#x", None),
        ("0014" + "11" * 20, "tr(" + "22" * 32 + ")#x", None),  # inconsistent listing
    ],
)
def test_only_single_key_outputs_of_known_size(
    script: str, descriptor: str, kind: str | None
) -> None:
    assert input_kind(script, descriptor) == kind


def test_unsupported_request() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        select_funding_inputs([], value_sat=0, script_len=34, rate_sat_kvb=1_000, max_fee_sat=1)
    with pytest.raises(ValueError, match="unsupported"):
        select_funding_inputs([], value_sat=1, script_len=34, rate_sat_kvb=0, max_fee_sat=1)


@pytest.mark.parametrize("seed", range(40))
def test_search_matches_brute_force(seed: int) -> None:
    generator = random.Random(seed)  # noqa: S311 - reproducible fixtures, not keys
    values = [generator.randrange(1_000, 120_000) for _ in range(generator.randrange(2, 11))]
    weights = [generator.choice(list(INPUT_WEIGHTS.values())) for _ in values]
    coins = [
        Coin(f"{i:064x}", i, v, w, confirmed=True)
        for i, (v, w) in enumerate(zip(values, weights, strict=True))
    ]
    target, rate = (
        generator.randrange(20_000, 200_000),
        generator.choice([100, 1_000, 2_500, 25_000]),
    )
    selection = select_funding_inputs(
        coins, value_sat=target, script_len=34, rate_sat_kvb=rate, max_fee_sat=10**9
    )
    expected = None
    for count in range(1, len(coins) + 1):
        excesses = []
        for subset in itertools.combinations(coins, count):
            # Coins worth less than their own input fee are never spent.
            if any(c.value_sat * 4000 <= rate * c.weight for c in subset):
                continue
            weight = 42 + 172 + sum(c.weight for c in subset)
            excess = sum(c.value_sat for c in subset) - target - fee_for_weight(weight, rate)
            if excess >= 0:
                excesses.append(excess)
        if excesses:
            expected = (count, min(excesses))
            break
    if expected is None:
        assert selection is None
    else:
        assert selection is not None
        assert (len(selection.coins), selection.excess_sat) == expected


def test_large_wallets_stay_bounded() -> None:
    generator = random.Random(7)  # noqa: S311 - reproducible fixtures, not keys
    coins = _coins(*(generator.randrange(500, 40_000) for _ in range(3_000)))
    selection = _select(coins, value=250_000)
    assert selection is not None
    assert sum(coin.value_sat for coin in selection.coins) >= 250_000 + selection.changeless_fee_sat
