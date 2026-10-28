"""The LN-to-BTC claim holds its fee, then is bumped toward the maximum until it confirms."""

from __future__ import annotations

import pytest

from rill_cli.claim_watcher import ClaimWatcher, ClaimWatchError, claim_fee_target
from rill_cli.refund_watcher import ChainView

VSIZE = 150


class Chain:
    def __init__(self) -> None:
        self.tip = 100
        self.unspent = True
        self.mined: str | None = None
        self.sent: list[tuple[str, int]] = []

    def view(self) -> ChainView:
        return ChainView(self.tip, self.unspent)

    def confirmations(self, txid: str) -> int | None:
        return 1 if txid == self.mined else None

    def sign(self, fee: int, _tip: int) -> tuple[bytes, str, int, int]:
        return f"{fee}".encode(), f"{fee:064x}", fee, VSIZE

    def submit(self, raw: bytes, txid: str) -> bool:
        self.sent.append((txid, int(raw)))
        return True


def _watcher(fake: Chain, **overrides: object) -> ClaimWatcher:
    arguments: dict[str, object] = {
        "initial_fee_sat": 300,
        "max_fee_sat": 3_300,
        "deadline_height": 110,
        "chain": fake.view,
        "confirmations": fake.confirmations,
        "sign": fake.sign,
        "submit": fake.submit,
        "report": lambda _line: None,
    }
    arguments.update(overrides)
    return ClaimWatcher(**arguments)  # type: ignore[arg-type]


def test_the_fee_holds_then_rises_linearly_to_the_maximum_in_the_last_quarter() -> None:
    target = {
        tip: claim_fee_target(
            initial=300, maximum=3_300, start_height=100, deadline_height=110, tip=tip
        )
        for tip in (99, 100, 105, 107, 108, 109, 110, 200)
    }
    # A 10-block window ramps over its last ceil(10 / 4) = 3 blocks.
    assert target == {
        99: 300,
        100: 300,
        105: 300,
        107: 300,
        108: 1_300,
        109: 2_300,
        110: 3_300,
        200: 3_300,
    }
    assert (
        claim_fee_target(initial=300, maximum=100, start_height=0, deadline_height=0, tip=0) == 300
    )
    # Default provider timing: about 135 blocks, so the exact reserve holds for
    # 101 blocks and the claim pays more only in the last 34.
    assert {
        tip: claim_fee_target(
            initial=155, maximum=5_000, start_height=3, deadline_height=138, tip=tip
        )
        for tip in (3, 104, 105, 138)
    } == {3: 155, 104: 155, 105: 155 + 4_845 // 34, 138: 5_000}
    # One-block window: the deadline block already pays the maximum.
    assert [
        claim_fee_target(initial=300, maximum=900, start_height=9, deadline_height=10, tip=tip)
        for tip in (9, 10)
    ] == [300, 900]


def test_one_attempt_per_block_until_it_confirms() -> None:
    chain = Chain()
    watcher = _watcher(chain)
    assert watcher.step() is None
    assert watcher.step() is None  # same block: rebroadcast only
    assert [fee for _txid, fee in chain.sent] == [300, 300]
    chain.tip = 105  # still the initial fee: rebroadcast, no new attempt
    assert watcher.step() is None
    assert [attempt.fee_sat for attempt in watcher.attempts] == [300]
    assert [fee for _txid, fee in chain.sent] == [300, 300, 300]
    chain.tip = 108
    assert watcher.step() is None
    assert [attempt.fee_sat for attempt in watcher.attempts] == [300, 1_300]
    chain.unspent, chain.mined = False, watcher.attempts[0].txid  # the first one won
    assert watcher.step() == ("claim_confirmed", watcher.attempts[0].txid)


def test_a_bump_must_beat_the_previous_attempt_by_the_relay_increment() -> None:
    chain = Chain()
    watcher = _watcher(chain, max_fee_sat=400, deadline_height=1_000)
    watcher.step()
    chain.tip = 101  # scheduled 300: below 300 + 150
    watcher.step()
    assert [attempt.fee_sat for attempt in watcher.attempts] == [300]
    chain.tip = 2_000  # the maximum 400 still does not beat 450
    watcher.step()
    assert len(watcher.attempts) == 1


def test_a_foreign_spend_is_reported_not_retried() -> None:
    chain = Chain()
    watcher = _watcher(chain)
    watcher.step()
    chain.unspent = False  # the provider's refund, not our claim
    assert watcher.step() == ("outpoint_spent_elsewhere", None)


def test_an_unavailable_chain_view_waits() -> None:
    chain = Chain()
    watcher = _watcher(chain, chain=lambda: None)
    assert watcher.step() is None
    assert chain.sent == []


def test_unknown_outpoint_still_detects_our_confirmed_claim() -> None:
    chain = Chain()
    watcher = _watcher(chain, chain=lambda: None)
    assert watcher.step() is None
    assert watcher.attempts == []
    active = _watcher(chain)
    assert active.step() is None
    chain.mined = active.attempts[0].txid
    active._chain = lambda: None  # noqa: SLF001 - Core no longer sees a chain UTXO
    assert active.step() == ("claim_confirmed", chain.mined)


def test_timeout_and_bounds() -> None:
    chain = Chain()
    with pytest.raises(TimeoutError):
        _watcher(chain, sleep=lambda _s: None).run(timeout=0)
    with pytest.raises(ClaimWatchError):
        _watcher(chain, initial_fee_sat=0)
    bad = _watcher(chain, sign=lambda fee, _tip: (b"1", "00" * 32, fee + 1, VSIZE))
    with pytest.raises(ClaimWatchError, match="differs"):
        bad.step()


def test_nothing_is_signed_after_the_deadline() -> None:
    chain = Chain()
    chain.tip = 111
    assert _watcher(chain).step() == ("claim_window_passed", None)
    chain.tip = 110
    watcher = _watcher(chain)
    watcher.step()
    chain.tip = 111
    watcher.step()  # rebroadcast only
    assert len(watcher.attempts) == 1
    assert chain.sent == [(watcher.attempts[0].txid, 3_300)] * 2


def test_a_recorded_claim_is_only_observed_until_it_confirms() -> None:
    fake = Chain()
    recorded = "ab" * 32
    depth: dict[str, object] = {recorded: None}
    signed: list[int] = []

    def sign(fee: int, tip: int) -> tuple[bytes, str, int, int]:
        signed.append(fee)
        return fake.sign(fee, tip)

    watcher = _watcher(
        fake,
        chain=lambda: None,
        confirmations=depth.get,
        sign=sign,
        recorded_txids=(recorded,),
    )
    # The output is unavailable (spent or unknown): unknown, zero, negative
    # (conflicted) or malformed depths of the recorded claim prove nothing.
    for unproven in (None, 0, -1, True, "1"):
        depth[recorded] = unproven
        assert watcher.step() is None
    assert (signed, fake.sent, watcher.attempts) == ([], [], [])
    depth[recorded] = 1
    assert watcher.step() == ("claim_confirmed", recorded)
    assert (signed, fake.sent, watcher.attempts) == ([], [], [])


def test_a_definitively_spent_view_still_prefers_a_confirmed_recorded_claim() -> None:
    fake = Chain()
    fake.unspent = False
    recorded = "cd" * 32
    watcher = _watcher(fake, recorded_txids=(recorded,))
    assert watcher.step() == ("outpoint_spent_elsewhere", None)
    fake.mined = recorded
    assert watcher.step() == ("claim_confirmed", recorded)


@pytest.mark.parametrize("recorded", [["ab" * 32], ("AB" * 32,), ("ab" * 31,), (b"ab" * 32,)])
def test_recorded_claim_txids_must_be_exact_lowercase_txids(recorded: object) -> None:
    with pytest.raises(ClaimWatchError, match="recorded claim txids unsupported"):
        _watcher(Chain(), recorded_txids=recorded)
