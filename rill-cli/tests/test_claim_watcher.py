"""The LN-to-BTC claim is bumped each block toward the maximum until it confirms."""

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


def test_the_fee_rises_linearly_to_the_maximum_at_the_deadline() -> None:
    target = {
        tip: claim_fee_target(
            initial=300, maximum=3_300, start_height=100, deadline_height=110, tip=tip
        )
        for tip in (99, 100, 105, 110, 200)
    }
    assert target == {99: 300, 100: 300, 105: 1_800, 110: 3_300, 200: 3_300}
    assert (
        claim_fee_target(initial=300, maximum=100, start_height=0, deadline_height=0, tip=0) == 300
    )


def test_one_attempt_per_block_until_it_confirms() -> None:
    chain = Chain()
    watcher = _watcher(chain)
    assert watcher.step() is None
    assert watcher.step() is None  # same block: rebroadcast only
    assert [fee for _txid, fee in chain.sent] == [300, 300]
    chain.tip = 105
    assert watcher.step() is None
    assert [attempt.fee_sat for attempt in watcher.attempts] == [300, 1_800]
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
