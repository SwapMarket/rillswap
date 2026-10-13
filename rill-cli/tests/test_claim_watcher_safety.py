"""Private claims never become late disclosures; ambiguous claims remain recoverable."""

from __future__ import annotations

import pytest
from test_claim_watcher import Chain, _watcher

from rill_cli.claim_watcher import MAX_ATTEMPTS, ClaimAttempt, ClaimSubmission


def test_definite_prebroadcast_refusal_does_not_allow_late_submission() -> None:
    chain = Chain()
    calls: list[int] = []

    def submit(_raw: bytes, _txid: str) -> ClaimSubmission:
        calls.append(chain.tip)
        return ClaimSubmission.NOT_BROADCAST

    watcher = _watcher(chain, submit=submit)
    watcher.step()
    chain.tip = 200
    assert watcher.step() == ("claim_window_passed", None)
    assert calls == [100]


@pytest.mark.parametrize("submission", [False, ClaimSubmission.UNKNOWN, ClaimSubmission.ACCEPTED])
def test_possible_submission_preserves_late_rebroadcast(
    *,
    submission: bool | ClaimSubmission,
) -> None:
    chain = Chain()
    calls: list[int] = []

    def submit(_raw: bytes, _txid: str) -> bool | ClaimSubmission:
        calls.append(chain.tip)
        return submission

    watcher = _watcher(chain, submit=submit)
    watcher.step()
    chain.tip = 200
    assert watcher.step() is None
    assert calls == [100, 200]


def test_signed_attempt_without_submission_authority_stays_private() -> None:
    chain = Chain()
    allowed = True

    def sign(fee: int, height: int) -> tuple[bytes, str, int, int]:
        nonlocal allowed
        allowed = False
        return chain.sign(fee, height)

    watcher = _watcher(chain, sign=sign, effect_allowed=lambda: allowed)
    with pytest.raises(TimeoutError):
        watcher.step()
    assert len(watcher.attempts) == 1
    allowed = True
    chain.tip = 200
    assert watcher.step() == ("claim_window_passed", None)
    assert chain.sent == []


@pytest.mark.parametrize("disclosed", [False, True])
def test_seeded_attempt_requires_affirmative_disclosure_before_late_rebroadcast(
    *, disclosed: bool
) -> None:
    chain = Chain()
    watcher = _watcher(chain, preimage_disclosed=disclosed)
    raw, txid, fee, size = chain.sign(300, 100)
    watcher.attempts.append(ClaimAttempt(txid, raw, fee, size, 100))
    chain.tip = 200
    assert watcher.step() == (None if disclosed else ("claim_window_passed", None))
    assert len(chain.sent) == int(disclosed)


def test_unknown_submission_before_callback_failure_is_not_forgotten() -> None:
    chain = Chain()

    def submit(raw: bytes, txid: str) -> bool:
        chain.submit(raw, txid)
        raise OSError("response lost")

    watcher = _watcher(chain, submit=submit)
    with pytest.raises(OSError, match="response lost"):
        watcher.step()
    chain.tip = 200
    with pytest.raises(OSError, match="response lost"):
        watcher.step()
    assert len(chain.sent) == 2


def test_long_schedule_reaches_cap_without_evicting_older_confirmation_evidence() -> None:
    chain = Chain()
    watcher = _watcher(chain, max_fee_sat=20_000, deadline_height=200)
    for chain.tip in range(100, 201):
        watcher.step()
    assert len(watcher.attempts) == MAX_ATTEMPTS
    assert watcher.attempts[-1].fee_sat == 20_000
    first = watcher.attempts[0].txid
    chain.unspent, chain.mined = False, first
    assert watcher.step() == ("claim_confirmed", first)


def test_replacement_uses_candidate_size_and_reserves_final_relay_headroom() -> None:
    chain = Chain()

    def sign(fee: int, height: int) -> tuple[bytes, str, int, int]:
        raw, txid, signed_fee, size = chain.sign(fee, height)
        return raw, txid, signed_fee, size if height == 100 else 350

    watcher = _watcher(chain, max_fee_sat=1_000, deadline_height=110, sign=sign)
    watcher.step()
    chain.tip = 103  # 510 sat beats the old size, but not the candidate's 350 sat relay increment.
    watcher.step()
    assert len(watcher.attempts) == 1
    chain.tip = 107  # 790 sat would leave too little headroom for the final replacement.
    watcher.step()
    assert len(watcher.attempts) == 1
    chain.tip = 110
    watcher.step()
    assert [attempt.fee_sat for attempt in watcher.attempts] == [300, 1_000]
