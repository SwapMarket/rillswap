"""Claim signing and disclosure cannot renew the caller's original lifetime."""

from __future__ import annotations

from contextlib import suppress
from unittest.mock import Mock

import pytest
from test_claim_watcher import Chain, _watcher

from rill_cli.claim_watcher import ClaimWatchError


@pytest.mark.parametrize(
    "reason",
    ["expired", "revoked", "predicate error", "nonboolean", "predicate delay", "broken clock"],
)
def test_invalid_authority_cannot_observe_sign_or_submit(reason: str) -> None:
    chain = Chain()
    now = 10.0 if reason == "expired" else 0.0

    def allowed() -> object:
        nonlocal now
        if reason == "predicate error":
            raise RuntimeError("private callback details")
        if reason == "predicate delay":
            now = 10.0
        if reason == "nonboolean":
            return 1
        return reason != "revoked"

    observe, sign, submit = Mock(), Mock(), Mock()
    watcher = _watcher(
        chain,
        chain=observe,
        sign=sign,
        submit=submit,
        deadline=10.0,
        effect_allowed=allowed,
        monotonic_clock=lambda: float("nan") if reason == "broken clock" else now,
    )
    with pytest.raises(TimeoutError):
        watcher.step()
    observe.assert_not_called()
    sign.assert_not_called()
    submit.assert_not_called()


@pytest.mark.parametrize("boundary", ["chain", "confirmations", "sign"])
@pytest.mark.parametrize("reason", ["expired", "revoked"])
def test_blocking_callback_return_is_rechecked_before_further_effects(
    boundary: str, reason: str
) -> None:
    chain = Chain()
    state = {"now": 0.0, "allowed": True}

    def revoke() -> None:
        state["now"] = 10.0 if reason == "expired" else 0.0
        state["allowed"] = reason != "revoked"

    def observe() -> object:
        if boundary == "chain":
            revoke()
        return chain.view()

    def sign(fee: int, tip: int) -> tuple:
        if boundary == "sign":
            revoke()
        return chain.sign(fee, tip)

    def confirmations(_txid: str) -> int:
        revoke()
        return 1

    submit = Mock(return_value=True)
    watcher = _watcher(
        chain,
        chain=observe,
        sign=sign,
        confirmations=confirmations,
        submit=submit,
        deadline=10.0,
        effect_allowed=lambda: state["allowed"],
        monotonic_clock=lambda: state["now"],
    )
    if boundary == "confirmations":
        watcher.step()
        chain.unspent = False
        submit.reset_mock()
    with pytest.raises(TimeoutError):
        watcher.step()
    submit.assert_not_called()
    # A late signed claim remains prepared evidence, not proof of disclosure.
    assert len(watcher.attempts) == (0 if boundary == "chain" else 1)


@pytest.mark.parametrize("tip", [100, 111])
def test_revocation_prevents_both_normal_and_post_height_rebroadcast(tip: int) -> None:
    chain = Chain()
    enabled = True
    watcher = _watcher(
        chain, deadline=10.0, monotonic_clock=lambda: 0.0, effect_allowed=lambda: enabled
    )
    watcher.step()
    chain.tip = tip
    enabled = False
    with pytest.raises(TimeoutError):
        watcher.step()
    assert len(chain.sent) == 1
    assert len(watcher.attempts) == 1


@pytest.mark.parametrize("accepted", [False, True])
def test_late_submission_preserves_prepared_attempt_without_claiming_privacy(
    *,
    accepted: bool,
) -> None:
    chain = Chain()
    clock = {"now": 0.0}
    reports: list[str] = []

    def submit(raw: bytes, txid: str) -> bool:
        chain.submit(raw, txid)
        clock["now"] = 10.0
        return accepted

    watcher = _watcher(
        chain,
        submit=submit,
        report=reports.append,
        deadline=10.0,
        monotonic_clock=lambda: clock["now"],
    )
    with pytest.raises(TimeoutError):
        watcher.run()
    assert len(watcher.attempts) == len(chain.sent) == len(reports) == 1
    assert "private" not in reports[0]
    with pytest.raises(TimeoutError):
        watcher.run(timeout=100)
    assert len(chain.sent) == 1


@pytest.mark.parametrize("relative", [None, 100.0, 2.0])
def test_sleep_and_relative_timeout_cannot_extend_original_deadline(relative: float | None) -> None:
    chain = Chain()
    clock = {"now": 0.0}
    sleeps: list[float] = []

    def sleep(duration: float) -> None:
        sleeps.append(duration)
        clock["now"] += duration

    watcher = _watcher(
        chain,
        chain=lambda: None,
        deadline=5.0,
        poll_seconds=10,
        sleep=sleep,
        monotonic_clock=lambda: clock["now"],
    )
    with pytest.raises(TimeoutError):
        watcher.run(timeout=relative)
    assert sleeps == [2.0 if relative == 2.0 else 5.0]
    assert chain.sent == []


def test_zero_relative_budget_does_not_run_the_old_first_step_effects() -> None:
    chain = Chain()
    with pytest.raises(TimeoutError):
        _watcher(chain).run(timeout=0)
    assert chain.sent == []


def test_existing_zero_poll_interval_remains_supported_with_a_deadline() -> None:
    chain = Chain()
    slept: list[float] = []

    def sleep(duration: float) -> None:
        slept.append(duration)
        chain.unspent = False
        chain.mined = watcher.attempts[0].txid

    watcher = _watcher(
        chain, poll_seconds=0, sleep=sleep, deadline=10.0, monotonic_clock=lambda: 0.0
    )
    assert watcher.run() == ("claim_confirmed", watcher.attempts[0].txid)
    assert slept == [0]


def test_cancellation_inside_clock_callback_cannot_reach_an_effect() -> None:
    chain = Chain()
    enabled = True

    def clock() -> float:
        nonlocal enabled
        enabled = False
        return 0.0

    observe = Mock(side_effect=AssertionError("no effect after caller clock revocation"))
    watcher = _watcher(
        chain, chain=observe, deadline=10.0, effect_allowed=lambda: enabled, monotonic_clock=clock
    )
    with pytest.raises(TimeoutError):
        watcher.step()
    observe.assert_not_called()


def test_delayed_permission_after_final_sample_cannot_authorize_a_late_effect() -> None:
    chain = Chain()
    state = {"now": 0.0, "samples": 0}
    observed_at: list[float] = []

    def clock() -> float:
        state["samples"] += 1
        return state["now"]

    def allowed() -> bool:
        # The old helper's final permission call ran AFTER sample two and
        # returned that stale sample even after this callback consumed the
        # remaining budget. The safe ordering makes sample two the last check.
        if state["samples"] == 2:
            state["now"] = 10.0
        return True

    def observe() -> object:
        observed_at.append(state["now"])
        return chain.view()

    watcher = _watcher(
        chain, chain=observe, deadline=10.0, monotonic_clock=clock, effect_allowed=allowed
    )
    with suppress(TimeoutError):
        watcher.step()
    assert all(observed < 10.0 for observed in observed_at)


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), "10"])
def test_malformed_lifetime_is_refused_without_effects(value: object) -> None:
    chain = Chain()
    with pytest.raises(ClaimWatchError):
        _watcher(chain, deadline=value)
    with pytest.raises(ClaimWatchError):
        _watcher(chain).step(deadline=value)
    with pytest.raises(ClaimWatchError):
        _watcher(chain).run(timeout=value)
    assert chain.sent == []
