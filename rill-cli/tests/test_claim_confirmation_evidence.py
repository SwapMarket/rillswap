"""Conflicted or malformed observations cannot confirm a recorded claim attempt.

These controller tests use pre-recorded placeholder attempts, not financial or
cryptographic evidence. Existing positive-depth and effect-authority tests remain
unchanged. In particular, an older confirmed attempt can beat a conflicted newer
replacement; rejecting one observation must not stop the complete search.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, cast
from unittest.mock import Mock

import pytest

from rill_cli.claim_watcher import ClaimAttempt, ClaimWatcher
from rill_cli.refund_watcher import ChainView

if TYPE_CHECKING:
    from collections.abc import Callable

OLDER = ClaimAttempt("01" * 32, b"older-placeholder", 300, 150, 100)
NEWER = ClaimAttempt("02" * 32, b"newer-placeholder", 1800, 150, 105)


class IntegerSubclass(int):
    """Custom callbacks cannot promote an integer subtype to financial evidence."""


def _watcher(
    view: ChainView | None,
    confirmations: Callable[[str], int | None],
    state: SimpleNamespace,
) -> tuple[ClaimWatcher, Mock, Mock]:
    sign = Mock(side_effect=AssertionError("observation must not sign"))
    submit = Mock(side_effect=AssertionError("observation must not submit"))
    watcher = ClaimWatcher(
        initial_fee_sat=300,
        max_fee_sat=3300,
        deadline_height=110,
        chain=lambda: view,
        confirmations=confirmations,
        sign=sign,
        submit=submit,
        deadline=10.0,
        monotonic_clock=lambda: state.now,
        effect_allowed=lambda: state.allowed,
    )
    watcher.attempts.append(OLDER)
    return watcher, sign, submit


@pytest.mark.parametrize(
    "view", [None, ChainView(105, unspent_on_chain=False)], ids=["unavailable", "spent"]
)
@pytest.mark.parametrize(
    "observation",
    [-1, -3, 0, None, True, IntegerSubclass(1), 1.0, "1", [1]],
    ids=[
        "conflict-one",
        "conflict-three",
        "zero",
        "unknown",
        "boolean",
        "int-subclass",
        "float",
        "string",
        "list",
    ],
)
def test_only_exact_positive_integers_can_confirm_an_attempt(
    view: ChainView | None,
    observation: object,
) -> None:
    queried: list[str] = []

    def observe(txid: str) -> int | None:
        queried.append(txid)
        # Deliberately exercise malformed collaborator values at the boundary.
        return cast("int | None", observation)

    watcher, sign, submit = _watcher(view, observe, SimpleNamespace(now=0.0, allowed=True))
    expected = None if view is None else ("outpoint_spent_elsewhere", None)
    assert watcher.step() == expected
    assert queried == [OLDER.txid]
    assert watcher.attempts == [OLDER]
    sign.assert_not_called()
    submit.assert_not_called()


@pytest.mark.parametrize(
    "view", [None, ChainView(105, unspent_on_chain=False)], ids=["unavailable", "spent"]
)
@pytest.mark.parametrize("depth", [1, 3])
def test_existing_positive_depth_contract_is_preserved(view: ChainView | None, depth: int) -> None:
    watcher, sign, submit = _watcher(
        view,
        lambda _txid: depth,
        SimpleNamespace(now=0.0, allowed=True),
    )
    assert watcher.step() == ("claim_confirmed", OLDER.txid)
    sign.assert_not_called()
    submit.assert_not_called()


@pytest.mark.parametrize(
    "view", [None, ChainView(105, unspent_on_chain=False)], ids=["unavailable", "spent"]
)
def test_conflicted_newest_replacement_does_not_hide_an_older_confirmed_claim(
    view: ChainView | None,
) -> None:
    queried: list[str] = []

    def observe(txid: str) -> int:
        queried.append(txid)
        return -1 if txid == NEWER.txid else 1

    watcher, sign, submit = _watcher(view, observe, SimpleNamespace(now=0.0, allowed=True))
    watcher.attempts.append(NEWER)
    assert watcher.step() == ("claim_confirmed", OLDER.txid)
    assert queried == [NEWER.txid, OLDER.txid]
    assert watcher.attempts == [OLDER, NEWER]
    sign.assert_not_called()
    submit.assert_not_called()


@pytest.mark.parametrize(
    "view", [None, ChainView(105, unspent_on_chain=False)], ids=["unavailable", "spent"]
)
@pytest.mark.parametrize("observation", [-1, 1])
@pytest.mark.parametrize("reason", ["expired", "revoked"])
def test_late_or_revoked_confirmation_never_returns_an_outcome(
    view: ChainView | None,
    observation: int,
    reason: str,
) -> None:
    state = SimpleNamespace(now=0.0, allowed=True)

    def observe(_txid: str) -> int:
        if reason == "expired":
            state.now = 10.0
        else:
            state.allowed = False
        return observation

    watcher, sign, submit = _watcher(view, observe, state)
    with pytest.raises(TimeoutError):
        watcher.step()
    assert watcher.attempts == [OLDER]
    sign.assert_not_called()
    submit.assert_not_called()
