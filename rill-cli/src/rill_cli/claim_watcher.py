"""Keep an LN-to-BTC claim moving until it confirms (RS-004, client side).

The claim must confirm before ``refund_lock_height``: after that the provider
may refund, and a refund that wins the race keeps both the Lightning payment
(already settled from the claim's preimage) and the coins. Each new block
re-signs the claim at a fee that rises linearly from the initial fee to the
maximum by ``deadline_height`` and replaces the previous attempt when it
beats it by the incremental relay fee; otherwise the latest attempt is
rebroadcast. The preimage is public from the first broadcast, so no attempt
reveals anything new. Nothing is signed after ``deadline_height`` (the fee is
at its maximum by then anyway): a first claim that late would reveal the
preimage while the provider may already refund. Attempts are kept in memory
only: after a restart the schedule starts again, and Core refuses a
replacement below one already in its mempool, which keeps working for us
meanwhile.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_cli.refund_watcher import ChainView

LOG = logging.getLogger(__name__)
INCREMENTAL_RELAY_SAT_VB = 1  # BIP125 rule 4 at Core's default incremental relay fee
MAX_ATTEMPTS = 32

type ClaimOutcome = Literal["claim_confirmed", "outpoint_spent_elsewhere", "claim_window_passed"]


class ClaimWatchError(ValueError):
    """The claim could not be signed as scheduled."""


@dataclass(frozen=True)
class ClaimAttempt:
    """One signed claim: its bytes, fee, size, and the tip it was signed at."""

    txid: str
    raw: bytes
    fee_sat: int
    vsize: int
    height: int


def claim_fee_target(
    *, initial: int, maximum: int, start_height: int, deadline_height: int, tip: int
) -> int:
    """Linear from ``initial`` at ``start_height`` to ``maximum`` at the deadline."""
    maximum = max(initial, maximum)
    span = deadline_height - start_height
    if span <= 0 or tip >= deadline_height:
        return maximum
    elapsed = max(0, tip - start_height)
    return initial + (maximum - initial) * elapsed // span


class ClaimWatcher:
    """Poll the chain; bump or rebroadcast the claim until one attempt confirms."""

    def __init__(  # noqa: PLR0913 - explicit collaborators
        self,
        *,
        initial_fee_sat: int,
        max_fee_sat: int,
        deadline_height: int,
        chain: Callable[[], ChainView | None],
        confirmations: Callable[[str], int | None],
        sign: Callable[[int, int], tuple[bytes, str, int, int]],
        submit: Callable[[bytes, str], bool],
        report: Callable[[str], None] = LOG.info,
        poll_seconds: float = 10.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """``sign(fee, tip)`` returns checked ``(raw, txid, fee, vsize)``."""
        if not 0 < initial_fee_sat <= max_fee_sat:
            raise ClaimWatchError("claim fee bounds unsupported")
        self.attempts: list[ClaimAttempt] = []
        self._fees = (initial_fee_sat, max_fee_sat)
        self._deadline = deadline_height
        self._start: int | None = None
        self._chain = chain
        self._confirmations = confirmations
        self._sign = sign
        self._submit = submit
        self._report = report
        self._poll = poll_seconds
        self._sleep = sleep

    def run(self, *, timeout: float | None = None) -> tuple[ClaimOutcome, str | None]:
        """Step until an outcome; raise ``TimeoutError`` after ``timeout`` seconds."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            outcome = self.step()
            if outcome is not None:
                return outcome
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError
            self._sleep(self._poll)

    def step(self) -> tuple[ClaimOutcome, str | None] | None:
        """One poll: finish, wait, rebroadcast, or sign and send a replacement."""
        view = self._chain()
        if view is None or not view.unspent_on_chain:
            for attempt in reversed(self.attempts):
                if self._confirmations(attempt.txid):
                    return "claim_confirmed", attempt.txid
            return None if view is None else ("outpoint_spent_elsewhere", None)
        if self._start is None:
            self._start = view.tip_height
        latest = self.attempts[-1] if self.attempts else None
        if view.tip_height > self._deadline:
            if latest is None:
                return "claim_window_passed", None
            self._submit(latest.raw, latest.txid)
            return None
        initial, maximum = self._fees
        fee = claim_fee_target(
            initial=initial,
            maximum=maximum,
            start_height=self._start,
            deadline_height=self._deadline,
            tip=view.tip_height,
        )
        due = latest is None or (
            len(self.attempts) < MAX_ATTEMPTS
            and view.tip_height > latest.height
            and fee >= latest.fee_sat + latest.vsize * INCREMENTAL_RELAY_SAT_VB
        )
        if not due:
            if latest is not None:
                self._submit(latest.raw, latest.txid)  # rebroadcast
            return None
        raw, txid, signed_fee, vsize = self._sign(fee, view.tip_height)
        if signed_fee != fee:
            raise ClaimWatchError("signed claim fee differs from the scheduled fee")
        self.attempts.append(ClaimAttempt(txid, raw, fee, vsize, view.tip_height))
        accepted = self._submit(raw, txid)
        self._report(
            f"claim {txid} at {fee} sat (tip {view.tip_height}) "
            f"{'broadcast' if accepted else 'not accepted yet'}"
        )
        return None
