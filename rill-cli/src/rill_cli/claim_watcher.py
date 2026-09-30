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
import math
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
        deadline: float | None = None,
        effect_allowed: Callable[[], bool] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        """``sign(fee, tip)`` returns checked ``(raw, txid, fee, vsize)``."""
        if not 0 < initial_fee_sat <= max_fee_sat:
            raise ClaimWatchError("claim fee bounds unsupported")
        if deadline is not None and (
            type(deadline) not in (int, float) or not math.isfinite(deadline)
        ):
            raise ClaimWatchError("claim lifetime deadline unsupported")
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
        self._lifetime_deadline = deadline
        self._effect_allowed = effect_allowed
        self._monotonic = monotonic_clock

    def run(self, *, timeout: float | None = None) -> tuple[ClaimOutcome, str | None]:
        """Step within one lifetime; cleanup must retain the worker and crypto.

        A relative timeout may shorten, never renew, the original deadline.
        Guards bound authorization before callbacks, not an already-started
        RPC's physical effects. Attempts retain signed bytes, not proof that
        submission succeeded or that the preimage stayed private.
        Clock and permission collaborators must be trusted, prompt local
        observations. Reporting may follow a late submission to retain evidence.
        """
        if timeout is not None and (
            type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout < 0
        ):
            raise ClaimWatchError("claim timeout unsupported")
        deadline = self._lifetime_deadline
        if timeout is not None:
            relative = self._now() + timeout
            deadline = relative if deadline is None else min(deadline, relative)
        while True:
            outcome = self.step(deadline=deadline)
            if outcome is not None:
                return outcome
            self._check_authority(deadline)
            delay = (
                self._poll if deadline is None else min(self._poll, max(0, deadline - self._now()))
            )
            self._sleep(delay)

    def step(self, *, deadline: float | None = None) -> tuple[ClaimOutcome, str | None] | None:
        """One poll: finish, wait, rebroadcast, or sign and send a replacement."""
        if deadline is not None and (
            type(deadline) not in (int, float) or not math.isfinite(deadline)
        ):
            raise ClaimWatchError("claim lifetime deadline unsupported")
        if self._lifetime_deadline is not None:
            deadline = (
                self._lifetime_deadline
                if deadline is None
                else min(deadline, self._lifetime_deadline)
            )
        self._check_authority(deadline)
        view = self._chain()
        self._check_authority(deadline)
        if view is None or not view.unspent_on_chain:
            for attempt in reversed(self.attempts):
                self._check_authority(deadline)
                confirmed = self._confirmations(attempt.txid)
                self._check_authority(deadline)
                if confirmed:
                    return "claim_confirmed", attempt.txid
            return None if view is None else ("outpoint_spent_elsewhere", None)
        if self._start is None:
            self._start = view.tip_height
        latest = self.attempts[-1] if self.attempts else None
        if view.tip_height > self._deadline:
            if latest is None:
                return "claim_window_passed", None
            self._check_authority(deadline)
            self._submit(latest.raw, latest.txid)
            self._check_authority(deadline)
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
                self._check_authority(deadline)
                self._submit(latest.raw, latest.txid)  # rebroadcast
                self._check_authority(deadline)
            return None
        self._check_authority(deadline)
        raw, txid, signed_fee, vsize = self._sign(fee, view.tip_height)
        if signed_fee != fee:
            raise ClaimWatchError("signed claim fee differs from the scheduled fee")
        self.attempts.append(ClaimAttempt(txid, raw, fee, vsize, view.tip_height))
        self._check_authority(deadline)
        accepted = self._submit(raw, txid)
        self._report(
            f"claim {txid} at {fee} sat (tip {view.tip_height}) "
            f"{'broadcast' if accepted else 'not accepted yet'}"
        )
        self._check_authority(deadline)
        return None

    def _check_authority(self, deadline: float | None) -> None:
        """Recheck nonconsuming permission and fence a delayed predicate."""
        if deadline is not None and self._now() >= deadline:
            raise TimeoutError
        self._check_permission()
        if deadline is not None and self._now() >= deadline:
            raise TimeoutError

    def _now(self) -> float:
        """Refuse broken clocks rather than granting effect authority."""
        try:
            current = time.monotonic() if self._monotonic is None else self._monotonic()
        except Exception:  # noqa: BLE001 - clock failure is a refusal, not new authority
            raise TimeoutError from None
        if type(current) not in (int, float) or not math.isfinite(current):
            raise TimeoutError
        return current

    def _check_permission(self) -> None:
        """Observe permission before the final deadline sample, never after it."""
        if self._effect_allowed is not None:
            try:
                allowed = self._effect_allowed() is True
            except Exception:  # noqa: BLE001 - caller details may contain secrets
                allowed = False
            if not allowed:
                raise TimeoutError
