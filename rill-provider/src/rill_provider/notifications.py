"""Optional operator notifications through Apprise (``rill-provider[notifications]``).

The notifier follows the swap ledger (store schema v18) from where it stood
when serving started, watches the service health snapshot, and sends a daily
summary computed from the durable ledger. It only reads the store, on the
event-loop thread; delivery runs in a worker thread with a timeout, at most
once per poll (several events are combined). Failures are logged, never with
the URLs (they carry service tokens), and never affect serving. Nothing is
persisted: events while the service is down are not sent one by one, but the
next daily summary still counts them.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Protocol

from rill_provider.operator_config import OperatorConfigError, read_private_file
from rill_provider.swap_accounting import (
    ABORTED,
    ACCEPTED,
    COMPLETED,
    FAILED,
    LOST,
    MSAT_PER_SAT,
    REFUNDED,
    LedgerSummary,
    SwapResult,
    summarize,
    swap_result,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from rill_provider.handshake_service import ServiceHealth
    from rill_provider.live_session_store import LiveSessionStore
    from rill_provider.operator_config import NotificationSettings

LOG = logging.getLogger(__name__)
MAX_URLS_FILE_BYTES = 16 * 1024
SEND_TIMEOUT_SECONDS = 20
CLOSE_TIMEOUT_SECONDS = 10.0
POLL_SECONDS = 15.0
MAX_EVENTS_PER_POLL = 256
DAY_SECONDS = 24 * 60 * 60
OUTCOME_ORDER = (COMPLETED, FAILED, REFUNDED, ABORTED, LOST)


class Sender(Protocol):
    """Blocking delivery to every configured service; True when all accepted it."""

    def send(self, title: str, body: str, *, warning: bool) -> bool:
        """Deliver one notification."""
        ...


@contextlib.contextmanager
def _quiet_apprise() -> Iterator[None]:
    """Silence Apprise while it parses URLs: its parse errors echo them, tokens included."""
    logger = logging.getLogger("apprise")
    disabled, logger.disabled = logger.disabled, True
    try:
        yield
    finally:
        logger.disabled = disabled


class AppriseSender:
    """Delivers to the URLs of an owner-only file, each accepted by Apprise at startup."""

    def __init__(self, urls_file: Path) -> None:
        """Read and check every URL; refuse the file naming only the offending line."""
        try:
            import apprise  # noqa: PLC0415 - optional extra, imported only when configured
        except ImportError:
            raise OperatorConfigError(
                "notifications need the apprise package: install rill-provider[notifications]"
            ) from None
        data = read_private_file(urls_file, "notification URLs file", max_bytes=MAX_URLS_FILE_BYTES)
        if len(data) > MAX_URLS_FILE_BYTES:
            raise OperatorConfigError("notification URLs file too large")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise OperatorConfigError("notification URLs file must be UTF-8 text") from None
        # Memory storage: Apprise writes nothing (the image's root is read-only).
        asset = apprise.AppriseAsset(storage_mode="memory", service_timeout=SEND_TIMEOUT_SECONDS)
        self._apprise = apprise.Apprise(asset=asset)
        self._types = (apprise.NotifyType.INFO, apprise.NotifyType.WARNING)
        self._format = apprise.NotifyFormat.TEXT
        with _quiet_apprise():
            for number, line in enumerate(text.splitlines(), start=1):
                url = line.strip()
                if not url or url.startswith("#"):
                    continue
                service = apprise.Apprise.instantiate(url, asset=asset)
                if service is None or not self._apprise.add(service):
                    raise OperatorConfigError(f"notification URL refused (line {number})")
        if not len(self._apprise):
            raise OperatorConfigError("notification URLs file holds no URL")

    def send(self, title: str, body: str, *, warning: bool) -> bool:
        """Deliver to every service, bounded by ``SEND_TIMEOUT_SECONDS`` overall."""
        result = self._apprise.notify(
            body,
            title=title,
            notify_type=self._types[warning],
            body_format=self._format,
            timeout=SEND_TIMEOUT_SECONDS,
        )
        return bool(result)


@dataclass(frozen=True)
class Message:
    """One notification before delivery; ``warning`` asks for operator action."""

    title: str
    body: str
    warning: bool = False


@dataclass
class _Condition:
    """A health alert: raised once after the grace period, cleared once on recovery."""

    since: float | None = None
    raised: bool = False

    def update(self, *, bad: bool, now: float, grace: float) -> bool | None:
        """Return True to raise the alert, False to clear it, None for no change."""
        if not bad:
            self.since = None
            if self.raised:
                self.raised = False
                return False
            return None
        if self.since is None:
            self.since = now
        if not self.raised and now - self.since >= grace:
            self.raised = True
            return True
        return None


class Notifier:
    """Turns ledger entries, health changes and the daily clock into notifications."""

    def __init__(  # noqa: PLR0913 - explicit injected resources
        self,
        settings: NotificationSettings,
        sender: Sender,
        store: LiveSessionStore,
        *,
        profile: str,
        network: str,
        health: Callable[[], ServiceHealth],
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        poll_seconds: float = POLL_SECONDS,
    ) -> None:
        """Bind an acquired store; only entries appended from now on are announced."""
        self._settings = settings
        self._sender = sender
        self._store = store
        self._profile = profile
        self._prefix = f"RillSwap {profile} ({network})"
        self._health = health
        self._clock, self._monotonic = clock, monotonic
        self._poll_seconds = poll_seconds
        self._cursor = store.ledger_head()  # history is summarized, never replayed
        self._next_summary = next_summary_at(int(clock()), settings.summary_time)
        self._conditions: dict[str, _Condition] = {
            name: _Condition()
            for name in ("relays_down", "quotes_paused", "low_liquidity")
            if getattr(settings, name)
        }
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Start polling in the background, announcing the start when enabled."""
        self._task = asyncio.create_task(self._run())

    async def close(self, *, failed: bool) -> None:
        """Stop polling, send the last swap events and, when enabled, the stop."""
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        messages = self._collect(self._swap_messages)
        if self._settings.service_start_stop:
            if failed:
                messages.append(
                    Message("service stopped", "Serving ended on an error.", warning=True)
                )
            else:
                messages.append(Message("service stopped", "Serving stopped."))
        try:
            await asyncio.wait_for(self._deliver(messages), CLOSE_TIMEOUT_SECONDS)
        except TimeoutError:
            LOG.warning("last notification not delivered before shutdown")

    async def poll(self) -> None:
        """Deliver what is due as one notification; never raises but cancellation."""
        await self._deliver(
            [
                *self._collect(self._swap_messages),
                *self._collect(self._health_messages),
                *self._collect(self._summary_messages),
            ]
        )

    async def _run(self) -> None:
        if self._settings.service_start_stop:
            await self._deliver([Message("service started", "Serving started.")])
        while True:
            await asyncio.sleep(self._poll_seconds)
            await self.poll()

    @staticmethod
    def _collect(source: Callable[[], list[Message]]) -> list[Message]:
        try:
            return source()
        except Exception as error:  # noqa: BLE001 - notifications never affect serving
            LOG.warning("notifications skipped: %s", type(error).__name__)
            return []

    async def _deliver(self, messages: list[Message]) -> None:
        if not messages:
            return
        if len(messages) == 1:
            (message,) = messages
        else:
            message = Message(
                f"{len(messages)} notifications",
                "\n\n".join(f"{item.title}\n{item.body}" for item in messages),
                warning=any(item.warning for item in messages),
            )
        try:
            delivered = await asyncio.to_thread(
                self._sender.send,
                f"{self._prefix}: {message.title}",
                message.body,
                warning=message.warning,
            )
        except Exception as error:  # noqa: BLE001 - never echo URLs or payloads
            LOG.warning("notification not delivered: %s", type(error).__name__)
            return
        if not delivered:
            LOG.warning("notification not delivered to every service")

    def _swap_messages(self) -> list[Message]:
        settings = self._settings
        entries = self._store.ledger_after(self._cursor, limit=MAX_EVENTS_PER_POLL)
        if entries:
            self._cursor = entries[-1].entry_id
        wanted = {
            COMPLETED: settings.swap_confirmed,
            FAILED: settings.swap_failed,
            REFUNDED: settings.swap_failed,
            ABORTED: settings.swap_failed,
            LOST: settings.swap_lost,
        }
        messages: list[Message] = []
        for entry in entries:
            if entry.kind == ACCEPTED and settings.swap_request:
                amount = "" if entry.amount is None else f" for {_sat(entry.amount * MSAT_PER_SAT)}"
                messages.append(
                    Message("swap accepted", f"Swap {entry.session_id[:16]} accepted{amount}.")
                )
            elif wanted.get(entry.kind, False):
                result = swap_result(self._store.ledger_session(entry.session_id), self._profile)
                if result is not None:
                    messages.append(_outcome_message(result))
        return messages

    def _health_messages(self) -> list[Message]:
        if not self._conditions:
            return []
        health, now = self._health(), self._monotonic()
        grace = self._settings.alert_after_seconds
        paused = [
            reason
            for reason, available in (
                ("chain tip", health.tip_available),
                ("claim fee estimate", health.claim_fee_available),
            )
            if not available
        ]
        checks = {
            "relays_down": (
                health.relays_connected == 0,
                Message(
                    "relays down",
                    f"No relay connected for {_duration(grace)}: clients cannot reach "
                    "this provider.",
                    warning=True,
                ),
                Message("relays back", "A relay is connected again."),
            ),
            "quotes_paused": (
                bool(paused),
                Message(
                    "quotes paused",
                    f"Quotes refused for {_duration(grace)}: {' and '.join(paused)} unavailable.",
                    warning=True,
                ),
                Message("quotes resumed", "Quotes are answered again."),
            ),
            "low_liquidity": (
                not health.announcing,
                Message(
                    "low liquidity",
                    f"Liquidity below every amount band for {_duration(grace)}: not announcing.",
                    warning=True,
                ),
                Message("liquidity back", "Liquidity covers an amount band: announcing again."),
            ),
        }
        messages: list[Message] = []
        for name, condition in self._conditions.items():
            bad, raised, cleared = checks[name]
            change = condition.update(bad=bad, now=now, grace=grace)
            if change is not None:
                messages.append(raised if change else cleared)
        return messages

    def _summary_messages(self) -> list[Message]:
        now = int(self._clock())
        if now < self._next_summary:
            return []
        until = self._next_summary
        while self._next_summary <= now:  # after a stall: the latest day, not a backlog
            until = self._next_summary
            self._next_summary += DAY_SECONDS
        if not self._settings.daily_summary:
            return []
        since = until - DAY_SECONDS
        summary = summarize(self._store.ledger_window(since, until), self._profile, since, until)
        return [Message("daily summary", summary_text(summary, self._health()))]


def next_summary_at(now: int, at: str) -> int:
    """Return the first ``HH:MM`` UTC strictly after ``now``."""
    hours, minutes = (int(part) for part in at.split(":"))
    boundary = now - now % DAY_SECONDS + hours * 3600 + minutes * 60
    return boundary if boundary > now else boundary + DAY_SECONDS


def summary_text(summary: LedgerSummary, health: ServiceHealth) -> str:
    """Render the daily summary as plain text."""
    since, until = (
        datetime.fromtimestamp(moment, UTC).strftime("%Y-%m-%d %H:%M")
        for moment in (summary.since, summary.until)
    )
    lines = [
        f"From {since} to {until} UTC.",
        (
            f"Requests: {summary.accepted} accepted "
            f"({_sat(summary.accepted_sat * MSAT_PER_SAT)}) of {summary.offered} firm offers."
        ),
    ]
    if summary.success_percent is None:
        lines.append("Closed: none.")
    else:
        outcomes = ", ".join(
            f"{summary.outcomes[kind]} {kind}" for kind in OUTCOME_ORDER if kind in summary.outcomes
        )
        lines.append(
            f"Closed: {summary.closed}, {summary.success_percent:.0f}% success ({outcomes})."
        )
        lines.append(
            f"Revenue {_sat(summary.revenue_sat * MSAT_PER_SAT)}, costs "
            f"{_sat(summary.costs_msat)}, losses {_sat(summary.lost_sat * MSAT_PER_SAT)}."
        )
        lines.append(f"Net profit: {_sat(summary.net_msat)}.")
    if summary.gas_wei or summary.gas_unmeasured:
        unmeasured = f" ({summary.gas_unmeasured} swaps not measured)" * bool(
            summary.gas_unmeasured
        )
        lines.append(f"Gas: {_gwei(summary.gas_wei)}{unmeasured}.")
    if summary.inexact:
        lines.append(
            f"Costs of {summary.inexact} swaps were not all recorded (accepted before the "
            "accounting upgrade, or not reported by a backend): the net profit is at most this."
        )
    lines.append(
        f"Now: {health.relays_connected} relays connected, "
        + ("announcing." if health.announcing else "not announcing (low liquidity).")
    )
    return "\n".join(lines)


def _outcome_message(result: SwapResult) -> Message:
    session = result.session_id[:16]
    parts = []
    if result.revenue_sat:
        parts.append(f"revenue {_sat(result.revenue_sat * MSAT_PER_SAT)}")
    if result.lost_sat:
        parts.append(f"loss {_sat(result.lost_sat * MSAT_PER_SAT)}")
    if result.costs_msat:
        parts.append(f"costs {_sat(result.costs_msat)}")
    if parts:
        parts.append(f"net {_sat(result.net_msat)}")
    if result.gas_wei:
        parts.append(f"gas {_gwei(result.gas_wei)}")
    details = f": {', '.join(parts)}" if parts else ""
    note = ""  # qualifies a net shown, never a bare outcome
    if parts and not result.exact:
        note = " Some costs were not recorded: the net is at most this."
    if result.outcome == LOST:
        body = f"Swap {session} lost{details}. Check it with inspect-swaps.{note}"
        return Message("swap lost", body, warning=True)
    title = {COMPLETED: "swap completed"}.get(result.outcome, f"swap {result.outcome}")
    return Message(title, f"Swap {session} {result.outcome}{details}.{note}")


def _sat(msat: int) -> str:
    whole, fraction = divmod(abs(msat), MSAT_PER_SAT)
    text = f"{whole:,}" + (f".{fraction:03d}".rstrip("0") if fraction else "")
    return f"{'-' * (msat < 0)}{text} sat"


def _gwei(wei: int) -> str:
    text = f"{Decimal(wei).scaleb(-9):,f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text} gwei"


def _duration(seconds: int) -> str:
    if seconds % 60:
        return f"{seconds} seconds"
    minutes = seconds // 60
    return f"{minutes} minute{'s' * (minutes != 1)}"
