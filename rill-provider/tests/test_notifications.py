"""Operator notifications: ledger accounting, alerts, summaries and Apprise delivery."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from rill_provider import notifications
from rill_provider.handshake_service import ServiceHealth
from rill_provider.notifications import AppriseSender, Notifier, next_summary_at, summary_text
from rill_provider.operator_config import NotificationSettings, OperatorConfigError, load_config
from rill_provider.swap_accounting import TERMINAL_KINDS, LedgerEntry, summarize, swap_result

if TYPE_CHECKING:
    from collections.abc import Iterator

DAY = 24 * 60 * 60
MIDNIGHT = 1_798_761_600  # 2027-01-01 00:00 UTC
HEALTHY = ServiceHealth(
    relays_connected=2, announcing=True, tip_available=True, claim_fee_available=True
)


class Ledger:
    """The store's ledger read API over a list, for notifier logic only."""

    def __init__(self) -> None:
        self.entries: list[LedgerEntry] = []
        self.fail = False

    def add(self, session: str, at: int, kind: str, amount: int | None = None) -> None:
        unit = None
        if amount is not None:
            unit = {"routing_fee": "msat", "gas": "wei"}.get(kind, "sat")
        self.entries.append(LedgerEntry(len(self.entries) + 1, session, at, kind, amount, unit))

    def ledger_head(self) -> int:
        return len(self.entries)

    def ledger_after(self, entry_id: int, *, limit: int = 256) -> tuple[LedgerEntry, ...]:
        if self.fail:
            raise OSError("store gone")
        return tuple(entry for entry in self.entries if entry.entry_id > entry_id)[:limit]

    def ledger_session(self, session: str) -> tuple[LedgerEntry, ...]:
        return tuple(entry for entry in self.entries if entry.session_id == session)

    def ledger_window(self, since: int, until: int) -> tuple[LedgerEntry, ...]:
        closed = {
            entry.session_id
            for entry in self.entries
            if entry.kind in TERMINAL_KINDS and since <= entry.recorded_at < until
        }
        return tuple(
            entry
            for entry in self.entries
            if since <= entry.recorded_at < until or entry.session_id in closed
        )


def _entries(*rows: tuple[str, int | None]) -> list[LedgerEntry]:
    ledger = Ledger()
    for kind, amount in rows:
        ledger.add("s1" * 32, 100, kind, amount)
    return ledger.entries


# btc-to-ln: 1000 sat fee, 1.5 sat routing, 300 sat claim -> 698.5 sat
CLAIMED = (("accepted", 100_000), ("routing_fee", 1500), ("completed", 1000), ("claim_fee", 300))


@pytest.mark.parametrize(
    ("profile", "rows", "net_msat", "exact"),
    [
        ("btc-to-ln/v1", CLAIMED, 698_500, True),
        ("btc-to-ln/v1", CLAIMED[1:], 698_500, False),  # accepted before the ledger
        ("btc-to-ln/v1", CLAIMED[:3], 998_500, False),  # the claim fee never recorded
        ("btc-to-ln/v1", (*CLAIMED[:3], ("claim_fee", None)), 998_500, False),  # unmeasured
        ("btc-to-ln/v1", (("accepted", 9), ("failed", None)), 0, True),
        (
            "btc-to-ln/v1",
            (("accepted", 100_000), ("routing_fee", 1500), ("lost", 100_000)),
            -100_001_500,
            True,
        ),
        ("btc-to-ln/v1", (("accepted", 9), ("routing_fee", 1), ("lost", None)), -1, False),
        (
            "ln-to-btc/v1",
            (("accepted", 9), ("funding_fee", 210), ("refund_fee", 180), ("refunded", None)),
            -390_000,
            True,
        ),
        (  # the client's claim beat our refund: its fee never confirmed
            "ln-to-btc/v1",
            (("accepted", 9), ("funding_fee", 210), ("refund_fee", 180), ("completed", 1500)),
            1_290_000,
            True,
        ),
        ("ln-to-btc/v1", (("accepted", 9), ("refunded", None)), 0, False),
        ("ln-to-erc20/v1", (("accepted", 9), ("gas", 50_000), ("completed", 100)), 100_000, True),
        ("erc20-to-ln/v1", (("accepted", 9), ("gas", 5), ("completed", 5)), 5000, False),
    ],
)
def test_swap_net_is_exact_only_when_every_expected_cost_was_measured(
    profile: str, rows: tuple[tuple[str, int | None], ...], net_msat: int, *, exact: bool
) -> None:
    result = swap_result(_entries(*rows), profile)
    assert result is not None
    assert (result.net_msat, result.exact) == (net_msat, exact)


def test_gas_is_reported_apart_and_an_open_swap_has_no_result() -> None:
    result = swap_result(
        _entries(("accepted", 9), ("gas", 50_000), ("gas", None), ("refunded", None)),
        "ln-to-erc20/v1",
    )
    assert result is not None
    assert (result.gas_wei, result.gas_measured, result.exact) == (50_000, False, True)
    assert swap_result(_entries(("accepted", 9), ("routing_fee", 5)), "btc-to-ln/v1") is None


def test_summary_counts_the_window_and_the_full_cost_of_swaps_closed_in_it() -> None:
    ledger = Ledger()
    since, until = MIDNIGHT, MIDNIGHT + DAY
    ledger.add("old", since - 10, "accepted", 50_000)  # accepted yesterday, closed today
    ledger.add("old", since - 5, "routing_fee", 2000)
    ledger.add("old", since + 10, "completed", 500)
    ledger.add("old", since + 10, "claim_fee", 100)
    ledger.add("new", since + 20, "offered", 70_000)
    ledger.add("new", since + 30, "accepted", 70_000)
    ledger.add("new", since + 40, "failed")
    ledger.add("open", since + 50, "offered", 1000)
    ledger.add("open", since + 60, "accepted", 1000)
    ledger.add("later", until, "accepted", 1)  # the next window
    summary = summarize(ledger.ledger_window(since, until), "btc-to-ln/v1", since, until)
    assert (summary.offered, summary.accepted, summary.accepted_sat) == (2, 2, 71_000)
    assert summary.outcomes == {"completed": 1, "failed": 1}
    assert summary.success_percent == 50
    assert (summary.revenue_sat, summary.costs_msat, summary.net_msat) == (500, 102_000, 398_000)
    assert summary.inexact == 0
    text = summary_text(summary, HEALTHY)
    assert "From 2027-01-01 00:00 to 2027-01-02 00:00 UTC." in text
    assert "Requests: 2 accepted (71,000 sat) of 2 firm offers." in text
    assert "Closed: 2, 50% success (1 completed, 1 failed)." in text
    assert "Revenue 500 sat, costs 102 sat, losses 0 sat." in text
    assert "Net profit: 398 sat." in text
    assert "Gas" not in text
    assert "not all recorded" not in text
    assert text.endswith("Now: 2 relays connected, announcing.")


def test_summary_of_a_quiet_day_and_of_unrecorded_costs() -> None:
    quiet = summarize((), "btc-to-ln/v1", MIDNIGHT, MIDNIGHT + DAY)
    assert quiet.success_percent is None
    assert "Closed: none." in summary_text(quiet, HEALTHY)
    ledger = Ledger()
    ledger.add("pre", MIDNIGHT + 1, "completed", 1000)  # accepted before the upgrade
    ledger.add("evm", MIDNIGHT + 1, "gas", None)
    ledger.add("evm", MIDNIGHT + 2, "failed")
    summary = summarize(ledger.entries, "btc-to-ln/v1", MIDNIGHT, MIDNIGHT + DAY)
    text = summary_text(summary, ServiceHealth(0, False, True, True))  # noqa: FBT003
    assert summary.inexact == 2
    assert "Costs of 2 swaps were not all recorded" in text
    assert "the net profit is at most this" in text
    assert "Gas: 0 gwei (1 swaps not measured)." in text
    assert text.endswith("Now: 0 relays connected, not announcing (low liquidity).")


@pytest.mark.parametrize(
    ("msat", "text"),
    [(0, "0 sat"), (698_500, "698.5 sat"), (-100_001_500, "-100,001.5 sat"), (1, "0.001 sat")],
)
def test_sat_amounts_keep_millisatoshi_precision(msat: int, text: str) -> None:
    assert notifications._sat(msat) == text  # noqa: SLF001


@pytest.mark.parametrize(
    ("wei", "text"), [(42_000, "0.000042 gwei"), (21_000 * 10**9, "21,000 gwei"), (0, "0 gwei")]
)
def test_gas_is_shown_in_gwei(wei: int, text: str) -> None:
    assert notifications._gwei(wei) == text  # noqa: SLF001


@pytest.mark.parametrize(
    ("now", "at", "expected"),
    [
        (MIDNIGHT, "00:00", MIDNIGHT + DAY),  # strictly after: never twice at the boundary
        (MIDNIGHT - 1, "00:00", MIDNIGHT),
        (MIDNIGHT + 3600, "08:30", MIDNIGHT + 8 * 3600 + 1800),
        (MIDNIGHT + 9 * 3600, "08:30", MIDNIGHT + DAY + 8 * 3600 + 1800),
    ],
)
def test_summary_time_is_the_next_utc_clock_time(now: int, at: str, expected: int) -> None:
    assert next_summary_at(now, at) == expected


class Sender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, bool]] = []
        self.result: bool | BaseException = True

    def send(self, title: str, body: str, *, warning: bool) -> bool:
        self.sent.append((title, body, warning))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class Clocks:
    def __init__(self) -> None:
        self.wall = float(MIDNIGHT + 3600)
        self.mono = 0.0
        self.health = HEALTHY


def _notifier(
    ledger: Ledger,
    clocks: Clocks,
    **settings: Any,  # noqa: ANN401 - settings fields
) -> tuple[Notifier, Sender]:
    sender = Sender()
    notifier = Notifier(
        NotificationSettings(urls_file=Path("unused"), **settings),
        sender,
        ledger,  # type: ignore[arg-type]
        profile="btc-to-ln/v1",
        network="regtest",
        health=lambda: clocks.health,
        clock=lambda: clocks.wall,
        monotonic=lambda: clocks.mono,
    )
    return notifier, sender


def _claimed(ledger: Ledger, session: str, at: int) -> None:
    for kind, amount in CLAIMED:
        ledger.add(session, at, kind, amount)


def test_defaults_announce_only_losses_and_never_replay_history() -> None:
    ledger, clocks = Ledger(), Clocks()
    _claimed(ledger, "a" * 64, MIDNIGHT)
    ledger.add("b" * 64, MIDNIGHT, "accepted", 5)
    ledger.add("b" * 64, MIDNIGHT, "lost", 5)  # before serving started: summarized only
    notifier, sender = _notifier(ledger, clocks)
    asyncio.run(notifier.poll())
    assert sender.sent == []
    _claimed(ledger, "c" * 64, MIDNIGHT + 10)
    ledger.add("d" * 64, MIDNIGHT + 10, "accepted", 100_000)
    ledger.add("d" * 64, MIDNIGHT + 10, "routing_fee", 1500)
    ledger.add("d" * 64, MIDNIGHT + 11, "lost", 100_000)
    asyncio.run(notifier.poll())
    assert sender.sent == [
        (
            "RillSwap btc-to-ln/v1 (regtest): swap lost",
            (
                f"Swap {'d' * 16} lost: loss 100,000 sat, costs 1.5 sat, net -100,001.5 sat. "
                "Check it with inspect-swaps."
            ),
            True,
        )
    ]
    asyncio.run(notifier.poll())
    assert len(sender.sent) == 1  # each entry once


def test_enabled_swap_events_are_combined_into_one_delivery_per_poll() -> None:
    ledger, clocks = Ledger(), Clocks()
    notifier, sender = _notifier(
        ledger, clocks, swap_request=True, swap_confirmed=True, swap_failed=True
    )
    ledger.add("a" * 64, MIDNIGHT, "accepted", 100_000)
    asyncio.run(notifier.poll())
    assert sender.sent == [
        (
            "RillSwap btc-to-ln/v1 (regtest): swap accepted",
            f"Swap {'a' * 16} accepted for 100,000 sat.",
            False,
        )
    ]
    for kind, amount in CLAIMED[1:]:
        ledger.add("a" * 64, MIDNIGHT + 5, kind, amount)
    ledger.add("b" * 64, MIDNIGHT + 6, "failed")
    ledger.add("c" * 64, MIDNIGHT + 7, "completed", 1000)  # accepted before the upgrade
    asyncio.run(notifier.poll())
    title, body, warning = sender.sent[-1]
    assert (title, warning) == ("RillSwap btc-to-ln/v1 (regtest): 3 notifications", False)
    assert body.split("\n\n") == [
        (
            f"swap completed\nSwap {'a' * 16} completed: revenue 1,000 sat, costs 301.5 sat, "
            "net 698.5 sat."
        ),
        f"swap failed\nSwap {'b' * 16} failed.",
        (
            f"swap completed\nSwap {'c' * 16} completed: revenue 1,000 sat, net 1,000 sat. "
            "Some costs were not recorded: the net is at most this."
        ),
    ]


def test_health_alerts_wait_for_the_grace_period_and_clear_once() -> None:
    ledger, clocks = Ledger(), Clocks()
    notifier, sender = _notifier(ledger, clocks)
    clocks.health = ServiceHealth(0, False, False, True)  # noqa: FBT003
    asyncio.run(notifier.poll())
    clocks.mono = 299
    asyncio.run(notifier.poll())
    assert sender.sent == []  # a reconnect or one slow RPC is not an alert
    clocks.mono = 300
    asyncio.run(notifier.poll())
    title, body, warning = sender.sent[-1]
    assert (title, warning) == ("RillSwap btc-to-ln/v1 (regtest): 3 notifications", True)
    assert body.split("\n\n") == [
        "relays down\nNo relay connected for 5 minutes: clients cannot reach this provider.",
        "quotes paused\nQuotes refused for 5 minutes: chain tip unavailable.",
        "low liquidity\nLiquidity below every amount band for 5 minutes: not announcing.",
    ]
    clocks.mono = 10_000
    asyncio.run(notifier.poll())
    assert len(sender.sent) == 1  # raised once per streak
    clocks.health = ServiceHealth(1, False, True, True)  # noqa: FBT003
    asyncio.run(notifier.poll())
    assert sender.sent[-1][1].split("\n\n") == [
        "relays back\nA relay is connected again.",
        "quotes resumed\nQuotes are answered again.",
    ]
    clocks.health = ServiceHealth(0, True, True, False)  # noqa: FBT003
    asyncio.run(notifier.poll())
    clocks.mono += 100
    clocks.health = HEALTHY  # recovered within the grace: nothing to clear
    asyncio.run(notifier.poll())
    assert sender.sent[-1] == (
        "RillSwap btc-to-ln/v1 (regtest): liquidity back",
        "Liquidity covers an amount band: announcing again.",
        False,
    )
    assert len(sender.sent) == 3


def test_disabled_alerts_are_not_tracked_and_both_quote_inputs_are_named() -> None:
    ledger, clocks = Ledger(), Clocks()
    notifier, sender = _notifier(
        ledger, clocks, relays_down=False, low_liquidity=False, alert_after_seconds=90
    )
    clocks.health = ServiceHealth(0, False, False, False)  # noqa: FBT003
    asyncio.run(notifier.poll())
    clocks.mono = 90
    asyncio.run(notifier.poll())
    assert sender.sent == [
        (
            "RillSwap btc-to-ln/v1 (regtest): quotes paused",
            "Quotes refused for 90 seconds: chain tip and claim fee estimate unavailable.",
            True,
        )
    ]


def test_daily_summary_at_the_configured_utc_time_once_per_day() -> None:
    ledger, clocks = Ledger(), Clocks()
    clocks.wall = MIDNIGHT + 7 * 3600
    notifier, sender = _notifier(ledger, clocks, summary_time="08:00")
    _claimed(ledger, "a" * 64, MIDNIGHT + 7 * 3600)
    clocks.wall = MIDNIGHT + 8 * 3600 - 1
    asyncio.run(notifier.poll())
    assert sender.sent == []
    clocks.wall = MIDNIGHT + 8 * 3600
    asyncio.run(notifier.poll())
    ((title, body, warning),) = sender.sent
    assert (title, warning) == ("RillSwap btc-to-ln/v1 (regtest): daily summary", False)
    assert body.startswith("From 2026-12-31 08:00 to 2027-01-01 08:00 UTC.\n")
    assert "Net profit: 698.5 sat." in body
    clocks.wall += DAY - 1
    asyncio.run(notifier.poll())
    assert len(sender.sent) == 1
    clocks.wall += 3 * DAY  # a stalled loop sends the latest day, not a backlog
    asyncio.run(notifier.poll())
    asyncio.run(notifier.poll())
    assert len(sender.sent) == 2
    assert "From 2027-01-03 08:00 to 2027-01-04 08:00 UTC." in sender.sent[-1][1]


def test_disabled_summary_is_never_computed(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger, clocks = Ledger(), Clocks()
    notifier, sender = _notifier(ledger, clocks, daily_summary=False)
    monkeypatch.setattr(ledger, "ledger_window", None)  # would fail if called
    clocks.wall += 2 * DAY
    asyncio.run(notifier.poll())
    assert sender.sent == []


def test_failures_are_logged_without_detail_and_never_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ledger, clocks = Ledger(), Clocks()
    notifier, sender = _notifier(ledger, clocks)
    ledger.add("a" * 64, MIDNIGHT, "lost", 5)
    sender.result = OSError("https://hooks.example/SECRET refused")
    asyncio.run(notifier.poll())
    sender.result = False
    ledger.add("b" * 64, MIDNIGHT, "lost", 5)
    asyncio.run(notifier.poll())
    ledger.fail = True  # the swap events fail; health and the summary still go out
    clocks.wall += DAY
    asyncio.run(notifier.poll())
    assert [title.rsplit(": ", 1)[1] for title, _body, _w in sender.sent] == [
        "swap lost",
        "swap lost",
        "daily summary",
    ]
    messages = [record.getMessage() for record in caplog.records]
    assert "notification not delivered: OSError" in messages
    assert "notification not delivered to every service" in messages
    assert "notifications skipped: OSError" in messages
    assert not any("SECRET" in message for message in messages)


def test_start_and_close_bracket_serving_and_flush_the_last_events() -> None:
    async def scenario() -> list[tuple[str, str, bool]]:
        ledger, clocks = Ledger(), Clocks()
        notifier, sender = _notifier(ledger, clocks, service_start_stop=True)
        notifier._poll_seconds = 3600  # noqa: SLF001 - only start and close deliver
        notifier.start()
        for _ in range(100):
            if sender.sent:
                break
            await asyncio.sleep(0.01)
        ledger.add("a" * 64, MIDNIGHT, "lost", 5)  # recorded during shutdown
        await notifier.close(failed=True)
        return sender.sent

    sent = asyncio.run(scenario())
    assert [(title.rsplit(": ", 1)[1], warning) for title, _body, warning in sent] == [
        ("service started", False),
        ("2 notifications", True),
    ]
    assert sent[1][1].split("\n\n") == [
        (  # no routing fee row: the net is only a bound
            f"swap lost\nSwap {'a' * 16} lost: loss 5 sat, net -5 sat. Check it with "
            "inspect-swaps. Some costs were not recorded: the net is at most this."
        ),
        "service stopped\nServing ended on an error.",
    ]


def test_close_never_waits_longer_than_its_bound(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    ledger, clocks = Ledger(), Clocks()
    notifier, sender = _notifier(ledger, clocks, service_start_stop=True)
    release = threading.Event()
    sender.send = lambda *_a, **_k: release.wait(5)  # type: ignore[method-assign]
    monkeypatch.setattr(notifications, "CLOSE_TIMEOUT_SECONDS", 0.05)

    async def scenario() -> None:
        try:
            await asyncio.wait_for(notifier.close(failed=False), 2)
        finally:
            release.set()  # let the stuck delivery thread end before the loop closes

    asyncio.run(scenario())
    assert "last notification not delivered before shutdown" in caplog.messages


class _Hook(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers["Content-Length"])
        self.server.received.append((self.path, json.loads(self.rfile.read(length))))  # type: ignore[attr-defined]
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


@contextlib.contextmanager
def serve_hook() -> Iterator[tuple[str, list[tuple[str, dict[str, Any]]]]]:
    """Run a local JSON webhook; its path stands in for a service token."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Hook)
    received: list[tuple[str, dict[str, Any]]] = []
    server.received = received  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"json://127.0.0.1:{server.server_port}/hook/SECRET", received
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def hook() -> Iterator[tuple[str, list[tuple[str, dict[str, Any]]]]]:
    with serve_hook() as served:
        yield served
    # Apprise delivers from process-wide pools whose idle workers outlive the
    # call; stop them so later tests that fork run single-threaded.
    from apprise import apprise as dispatch  # noqa: PLC0415 - optional extra

    for name in ("_coordinator_executor", "_shared_executor"):
        pool = getattr(dispatch, name)
        if pool is not None:
            pool.shutdown(wait=True)
            setattr(dispatch, name, None)


def _urls(tmp_path: Path, text: str | bytes, mode: int = 0o600, name: str = "notify") -> Path:
    path = tmp_path / f"{name}.urls"
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    path.chmod(mode)
    return path


def test_urls_file_is_private_and_each_url_is_checked_without_echoing_it(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    good = "json://127.0.0.1:9/hook"
    with pytest.raises(OperatorConfigError, match=r"^notification URL refused \(line 3\)$"):
        AppriseSender(_urls(tmp_path, f"# webhook\n\ntgram://SECRET\n{good}\n"))
    assert not any("SECRET" in message for message in caplog.messages)
    assert logging.getLogger("apprise").disabled is False
    link = tmp_path / "link.urls"
    link.symlink_to(_urls(tmp_path, good, name="target"))
    cases = [
        (_urls(tmp_path, good, 0o640, name="shared"), "must be a 0600 regular file"),
        (_urls(tmp_path, "# nothing yet\n\n", name="empty"), "holds no URL"),
        (_urls(tmp_path, f"{good}\n" * 1000, name="large"), "too large"),
        (_urls(tmp_path, b"\xff\xfe", name="binary"), "must be UTF-8 text"),
        (tmp_path / "missing.urls", "unavailable"),
        (link, "unavailable"),
    ]
    for path, message in cases:
        with pytest.raises(OperatorConfigError, match=message):
            AppriseSender(path)
    AppriseSender(_urls(tmp_path, f"  {good}  \n# another\n{good}/second\n"))


def test_notifications_without_the_extra_refuse_to_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "apprise", None)  # not installed
    with pytest.raises(OperatorConfigError, match=r"install rill-provider\[notifications\]"):
        AppriseSender(_urls(tmp_path, "json://127.0.0.1:9/hook"))


def test_settings_defaults_and_config_resolution(tmp_path: Path) -> None:
    from test_cli import _config  # noqa: PLC0415 - shared operator config fixture

    defaults = NotificationSettings(urls_file=Path("notify.urls"))
    assert defaults.model_dump(exclude={"urls_file"}) == {
        "swap_request": False,
        "swap_confirmed": False,
        "swap_failed": False,
        "swap_lost": True,
        "daily_summary": True,
        "summary_time": "00:00",
        "low_liquidity": True,
        "relays_down": True,
        "quotes_paused": True,
        "service_start_stop": False,
        "alert_after_seconds": 300,
    }
    assert load_config(_config(tmp_path)).notifications is None
    config = load_config(_config(tmp_path, notifications={"urls_file": "notify.urls"}))
    assert config.notifications is not None
    assert config.notifications.urls_file == tmp_path / "notify.urls"
    for bad in (
        {"summary_time": "24:00"},
        {"summary_time": "8:00"},
        {"alert_after_seconds": 59},
        {"swap_lost": None},
        {"surprise": True},
    ):
        with pytest.raises(OperatorConfigError):
            load_config(_config(tmp_path, notifications={"urls_file": "n.urls", **bad}))


def test_real_store_events_and_summary_reach_an_apprise_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hook: tuple[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    from test_live_session_store import Harness  # noqa: PLC0415 - real store fixtures
    from test_swap_ledger import _claimed_swap  # noqa: PLC0415

    url, received = hook
    urls = _urls(tmp_path, f"# webhook\n{url}\n")
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    wall = [1000.0]
    with harness.acquire() as store:
        notifier = Notifier(
            NotificationSettings(urls_file=urls, swap_confirmed=True),
            AppriseSender(urls),
            store,
            profile="btc-to-ln/v1",
            network="regtest",
            health=lambda: HEALTHY,
            clock=lambda: wall[0],
        )
        session = _claimed_swap(store, harness)  # 1.234 sat routing, 300 sat claim
        asyncio.run(notifier.poll())
        wall[0] = DAY  # the first midnight after the swap
        asyncio.run(notifier.poll())
    assert [(path, body["title"], body["type"]) for path, body in received] == [
        ("/hook/SECRET", "RillSwap btc-to-ln/v1 (regtest): swap completed", "info"),
        ("/hook/SECRET", "RillSwap btc-to-ln/v1 (regtest): daily summary", "info"),
    ]
    assert received[0][1]["message"] == (
        f"Swap {session[:16]} completed: revenue 1,000 sat, costs 301.234 sat, net 698.766 sat. "
        "Some costs were not recorded: the net is at most this."  # the fixture skips acceptance
    )
    summary = received[1][1]["message"]
    assert "Closed: 1, 100% success (1 completed)." in summary
    assert "Net profit: 698.766 sat." in summary
    assert "Costs of 1 swaps were not all recorded" in summary
