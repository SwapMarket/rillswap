"""Exclusive time, inclusive height, and terminal reverse attempt boundaries."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from test_live_session_store import Harness

from rill_provider.reverse_cooperation import ReverseCooperationWindow

if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class Clock:
    wall: float = 1000.0
    monotonic: float = 100.0

    def utc(self) -> float:
        return self.wall

    def steady(self) -> float:
        return self.monotonic

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.monotonic += seconds


def _window(clock: Clock, *, deadline: int = 1030) -> ReverseCooperationWindow:
    return ReverseCooperationWindow(
        signed_deadline_at=deadline,
        signed_deadline_height=110,
        claim_height_cutoff=110,
        wall_clock=clock.utc,
        monotonic_clock=clock.steady,
    )


@pytest.mark.parametrize("remaining", [1, 15, 30, 1000])
def test_signed_deadline_intersects_frozen_local_cap(remaining: int) -> None:
    clock = Clock()
    attempt = _window(clock, deadline=int(clock.wall) + remaining)
    assert attempt.monotonic_deadline == clock.monotonic + min(remaining, 30)
    clock.advance(min(remaining, 30) - 0.001)
    attempt.check(tip_height=110)  # Equality at the signed refund margin is permitted.
    clock.advance(0.001)
    with pytest.raises(TimeoutError, match="reverse cooperation window closed"):
        attempt.check(tip_height=110)
    clock.wall, clock.monotonic = 900, 90
    assert not attempt.time_allowed()  # Clock retreat never revives expiry.


@pytest.mark.parametrize(
    "movement",
    ["wall backward", "wall forward", "monotonic forward", "nonfinite wall", "nonfinite monotonic"],
)
def test_clock_movements_do_not_renew_or_restore_permission(movement: str) -> None:
    clock = Clock()
    attempt = _window(clock, deadline=1010)
    deadline = attempt.monotonic_deadline
    if movement == "wall backward":
        clock.wall = 990
        clock.monotonic = deadline
    elif movement == "wall forward":
        clock.wall = 1010
    elif movement == "monotonic forward":
        clock.monotonic = deadline
    elif movement == "nonfinite wall":
        clock.wall = float("nan")
    else:
        clock.monotonic = float("inf")
    assert not attempt.time_allowed()
    clock.wall, clock.monotonic = 1000, 100
    assert not attempt.time_allowed()
    assert attempt.monotonic_deadline == deadline


def test_pre_expiry_wall_retreat_preserves_frozen_monotonic_boundary() -> None:
    clock = Clock()
    attempt = _window(clock)
    clock.advance(20)
    assert attempt.time_allowed()
    clock.wall = 900
    assert attempt.time_allowed()
    assert attempt.monotonic_deadline == 130
    clock.wall, clock.monotonic = 900, 130
    assert not attempt.time_allowed()


def test_monotonic_clock_regression_is_terminal_not_extra_elapsed_time() -> None:
    clock = Clock()
    attempt = _window(clock)
    clock.advance(20)
    assert attempt.time_allowed()
    clock.monotonic = 90
    assert not attempt.time_allowed()
    clock.monotonic = 121
    assert not attempt.time_allowed()


@pytest.mark.parametrize("height", [111, -1, True])
def test_observed_height_violation_is_terminal_even_after_height_retreat(height: int) -> None:
    clock = Clock()
    attempt = _window(clock)
    with pytest.raises(TimeoutError):
        attempt.check(tip_height=height)
    with pytest.raises(TimeoutError):
        attempt.check(tip_height=110)
    assert not attempt.time_allowed()


def test_explicit_abandonment_never_changes_or_renews_deadline() -> None:
    clock = Clock()
    attempt = _window(clock)
    attempt.abandon()
    assert attempt.monotonic_deadline == 130
    assert not attempt.time_allowed()
    with pytest.raises(TimeoutError):
        attempt.check(tip_height=100)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signed_deadline_at", 1000),
        ("signed_deadline_at", True),
        ("signed_deadline_height", 0),
        ("signed_deadline_height", 111),
        ("signed_deadline_height", True),
        ("claim_height_cutoff", True),
    ],
)
def test_invalid_signed_bounds_cannot_construct_window(field: str, value: int) -> None:
    values = {"signed_deadline_at": 1030, "signed_deadline_height": 110, "claim_height_cutoff": 110}
    values[field] = value
    with pytest.raises(ValueError, match="invalid reverse cooperation bounds"):
        ReverseCooperationWindow(**values, wall_clock=lambda: 1000, monotonic_clock=lambda: 100)


def test_clock_sampling_consumes_budget_instead_of_shifting_its_anchor() -> None:
    clock = Clock()

    def slow_wall() -> float:
        clock.advance(5)
        return clock.wall

    attempt = ReverseCooperationWindow(
        signed_deadline_at=1030,
        signed_deadline_height=110,
        claim_height_cutoff=110,
        wall_clock=slow_wall,
        monotonic_clock=clock.steady,
    )
    assert attempt.monotonic_deadline == 125  # Initial sampling costs five seconds.


def test_clock_failure_permanently_fences_transport_guard() -> None:
    clock = Clock()
    failed = False

    def sample() -> float:
        if failed:
            raise RuntimeError("private adapter failure")
        return clock.wall

    attempt = ReverseCooperationWindow(
        signed_deadline_at=1030,
        signed_deadline_height=110,
        claim_height_cutoff=110,
        wall_clock=sample,
        monotonic_clock=clock.steady,
    )
    failed = True
    assert not attempt.time_allowed()
    failed = False
    assert not attempt.time_allowed()


def test_gate_wait_consumes_signed_deadline_without_starting_expensive_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()

    async def exercise() -> None:
        with harness.acquire() as store:
            clock = Clock()
            waiting = asyncio.Event()
            started: list[bool] = []

            async def queued() -> None:
                waiting.set()
                async with store.reverse_operations.operation() as operation:
                    # Authentication would precede construction. Gate wait is
                    # charged to the signed deadline, not refunded at acquisition.
                    attempt = _window(clock, deadline=1005)
                    await operation.worker(lambda: started.append(attempt.time_allowed()))

            async with store.reverse_operations.operation():
                task = asyncio.create_task(queued())
                await waiting.wait()
                clock.advance(5)
            with pytest.raises(ValueError, match="invalid reverse cooperation bounds"):
                await task
            assert started == []

    asyncio.run(exercise())


def test_late_settlement_cannot_reopen_permission_and_gate_retains_actual_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()

    async def exercise() -> None:
        with harness.acquire() as store:
            clock = Clock()
            attempt = _window(clock)
            entered, release = threading.Event(), threading.Event()
            competitor_entered = asyncio.Event()

            def settle() -> str:
                assert attempt.time_allowed()
                entered.set()
                assert release.wait(5)
                return "SETTLED"

            async def first() -> str:
                async with store.reverse_operations.operation() as operation:
                    result = await operation.worker(settle)
                    assert result == "SETTLED"  # Owed settlement can finish late.
                    with pytest.raises(TimeoutError):
                        attempt.check(tip_height=110)
                    return result

            async def competing() -> None:
                async with store.reverse_operations.operation():
                    competitor_entered.set()

            task = asyncio.create_task(first())
            assert await asyncio.to_thread(entered.wait, 5)
            competitor = asyncio.create_task(competing())
            await asyncio.sleep(0)
            assert not competitor_entered.is_set()
            clock.advance(30)
            assert not attempt.time_allowed()
            release.set()
            assert await task == "SETTLED"
            await competitor
            assert competitor_entered.is_set()
            assert not attempt.time_allowed()

    asyncio.run(exercise())


def test_queued_rpc_expiry_prevents_transport_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()

    async def exercise() -> None:
        asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
        with harness.acquire() as store:
            clock = Clock()
            attempt = _window(clock)
            entered, release = threading.Event(), threading.Event()
            transport_calls: list[bool] = []

            def occupy_executor() -> None:
                entered.set()
                assert release.wait(5)

            first = asyncio.get_running_loop().run_in_executor(None, occupy_executor)
            assert entered.wait(5)
            async with store.reverse_operations.operation() as operation:

                def guarded_rpc() -> bool:
                    if not attempt.time_allowed():
                        return False
                    transport_calls.append(True)
                    return True

                async def release_queue() -> None:
                    await asyncio.sleep(0)
                    clock.advance(30)
                    release.set()

                releasing = asyncio.create_task(release_queue())
                assert await operation.worker(guarded_rpc) is False
                await releasing
                await first
            assert transport_calls == []
            assert not attempt.time_allowed()

    asyncio.run(exercise())
