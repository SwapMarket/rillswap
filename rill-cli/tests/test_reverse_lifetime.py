"""The reverse SDK owns one anchored budget and actual worker completion."""

from __future__ import annotations

import asyncio
import contextvars
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from unittest.mock import Mock

import pytest
from test_live_session_ordering import _live_provider

from rill_cli import live_reverse_swap as reverse
from rill_cli.live_swap import SwapError
from rill_cli.wallet_rpc import WalletRpcError


def test_lifetime_requires_start_and_cannot_be_renewed_or_restarted() -> None:
    async def exercise() -> None:
        async with reverse._ReverseLifetime(10) as owner:  # noqa: SLF001 - original owner contract
            assert not owner.allowed()
            with pytest.raises(TimeoutError):
                owner.check()
            with pytest.raises(SwapError, match="not started"):
                _ = owner.deadline
            assert await owner.worker(lambda: "owned startup work") == "owned startup work"
            owner.start()
            deadline = owner.deadline
            assert owner.allowed()
            with pytest.raises(SwapError, match="start refused"):
                owner.start()
            assert owner.deadline == deadline
        assert not owner.allowed()
        with pytest.raises(SwapError, match="start refused"):
            owner.start()
        with pytest.raises(TimeoutError):
            await owner.worker(lambda: "must not run")

    asyncio.run(exercise())


@pytest.mark.parametrize("after_validation", [False, True])
def test_funding_wait_cannot_renew_original_deadline_or_accept_late_validation(
    monkeypatch: pytest.MonkeyPatch,
    *,
    after_validation: bool,
) -> None:
    async def exercise() -> None:
        session, _, frames = _live_provider(monkeypatch)
        contract = "ab" * 32
        session._buffer_inbox(  # noqa: SLF001 - retained authenticated FIFO fixture
            frames[b"seq1"].model_copy(
                update={
                    "message_type": "funding_binding",
                    "contract_hash": contract,
                    "in_reply_to": None,
                }
            )
        )
        clock = {"now": 100.0}
        monkeypatch.setattr(reverse, "time", Mock(monotonic=lambda: clock["now"]))

        def validate(*_args: object, **_kwargs: object) -> tuple:
            clock["now"] = 101.0
            return Mock(), "signature", b"funding"

        check = Mock(side_effect=validate)
        monkeypatch.setattr(reverse, "_check_funding", check)
        with pytest.raises(SwapError, match="funding not observed in time"):
            await reverse._await_funding(  # noqa: SLF001 - fixed original budget
                session,
                contract=contract,
                timeout=100,
                terms=Mock(),
                provider_key="cd" * 32,
                script=b"script",
                crypto=Mock(),
                absolute_deadline=101.0 if after_validation else 100.0,
            )
        assert check.call_count == (1 if after_validation else 0)
        assert len(session.inbox) == (0 if after_validation else 1)
        assert not session._settlement_active  # noqa: SLF001

    asyncio.run(exercise())


def test_stopped_startup_cannot_start_payment_lifetime() -> None:
    async def exercise() -> None:
        async with reverse._ReverseLifetime(10) as owner:  # noqa: SLF001
            assert not owner.allowed()
        with pytest.raises(SwapError, match="start refused"):
            owner.start()

    asyncio.run(exercise())


@pytest.mark.parametrize("reason", ["expiry", "cancel"])
def test_queued_payment_cannot_execute_after_authority_is_lost(reason: str) -> None:
    async def exercise() -> None:
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        entered, release = asyncio.Event(), threading.Event()

        def occupy() -> None:
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(2)

        blocker = loop.run_in_executor(None, occupy)
        # Do not enqueue another executor waiter behind the blocked worker.
        await entered.wait()
        payment = Mock(side_effect=AssertionError("late queued payment must not run"))
        owner = reverse._ReverseLifetime(0.01 if reason == "expiry" else 10)  # noqa: SLF001

        async def lifetime() -> None:
            async with owner:
                owner.start()
                await owner.worker(payment)

        running = asyncio.create_task(lifetime())
        try:
            await asyncio.sleep(0.03)
            if reason == "cancel":
                running.cancel()
                await asyncio.sleep(0)
            assert not running.done()
            assert not owner.allowed()
            release.set()
            with pytest.raises(TimeoutError if reason == "expiry" else asyncio.CancelledError):
                await running
            payment.assert_not_called()
        finally:
            release.set()
            await asyncio.gather(running, blocker, return_exceptions=True)

    asyncio.run(exercise())


@pytest.mark.parametrize("started", [False, True])
def test_three_cancellations_cannot_return_before_a_real_worker_finishes(*, started: bool) -> None:
    async def exercise() -> None:
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        context_open = True
        owner = reverse._ReverseLifetime(10)  # noqa: SLF001

        def writer() -> None:
            assert context_open
            entered.set()
            assert release.wait(2)
            assert context_open
            finished.set()

        async def lifetime() -> None:
            async with owner:
                if started:
                    owner.start()
                await owner.worker(writer)

        running = asyncio.create_task(lifetime())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            for _ in range(3):
                running.cancel()
                await asyncio.sleep(0)
                assert not running.done()
            assert not owner.allowed()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await running
            assert finished.is_set()
            context_open = False
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    asyncio.run(exercise())


def test_cancellation_during_successful_exit_cannot_return_success() -> None:
    async def exercise() -> None:
        entered, release = threading.Event(), threading.Event()
        owner = reverse._ReverseLifetime(10)  # noqa: SLF001

        def call() -> None:
            entered.set()
            assert release.wait(2)

        async def lifetime() -> str:
            async with owner:
                owner.start()
                with suppress(asyncio.CancelledError):
                    await owner.worker(call)
                # Simulate a caller otherwise returning successfully during drain.
                return "would otherwise succeed"

        running = asyncio.create_task(lifetime())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            running.cancel()
            await asyncio.sleep(0)
            running.cancel()
            await asyncio.sleep(0)
            assert not running.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await running
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    asyncio.run(exercise())


def test_completed_stage_cannot_renew_the_next_stage_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        clock = {"now": 100.0}
        monkeypatch.setattr(reverse, "time", Mock(monotonic=lambda: clock["now"]))
        async with reverse._ReverseLifetime(5) as owner:  # noqa: SLF001
            owner.start()
            assert owner.deadline == 105.0

            def first() -> str:
                clock["now"] = 104.0
                return "funding observed"

            assert await owner.worker(first) == "funding observed"

            def second() -> str:
                clock["now"] = 106.0
                return "late confirmed funding"

            with pytest.raises(TimeoutError):
                await owner.worker(second)
            assert owner.deadline == 105.0
            assert not owner.allowed()
            with pytest.raises(TimeoutError):
                await owner.worker(Mock(side_effect=AssertionError("no renewed watcher")))

    asyncio.run(exercise())


def test_submission_authority_failure_is_not_swallowed_as_a_retryable_false() -> None:
    async def exercise() -> None:
        async with reverse._ReverseLifetime(10) as owner:  # noqa: SLF001
            wallet = Mock(broadcast=Mock(side_effect=AssertionError("no pre-start submission")))
            with pytest.raises(TimeoutError):
                reverse._submit(wallet, b"witness", "aa" * 32, owner)  # noqa: SLF001
            wallet.broadcast.assert_not_called()
            owner.start()
            wallet.broadcast.side_effect = TimeoutError
            with pytest.raises(TimeoutError):
                reverse._submit(wallet, b"witness", "aa" * 32, owner)  # noqa: SLF001

    asyncio.run(exercise())


@pytest.mark.parametrize("expired", [False, True])
def test_wallet_rpc_error_rechecks_actual_authority_before_returning_false(
    monkeypatch: pytest.MonkeyPatch,
    *,
    expired: bool,
) -> None:
    async def exercise() -> None:
        clock = {"now": 100.0}
        monkeypatch.setattr(reverse, "time", Mock(monotonic=lambda: clock["now"]))
        async with reverse._ReverseLifetime(5) as owner:  # noqa: SLF001
            owner.start()

            def broadcast(*_args: object, **_kwargs: object) -> None:
                if expired:
                    clock["now"] = 105.0
                raise WalletRpcError("Core request authority expired or RPC unavailable")

            wallet = Mock(broadcast=Mock(side_effect=broadcast))
            if expired:
                with pytest.raises(TimeoutError):
                    reverse._submit(wallet, b"witness", "aa" * 32, owner)  # noqa: SLF001
            else:
                assert reverse._submit(wallet, b"witness", "aa" * 32, owner) is False  # noqa: SLF001
            wallet.broadcast.assert_called_once()

    asyncio.run(exercise())


@pytest.mark.parametrize("phase", ["work", "drain"])
@pytest.mark.parametrize("failure", [False, True])
def test_global_task_cancellation_cannot_complete_a_running_executor_worker(
    phase: str,
    *,
    failure: bool,
) -> None:
    async def exercise() -> None:
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        context_open = True
        context_violations: list[str] = []
        owner = reverse._ReverseLifetime(0.02 if phase == "drain" else 10)  # noqa: SLF001

        def work() -> None:
            entered.set()
            try:
                assert release.wait(2)
                if not context_open:
                    context_violations.append("caller closed context before worker completion")
                if failure:
                    raise RuntimeError("late worker failure must be consumed during drain")
            finally:
                finished.set()

        async def lifetime() -> None:
            nonlocal context_open
            try:
                async with owner:
                    owner.start()
                    await owner.worker(work)
            finally:
                context_open = False  # Model actual SDK caller cleanup, not controller timing.

        running = asyncio.create_task(lifetime())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            if phase == "drain":
                await asyncio.sleep(0.04)
            controller = asyncio.current_task()
            # Equivalent to runner-wide cancellation, not just canceling the
            # public SDK Task. Old to_thread and drain Tasks were also canceled.
            for task in asyncio.all_tasks():
                if task is not controller:
                    task.cancel()
            await asyncio.sleep(0.02)
            assert not running.done()
            assert not finished.is_set()
            assert not owner.allowed()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await running
            assert finished.is_set()
            assert not context_violations
            assert not context_open
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    asyncio.run(exercise())


def test_executor_future_preserves_caller_context_variables() -> None:
    marker = contextvars.ContextVar("reverse-test-context", default="unset")

    async def exercise() -> None:
        marker.set("caller value")
        async with reverse._ReverseLifetime(10) as owner:  # noqa: SLF001
            assert await owner.worker(marker.get) == "caller value"
            owner.start()
            assert await owner.worker(marker.get) == "caller value"

    asyncio.run(exercise())


@pytest.mark.parametrize("reason", ["caller", "global", "timeout"])
def test_late_reverse_worker_exceptions_are_consumed_without_loop_logging(reason: str) -> None:
    async def exercise() -> None:
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        loop_errors: list[dict] = []
        asyncio.get_running_loop().set_exception_handler(
            lambda _loop, context: loop_errors.append(context)
        )

        def fail() -> None:
            entered.set()
            try:
                assert release.wait(2)
                raise RuntimeError("private adapter details must not reach loop logging")
            finally:
                finished.set()

        async def lifetime() -> None:
            async with reverse._ReverseLifetime(0.02 if reason == "timeout" else 10) as owner:  # noqa: SLF001
                owner.start()
                await owner.worker(fail)

        running = asyncio.create_task(lifetime())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            if reason == "timeout":
                await asyncio.sleep(0.04)
            elif reason == "caller":
                running.cancel()
            else:
                controller = asyncio.current_task()
                for task in asyncio.all_tasks():
                    if task is not controller:
                        task.cancel()
            await asyncio.sleep(0.01)
            assert not running.done()
            release.set()
            with pytest.raises(TimeoutError if reason == "timeout" else asyncio.CancelledError):
                await running
            assert finished.is_set()
            assert not loop_errors
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    asyncio.run(exercise())
