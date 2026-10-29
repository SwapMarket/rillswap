"""Real owner exclusion outlives cancellation and actual reverse RPC workers."""

from __future__ import annotations

import asyncio
import contextvars
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from typing import TYPE_CHECKING

import pytest
from test_live_session_store import Harness

from rill_provider.live_session_store import LiveSessionStoreError, StaleOwnerError
from rill_provider.reverse_operations import ReverseOperation, ReverseOperations

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


def test_transport_predicate_is_worker_safe_and_expires_with_exact_gate_membership(
    harness: Harness,
) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            async with store.reverse_operations.operation() as operation:
                predicate = operation.submission_allowed
                assert predicate() is True
                assert await operation.worker(predicate) is True
                bare = ReverseOperation(store)
                assert bare.submission_allowed() is False
            assert predicate() is False
            async with store.reverse_operations.operation() as fresh:
                assert fresh.submission_allowed() is True
                assert predicate() is False

        asyncio.run(exercise())


@pytest.mark.parametrize("stop", ["abandon", "close", "foreign gate"])
def test_stopped_closed_or_foreign_gate_never_grants_transport_submission(
    harness: Harness, stop: str
) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            gate = ReverseOperations(store) if stop == "foreign gate" else store.reverse_operations
            async with gate.operation() as operation:
                if stop == "abandon":
                    operation.abandon()
                elif stop == "close":
                    store.close()
                assert operation.submission_allowed() is False
                # A plain executor read needs no event loop, SQL, or native context.
                assert await asyncio.to_thread(operation.submission_allowed) is False

        asyncio.run(exercise())


@pytest.mark.parametrize("cancellation", ["caller", "global"])
@pytest.mark.parametrize("late_error", [False, True])
def test_actual_worker_completion_keeps_closed_owner_pinned_through_repeated_cancellation(  # noqa: PLR0915 - one physical owner/RPC lifecycle
    harness: Harness,
    cancellation: str,
    *,
    late_error: bool,
) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            entered, release, finished = threading.Event(), threading.Event(), threading.Event()
            caller_done = asyncio.Event()
            loop_errors: list[dict] = []
            asyncio.get_running_loop().set_exception_handler(
                lambda _loop, context: loop_errors.append(context)
            )

            def rpc() -> None:
                entered.set()
                try:
                    assert release.wait(3)
                    if late_error:
                        raise RuntimeError("private RPC error must never reach loop logging")
                finally:
                    finished.set()

            async def call() -> None:
                try:
                    async with store.reverse_operations.operation() as operation:
                        await operation.worker(rpc)
                finally:
                    caller_done.set()

            running = asyncio.create_task(call())
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                store.close()
                assert not store.owner_is_open
                for _ in range(3):
                    if cancellation == "caller":
                        running.cancel()
                    else:
                        controller = asyncio.current_task()
                        for task in asyncio.all_tasks():
                            if task is not controller:
                                task.cancel()
                    await asyncio.sleep(0)
                    assert not caller_done.is_set()
                    with pytest.raises(LiveSessionStoreError, match="owned by another"):
                        harness.acquire()
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await running
                assert finished.is_set()
                assert caller_done.is_set()
                assert not loop_errors
                with harness.acquire() as fresh:
                    assert fresh.generation == store.generation + 1
            finally:
                release.set()
                await asyncio.gather(running, return_exceptions=True)

        asyncio.run(exercise())


def test_token_is_task_bound_stopped_after_caught_cancel_and_not_reusable(  # noqa: PLR0915 - cancellation and physical drainage lifecycle
    harness: Harness,
) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            calls: list[str] = []
            entered, release = threading.Event(), threading.Event()
            tokens = []
            cancellation_handled = asyncio.Event()

            def rpc() -> None:
                entered.set()
                assert release.wait(3)

            async def call() -> None:
                async with store.reverse_operations.operation() as operation:
                    tokens.append(operation)
                    with pytest.raises(LiveSessionStoreError, match="another task"):
                        await asyncio.create_task(operation.worker(lambda: calls.append("child")))
                    with pytest.raises(LiveSessionStoreError, match="already active"):
                        async with store.reverse_operations.operation():
                            pass
                    try:
                        await operation.worker(rpc)
                    except asyncio.CancelledError:
                        with pytest.raises(LiveSessionStoreError, match="stopped"):
                            operation.check()
                        with pytest.raises(LiveSessionStoreError, match="stopped"):
                            await operation.worker(lambda: calls.append("after canceled worker"))
                        cancellation_handled.set()

            running = asyncio.create_task(call())
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                running.cancel()
                await cancellation_handled.wait()
                assert not running.done()
                assert store.owner_is_open
                assert store.reverse_operations._active_operation is tokens[0]  # noqa: SLF001 - active drainage
                assert await asyncio.to_thread(tokens[0].submission_allowed) is False
                release.set()
                await running  # Caller deliberately caught cancellation; drainage still completed.
                assert not calls
                with pytest.raises(LiveSessionStoreError):
                    tokens[0].check()
                async with store.reverse_operations.operation() as operation:
                    assert operation.submission_allowed() is True
                    assert tokens[0].submission_allowed() is False
                    assert (
                        store.reserve(harness.initiation).revision == 0
                    )  # Renewed authoritative check.
                    await operation.worker(lambda: calls.append("fresh operation"))
                assert calls == ["fresh operation"]
                with pytest.raises(LiveSessionStoreError, match="stopped"):
                    operation.check()  # Same task cannot reuse a token after exit either.
            finally:
                release.set()
                await asyncio.gather(running, return_exceptions=True)

        asyncio.run(exercise())


def test_canceling_a_lock_waiter_does_not_disturb_active_or_next_operation(
    harness: Harness,
) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            entered, release = threading.Event(), threading.Event()
            events: list[str] = []

            def rpc() -> None:
                entered.set()
                assert release.wait(3)
                events.append("active completed")

            async def active() -> None:
                async with store.reverse_operations.operation() as operation:
                    await operation.worker(rpc)

            async def queued() -> None:
                async with store.reverse_operations.operation():
                    events.append("queued entered")

            running = asyncio.create_task(active())
            waiter = None
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                waiter = asyncio.create_task(queued())
                await asyncio.sleep(0)
                waiter.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiter
                assert not running.done()
                assert not events
                release.set()
                await running
                await queued()
                assert events == ["active completed", "queued entered"]
                assert store.owner_is_open
            finally:
                release.set()
                await asyncio.gather(
                    running, *(() if waiter is None else (waiter,)), return_exceptions=True
                )

        asyncio.run(exercise())


def test_checkpoint_fences_cancellation_caught_outside_a_worker(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            async with store.reverse_operations.operation() as operation:
                caller = asyncio.current_task()
                assert caller is not None
                caller.cancel()
                with suppress(asyncio.CancelledError):
                    await asyncio.sleep(0)
                with pytest.raises(LiveSessionStoreError, match="stopped"):
                    operation.check()
            # A fresh operation captures its own cancellation baseline and
            # requires renewed state, rather than permanently fencing recovery.
            async with store.reverse_operations.operation() as operation:
                assert store.reserve(harness.initiation).revision == 0
                assert await operation.worker(lambda: "fresh") == "fresh"

        asyncio.run(exercise())


@pytest.mark.parametrize("handling", ["escape", "abandon"])
def test_nonworker_timeout_must_escape_or_explicitly_abandon_its_token(
    harness: Harness,
    handling: str,
) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            if handling == "escape":
                with pytest.raises(TimeoutError):  # noqa: PT012 - exception must escape the gate scope
                    async with store.reverse_operations.operation() as operation:
                        async with asyncio.timeout(0):
                            await asyncio.sleep(0)
            else:
                async with store.reverse_operations.operation() as operation:
                    try:
                        async with asyncio.timeout(0):
                            await asyncio.sleep(0)
                    except TimeoutError:
                        operation.abandon()
                    with pytest.raises(LiveSessionStoreError, match="stopped"):
                        await operation.worker(lambda: "must not authorize follow-up effects")
            with pytest.raises(LiveSessionStoreError, match="stopped"):
                operation.check()
            async with store.reverse_operations.operation() as fresh:
                assert store.reserve(harness.initiation).revision == 0
                assert (
                    await fresh.worker(lambda: "recovery remains available")
                    == "recovery remains available"
                )

        asyncio.run(exercise())


@pytest.mark.parametrize("reason", ["cancellation", "closure"])
def test_executor_queue_cannot_reserve_execution_after_stop_or_owner_closure(
    harness: Harness,
    reason: str,
) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            blocker_entered, release = threading.Event(), threading.Event()
            entered_operation = asyncio.Event()
            calls: list[str] = []
            pool = ThreadPoolExecutor(max_workers=1)
            asyncio.get_running_loop().set_default_executor(pool)

            def blocker() -> None:
                blocker_entered.set()
                assert release.wait(3)

            blocking = pool.submit(blocker)
            assert blocker_entered.wait(1)

            async def call() -> None:
                async with store.reverse_operations.operation() as operation:
                    entered_operation.set()
                    await operation.worker(lambda: calls.append("must not execute"))

            running = asyncio.create_task(call())
            try:
                await entered_operation.wait()
                await asyncio.sleep(0)
                if reason == "cancellation":
                    running.cancel()
                else:
                    store.close()
                await asyncio.sleep(0)
                assert not running.done()
                release.set()
                with pytest.raises(
                    asyncio.CancelledError if reason == "cancellation" else StaleOwnerError
                ):
                    await running
                assert not calls
                blocking.result(1)
                if reason == "cancellation":
                    async with store.reverse_operations.operation() as operation:
                        await operation.worker(lambda: calls.append("fresh recovery"))
                    assert calls == ["fresh recovery"]
            finally:
                release.set()
                await asyncio.gather(running, return_exceptions=True)
                pool.shutdown(wait=True)

        asyncio.run(exercise())


@pytest.mark.parametrize("placement", ["inside", "outside"])
def test_timeout_placement_does_not_disable_fresh_recovery_after_actual_drain(
    harness: Harness,
    placement: str,
) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            entered, release, finished = threading.Event(), threading.Event(), threading.Event()

            def rpc() -> None:
                entered.set()
                try:
                    assert release.wait(3)
                finally:
                    finished.set()

            async def call() -> None:
                if placement == "inside":
                    async with store.reverse_operations.operation() as operation:
                        async with asyncio.timeout(0.1):
                            await operation.worker(rpc)
                else:
                    async with asyncio.timeout(0.1):
                        async with store.reverse_operations.operation() as operation:
                            await operation.worker(rpc)

            running = asyncio.create_task(call())
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                await asyncio.sleep(0.15)
                assert not running.done()
                release.set()
                with pytest.raises(TimeoutError):
                    await running
                assert finished.is_set()
                async with store.reverse_operations.operation() as operation:
                    assert store.reserve(harness.initiation).revision == 0
                    assert (
                        await operation.worker(lambda: "fresh debt/refund recovery")
                        == "fresh debt/refund recovery"
                    )
            finally:
                release.set()
                await asyncio.gather(running, return_exceptions=True)

        asyncio.run(exercise())


def test_shared_gate_preserves_context_and_refuses_followup_effect_after_close(
    harness: Harness,
) -> None:
    harness.provision()
    with harness.acquire() as store:

        async def exercise() -> None:
            assert store.reverse_operations is store.reverse_operations
            marker = contextvars.ContextVar("reverse-rpc-context", default="missing")
            marker.set("original caller")
            entered, release = threading.Event(), threading.Event()
            effects: list[str] = []
            observed_context: list[str] = []

            def rpc() -> str:
                entered.set()
                assert release.wait(3)
                observed_context.append(marker.get())
                return marker.get()

            async def call() -> None:
                async with store.reverse_operations.operation() as operation:
                    assert await operation.worker(rpc) == "original caller"
                    operation.check()
                    effects.append("must not happen after logical closure")

            running = asyncio.create_task(call())
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                store.close()
                release.set()
                with pytest.raises(StaleOwnerError):
                    await running
                assert not effects
                assert observed_context == ["original caller"]
                with harness.acquire() as fresh:
                    async with fresh.reverse_operations.operation() as operation:
                        assert await operation.worker(marker.get) == "original caller"
            finally:
                release.set()
                await asyncio.gather(running, return_exceptions=True)

        asyncio.run(exercise())
