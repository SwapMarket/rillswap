"""One acquired owner's reverse economic execution and physical completion."""

from __future__ import annotations

import asyncio
import contextvars
import threading
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, TypeVar

from rill_provider.live_session_store import LiveSessionStoreError, StaleOwnerError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from typing import Any

    from rill_provider.live_session_store import LiveSessionStore

_T = TypeVar("_T")


class ReverseOperation:
    """Task-bound execution token, never signing or payment authority.

    Check again before synchronous economic effects. Workers must not access
    SQLite or native handles: store closure destroys those immediately, even
    while physical owner exclusion remains pinned for external RPC completion.
    A timeout around non-worker awaits must escape the operation context, or
    its handler must explicitly abandon this token before continuing. Standard
    timeout scopes restore cancellation counts, which check() cannot detect.
    """

    def __init__(self, store: LiveSessionStore) -> None:
        """Create a fresh token inside the acquired owner's operation gate."""
        self._store = store
        self._task = asyncio.current_task()
        self._initial_cancellations = 0 if self._task is None else self._task.cancelling()
        self._stopped = threading.Event()
        self._workers: set[asyncio.Future[Any]] = set()

    def _check_execution(self) -> None:
        if self._stopped.is_set():
            raise LiveSessionStoreError("reverse operation stopped")
        if not self._store.owner_is_open:
            raise StaleOwnerError("store handle closed or inherited across fork")

    def check(self) -> None:
        """Fence reuse, child-task borrowing, and observed cancellation."""
        if asyncio.current_task() is not self._task:
            raise LiveSessionStoreError("reverse operation belongs to another task")
        if self._task is not None and self._task.cancelling() > self._initial_cancellations:
            self._stopped.set()
        self._check_execution()

    def abandon(self) -> None:
        """Invalidate a caught non-worker timeout; never reactivate this token."""
        if asyncio.current_task() is not self._task:
            raise LiveSessionStoreError("reverse operation belongs to another task")
        self._stopped.set()

    async def worker(self, function: Callable[[], _T]) -> _T:
        """Own actual external execution, including uncertain late completion."""
        self.check()

        def execute() -> _T:
            self._check_execution()  # Queueing does not reserve authority.
            return function()

        context = contextvars.copy_context()
        future = asyncio.get_running_loop().run_in_executor(None, context.run, execute)
        self._workers.add(future)
        try:
            # A canceled shield can log private late errors on Python 3.14.
            # wait isolates cancellation without canceling the executor Future.
            await asyncio.wait((future,))
            result = future.result()
            self.check()
            return result  # noqa: TRY300 - reject late ownership before returning evidence
        except asyncio.CancelledError:
            self._stopped.set()
            raise
        finally:
            if future.done():
                if not future.cancelled():
                    future.exception()
                self._workers.discard(future)

    async def _drain(self) -> None:
        self._stopped.set()
        draining = asyncio.gather(*self._workers, return_exceptions=True)
        canceled = False
        while not draining.done():
            try:
                await asyncio.shield(draining)
            except asyncio.CancelledError:
                canceled = True
        draining.result()
        self._workers.clear()
        if canceled:
            raise asyncio.CancelledError


class ReverseOperations:
    """Serialize one store owner's reverse decisions through actual drainage."""

    def __init__(self, store: LiveSessionStore) -> None:
        """Bind one owner without I/O or reconstructing persisted authority."""
        self._store = store
        self._lock = asyncio.Lock()
        self._active_task: asyncio.Task[Any] | None = None
        self._active_operation: ReverseOperation | None = None

    def check(self, operation: ReverseOperation) -> None:
        """Require this exact active gate token, not merely another live owner."""
        if operation is not self._active_operation or operation is None:
            raise LiveSessionStoreError("reverse operation is not active in this gate")
        operation.check()

    @asynccontextmanager
    async def operation(self) -> AsyncIterator[ReverseOperation]:
        """Acquire before fresh evidence; no SQLite transaction spans RPC waits.

        Cancellation before acquisition affects only that waiter. Cancellation
        after acquisition stops this token and drains, but does not disable
        subsequent fresh unilateral recovery on a still-open owner.
        """
        if asyncio.current_task() is self._active_task:
            raise LiveSessionStoreError("reverse operation already active")
        async with self._lock:
            with self._store.retain_owner():
                operation = ReverseOperation(self._store)
                self._active_task = asyncio.current_task()
                self._active_operation = operation
                try:
                    yield operation
                finally:
                    try:
                        await operation._drain()  # noqa: SLF001 - token lifetime belongs to this gate
                    finally:
                        self._active_task = None
                        self._active_operation = None
