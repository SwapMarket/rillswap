"""Test-only paid-phase guard capture, never product authority or root-cause proof.

Only explicit raise instructions in registered synchronous functions are named.
Trace callbacks never inspect exception values, locals or traceback chains.
Timing overhead remains charged to the original operation's unchanged window.
"""

from __future__ import annotations

import ast
import contextvars
import dis
import inspect
import sys
import textwrap
import threading
import time
from functools import wraps
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from types import FrameType

T = TypeVar("T")

# Diagnostic machinery must never replace even a BaseException from the
# original invocation. Failures below set UNKNOWN instead of escaping hooks.
# ruff: noqa: BLE001


def _raise_sites(
    original: Callable[..., object],
    guards: dict[tuple[type[BaseException], str], str],
) -> dict[int, tuple[type[BaseException], str]]:
    source, first = inspect.getsourcelines(original)
    tree = ast.parse(textwrap.dedent("".join(source)))
    statements = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and len(node.exc.args) == 1
            and isinstance(node.exc.args[0], ast.Constant)
            and type(node.exc.args[0].value) is str
        ):
            name = node.exc.func.id
            if (
                name
                in original.__code__.co_varnames
                + original.__code__.co_freevars
                + original.__code__.co_cellvars
            ):
                continue
            error_type = original.__globals__.get(name, original.__builtins__.get(name))
            for (expected, message), category in guards.items():
                if error_type is expected and node.exc.args[0].value == message:
                    statements.append(
                        (first + node.lineno - 1, first + node.end_lineno - 1, expected, category)
                    )
    sites = {}
    for instruction in dis.get_instructions(original):
        line = instruction.positions.lineno
        if instruction.opname == "RAISE_VARARGS" and line is not None:
            matches = [
                (kind, category)
                for begin, end, kind, category in statements
                if begin <= line <= end
            ]
            if len(matches) == 1:
                sites[instruction.offset] = matches[0]
    if {category for _kind, category in sites.values()} != set(guards.values()):
        raise ValueError("diagnostic static guard map differs")
    return sites


class PaidRefusalProbe:
    """Own bounded metadata and one copied paid-phase context, not operation rights."""

    def __init__(self, categories: tuple[tuple[type[BaseException], str], ...]) -> None:
        self.events: list[dict[str, str | int]] = []
        self.unknown = False
        self._categories = categories
        self._paid = contextvars.ContextVar("test_paid_refusal_scope", default=False)
        self._lock = threading.Lock()

    @staticmethod
    def preflight() -> None:
        if sys.gettrace() is not None or threading.gettrace() is not None:
            raise RuntimeError("diagnostic trace ownership unavailable")

    def _record(self, method: str, guard: str, category: str, started: float) -> None:
        try:
            elapsed = min(600_000, max(0, int((time.monotonic() - started) * 1000)))
            with self._lock:
                if len(self.events) < 64:
                    self.events.append(
                        {
                            "method": method,
                            "guard": guard,
                            "category": category,
                            "elapsed_ms": elapsed,
                        }
                    )
                else:
                    self.unknown = True
        except BaseException:  # Diagnostic failures must not replace original control flow.
            self.unknown = True

    def paid_phase(self, original: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(original)
        async def observed(*args: object, **kwargs: object) -> T:
            token = self._paid.set(True)
            started = time.monotonic()
            self._record("paid_scope", "enter", "none", started)
            try:
                return await original(*args, **kwargs)
            finally:
                self._paid.reset(token)
                self._record("paid_scope", "exit", "none", started)

        return observed

    def synchronous(
        self,
        original: Callable[..., T],
        method: str,
        guards: dict[tuple[type[BaseException], str], str],
    ) -> Callable[..., T]:
        sites = _raise_sites(original, guards)
        code = original.__code__

        @wraps(original)
        def observed(*args: object, **kwargs: object) -> T:
            # Context is copied into actual operation workers. Snapshot at entry,
            # including workers that outlive the parent's cancellation/reset.
            if not self._paid.get():
                return original(*args, **kwargs)
            previous = sys.gettrace()
            if previous is not None:
                self.unknown = True
                return original(*args, **kwargs)
            started = time.monotonic()

            def trace(frame: FrameType, event: str, data: object) -> Callable | None:
                try:
                    if frame.f_code is not code:
                        return None
                    frame.f_trace_lines = False
                    frame.f_trace_opcodes = False
                    if event == "exception":
                        if not isinstance(data, tuple) or len(data) != 3:
                            self.unknown = True
                            return trace
                        # The first tuple item is a type, never the exception's
                        # arguments/value or traceback. Only exact identities.
                        error_type = data[0]
                        category = next(
                            (label for kind, label in self._categories if error_type is kind),
                            "other",
                        )
                        site = sites.get(frame.f_lasti)
                        guard = site[1] if site is not None and error_type is site[0] else "unknown"
                        if guard == "unknown":
                            self.unknown = True
                        self._record(method, guard, category, started)
                except BaseException:
                    self.unknown = True
                return trace

            installed = False
            try:
                try:
                    sys.settrace(trace)
                    installed = True
                except BaseException:
                    self.unknown = True
                return original(*args, **kwargs)
            finally:
                # Never overwrite a different tool installed during the call.
                if installed and sys.gettrace() is trace:
                    try:
                        sys.settrace(previous)
                    except BaseException:
                        self.unknown = True
                elif installed:
                    self.unknown = True

        return observed
