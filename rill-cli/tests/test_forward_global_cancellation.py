"""Loop-wide cancellation cannot turn forward thread wrappers into completion."""

from __future__ import annotations

import asyncio
import contextvars
import json
import threading
from typing import TYPE_CHECKING

import pytest
from rill_crypto import Context
from test_cooperative_forward_dispatch import LIBRARY, NATIVE, Forward

from rill_cli.live_swap import SwapError

if TYPE_CHECKING:
    from pathlib import Path


@NATIVE
@pytest.mark.native_crypto
@pytest.mark.parametrize("phase", ["work", "cleanup", "timeout"])
@pytest.mark.parametrize("late_error", [False, True])
def test_forward_global_cancellation_retains_native_context_and_actual_publication(  # noqa: PLR0915 - one blocked publication lifetime
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    *,
    late_error: bool,
) -> None:
    async def exercise(crypto: Context) -> None:  # noqa: PLR0915 - one blocked publication lifetime
        fixture = Forward(crypto, tmp_path, monkeypatch)
        entered, release, finished, caller_cleanup = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        marker = contextvars.ContextVar("forward-publication-context", default="missing")
        marker.set("original caller context")
        observed: list[str] = []
        context_violations: list[str] = []
        loop_errors: list[dict] = []
        asyncio.get_running_loop().set_exception_handler(
            lambda _loop, context: loop_errors.append(context)
        )

        def write(candidate: bytes, previous: bytes | None) -> None:
            if not json.loads(candidate)["monotonic_knowledge"]["preimage_known"]:
                fixture.write(candidate, previous)
                return
            entered.set()
            observed.append(marker.get())
            try:
                assert release.wait(3)
                if caller_cleanup.is_set():
                    context_violations.append("caller cleanup preceded actual worker completion")
                fixture.write(candidate, previous)
                if late_error:
                    raise RuntimeError("late forward publication error must be consumed")
            finally:
                finished.set()

        async def sdk() -> None:
            try:
                await fixture.run(write, settle_timeout=0.05 if phase != "work" else 60)
            finally:
                caller_cleanup.set()

        running = asyncio.create_task(sdk())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            if phase != "work":
                await asyncio.sleep(0.1)
            controller = asyncio.current_task()
            if phase != "timeout":
                for task in asyncio.all_tasks():
                    if task is not controller:
                        task.cancel()
            await asyncio.sleep(0.02)
            assert not running.done()
            assert not caller_cleanup.is_set()
            assert not finished.is_set()
            assert fixture.sent == []
            release.set()
            expected = asyncio.CancelledError if phase != "timeout" else SwapError
            with pytest.raises(expected):
                await running
            assert finished.is_set()
            assert caller_cleanup.is_set()
            assert not context_violations
            assert observed == ["original caller context"]
            assert (tmp_path / "forward.age.paid").exists()
            assert not (tmp_path / "forward.age.cooperating").exists()
            assert not loop_errors
            assert fixture.sent == []
            assert (
                crypto.public_key((4).to_bytes(32, "big")).hex()
                == fixture.terms.client_contract_compressed_key
            )
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)
            fixture.provider_attempt.close()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))
