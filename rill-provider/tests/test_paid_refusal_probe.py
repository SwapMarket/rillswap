"""Guard offsets and metadata hygiene, not classification of historical incidents."""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from typing import TYPE_CHECKING

import pytest
from _paid_refusal_probe import PaidRefusalProbe, _raise_sites

from rill_provider.live_session_store import LiveSessionStore, LiveSessionStoreError
from rill_provider.lnd_hold_invoice import LndHoldInvoices, LndProtocolError

if TYPE_CHECKING:
    from collections.abc import Callable

# Test-owned event metadata and original private-code admission are intentional.
# ruff: noqa: SLF001

LIVE_GUARDS = {
    (ValueError, "original reverse reservation absent"): "original_reservation_absent",
    (ValueError, "reverse acquisition lifecycle refused"): "paid_lifecycle_guard_refused",
    (ValueError, "reverse acquisition reservation differs"): "burned_reservation_differs",
    (LiveSessionStoreError, "reverse proposal live context refused"): "live_context_sanitized",
}
INVOICE_GUARDS = {
    (LndProtocolError, "LND original invoice binding unsupported"): "invoice_binding_unsupported",
    (
        LndProtocolError,
        "LND original invoice is not sufficiently settled",
    ): "invoice_not_sufficiently_settled",
}


def _guard() -> None:
    raise ValueError("synthetic guard")


def _propagation() -> None:
    _guard()


def _run(probe: PaidRefusalProbe, callback: Callable[[], object]) -> object:
    async def invoke() -> object:
        return callback()

    return asyncio.run(probe.paid_phase(invoke)())


def test_actual_product_raise_offsets_are_all_recognized() -> None:
    for original, guards in (
        (LiveSessionStore._reverse_live_context_in_connection, LIVE_GUARDS),
        (LndHoldInvoices.observe_bound_settled_invoice, INVOICE_GUARDS),
    ):
        sites = _raise_sites(original, guards)
        assert {category for _kind, category in sites.values()} == set(guards.values())


def test_explicit_guard_is_named_only_in_paid_scope_and_trace_is_restored() -> None:
    probe = PaidRefusalProbe(((ValueError, "ValueError"),))
    probe.preflight()
    previous = sys.gettrace()
    observed = probe.synchronous(
        _guard, "context", {(ValueError, "synthetic guard"): "guard_refused"}
    )
    with pytest.raises(ValueError, match="synthetic guard"):
        observed()
    assert probe.events == []
    with pytest.raises(ValueError, match="synthetic guard"):
        _run(probe, observed)
    assert sys.gettrace() is previous
    assert [event["guard"] for event in probe.events] == ["enter", "guard_refused", "exit"]
    assert probe.unknown is False


def test_propagated_matching_message_is_not_mislabeled_as_a_local_guard() -> None:
    probe = PaidRefusalProbe(((ValueError, "ValueError"),))
    observed = probe.synchronous(_propagation, "context", {})
    with pytest.raises(ValueError, match="synthetic guard"):
        _run(probe, observed)
    assert probe.events[1]["guard"] == "unknown"
    assert probe.unknown is True


def test_exception_identity_and_private_values_remain_untouched() -> None:
    class PrivateValue:
        def __repr__(self) -> str:
            raise AssertionError("must not inspect private value")

        def __str__(self) -> str:
            raise AssertionError("must not inspect private value")

    error = ValueError(PrivateValue())

    def original() -> None:
        private_local = PrivateValue()
        assert private_local is not None
        raise error

    probe = PaidRefusalProbe(((ValueError, "ValueError"),))
    observed = probe.synchronous(original, "context", {})
    with pytest.raises(ValueError) as captured:  # noqa: PT011 - identity checked, matching must not stringify private values
        _run(probe, observed)
    assert captured.value is error
    output = json.dumps(probe.events)
    assert "PrivateValue" not in output
    assert "private_local" not in output
    assert all(
        set(event) == {"method", "guard", "category", "elapsed_ms"} for event in probe.events
    )


def test_existing_trace_is_not_overwritten_and_probe_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = object()
    probe = PaidRefusalProbe(((ValueError, "ValueError"),))
    observed = probe.synchronous(
        _guard, "context", {(ValueError, "synthetic guard"): "guard_refused"}
    )
    monkeypatch.setattr(sys, "gettrace", lambda: sentinel)
    with pytest.raises(RuntimeError, match="ownership unavailable"):
        probe.preflight()
    with pytest.raises(ValueError, match="synthetic guard"):
        _run(probe, observed)
    assert sys.gettrace() is sentinel
    assert probe.unknown is True
    assert [event["guard"] for event in probe.events] == ["enter", "exit"]


def test_callback_failure_does_not_replace_original_exception() -> None:
    class BrokenCategories:
        def __iter__(self) -> object:
            raise RuntimeError("PRIVATE_DIAGNOSTIC_CANARY")

    probe = PaidRefusalProbe(((ValueError, "ValueError"),))
    probe._categories = BrokenCategories()
    observed = probe.synchronous(
        _guard, "context", {(ValueError, "synthetic guard"): "guard_refused"}
    )
    with pytest.raises(ValueError, match="synthetic guard"):
        _run(probe, observed)
    assert sys.gettrace() is None
    assert probe.unknown is True
    assert "PRIVATE_DIAGNOSTIC_CANARY" not in json.dumps(probe.events)


def test_trace_installation_failure_preserves_original_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def original() -> object:
        return result

    def fail(_trace: object) -> None:
        raise RuntimeError("PRIVATE_INSTALL_CANARY")

    result = object()
    probe = PaidRefusalProbe(())
    observed = probe.synchronous(original, "context", {})
    monkeypatch.setattr(sys, "settrace", fail)
    assert _run(probe, observed) is result
    assert probe.unknown is True


def test_newer_trace_owner_installed_during_call_is_preserved() -> None:
    def newer(_frame: object, _event: str, _data: object) -> None:
        return None

    def original() -> object:
        sys.settrace(newer)
        return result

    result = object()
    previous = sys.gettrace()
    probe = PaidRefusalProbe(())
    observed = probe.synchronous(original, "context", {})
    try:
        assert _run(probe, observed) is result
        assert sys.gettrace() is newer
        assert probe.unknown is True
    finally:
        sys.settrace(previous)


def test_event_output_and_durations_are_bounded() -> None:
    probe = PaidRefusalProbe(((ValueError, "ValueError"),))
    observed = probe.synchronous(
        _guard, "context", {(ValueError, "synthetic guard"): "guard_refused"}
    )

    def many() -> None:
        for _ in range(100):
            with pytest.raises(ValueError, match="synthetic guard"):
                observed()

    _run(probe, many)
    assert len(probe.events) == 64
    assert probe.unknown is True
    assert all(0 <= event["elapsed_ms"] <= 600_000 for event in probe.events)
    assert sys.gettrace() is None


def test_cancelled_paid_scope_retains_late_worker_attribution_without_authority() -> None:
    probe = PaidRefusalProbe(((ValueError, "ValueError"),))
    release = threading.Event()

    async def exercise() -> None:
        admitted = asyncio.Event()
        loop = asyncio.get_running_loop()
        workers: list[asyncio.Task] = []

        def original() -> None:
            loop.call_soon_threadsafe(admitted.set)
            assert release.wait(2)
            raise ValueError("synthetic guard")

        observed = probe.synchronous(
            original, "invoice", {(ValueError, "synthetic guard"): "guard_refused"}
        )

        async def paid() -> None:
            worker = asyncio.create_task(asyncio.to_thread(observed))
            workers.append(worker)
            await asyncio.shield(worker)

        parent = asyncio.create_task(probe.paid_phase(paid)())
        try:
            await asyncio.wait_for(admitted.wait(), timeout=2)
            parent.cancel()
            with pytest.raises(asyncio.CancelledError):
                await parent
            assert [event["guard"] for event in probe.events] == ["enter", "exit"]
        finally:
            release.set()
            if workers:
                with pytest.raises(ValueError, match="synthetic guard"):
                    await workers[0]
        assert [event["guard"] for event in probe.events] == ["enter", "exit", "guard_refused"]

    asyncio.run(exercise())
    assert sys.gettrace() is None
    assert probe.unknown is False  # Named late guard is evidence, not the parent's cause.
