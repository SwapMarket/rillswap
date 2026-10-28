"""Lost store ownership is fatal, not a per-swap backend delay."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from rill_provider.core_tx_bytes import CoreUnavailableError
from rill_provider.live_session_store import StaleOwnerError
from rill_provider.settlement_engine import SettlementEngine


def _engine() -> tuple[SettlementEngine, Mock, Mock]:
    store, chain = Mock(), Mock()
    return SettlementEngine(store, chain, Mock(), Mock()), store, chain  # type: ignore[arg-type]


def test_fenced_swap_step_stops_tick_before_other_swaps_or_cleanup() -> None:
    engine, store, _ = _engine()
    store.settlement_work.return_value = (
        SimpleNamespace(session_id="aa" * 32, state="PAID"),
        SimpleNamespace(session_id="bb" * 32, state="PAID"),
    )
    engine._advance = AsyncMock(side_effect=StaleOwnerError("ownership lost"))  # type: ignore[method-assign]  # noqa: SLF001
    with pytest.raises(StaleOwnerError, match="ownership lost"):
        asyncio.run(engine.tick(1000))
    engine._advance.assert_awaited_once()  # type: ignore[attr-defined]  # noqa: SLF001
    store.unfunded_swaps.assert_not_called()
    store.expirable_exposure_pending.assert_not_called()


def test_fenced_exposure_release_is_never_retried_on_a_stale_handle() -> None:
    engine, store, chain = _engine()
    store.expirable_exposure_pending.return_value = True
    chain.tip_height.return_value = 500
    store.release_expired_exposure.side_effect = StaleOwnerError("ownership lost")
    with pytest.raises(StaleOwnerError, match="ownership lost"):
        asyncio.run(engine._release_expired())  # noqa: SLF001 - isolate cleanup's catch


def test_a_deferred_swap_is_named_with_its_error_class_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    engine, store, _ = _engine()
    store.settlement_work.return_value = (
        SimpleNamespace(session_id="aa" * 32, state="FUNDING_SEEN"),
        SimpleNamespace(session_id="bb" * 32, state="FUNDING_SEEN"),
    )
    engine._advance = AsyncMock(  # type: ignore[method-assign]  # noqa: SLF001
        side_effect=[CoreUnavailableError("backend detail stays private"), "PAYING"]
    )
    engine._close_unfunded = AsyncMock(return_value=[])  # type: ignore[method-assign]  # noqa: SLF001
    engine._release_expired = AsyncMock()  # type: ignore[method-assign]  # noqa: SLF001
    with caplog.at_level("WARNING", logger="rill_provider.settlement_engine"):
        assert asyncio.run(engine.tick(1000)) == {"bb" * 32: "PAYING"}
    assert caplog.messages == [f"settlement step deferred for {'aa' * 8} (CoreUnavailableError)"]
