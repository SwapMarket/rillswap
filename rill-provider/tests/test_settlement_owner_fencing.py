"""Lost store ownership is fatal, not a per-swap backend delay."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

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
    store.unreleased_claims.assert_not_called()


def test_fenced_claim_release_is_never_logged_as_one_retryable_swap() -> None:
    engine, store, chain = _engine()
    store.unreleased_claims.return_value = [("aa" * 32, "bb" * 32, 1)]
    chain.confirmations.return_value = 1
    store.release_claim.side_effect = StaleOwnerError("ownership lost")
    with pytest.raises(StaleOwnerError, match="ownership lost"):
        asyncio.run(engine._release_claims())  # noqa: SLF001 - isolate cleanup's catch


def test_fenced_exposure_release_is_never_retried_on_a_stale_handle() -> None:
    engine, store, chain = _engine()
    store.expirable_exposure_pending.return_value = True
    chain.tip_height.return_value = 500
    store.release_expired_exposure.side_effect = StaleOwnerError("ownership lost")
    with pytest.raises(StaleOwnerError, match="ownership lost"):
        asyncio.run(engine._release_expired())  # noqa: SLF001 - isolate cleanup's catch
