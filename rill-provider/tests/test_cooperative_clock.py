"""A failed or regressing owner clock cannot renew cooperative eligibility."""

from __future__ import annotations

import pytest

from rill_provider.live_session_store import LiveSessionStoreError, _cooperative_now


def test_cooperative_clock_refresh_never_moves_backward() -> None:
    assert _cooperative_now(1001, lambda: 1000) == 1001
    assert _cooperative_now(1001, lambda: 1002) == 1002
    # Fixed-time internal fixtures are separate from selected live entrances.
    assert _cooperative_now(1001, None) == 1001


@pytest.mark.parametrize("value", [True, -1, 1001.0, "1001", None])
def test_cooperative_clock_rejects_invalid_values(value: object) -> None:
    with pytest.raises(LiveSessionStoreError, match="clock unavailable"):
        _cooperative_now(1000, lambda: value)  # type: ignore[arg-type] - runtime guard


def test_cooperative_clock_failure_is_redacted() -> None:
    def failed_clock() -> int:
        raise OSError("test-only sensitive clock failure context")

    with pytest.raises(LiveSessionStoreError, match="clock unavailable") as error:
        _cooperative_now(1000, failed_clock)
    assert error.value.__cause__ is None
    assert "sensitive" not in str(error.value)
