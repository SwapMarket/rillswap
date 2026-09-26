"""Arrival order must not select an older signed provider announcement."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, Mock

import pytest

from rill_cli import live_swap

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


def _discover(
    advertisements: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    async def events() -> AsyncIterator[bytes]:
        for advertisement in advertisements:
            yield json.dumps(advertisement).encode()

    connection = Mock(subscribe=AsyncMock(), events=events)
    # This isolates selection. Native live-swap tests cover signature checking.
    monkeypatch.setattr(live_swap, "verify_announcement", lambda raw, **_kw: json.loads(raw))
    return asyncio.run(
        live_swap.discover(connection, identity="11" * 32, network=Mock(), crypto=Mock(), now=1)
    )


@pytest.mark.parametrize("revisions", [[1, 3, 2], [3, 2, 1], [2, 1, 3]])
def test_discovery_selects_highest_observed_revision(
    revisions: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _discover([{"revision": revision} for revision in revisions], monkeypatch) == {
        "revision": 3
    }


def test_discovery_accepts_identical_replays(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _discover([{"revision": 1}] * 3, monkeypatch) == {"revision": 1}


def test_discovery_refuses_equal_revision_equivocation(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(live_swap.SwapError, match="conflicting"):
        _discover([{"revision": 1, "endpoint": "a"}, {"revision": 1, "endpoint": "b"}], monkeypatch)


def test_discovery_refuses_a_truncated_flood(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(live_swap.SwapError, match="event limit"):
        _discover([{"revision": 1}] * (live_swap.MAX_DISCOVERY_EVENTS + 1), monkeypatch)


@pytest.mark.parametrize("revision", [True, -1, "2", None, 9_007_199_254_740_992])
def test_announcement_revision_must_be_an_exact_bounded_integer(
    revision: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = "11" * 32
    network = Mock()
    network.model_dump.return_value = {"name": "regtest"}
    event = Mock(
        pubkey=identity,
        kind=live_swap.ANNOUNCEMENT_KIND,
        content=json.dumps(
            {
                "advertisement": {
                    "provider_identity_xonly_key": identity,
                    "network_identities": [{"name": "regtest"}],
                    "profiles": [live_swap.PROFILE],
                    "created_at": 0,
                    "expires_at": 10,
                    "epoch_inbox_xonly_keys": ["22" * 32],
                    "revision": revision,
                },
                "signature": "33" * 64,
            }
        ),
    )
    monkeypatch.setattr(live_swap.nip01, "_verify_signed_event", lambda *_a, **_kw: event)
    with pytest.raises(live_swap.SwapError, match="does not offer"):
        live_swap.verify_announcement(
            b"event", identity=identity, network=network, crypto=Mock(), now=1
        )


@pytest.mark.parametrize(
    "requirement",
    [
        None,
        True,
        [],
        "epoch-bound-session/v1",
        ["unknown/v1"],
        ["epoch-bound-session/v1", "unknown/v1"],
    ],
)
def test_advertised_handshake_requirement_never_downgrades_on_malformed_or_unknown(
    requirement: object,
) -> None:
    with pytest.raises(live_swap.SwapError, match="handshake requirements"):
        live_swap._requires_epoch_binding(  # noqa: SLF001
            {"extensions": {live_swap.HANDSHAKE_FEATURES_EXTENSION: requirement}}
        )


def test_handshake_mode_requires_an_explicit_advertised_requirement() -> None:
    assert not live_swap._requires_epoch_binding({"extensions": {}})  # noqa: SLF001
    assert live_swap._requires_epoch_binding(  # noqa: SLF001
        {"extensions": {live_swap.HANDSHAKE_FEATURES_EXTENSION: [live_swap.EPOCH_SESSION_FEATURE]}}
    )


def test_nostr_requirement_does_not_enable_unknown_extensions() -> None:
    for extensions in (
        {"test/data": "signed"},
        {
            live_swap.HANDSHAKE_FEATURES_EXTENSION: [live_swap.EPOCH_SESSION_FEATURE],
            "test/data": "signed",
        },
    ):
        with pytest.raises(live_swap.SwapError, match="handshake requirements"):
            live_swap._requires_epoch_binding({"extensions": extensions})  # noqa: SLF001
