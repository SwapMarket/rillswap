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


def test_unknown_extensions_are_ignored_and_enable_nothing() -> None:
    # RS-005: a key this client does not know neither hides the provider nor
    # changes what it requires. The retired handshake requirement is such a key:
    # every session is epoch-bound, whatever it says.
    for unknown in ({"test/data": 1}, {"rillswap/handshake-required-features": ["unknown/v1"]}):
        assert live_swap.announced_funding_confirmations({"extensions": unknown}) is None
        assert live_swap._transport_work({"extensions": unknown}) == 0  # noqa: SLF001


DEPTH = live_swap.FUNDING_CONFIRMATIONS_EXTENSION


@pytest.mark.parametrize(
    ("value", "profiles", "depth"),
    [
        ({"confirmations": 0}, [live_swap.PROFILE], 0),
        ({"confirmations": 1}, [live_swap.PROFILE, "ln-to-btc/v1"], 1),
        ({"confirmations": 6}, ["ln-to-btc/v1"], 6),
    ],
)
def test_announced_funding_confirmations_are_read_exactly(
    value: object, profiles: list[str], depth: int
) -> None:
    advertisement = {"profiles": profiles, "extensions": {DEPTH: value}}
    assert live_swap.announced_funding_confirmations(advertisement) == depth


def test_an_unannounced_depth_is_unknown_not_zero_or_one() -> None:
    assert live_swap.announced_funding_confirmations({"profiles": [live_swap.PROFILE]}) is None
    assert (
        live_swap.announced_funding_confirmations(
            {"profiles": [live_swap.PROFILE], "extensions": {}}
        )
        is None
    )


@pytest.mark.parametrize(
    ("value", "profiles"),
    [
        (None, [live_swap.PROFILE]),
        (1, [live_swap.PROFILE]),
        ({}, [live_swap.PROFILE]),
        ({"confirmations": -1}, [live_swap.PROFILE]),
        ({"confirmations": True}, [live_swap.PROFILE]),
        ({"confirmations": "1"}, [live_swap.PROFILE]),
        ({"confirmations": 1.0}, [live_swap.PROFILE]),
        ({"confirmations": 9_007_199_254_740_992}, [live_swap.PROFILE]),
        ({"confirmations": 1, "more": 1}, [live_swap.PROFILE]),
        # Zero is only for BTC to LN: there the paying provider alone takes the risk.
        ({"confirmations": 0}, ["ln-to-btc/v1"]),
        ({"confirmations": 0}, [live_swap.PROFILE, "ln-to-btc/v1"]),
    ],
)
def test_a_malformed_announced_depth_refuses_the_announcement(
    value: object, profiles: list[str]
) -> None:
    with pytest.raises(live_swap.SwapError, match="funding confirmations unsupported"):
        live_swap.announced_funding_confirmations(
            {"profiles": profiles, "extensions": {DEPTH: value}}
        )


def test_terms_may_wait_fewer_confirmations_than_announced_never_more() -> None:
    announced = {"profiles": [live_swap.PROFILE], "extensions": {DEPTH: {"confirmations": 1}}}
    live_swap.require_announced_depth(0, announced)
    live_swap.require_announced_depth(1, announced)
    live_swap.require_announced_depth(6, {"profiles": [live_swap.PROFILE]})  # nothing announced
    with pytest.raises(live_swap.SwapError, match="more than the announced 1"):
        live_swap.require_announced_depth(2, announced)
