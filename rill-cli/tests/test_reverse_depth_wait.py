"""LN to BTC: once funded, a failed Core read waits; it never ends the swap."""

from __future__ import annotations

import asyncio
import itertools
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest

from rill_cli import live_reverse_swap as reverse
from rill_cli import main
from rill_cli.live_swap import SwapError
from rill_cli.wallet_rpc import ConfirmedOutput, WalletRpcError

if TYPE_CHECKING:
    from collections.abc import Iterable

SCRIPT = bytes.fromhex("5120" + "22" * 32)
VALUE = 30_012
BINDING = SimpleNamespace(funding_txid="ab" * 32, contract_vout=0)
DOWN = WalletRpcError("Core RPC unavailable")


class _Wallet:
    """Replay one Core answer per poll: ``(depth, tip)``, each value or an exception."""

    def __init__(self, answers: Iterable[tuple[Any, Any] | Exception]) -> None:
        self._answers = iter(answers)
        self._tip: Any = None

    def confirmed_output(self, _txid: str, _vout: int) -> ConfirmedOutput | None:
        answer = next(self._answers)
        if isinstance(answer, Exception):
            raise answer
        depth, self._tip = answer
        if isinstance(depth, Exception):
            raise depth
        return None if depth is None else ConfirmedOutput(VALUE, SCRIPT, depth)

    def tip_height(self) -> int:
        if isinstance(self._tip, Exception):
            raise self._tip
        return int(self._tip)


async def _wait(
    wallet: _Wallet, *, value: int = VALUE, lock_height: int = 500, lifetime: float = 60
) -> list[str]:
    lines: list[str] = []
    async with reverse._ReverseLifetime(lifetime) as owned:  # noqa: SLF001
        owned.start()
        await reverse._await_depth(  # noqa: SLF001
            wallet,  # type: ignore[arg-type]
            binding=BINDING,  # type: ignore[arg-type]
            script=SCRIPT,
            value=value,
            depth=2,
            lock_height=lock_height,
            lifetime=owned,
            report=lines.append,
        )
    return lines


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reverse, "POLL_SECONDS", 0.01)


def test_a_core_outage_while_funding_confirms_is_waited_out() -> None:
    # A signet swap ended with "Swap failed" after one failed read through a tunnel.
    wallet = _Wallet([(0, 100), DOWN, (1, DOWN), DOWN, (1, 101), (2, 102)])
    lines = asyncio.run(_wait(wallet))
    funding = "ab" * 32
    assert lines == [
        f"funding {funding} at depth 0/2",
        f"Core unavailable while funding {funding} confirms; retrying",  # once per outage
        f"funding {funding} at depth 1/2",
    ]


def test_after_an_outage_the_refund_lock_still_ends_the_wait() -> None:
    with pytest.raises(SwapError, match="refund lock passed"):
        asyncio.run(_wait(_Wallet([DOWN, (0, 500)])))


def test_after_an_outage_a_different_output_still_ends_the_wait() -> None:
    with pytest.raises(SwapError, match="another output"):
        asyncio.run(_wait(_Wallet([DOWN, (2, 101)]), value=VALUE + 1))


def test_an_outage_lasting_the_whole_lifetime_still_expires() -> None:
    # run_reverse_swap reports the expiry with the watch-claim advice.
    with pytest.raises(TimeoutError):
        asyncio.run(_wait(_Wallet(itertools.repeat(DOWN)), lifetime=0.2))


@pytest.mark.parametrize(
    ("command", "advice", "absent"),
    [
        ("ln-to-btc", "`rill recover watch-claim` before its refund lock", "refund after"),
        ("btc-to-ln", "refund after its lock height with `rill recover`", "watch-claim"),
    ],
)
def test_an_unexpected_failure_advises_each_direction_correctly(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    advice: str,
    absent: str,
) -> None:
    # ln-to-btc users cannot refund: the provider funds the contract and refunds it.
    monkeypatch.setattr(main, "_network", lambda _path: None)
    monkeypatch.setattr(main, "_identity", lambda _path: "")
    monkeypatch.setattr(main.swap_command, "run", Mock(side_effect=RuntimeError("secret detail")))
    args = SimpleNamespace(command=command, network="unused", identity="unused")
    assert main._swap(args) == 2  # type: ignore[arg-type]  # noqa: SLF001
    stderr = capsys.readouterr().err
    assert advice in stderr
    assert absent not in stderr
    assert "secret detail" not in stderr
