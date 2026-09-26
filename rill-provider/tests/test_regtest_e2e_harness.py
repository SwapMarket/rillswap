"""The disposable miner must not outrun LND's polling/sync consumers."""

from __future__ import annotations

import runpy
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

RUNNER = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/regtest_e2e.py"))


@pytest.mark.parametrize(
    "not_ready",
    [
        {"synced_to_chain": False, "block_hash": "tip"},
        {"synced_to_chain": True, "block_hash": "older-tip"},
    ],
)
def test_mining_barrier_requires_both_nodes_synced_to_exact_tip(not_ready: dict) -> None:
    ready = {"synced_to_chain": True, "block_hash": "tip"}
    stack = SimpleNamespace(
        cli=Mock(return_value="tip\n"),
        lncli=Mock(side_effect=[ready, not_ready, ready, ready]),
    )
    stop = Mock(spec=threading.Event)
    stop.is_set.return_value = False
    assert RUNNER["wait_chain_ready"](stack, stop)
    stack.cli.assert_called_once_with("getbestblockhash")
    assert stack.lncli.call_count == 4
    stop.wait.assert_called_once_with(0.25)


def test_mining_barrier_times_out_without_claiming_readiness() -> None:
    stack = SimpleNamespace(
        cli=Mock(return_value="tip"),
        lncli=Mock(return_value={"synced_to_chain": False, "block_hash": "tip"}),
    )
    with pytest.raises(RuntimeError, match="did not synchronize"):
        RUNNER["wait_chain_ready"](stack, threading.Event(), timeout=0)


def test_mining_barrier_obeys_cleanup_stop() -> None:
    stack = SimpleNamespace(cli=Mock(return_value="tip"), lncli=Mock())
    stop = threading.Event()
    stop.set()
    assert not RUNNER["wait_chain_ready"](stack, stop)
    stack.lncli.assert_not_called()
