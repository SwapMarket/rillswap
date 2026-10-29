"""Overlapping dev swaps must not share recovery directories."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_dev_stack import load_devtool


@pytest.mark.parametrize("direction", ["btc-to-ln", "ln-to-btc"])
def test_same_second_swaps_have_private_independent_recovery_paths(
    tmp_path, monkeypatch, direction
):
    devtool = load_devtool()
    monkeypatch.setattr(devtool, "STATE", tmp_path)
    monkeypatch.setattr(devtool.time, "strftime", lambda *_: "20261029T120000")
    monkeypatch.setattr(
        devtool,
        "load_info",
        lambda: {"makers": {direction: "maker"}, "user_age_recipient": "age-recipient"},
    )
    monkeypatch.setattr(
        devtool, "Lnd", lambda _: SimpleNamespace(add_invoice=lambda *_: "lnbcrt-test")
    )
    paths = []

    def run(command, *, check):
        assert check is False
        recovery = Path(command[command.index("--recovery-output") + 1])
        assert recovery.parent.stat().st_mode & 0o777 == 0o700
        recovery.write_text("swap-specific recovery")
        paths.append(recovery)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(devtool.subprocess, "run", run)
    args = argparse.Namespace(
        direction=direction, max_fee=1000, settle_timeout=120, target="50000", extra=[]
    )

    def swap():
        with pytest.raises(SystemExit) as result:
            devtool.cmd_swap(args)
        assert result.value.code == 0

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: swap(), range(2)))

    assert len(set(paths)) == 2
    assert all(path.parent.parent == tmp_path / "user/swaps" for path in paths)
    assert all(path.read_text() == "swap-specific recovery" for path in paths)
