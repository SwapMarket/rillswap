"""Manual regtest deposits use exact amounts and never subtract the recipient's fee."""

from __future__ import annotations

import argparse

import pytest
from test_dev_stack import load_devtool


@pytest.mark.parametrize("amount", ["0.00100150", "0.00000001", "1", "21000000"])
def test_send_btc_dispatch_preserves_exact_amount(monkeypatch, capsys, amount):
    module = load_devtool()
    calls = []

    class Core:
        def __init__(self, wallet=None):
            self.wallet = wallet

        def __call__(self, method, *params):
            calls.append((self.wallet, method, params))
            return {"chain": "regtest"} if method == "getblockchaininfo" else "ab" * 32

    monkeypatch.setattr(module, "Core", Core)
    monkeypatch.setattr("sys.argv", ["devtool", "send-btc", "bcrt1ptest-address", amount])
    module.main()
    assert calls == [
        (None, "getblockchaininfo", ()),
        ("user", "sendtoaddress", ("bcrt1ptest-address", amount, "", "", False)),
    ]
    assert capsys.readouterr().out == "ab" * 32 + "\n"


@pytest.mark.parametrize(
    "amount",
    ["0", "-1", "NaN", "Infinity", "1e-8", "0.000000001", "21000000.00000001", "01", " 1", "1."],
)
def test_invalid_send_amount_never_reaches_core(monkeypatch, amount):
    module = load_devtool()
    monkeypatch.setattr(module, "Core", lambda *_: pytest.fail("invalid amount reached Core"))
    monkeypatch.setattr("sys.argv", ["devtool", "send-btc", "address", amount])
    with pytest.raises(SystemExit):
        module.main()


@pytest.mark.parametrize("info", [{"chain": "main"}, {"chain": "signet"}, {}, None])
def test_send_btc_refuses_unknown_or_nonregtest_chain(monkeypatch, capsys, info):
    module = load_devtool()
    calls = []

    def core(wallet=None):
        assert wallet is None
        return lambda method: calls.append(method) or info

    monkeypatch.setattr(module, "Core", core)
    with pytest.raises(SystemExit, match="regtest chain"):
        module.cmd_send_btc(argparse.Namespace(address="address", amount="0.00100150"))
    assert calls == ["getblockchaininfo"]
    assert capsys.readouterr().out == ""


def test_send_rpc_failure_is_not_reported_as_success(monkeypatch, capsys):
    module = load_devtool()

    def core(wallet=None):
        if wallet is None:
            return lambda _method: {"chain": "regtest"}

        def fail(*_args):
            raise module.RpcError(-6, "Insufficient funds")

        return fail

    monkeypatch.setattr(module, "Core", core)
    with pytest.raises(module.RpcError, match="Insufficient funds"):
        module.cmd_send_btc(argparse.Namespace(address="address", amount="0.00100150"))
    assert capsys.readouterr().out == ""
