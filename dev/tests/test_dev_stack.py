"""Static checks for the regtest dev stack (dev/compose.yaml, dev/devtool.py)."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "dev/compose.yaml").read_text()


def load_devtool():
    pytest.importorskip("httpx")
    spec = importlib.util.spec_from_file_location("devtool", ROOT / "dev/devtool.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rpcauth_entries() -> dict[str, tuple[str, str]]:
    entries = {}
    for user, salt, digest in re.findall(r"-rpcauth=([^:]+):([0-9a-f]+)\$\$([0-9a-f]+)", COMPOSE):
        entries[user] = (salt, digest)
    return entries


def matches(user: str, password: str) -> bool:
    salt, digest = rpcauth_entries()[user]
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest() == digest


def test_rpcauth_matches_devtool_credentials():
    devtool = load_devtool()
    user, password = devtool.CORE_AUTH
    assert matches(user, password)
    assert f"--bitcoind.rpcuser={user}" in COMPOSE
    assert f"--bitcoind.rpcpass={password}" in COMPOSE


def test_static_cookie_matches_rpcauth():
    devtool = load_devtool()
    user, password = devtool.CORE_COOKIE.strip().split(":", 1)
    # Rill's cookie reader only accepts the `__cookie__` username.
    assert user == "__cookie__"
    assert matches(user, password)


def test_has_channel_counts_open_and_pending_local_initiator():
    devtool = load_devtool()

    class FakeLnd:
        def __init__(self, channels, pending):
            self._channels, self._pending = channels, pending

        def channels(self):
            return self._channels

        def pending_open(self):
            return self._pending

    remote = "02" + "ab" * 32
    assert devtool.has_channel(FakeLnd([{"remote_pubkey": remote, "initiator": True}], []), remote)
    assert not devtool.has_channel(
        FakeLnd([{"remote_pubkey": remote, "initiator": False}], []), remote
    )
    pending = [{"channel": {"remote_node_pub": remote, "initiator": "INITIATOR_LOCAL"}}]
    assert devtool.has_channel(FakeLnd([], pending), remote)
    remote_pending = [{"channel": {"remote_node_pub": remote, "initiator": "INITIATOR_REMOTE"}}]
    assert not devtool.has_channel(FakeLnd([], remote_pending), remote)


def compose_service(name: str) -> str:
    match = re.search(rf"^  {name}:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)", COMPOSE, re.M | re.S)
    assert match, name
    return match.group(1)


def test_monero_chain_persists_and_wallet_rpc_stays_private():
    monerod = compose_service("monerod")
    # Without --keep-fakechain monerod deletes the regtest chain at every start.
    for flag in ("--regtest", "--keep-fakechain", "--offline", "--fixed-difficulty=1"):
        assert flag in monerod
    wallet = COMPOSE.split("x-monero-wallet: &monero-wallet", 1)[1].split("\nx-", 1)[0]
    assert "--disable-rpc-login" in wallet
    for name in ("monerod", "monero-wallet-merchant", "monero-wallet-buyer"):
        assert "ports:" not in compose_service(name)
        assert "ports:" not in wallet


def test_monero_wallet_reopens_after_wallet_rpc_restart(monkeypatch):
    devtool = load_devtool()
    calls = []
    opened = {"wallet": False}

    def raw(self, method, **params):
        calls.append(method)
        if method == "open_wallet":
            opened["wallet"] = True
            return {}
        if not opened["wallet"]:
            raise devtool.RpcError(-13, "No wallet file")
        return {"height": 5}

    monkeypatch.setattr(devtool.MoneroWallet, "raw", raw)
    assert devtool.MoneroWallet("merchant")("get_height") == {"height": 5}
    assert calls == ["get_height", "open_wallet", "get_height"]
    monkeypatch.setattr(
        devtool.MoneroWallet,
        "raw",
        lambda self, method, **params: (_ for _ in ()).throw(devtool.RpcError(-1, "other")),
    )
    with pytest.raises(devtool.RpcError):
        devtool.MoneroWallet("merchant")("get_height")


def test_monero_wallet_created_only_in_an_empty_volume(tmp_path, monkeypatch):
    devtool = load_devtool()
    calls = []
    monkeypatch.setattr(devtool, "MONERO_WALLET_DIRS", tmp_path / "wallets")
    monkeypatch.setattr(devtool, "STATE", tmp_path / "state")
    monkeypatch.setattr(
        devtool.MoneroWallet, "raw", lambda self, method, **params: calls.append(method) or {}
    )
    with pytest.raises(SystemExit, match="not mounted"):
        devtool.ensure_monero_wallet("merchant")
    (tmp_path / "wallets/merchant").mkdir(parents=True)
    devtool.ensure_monero_wallet("merchant")
    assert calls == ["create_wallet"]
    (tmp_path / "wallets/merchant/merchant.keys").write_text("")
    devtool.ensure_monero_wallet("merchant")
    assert calls[-1] == "open_wallet"
    (tmp_path / "wallets/merchant/merchant.keys").unlink()
    (tmp_path / "state/shop/monero").mkdir(parents=True)
    (tmp_path / "state/shop/monero/ledger.sqlite-wal").write_text("")
    with pytest.raises(SystemExit, match="shop's Monero state"):
        devtool.ensure_monero_wallet("merchant")
