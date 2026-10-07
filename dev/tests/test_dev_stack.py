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
