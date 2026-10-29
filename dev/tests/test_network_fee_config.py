"""Fresh disposable providers can opt into fee tests without migrating config."""

from __future__ import annotations

import json

import pytest
from test_dev_stack import load_devtool


@pytest.mark.parametrize("enabled", [False, True])
def test_network_fee_flag_only_affects_fresh_bitcoin_config(tmp_path, monkeypatch, enabled):
    module = load_devtool()
    home = tmp_path / "makers/btc-to-ln"
    home.mkdir(parents=True)
    credentials = tmp_path / "lnd/maker"
    credentials.mkdir(parents=True)
    (credentials / "tls.cert").write_bytes(b"test certificate")
    (credentials / "admin.macaroon").write_bytes(b"test macaroon")
    (home / "custody.key").write_text("fixture key")
    (home / "custody.recipient").write_text("fixture recipient")
    (home / "provider.xonly").write_text("11" * 32)
    (home / "provider-store").mkdir()
    (home / "provider-store/live.sqlite").write_bytes(b"existing store untouched")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "network_identity", lambda: {"name": "regtest"})

    def core(method, *params):
        return "test address" if method == "getnewaddress" else {"scriptPubKey": "5120" + "11" * 32}

    monkeypatch.setattr(module, "Core", lambda *args: core)
    monkeypatch.setenv("RILL_DEV_NETWORK_FEES", "1" if enabled else "0")
    module.provision_maker("btc-to-ln", {})
    path = home / "provider.json"
    config = json.loads(path.read_text())
    assert ("network_fees" in config["terms"]) is enabled
    if enabled:
        assert config["terms"]["network_fees"] == {
            "max_feerate_sat_kvb": 10000,
            "max_routing_fee_ppm": 1000,
        }
    original = path.read_bytes()
    monkeypatch.setenv("RILL_DEV_NETWORK_FEES", "0" if enabled else "1")
    module.provision_maker("btc-to-ln", {})
    assert path.read_bytes() == original
    assert (home / "provider-store/live.sqlite").read_bytes() == b"existing store untouched"
