"""Disposable merchant configuration pins regtest without rewriting existing files."""

from __future__ import annotations

import json

from test_dev_stack import load_devtool


def test_fresh_merchant_config_pins_network_and_existing_config_is_not_migrated(
    tmp_path, monkeypatch
):
    module = load_devtool()
    merchant = tmp_path / "merchant"
    certificate = tmp_path / "lnd/merchant/tls.cert"
    certificate.parent.mkdir(parents=True)
    certificate.write_bytes(b"fixture certificate")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "MERCHANT_DIR", merchant)
    calls = []

    class Lnd:
        def post(self, path, body):
            calls.append((path, body))
            return {"macaroon": "00"}

        def pubkey(self):
            return "02" + "11" * 32

    module.provision_merchant(Lnd())
    path = merchant / "config.json"
    config = json.loads(path.read_text())
    assert config["network"] == "regtest"
    assert config["receiver"] == "02" + "11" * 32
    assert len(calls) == 1
    del config["network"]
    older = json.dumps(config).encode()
    path.write_bytes(older)
    module.provision_merchant(Lnd())
    assert path.read_bytes() == older
    assert len(calls) == 1
