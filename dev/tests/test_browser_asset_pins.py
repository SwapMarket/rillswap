"""Browser pins are regenerated from existing trusted deployment data, not discovery."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

import pytest


def test_existing_deployment_backfills_public_pins_without_changing_contract_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("devtool_asset_test", root / "dev/devtool.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(
        module, "NETWORK_FIXTURE", root / "rill-provider/tests/fixtures/initial-btc-to-ln-v1.json"
    )
    (tmp_path / "user").mkdir()
    (tmp_path / "user/age.recipient").write_text("disposable-recipient")
    deployment = {
        "chain_id": 31337,
        "htlc_contract": "0x" + "11" * 20,
        "token_contract": "0x" + "22" * 20,
        "token_symbol": "fUSDC",
        "token_decimals": 6,
    }
    (tmp_path / "evm").mkdir()
    contracts = tmp_path / "evm/contracts.json"
    contracts.write_text(json.dumps(deployment))
    original = contracts.read_bytes()
    lnd = Mock()
    lnd.pubkey.return_value = "disposable-node"
    module.write_info({"merchant": lnd}, {}, {}, deployment)
    pins = json.loads((tmp_path / "evm/browser-assets.json").read_text())
    assert pins["USDC"]["token_contract"] == deployment["token_contract"]
    assert pins["USDC"]["deployment_namespace"] == module.network_identity()["deployment_namespace"]
    (tmp_path / "evm/browser-assets.json").unlink()
    module.write_info({"merchant": lnd}, {}, {}, deployment)
    assert json.loads((tmp_path / "evm/browser-assets.json").read_text()) == pins
    assert contracts.read_bytes() == original
