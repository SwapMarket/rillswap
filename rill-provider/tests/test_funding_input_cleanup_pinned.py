"""Actual pinned Core fee refusal preserves unrelated locks and frees selected inputs."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
import sysconfig
import time
from importlib import import_module
from pathlib import Path

import pytest
from test_core_block_transaction_pinned import NETWORK

ROOT = Path(__file__).parents[1]
CHECK = """
import json
from pathlib import Path
from rill_core.wire.types import NetworkIdentity
from rill_provider.core_tx_bytes import CoreTransactionReader, CoreProtocolError
data = json.loads(Path('/work/private/input.json').read_text())
reader = CoreTransactionReader(port=18443, cookie_path=Path('/work/private/core.cookie'),
    network=NetworkIdentity.model_validate(data['network']), wallet='fund')
original = reader._rpc
selected = []
def record(client, method, params, request_id, **kwargs):
    result = original(client, method, params, request_id, **kwargs)
    if method == 'decodepsbt': selected.extend(result['tx']['vin'])
    return result
reader._rpc = record
try: reader.fund_output(bytes.fromhex(data['script']), 100500, max_fee_sat=1)
except CoreProtocolError as error: assert 'fee exceeds' in str(error)
else: raise AssertionError('over-cap funding was accepted')
assert len(selected) == 2
assert all((item['txid'], item['vout']) != (data['locked']['txid'], data['locked']['vout'])
    for item in selected)
print('funding input cleanup conformance passed')
"""


@pytest.mark.bitcoin_core
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_BITCOIN_CORE") != "1", reason="explicit owned Core cleanup opt-in"
)
def test_pinned_fee_refusal_unlocks_two_selected_inputs_only(tmp_path: Path) -> None:  # noqa: PLR0915 - one owned daemon lifecycle
    if shutil.which("docker") is None:
        pytest.skip("Docker required for isolated pinned Core")
    assert sys.version_info[:2] == (3, 14), "pinned sidecar dependency ABI differs"
    helpers = import_module("test_core_tx_bytes_bitcoin_core")
    docker, cli = helpers._docker, helpers._bitcoin_cli  # noqa: SLF001 - owned secret-safe helpers
    name = "rillswap-funding-cleanup-" + secrets.token_hex(6)
    tmp_path.chmod(0o700)
    try:
        docker(
            "run",
            "--detach",
            "--name",
            name,
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            helpers.CORE_IMAGE,
            "-regtest=1",
            "-server=1",
            "-listen=0",
            "-discover=0",
            "-dnsseed=0",
            "-fallbackfee=0.00001000",
            "-rpcbind=0.0.0.0",
            "-rpcallowip=127.0.0.1",
        )
        for _ in range(60):
            try:
                version = json.loads(cli(name, "getnetworkinfo"))["version"]
            except AssertionError:
                time.sleep(0.2)
            else:
                assert version == 300000
                break
        else:
            raise AssertionError("owned Core did not become ready")
        cli(name, "createwallet", "miner")
        cli(name, "createwallet", "fund")
        mining = cli(name, "-rpcwallet=miner", "getnewaddress", "", "bech32m")
        cli(name, "generatetoaddress", "101", mining)
        for _ in range(3):
            destination = cli(name, "-rpcwallet=fund", "getnewaddress", "", "bech32m")
            cli(name, "-rpcwallet=miner", "sendtoaddress", destination, "0.00060000")
        cli(name, "generatetoaddress", "1", mining)
        coins = json.loads(cli(name, "-rpcwallet=fund", "listunspent"))
        assert len(coins) == 3
        locked = {"txid": coins[0]["txid"], "vout": coins[0]["vout"]}
        cli(name, "-rpcwallet=fund", "lockunspent", "false", json.dumps([locked]))
        baseline = json.loads(cli(name, "-rpcwallet=fund", "listlockunspent"))
        destination = cli(name, "-rpcwallet=miner", "getnewaddress", "", "bech32m")
        script = json.loads(cli(name, "-rpcwallet=miner", "getaddressinfo", destination))[
            "scriptPubKey"
        ]
        private = tmp_path / "input.json"
        private.write_text(json.dumps({"network": NETWORK, "script": script, "locked": locked}))
        private.chmod(0o600)
        cookie = tmp_path / "core.cookie"
        docker("cp", f"{name}:/home/bitcoin/.bitcoin/regtest/.cookie", str(cookie))
        cookie.chmod(0o600)
        mounts = {
            ROOT / "src": "/work/provider",
            ROOT.parent / "rill-core/packages/core/src": "/work/core",
            Path(sysconfig.get_path("purelib")).resolve(): "/work/deps",
            tmp_path: "/work/private",
        }
        arguments = ["run", "--rm", "--platform", "linux/amd64", "--network", f"container:{name}"]
        for source, target in mounts.items():
            arguments.extend(("--mount", f"type=bind,src={source},dst={target},readonly"))
        arguments.extend(
            (
                "--env",
                "PYTHONPATH=/work/provider:/work/core:/work/deps",
                helpers.PYTHON_IMAGE,
                "python",
                "-c",
                CHECK,
            )
        )
        assert docker(*arguments) == "funding input cleanup conformance passed"
        assert json.loads(cli(name, "-rpcwallet=fund", "listlockunspent")) == baseline
        for coin in coins:
            assert json.loads(cli(name, "gettxout", coin["txid"], str(coin["vout"]))) is not None
        assert json.loads(cli(name, "getrawmempool")) == []
    finally:
        try:
            docker("rm", "--force", "--volumes", name)
        finally:
            (tmp_path / "core.cookie").unlink(missing_ok=True)
            (tmp_path / "input.json").unlink(missing_ok=True)
