"""Actual wallet-independent historical bytes with txindex disabled and spent funding."""

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

ROOT = Path(__file__).parents[1]
NETWORK = {
    "family": "bitcoin",
    "name": "regtest",
    "genesis_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    "signet_challenge": None,
    "consensus_profile": "bitcoin-core-v30.0-regtest-default",
    "deployment_namespace": "block-history-owned-core-v1",
}
CHECK = """
import json
from pathlib import Path
from rill_core.settlement import inspect_transaction_outputs
from rill_core.wire.types import NetworkIdentity
from rill_provider.core_tx_bytes import CoreTransactionReader, CoreUnavailableError
data=json.loads(Path('/work/private/input.json').read_bytes())
network=NetworkIdentity.model_validate(data['network'])
reader=CoreTransactionReader(port=18443,cookie_path='/work/private/core.cookie',network=network)
observations=[]
for item in data['transactions']:
    observed=reader.observe_block_transaction(item['txid'],block_height=item['blockheight'],
        block_hash=item['blockhash'])
    assert observed.raw_transaction.hex()==item['hex'] and observed.txid==item['txid']
    assert inspect_transaction_outputs(observed.raw_transaction).txid==item['txid']
    assert observed.configured_network==network
    assert observed.minimum_sampled_confirmations==item['depth']
    assert observed.tip_before_hash==observed.tip_after_hash==data['tip_hash']
    assert observed.completed_at>=observed.started_at
    observations.append(observed)
assert len(observations)==2 and observations[0].txid!=observations[1].txid
first,second=data['transactions']
# Complete but wrong hint: txid is not in the supplied active block. No global
# txindex, wallet fallback, UTXO check or scan should rescue this failed lookup.
try: reader.observe_block_transaction(first['txid'],block_height=second['blockheight'],
        block_hash=second['blockhash'])
except CoreUnavailableError as error:
    assert error.__cause__ is None and error.__context__ is None
else: raise AssertionError('wrong block hint obtained unrelated history')
print('block-qualified Core transaction conformance passed')
"""


@pytest.mark.bitcoin_core
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_BITCOIN_CORE") != "1",
    reason="explicit owned Core historical transaction conformance opt-in",
)
def test_pinned_block_bytes_without_txindex_after_funding_spent(tmp_path: Path) -> None:  # noqa: PLR0915 - one owned namespace lifecycle
    if shutil.which("docker") is None:
        pytest.skip("Docker required for isolated pinned Core")
    assert sys.version_info[:2] == (3, 14), "pinned sidecar dependency ABI differs"
    helpers = import_module("test_core_tx_bytes_bitcoin_core")
    docker, cli = helpers._docker, helpers._bitcoin_cli  # noqa: SLF001 - existing owned secret-safe RPC/Docker helpers
    name = "rillswap-block-history-" + secrets.token_hex(6)
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
            "-txindex=0",
            "-fallbackfee=0.00001000",
            "-rpcbind=0.0.0.0",
            "-rpcallowip=127.0.0.1",
            "-printtoconsole=1",
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
        cli(name, "createwallet", "fund")
        cli(name, "createwallet", "merchant")
        mining = cli(name, "-rpcwallet=fund", "getnewaddress", "", "bech32m")
        cli(name, "generatetoaddress", "101", mining)
        address = cli(name, "-rpcwallet=merchant", "getnewaddress", "", "bech32m")
        script = json.loads(cli(name, "-rpcwallet=merchant", "getaddressinfo", address))[
            "scriptPubKey"
        ]
        funding = cli(name, "-rpcwallet=fund", "sendtoaddress", address, "0.01000000")
        cli(name, "generatetoaddress", "1", mining)
        claim = cli(name, "-rpcwallet=merchant", "sendtoaddress", mining, "0.00990000")
        cli(name, "generatetoaddress", "1", mining)
        assert json.loads(cli(name, "getindexinfo")) == {}
        transactions = []
        for txid in (funding, claim):
            record = json.loads(cli(name, "-rpcwallet=merchant", "gettransaction", txid))
            transactions.append(
                {
                    "txid": txid,
                    "hex": record["hex"],
                    "blockheight": record["blockheight"],
                    "blockhash": record["blockhash"],
                    "depth": record["confirmations"],
                }
            )
        decoded = json.loads(cli(name, "decoderawtransaction", transactions[0]["hex"]))
        matches = [
            output["n"] for output in decoded["vout"] if output["scriptPubKey"]["hex"] == script
        ]
        assert len(matches) == 1
        assert cli(name, "gettxout", funding, str(matches[0])) == ""
        data = {
            "network": NETWORK,
            "transactions": transactions,
            "tip_hash": cli(name, "getbestblockhash"),
        }
        private = tmp_path / "input.json"
        private.write_text(json.dumps(data))
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
            assert source.is_dir()
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
        assert docker(*arguments) == "block-qualified Core transaction conformance passed"
    finally:
        try:
            docker("rm", "--force", "--volumes", name)
        finally:
            try:
                (tmp_path / "core.cookie").unlink(missing_ok=True)
            finally:
                (tmp_path / "input.json").unlink(missing_ok=True)
