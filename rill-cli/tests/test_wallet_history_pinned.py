"""Opt-in actual Core v30 historical recognition, explicitly not key-custody proof."""

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
CORE_IMAGE = (
    "docker.io/bitcoin/bitcoin@"
    "sha256:49b55ea5c949a9ceff50786ee678d53f2728a4daa40a8139e3ee20243d24f281"
)
PYTHON_IMAGE = "python@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
NETWORK = {
    "family": "bitcoin",
    "name": "regtest",
    "genesis_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    "signet_challenge": None,
    "consensus_profile": "bitcoin-core-v30.0-regtest-default",
    "deployment_namespace": "wallet-history-owned-core-v1",
}
CHECK = """
import json, os
from pathlib import Path
from rill_core.wire.types import NetworkIdentity
from rill_cli.wallet_rpc import WalletRpc, WalletRpcError
data=json.loads(Path('/work/private/input.json').read_bytes())
network=NetworkIdentity.model_validate(data['network'])
for name in ('merchant', 'public-only'):
    wallet=WalletRpc(port=18443, cookie_path='/work/private/core.cookie',
        wallet=name,network=network)
    if os.environ['HISTORY_EXPECTED'] == 'unknown':
        try: wallet.observe_historical_wallet_output(data['txid'], bytes.fromhex(data['script']))
        except WalletRpcError as error:
            assert error.__cause__ is None and error.__context__ is None
        else: raise AssertionError('unconfirmed transaction established evidence')
    else:
        output=wallet.observe_historical_wallet_output(data['txid'],bytes.fromhex(data['script']))
        assert output.txid==data['txid'] and output.vout==data['vout']
        assert output.value_sat==1000000 and output.script_pubkey.hex()==data['script']
        assert output.confirmations>=1 and output.block_hash==data['block_hash']
        assert output.network==network and output.completed_at>=output.started_at
        assert not hasattr(output,'owned') and not hasattr(output,'spendable_msat')
print('historical Core wallet recognition passed')
"""


@pytest.mark.bitcoin_core
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_BITCOIN_CORE") != "1",
    reason="explicit owned Core historical wallet conformance opt-in",
)
def test_pinned_core_historical_spent_and_public_only_recognition(tmp_path: Path) -> None:  # noqa: PLR0915 - one owned wallet/namespace lifecycle
    if shutil.which("docker") is None:
        pytest.skip("Docker required for isolated pinned Core")
    assert sys.version_info[:2] == (3, 14), "pinned Python sidecar requires matching dependency ABI"
    helper = import_module("test_recovery_core_pinned")
    docker, cli = helper._docker, helper._cli  # noqa: SLF001 - existing secret-safe owned Docker/RPC helpers
    name = "rillswap-wallet-history-" + secrets.token_hex(6)
    tmp_path.chmod(0o700)
    deps = Path(sysconfig.get_path("purelib")).resolve()
    assert deps.is_dir()

    def check(expected: str) -> None:
        mounts = {
            ROOT / "src": "/work/cli",
            ROOT.parent / "rill-core/packages/core/src": "/work/core",
            ROOT.parent / "rill-provider/src": "/work/provider",
            ROOT.parent / "rill-crypto/python/src": "/work/crypto",
            deps: "/work/deps",
            tmp_path: "/work/private",
        }
        arguments = ["run", "--rm", "--platform", "linux/amd64", "--network", f"container:{name}"]
        for source, target in mounts.items():
            arguments.extend(("--mount", f"type=bind,src={source},dst={target},readonly"))
        arguments.extend(
            (
                "--env",
                "PYTHONPATH=/work/cli:/work/core:/work/provider:/work/crypto:/work/deps",
                "--env",
                f"HISTORY_EXPECTED={expected}",
                PYTHON_IMAGE,
                "python",
                "-c",
                CHECK,
            )
        )
        assert docker(*arguments) == "historical Core wallet recognition passed"

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
            CORE_IMAGE,
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
                info = json.loads(cli(name, "getnetworkinfo"))
            except AssertionError:
                time.sleep(0.2)
            else:
                assert info["version"] == 300000
                break
        else:
            raise AssertionError("owned pinned Core did not become ready")
        cli(name, "createwallet", "fund")
        cli(name, "createwallet", "merchant")
        cli(name, "createwallet", "public-only", "true", "true")
        assert (
            json.loads(cli(name, "-rpcwallet=merchant", "getwalletinfo"))["private_keys_enabled"]
            is True
        )
        assert (
            json.loads(cli(name, "-rpcwallet=public-only", "getwalletinfo"))["private_keys_enabled"]
            is False
        )
        mining = cli(name, "-rpcwallet=fund", "getnewaddress", "", "bech32m")
        cli(name, "generatetoaddress", "101", mining)
        destination = cli(name, "-rpcwallet=merchant", "getnewaddress", "", "bech32m")
        script = json.loads(cli(name, "-rpcwallet=merchant", "getaddressinfo", destination))[
            "scriptPubKey"
        ]
        descriptor = json.loads(cli(name, "getdescriptorinfo", f"rawtr({script[4:]})"))[
            "descriptor"
        ]
        imported = json.loads(
            cli(
                name,
                "-rpcwallet=public-only",
                "importdescriptors",
                json.dumps([{"desc": descriptor, "timestamp": "now", "active": False}]),
            )
        )
        assert len(imported) == 1
        assert imported[0]["success"] is True
        txid = cli(name, "-rpcwallet=fund", "sendtoaddress", destination, "0.01000000")
        docker(
            "cp", f"{name}:/home/bitcoin/.bitcoin/regtest/.cookie", str(tmp_path / "core.cookie")
        )
        (tmp_path / "core.cookie").chmod(0o600)
        data = {"txid": txid, "script": script, "network": NETWORK}
        path = tmp_path / "input.json"
        path.write_text(json.dumps(data))
        path.chmod(0o600)
        check("unknown")
        cli(name, "generatetoaddress", "1", mining)
        data["block_hash"] = cli(name, "getbestblockhash")
        raw = json.loads(cli(name, "getrawtransaction", txid, "true", data["block_hash"]))
        outputs = [output["n"] for output in raw["vout"] if output["scriptPubKey"]["hex"] == script]
        assert len(outputs) == 1
        data["vout"] = outputs[0]
        path.write_text(json.dumps(data))
        recognition = json.loads(cli(name, "-rpcwallet=public-only", "getaddressinfo", destination))
        assert recognition["ismine"] is True
        assert recognition["iswatchonly"] is False
        check("recognized")
        cli(name, "-rpcwallet=merchant", "sendtoaddress", mining, "0.00990000")
        cli(name, "generatetoaddress", "1", mining)
        assert (
            cli(name, "gettxout", txid, str(data["vout"])) == ""
        )  # actual spent UTXO, not inferred absence
        check("recognized")
    finally:
        try:
            docker("rm", "--force", "--volumes", name)
        finally:
            try:
                (tmp_path / "core.cookie").unlink(missing_ok=True)
            finally:
                (tmp_path / "input.json").unlink(missing_ok=True)
