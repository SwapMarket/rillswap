"""Actual native contract funding coordinates without txindex or wallet fallback."""

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
FIXTURE = "initial-ln-to-btc-no-prepayment-v1.json"
CHECK = """
import json
from pathlib import Path
import httpx
from rill_core.recovery import construct_selected_recovery_claim
from rill_core.settlement import FundingOutput
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import funding_binding_hash
from rill_core.wire.messages import ContractTerms, FundingBinding
from rill_core.wire.types import NetworkIdentity
from rill_crypto import Context
from rill_provider.core_tx_bytes import CoreTransactionReader, CoreUnavailableError
data=json.loads(Path('/work/private/input.json').read_bytes())
phase='input'
source=json.loads(Path('/work/fixtures/initial-ln-to-btc-no-prepayment-v1.json').read_bytes())
network=NetworkIdentity.model_validate(source['network_identity'])
phase='terms'
terms=ContractTerms.model_validate_json(canonicalize(source['contract_terms']))
transaction=data['transaction']
selected=[item for item in transaction['vout']
    if item['scriptPubKey']['hex']==source['taproot_contract']['script_pubkey']]
assert len(selected)==1 and transaction['vin'] and 'txid' in transaction['vin'][0]
phase='binding'
binding=FundingBinding.model_validate(dict(contract_hash=source['contract_hash'],funding_attempt_id='cc'*32,
    binding_revision=0,funder_role='provider',lineage_anchor_txid=transaction['vin'][0]['txid'],
    lineage_anchor_vout=transaction['vin'][0]['vout'],funding_txid=transaction['txid'],
    contract_vout=selected[0]['n'],contract_value_sat=terms.economics.contract_amount_sat,
    contract_script_pubkey=source['taproot_contract']['script_pubkey'],replaces_txid=None,created_at=1700000200))
reader=CoreTransactionReader(port=18443,cookie_path='/work/private/core.cookie',network=network,wallet='DOES_NOT_EXIST')
phase='crypto'
with Context(library_path='/work/native/library.so') as crypto:
    # The host fixture authenticates this synthetic original binding independently.
    # The observation API itself establishes correspondence, not signatures.
    provider_key=(9).to_bytes(32,'big')
    expected_provider=source['verification_context']['provider_session_xonly_key']
    assert crypto.public_key(provider_key)[1:].hex()==expected_provider
    signature=crypto.schnorr_sign(provider_key,funding_binding_hash(binding),b'\\x33'*32)
    source['funding_history'].append(dict(binding=binding.model_dump(mode='json'),funder_session_signature=signature.hex()))
    if data['spent']:
        phase='confirmed_spent'
        try: reader.observe_funding_inclusion(binding,terms,keys=crypto)
        except CoreUnavailableError as error:
            assert error.__cause__ is None and error.__context__ is None
        else: raise AssertionError('spent funding yielded a new inclusion sample')
        historical=reader.observe_block_transaction(binding.funding_txid,
            block_height=data['observed_height'],block_hash=data['observed_hash'])
        assert historical.raw_transaction.hex()==data['raw']
        print('index-free native funding and confirmed-spent history passed')
    else:
        phase='unqualified_refusal'
        # Root getrawtransaction demonstrably fails, even though fund's wallet
        # knows its transaction. The actual observer must use qualified lookup.
        user,password=Path('/work/private/core.cookie').read_text().strip().split(':',1)
        with httpx.Client(base_url='http://127.0.0.1:18443',auth=httpx.BasicAuth(user,password),
                trust_env=False,follow_redirects=False,timeout=5) as client:
            result=client.post('/',json=dict(jsonrpc='2.0',id=1,method='getrawtransaction',
                params=[binding.funding_txid,False])).json()
        assert result['error']['code']==-5
        original=reader._rpc
        calls=[]
        def checked(client,method,params,request_id,**kwargs):
            assert method in ('getblockchaininfo','getblockhash','gettxout','getrawtransaction')
            if method=='getrawtransaction':
                assert len(params)==3
                assert params[0]==binding.funding_txid
            calls.append((method,params))
            return original(client,method,params,request_id,**kwargs)
        reader._rpc=checked
        phase='observe'
        observed=reader.observe_funding_inclusion(binding,terms,keys=crypto)
        assert observed.block_height==102 and observed.block_hash==data['expected_block']
        assert observed.minimum_sampled_confirmations==2
        assert observed.tip_before_hash==observed.tip_after_hash==data['tip']
        assert observed.raw_transaction.hex()==data['raw']
        assert sum(method=='gettxout' for method,params in calls)==2
        funding=FundingOutput(bytes.fromhex(binding.funding_txid),binding.contract_vout,
            int(binding.contract_value_sat),bytes.fromhex(binding.contract_script_pubkey))
        phase='construct_claim'
        claim=construct_selected_recovery_claim(canonicalize(source),network,funding_attempt_id='cc'*32,
            binding_revision=0,live_funding=funding,sampled_tip_height=observed.tip_after_height,
            sampled_confirmations=observed.minimum_sampled_confirmations,fee_sat=300,
            auxiliary_random=b'\\x55'*32,crypto=crypto)
        # This preimage is the repository's public synthetic fixture only.
        print(json.dumps(dict(claim=claim.hex(),height=observed.block_height,block_hash=observed.block_hash)))
"""


def _program() -> str:
    return (
        "import sys\nphase='imports'\ntry:\n"
        + "".join("    " + line + "\n" for line in CHECK.splitlines())
        + "except Exception as error:\n    sys.stderr.write('PHASE: index_free_'+phase+'\\n')\n"
        + "    category=type(error).__name__\n"
        + "    if category in ('AssertionError','CoreUnavailableError','ValidationError',"
        "'OSError','ImportError','TypeError','ValueError','KeyError'):\n"
        + "        sys.stderr.write(category+': refused\\n')\n"
        + "    sys.exit(1)\n"
    )


def test_index_free_native_sidecar_program_compiles() -> None:
    compile(_program(), "<index-free-native-funding>", "exec")


@pytest.mark.bitcoin_core
@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_BITCOIN_CORE") != "1"
    or os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="explicit native and owned Core inclusion conformance opt-ins",
)
def test_pinned_native_funding_without_txindex_then_confirmed_spent_refusal(tmp_path: Path) -> None:  # noqa: PLR0915 - one owned Core lifecycle
    if shutil.which("docker") is None:
        pytest.skip("Docker required for owned Core")
    assert sys.version_info[:2] == (3, 14), "pinned dependency ABI differs"
    helpers = import_module("test_core_tx_bytes_bitcoin_core")
    docker, cli = helpers._docker, helpers._bitcoin_cli  # noqa: SLF001 - existing fixed, secret-safe owned RPC helpers
    run_id = secrets.token_hex(16)
    name = "rillswap-funding-inclusion-" + run_id
    label = "org.rillswap.test-run=" + run_id
    fixture = json.loads((ROOT.parent / "rill-cli/tests/fixtures" / FIXTURE).read_bytes())
    tmp_path.chmod(0o700)
    cookie = tmp_path / "core.cookie"
    private = tmp_path / "input.json"
    native = Path(os.environ["RILL_CRYPTO_LIBRARY"]).resolve()
    assert native.is_file()
    try:
        docker(
            "run",
            "--detach",
            "--name",
            name,
            "--label",
            label,
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
        mining = cli(name, "-rpcwallet=fund", "getnewaddress", "", "bech32m")
        cli(name, "generatetoaddress", "101", mining)
        descriptor = json.loads(
            cli(
                name,
                "getdescriptorinfo",
                "rawtr(" + fixture["taproot_contract"]["output_xonly_key"] + ")",
            )
        )["descriptor"]
        address = json.loads(cli(name, "deriveaddresses", descriptor))[0]
        amount = int(fixture["contract_terms"]["economics"]["contract_amount_sat"])
        funding = cli(
            name,
            "-rpcwallet=fund",
            "sendtoaddress",
            address,
            f"{amount // 100000000}.{amount % 100000000:08d}",
        )
        cli(name, "generatetoaddress", "2", mining)
        assert json.loads(cli(name, "getindexinfo")) == {}
        # Setup uses the sender's owned wallet to assemble the test input, not as
        # a reader fallback. The API receives no block-coordinate input.
        raw = json.loads(cli(name, "-rpcwallet=fund", "gettransaction", funding))["hex"]
        transaction = json.loads(cli(name, "decoderawtransaction", raw))
        data = {
            "transaction": transaction,
            "raw": raw,
            "expected_block": cli(name, "getblockhash", "102"),
            "tip": cli(name, "getbestblockhash"),
            "spent": False,
        }
        with os.fdopen(
            os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w"
        ) as handle:
            json.dump(data, handle)
        docker("cp", f"{name}:/home/bitcoin/.bitcoin/regtest/.cookie", str(cookie))
        cookie.chmod(0o600)
        mounts = {
            ROOT / "src": "/work/provider",
            ROOT.parent / "rill-core/packages/core/src": "/work/core",
            ROOT.parent / "rill-crypto/python/src": "/work/crypto",
            ROOT.parent / "rill-cli/tests/fixtures": "/work/fixtures",
            Path(sysconfig.get_path("purelib")).resolve(): "/work/deps",
            tmp_path: "/work/private",
            native: "/work/native/library.so",
        }
        arguments = ["run", "--rm", "--platform", "linux/amd64", "--network", f"container:{name}"]
        for source, target in mounts.items():
            assert source.exists()
            arguments.extend(("--mount", f"type=bind,src={source},dst={target},readonly"))
        arguments.extend(
            (
                "--env",
                "PYTHONPATH=/work/provider:/work/core:/work/crypto:/work/deps",
                helpers.PYTHON_IMAGE,
                "python",
                "-c",
                _program(),
            )
        )
        safe_docker = import_module("test_lnd_payment_pinned")._docker  # noqa: SLF001 - fixed private-safe diagnostic tags, no raw child errors
        result = json.loads(safe_docker(*arguments))
        allowed = json.loads(cli(name, "testmempoolaccept", json.dumps([result["claim"]])))
        assert len(allowed) == 1
        assert allowed[0]["allowed"] is True
        cli(name, "sendrawtransaction", result["claim"])
        cli(name, "generatetoaddress", "1", mining)
        selected = [
            item
            for item in transaction["vout"]
            if item["scriptPubKey"]["hex"] == fixture["taproot_contract"]["script_pubkey"]
        ]
        assert len(selected) == 1
        assert cli(name, "gettxout", funding, str(selected[0]["n"]), "false") == ""
        data.update(
            spent=True, observed_height=result["height"], observed_hash=result["block_hash"]
        )
        private.write_text(json.dumps(data))
        assert (
            safe_docker(*arguments)
            == "index-free native funding and confirmed-spent history passed"
        )
    finally:
        cleanup = import_module("test_lnd_payment_pinned")
        try:
            cleanup._cleanup_containers((name,), run_id, cookie)  # noqa: SLF001 - label-verified owned cleanup only
        finally:
            private.unlink(missing_ok=True)
