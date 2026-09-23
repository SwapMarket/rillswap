"""Opt-in pinned Core v30 real-byte recovery candidate, no txindex or signing."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest

CORE_IMAGE = (
    "docker.io/bitcoin/bitcoin@"
    "sha256:49b55ea5c949a9ceff50786ee678d53f2728a4daa40a8139e3ee20243d24f281"
)
PYTHON_IMAGE = "python@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
ROOT = Path(__file__).parents[1]
CORE = ROOT.parent / "rill-core"
CRYPTO = ROOT.parent / "rill-crypto"
DOCKER = shutil.which("docker")


def _docker(*args: str) -> str:
    assert DOCKER is not None
    result = subprocess.run(  # noqa: S603 - pinned Docker and explicit args, no shell
        [DOCKER, *args],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if result.returncode:
        raise AssertionError("pinned Core recovery integration did not pass")
    return result.stdout.strip()


def _cli(container: str, *args: str) -> str:
    return _docker(
        "exec",
        "--user",
        "bitcoin:bitcoin",
        container,
        "bitcoin-cli",
        "-regtest",
        "-datadir=/home/bitcoin/.bitcoin",
        *args,
    )


def _p2tr_regtest_address(script_pubkey: bytes) -> str:
    assert len(script_pubkey) == 34
    assert script_pubkey[:2] == b"\x51\x20"
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    accumulator, bits, data = 0, 0, [1]
    for byte in script_pubkey[2:]:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((accumulator >> bits) & 31)
    if bits:
        data.append((accumulator << (5 - bits)) & 31)
    hrp = "bcrt"
    values = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]
    checksum = 1
    for value in values + data + [0] * 6:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for index, generator in enumerate(generators):
            if top >> index & 1:
                checksum ^= generator
    checksum ^= 0x2BC830A3
    data.extend((checksum >> (5 * (5 - index))) & 31 for index in range(6))
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + "".join(alphabet[value] for value in data)


PYTHON_CHECK = """
import contextlib, io, json, os
from pathlib import Path
import pyrage
from pyrage import x25519
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import funding_binding_hash
from rill_core.wire.messages import FundingBinding
from rill_crypto import Context
from rill_cli.main import main
source = Path('/work/cli/tests/fixtures') / os.environ['RILL_TEST_FIXTURE']
fixture = json.loads(source.read_bytes())
txid = os.environ['RILL_TEST_TXID']
spent = json.loads(os.environ['RILL_TEST_TRANSACTION'])
vout = [item for item in spent['vout']
        if item['scriptPubKey']['hex'] == fixture['taproot_contract']['script_pubkey']]
assert len(vout) == 1
assert spent['vin'] and 'txid' in spent['vin'][0]
binding = FundingBinding.model_validate({
    'contract_hash': fixture['contract_hash'], 'funding_attempt_id': 'cc' * 32,
    'binding_revision': 0,
    'funder_role': 'client' if fixture['profile_id'] == 'btc-to-ln/v1' else 'provider',
    'lineage_anchor_txid': spent['vin'][0]['txid'],
    'lineage_anchor_vout': spent['vin'][0]['vout'],
    'funding_txid': txid, 'contract_vout': vout[0]['n'],
    'contract_value_sat': fixture['contract_terms']['economics']['contract_amount_sat'],
    'contract_script_pubkey': fixture['taproot_contract']['script_pubkey'],
    'replaces_txid': None, 'created_at': 1700000200,
})
with Context(library_path=os.environ['RILL_CRYPTO_LIBRARY']) as crypto:
    session_key = (2 if binding.funder_role == 'client' else 9).to_bytes(32, 'big')
    assert crypto.public_key(session_key)[1:].hex() == (
        fixture['verification_context'][binding.funder_role + '_session_xonly_key'])
    signature = crypto.schnorr_sign(session_key, funding_binding_hash(binding), b'\\x33' * 32)
fixture['funding_history'].append({'binding': binding.model_dump(mode='json'),
                                   'funder_session_signature': signature.hex()})
identity = x25519.Identity.generate()
work = Path('/work/cookie')
age_path = work / 'selected.age'
age_path.write_bytes(pyrage.encrypt(canonicalize(fixture), [identity.to_public()]))
key_path = work / 'identity'
key_path.write_text(str(identity) + '\\n')
key_path.chmod(0o600)
network = work / 'network.json'
network.write_text(json.dumps(fixture['network_identity']))
arguments = ['recover', 'observe-funding', '--network', str(network),
             '--crypto-library', os.environ['RILL_CRYPTO_LIBRARY'], '--identity', str(key_path),
             '--rpc-cookie', str(work / 'core.cookie'), '--rpc-port', '18443',
             '--funding-attempt-id', 'cc' * 32, '--binding-revision', '0', str(age_path)]
capture = io.StringIO()
with contextlib.redirect_stdout(capture):
    assert main(arguments) == 0
report = json.loads(capture.getvalue())
assert report['kind'] == 'selected-funding-candidate-observation/v1'
assert report['funding_txid'] == txid
assert report['contract_vout'] == binding.contract_vout
assert report['static_transaction_bytes_match'] is True
assert report['chain_only_confirmations'] >= 1
assert report['transaction_lookup_block_hash'] == os.environ['RILL_TEST_INCLUSION_BLOCK']
assert report['authority'].startswith('none')
assert report['first_refund_eligible_height'] == 1101
print('pinned Core v30 byte-matched selected read-only recovery candidate; no txindex')
"""


@pytest.mark.bitcoin_core
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_BITCOIN_CORE") != "1",
    reason="set RILLSWAP_RUN_BITCOIN_CORE=1 for disposable pinned Core regtest",
)
@pytest.mark.parametrize(
    "fixture_name",
    [
        "initial-btc-to-ln-v1.json",
        "initial-ln-to-btc-no-prepayment-v1.json",
    ],
)
def test_pinned_core_v30_observes_signed_age_binding_without_txindex(
    tmp_path: Path,
    fixture_name: str,
) -> None:
    assert DOCKER is not None
    assert (CRYPTO / "tmp/build/librill_crypto.so").is_file()
    container = f"rillswap-recovery-observe-{secrets.token_hex(6)}"
    try:
        _docker(
            "run",
            "--detach",
            "--name",
            container,
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
            ready = subprocess.run(  # noqa: S603 - fixed pinned Core container
                [
                    DOCKER,
                    "exec",
                    "--user",
                    "bitcoin:bitcoin",
                    container,
                    "bitcoin-cli",
                    "-regtest",
                    "-datadir=/home/bitcoin/.bitcoin",
                    "getblockchaininfo",
                ],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("pinned Core did not become ready")
        _cli(container, "createwallet", "recovery-observation-test")
        mining = _cli(
            container, "-rpcwallet=recovery-observation-test", "getnewaddress", "", "bech32m"
        )
        _cli(container, "generatetoaddress", "101", mining)
        assert not json.loads(_cli(container, "getindexinfo")).get("txindex")
        fixture = json.loads((ROOT / "tests/fixtures" / fixture_name).read_text())
        address = _p2tr_regtest_address(bytes.fromhex(fixture["taproot_contract"]["script_pubkey"]))
        amount = int(fixture["contract_terms"]["economics"]["contract_amount_sat"])
        txid = _cli(
            container,
            "-rpcwallet=recovery-observation-test",
            "sendtoaddress",
            address,
            f"{amount / 100_000_000:.8f}",
        )
        _cli(container, "generatetoaddress", "1", mining)
        inclusion = _cli(container, "getbestblockhash")
        transaction = _cli(container, "getrawtransaction", txid, "true", inclusion)
        cookie = tmp_path / "core.cookie"
        _docker("cp", f"{container}:/home/bitcoin/.bitcoin/regtest/.cookie", str(cookie))
        cookie.chmod(0o600)
        result = _docker(
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            f"container:{container}",
            "--mount",
            f"type=bind,src={ROOT},dst=/work/cli,readonly",
            "--mount",
            f"type=bind,src={CORE},dst=/work/core,readonly",
            "--mount",
            f"type=bind,src={CRYPTO},dst=/work/crypto,readonly",
            "--mount",
            f"type=bind,src={tmp_path},dst=/work/cookie",
            "--env",
            "PYTHONPATH=/work/cli/.venv/lib/python3.14/site-packages:/work/cli/src:"
            "/work/core/packages/core/src:/work/crypto/python/src",
            "--env",
            "RILL_CRYPTO_LIBRARY=/work/crypto/tmp/build/librill_crypto.so",
            "--env",
            f"RILL_TEST_TXID={txid}",
            "--env",
            f"RILL_TEST_TRANSACTION={transaction}",
            "--env",
            f"RILL_TEST_INCLUSION_BLOCK={inclusion}",
            "--env",
            f"RILL_TEST_FIXTURE={fixture_name}",
            PYTHON_IMAGE,
            "python",
            "-c",
            PYTHON_CHECK,
        )
        assert (
            result
            == "pinned Core v30 byte-matched selected read-only recovery candidate; no txindex"
        )
    finally:
        subprocess.run(  # noqa: S603 - best-effort isolated container cleanup
            [DOCKER, "rm", "--force", "--volumes", container],
            capture_output=True,
            timeout=30,
            check=False,
        )
