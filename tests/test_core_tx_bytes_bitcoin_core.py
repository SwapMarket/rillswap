"""Opt-in pinned Core v30 RPC over an isolated, shared Docker network namespace."""

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
DOCKER = shutil.which("docker")


def _docker(*args: str) -> str:
    assert DOCKER is not None
    result = subprocess.run(  # noqa: S603 - fixed Docker executable, explicit args
        [DOCKER, *args],
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        # Never echo docker stderr: cookie and RPC response text are not logs.
        raise AssertionError("pinned regtest Docker check failed")
    return result.stdout.strip()


def _bitcoin_cli(container: str, *args: str) -> str:
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


PYTHON_CHECK = """
import json, os
from pathlib import Path
from rill_core.errors import ValidationError
from rill_core.wire.messages import ContractTerms, FundingBinding
from rill_provider.core_tx_bytes import CoreUnavailableError, RegtestCoreTransactionReader
fixture = json.loads(Path('/work/provider/tests/fixtures/initial-btc-to-ln-v1.json').read_bytes())
terms = ContractTerms.model_validate_json(json.dumps(fixture['contract_terms']))
txid = os.environ['RILL_TEST_TXID']
binding = FundingBinding.model_validate({
    'contract_hash': fixture['contract_hash'], 'funding_attempt_id': 'ab' * 32,
    'binding_revision': 0, 'funder_role': 'client', 'lineage_anchor_txid': '11' * 32,
    'lineage_anchor_vout': 0, 'funding_txid': txid, 'contract_vout': 0,
    'contract_value_sat': terms.economics.contract_amount_sat,
    'contract_script_pubkey': fixture['taproot_contract']['script_pubkey'],
    'replaces_txid': None, 'created_at': 1_700_000_000,
})
artifacts = fixture['taproot_contract']
class Keys:
    def musig_internal_key(self, *_):
        return bytes.fromhex(artifacts['internal_xonly_key']), artifacts['internal_key_parity']
    def musig_output_key(self, *_):
        return bytes.fromhex(artifacts['output_xonly_key']), artifacts['output_key_parity']
reader = RegtestCoreTransactionReader(
    port=18443, cookie_path='/work/cookie/core.cookie', network=terms.network_identity)
try:
    reader.fetch_binding_byte_match(binding, terms, keys=Keys())
except ValidationError as exc:
    assert 'coinbase null outpoint' in str(exc)
else:
    raise AssertionError('coinbase must not be accepted as funding')
try:
    reader.fetch_binding_byte_match(binding.model_copy(update={'funding_txid': '22' * 32}),
                                    terms, keys=Keys())
except CoreUnavailableError:
    pass
else:
    raise AssertionError('unavailable transaction unexpectedly matched')
print('Core v30 byte retrieval and conservative rejection passed')
"""


@pytest.mark.bitcoin_core
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_BITCOIN_CORE") != "1",
    reason="set RILLSWAP_RUN_BITCOIN_CORE=1 for pinned Docker interoperability",
)
def test_pinned_core_regtest_http_retrieval_is_not_funding_authority(tmp_path: Path) -> None:
    assert DOCKER is not None
    container = f"rillswap-read-core-{secrets.token_hex(6)}"
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
            "-txindex=1",
            "-rpcbind=0.0.0.0",
            "-rpcallowip=127.0.0.1",
            "-printtoconsole=1",
        )
        for _ in range(60):
            result = subprocess.run(  # noqa: S603 - fixed Docker executable
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
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("pinned Core did not start within the test budget")
        _bitcoin_cli(container, "createwallet", "read-only-adapter-test")
        address = _bitcoin_cli(container, "-rpcwallet=read-only-adapter-test", "getnewaddress")
        block = json.loads(_bitcoin_cli(container, "generatetoaddress", "1", address))[0]
        coinbase = json.loads(_bitcoin_cli(container, "getblock", block, "1"))["tx"][0]
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
            f"type=bind,src={ROOT},dst=/work/provider,readonly",
            "--mount",
            f"type=bind,src={CORE},dst=/work/core,readonly",
            "--mount",
            f"type=bind,src={tmp_path},dst=/work/cookie,readonly",
            "--env",
            "PYTHONPATH=/work/provider/.venv/lib/python3.14/site-packages:"
            "/work/provider/src:/work/core/packages/core/src",
            "--env",
            f"RILL_TEST_TXID={coinbase}",
            PYTHON_IMAGE,
            "python",
            "-c",
            PYTHON_CHECK,
        )
        assert result == "Core v30 byte retrieval and conservative rejection passed"
    finally:
        subprocess.run(  # noqa: S603 - best-effort cleanup, no secrets in command
            [DOCKER, "rm", "--force", "--volumes", container],
            capture_output=True,
            timeout=30,
            check=False,
        )
