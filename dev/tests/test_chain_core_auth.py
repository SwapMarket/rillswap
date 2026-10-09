"""Opt-in authorization check on an isolated disposable pinned Core node."""

from __future__ import annotations

import os
import re
import subprocess
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RILLSWAP_TEST_CHAIN_AUTH") != "1",
    reason="Requires Docker and a built rillswap-dev:local image; creates isolated containers",
)

CHECK = r"""
import base64, json, sys, time, urllib.request, urllib.error
def call(payload, user='rill-chain', password='rill-dev-chain-regtest', path=''):
    auth = base64.b64encode(f'{user}:{password}'.encode()).decode()
    request = urllib.request.Request(sys.argv[1] + path, data=json.dumps(payload).encode(),
        headers={'Authorization': f'Basic {auth}', 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
def request(method, params=None):
    return {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}
for attempt in range(20):
    try:
        code, body = call(request('getblockchaininfo'))
        if code == 200: break
    except urllib.error.URLError: pass
    time.sleep(0.5)
else: raise RuntimeError('isolated reader node not ready')
assert json.loads(body)['result']['chain'] == 'regtest'
assert call(request('getblockhash', [0]))[0] == 200
for payload, path in [(request('getwalletinfo'), ''), (request('getwalletinfo'), '/wallet/unused'),
    (request('generatetoaddress', [1, 'invalid']), ''),
    ([request('getblockhash', [0]), request('generatetoaddress', [1, 'invalid'])], '')]:
    assert call(payload, path=path)[0] == 403
assert call([request('getblockchaininfo'), request('getblockhash', [0])])[0] == 200
for user, password in [('rill', 'rill-dev-regtest'), ('__cookie__', 'rill-dev-regtest-cookie')]:
    assert call(request('getrpcinfo'), user, password)[0] == 200
"""


def test_core_reader_whitelist_preserves_existing_clients():
    compose = (Path(__file__).parents[1] / "compose.yaml").read_text()
    image = re.search(r"image: (bitcoin/bitcoin@sha256:[0-9a-f]+)", compose)
    assert image
    credentials = re.findall(r"-rpcauth=[^\s]+", compose)
    flags = [item.replace("$$", "$") for item in credentials]
    flags += re.findall(r"-rpcwhitelist[^\s]*", compose)
    name = "rillswap-chain-check-" + uuid.uuid4().hex[:12]

    def docker(*args):
        return subprocess.run(
            ["docker", *args], check=True, capture_output=True, text=True, timeout=60
        )

    docker("network", "create", name)
    try:
        docker(
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "--network",
            name,
            image.group(1),
            "-regtest=1",
            "-server=1",
            "-listen=0",
            "-rpcbind=0.0.0.0",
            "-rpcallowip=0.0.0.0/0",
            *flags,
        )
        docker(
            "run",
            "--rm",
            "--network",
            name,
            "rillswap-dev:local",
            "python",
            "-c",
            CHECK,
            f"http://{name}:18443",
        )
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)
        docker("network", "rm", name)
