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
genesis = json.loads(call(request('getblockhash', [0]))[1])['result']
assert json.loads(call(request('getblockheader', [genesis, True]))[1])['result']['height'] == 0
for method, params in [('getrawtransaction', ['0'*64, False]), ('gettxout', ['0'*64, 0, False]),
    ('gettxout', ['0'*64, 0, True])]:
    assert call(request(method, params))[0] == 200
for payload, path in [(request('getwalletinfo'), ''), (request('getwalletinfo'), '/wallet/unused'),
    (request('generatetoaddress', [1, 'invalid']), ''),
    (request('sendrawtransaction', ['00']), ''), (request('testmempoolaccept', [['00']]), ''),
    ([request('getblockhash', [0]), request('generatetoaddress', [1, 'invalid'])], '')]:
    assert call(payload, path=path)[0] == 403
assert call([request('getblockchaininfo'), request('getblockhash', [0])])[0] == 200
for user, password in [('rill', 'rill-dev-regtest'), ('__cookie__', 'rill-dev-regtest-cookie')]:
    assert call(request('getrpcinfo'), user, password)[0] == 200
for method, params in [('testmempoolaccept', [['00'], 0.1]),
    ('sendrawtransaction', ['00', 0.1, 0])]:
    assert call(request(method, params), 'rill-broadcast', 'rill-dev-broadcast-regtest')[0] == 200
for method in ['getblockchaininfo', 'getblockhash', 'getrawtransaction', 'getblockheader',
    'gettxout', 'getwalletinfo', 'generatetoaddress', 'signrawtransactionwithwallet', 'getrpcinfo']:
    assert call(request(method), 'rill-broadcast', 'rill-dev-broadcast-regtest')[0] == 403

# Actual transaction observations on this isolated node, not existing dev funds.
# Only the privileged test setup mines/sends; the adapter has read-only RPCs.
import importlib.util
spec = importlib.util.spec_from_file_location('chain_api', '/check/chain_api.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
api.CORE_URL = sys.argv[1]
sys.modules['chain_api'] = api
sys.path.insert(0, '/check')
import broadcast_api
broadcaster = broadcast_api.Broadcaster()
reader = api.ChainReader()
def setup_rpc(method, params=None, wallet=False):
    code, body = call(request(method, params), '__cookie__', 'rill-dev-regtest-cookie',
        '/wallet/observation-check' if wallet else '')
    result = json.loads(body)
    assert code == 200 and not result.get('error'), (method, result)
    return result['result']
def unavailable(path):
    try: reader.observe(path)
    except api.ChainUnavailable: return
    raise AssertionError('ambiguous observation must be unavailable')
setup_rpc('createwallet', ['observation-check'])
address = setup_rpc('getnewaddress', wallet=True)
setup_rpc('generatetoaddress', [101, address])
assert reader.observe('/api/block-height/0') == api.GENESIS
assert int(reader.observe('/api/blocks/tip/height')) == 101
assert reader.observe('/api/block-height/101') == reader.observe('/api/blocks/tip/hash')
destination = setup_rpc('getnewaddress', wallet=True)
txid = setup_rpc('sendtoaddress', [destination, 0.001], wallet=True)
assert json.loads(reader.observe(f'/api/tx/{txid}/status')) == {'confirmed': False}
transaction = setup_rpc('getrawtransaction', [txid, True])
vout = next(item['n'] for item in transaction['vout']
    if item['scriptPubKey'].get('address') == destination)
assert reader.observe(f'/api/tx/{txid}/hex') == transaction['hex']
history = json.loads(reader.observe(f'/api/address/{destination}/txs'))
assert len(history) == 1 and history[0]['txid'] == txid
assert history[0]['vout'][vout]['value'] == 100000
assert history[0]['status'] == {'confirmed': False}
assert 'Not confirmed on the active chain' in reader.observe(f'/tx/{txid}')
unavailable(f'/api/tx/{txid}/outspend/{vout}')  # Mempool-only is not confirmed UTXO evidence.
mined = setup_rpc('generatetoaddress', [1, address])[0]
status = json.loads(reader.observe(f'/api/tx/{txid}/status'))
assert status['confirmed'] and status['block_height'] == 102 and status['block_hash'] == mined
assert json.loads(reader.observe(f'/api/address/{destination}/txs'))[0]['status'] == status
assert '1 confirmation(s), block 102' in reader.observe(f'/tx/{txid}')
assert json.loads(reader.observe(f'/api/tx/{txid}/outspend/{vout}')) == {'spent': False}
unavailable(f'/api/tx/{txid}/outspend/4294967295')
unavailable('/api/tx/' + '0'*64 + '/hex')
spend_address = setup_rpc('getnewaddress', wallet=True)
raw = setup_rpc('createrawtransaction', [[{'txid': txid, 'vout': vout}], {spend_address: 0.00099}])
signed = setup_rpc('signrawtransactionwithwallet', [raw], wallet=True)
assert signed['complete']
low_cap = json.loads(call(request('testmempoolaccept', [[signed['hex']], 0.000001]),
    'rill-broadcast', 'rill-dev-broadcast-regtest')[1])['result']
assert low_cap[0]['allowed'] is False and low_cap[0]['reject-reason'] == 'max-fee-exceeded'
# A positive OP_RETURN burn must not be submitted by the zero-burn adapter.
burn_raw = setup_rpc('createrawtransaction', [[{'txid': txid, 'vout': vout}],
    [{spend_address: 0.00098}, {'data': '01'}]])
marker = '0000000000000000036a0101'
assert burn_raw.count(marker) == 1
burn_raw = burn_raw.replace(marker, (1000).to_bytes(8, 'little').hex() + '036a0101')
burn_signed = setup_rpc('signrawtransactionwithwallet', [burn_raw], wallet=True)
assert burn_signed['complete']
try: broadcaster.submit(burn_signed['hex'])
except broadcast_api.BroadcastUnavailable: pass
else: raise AssertionError('positive burn must be refused')
spend = broadcaster.submit(signed['hex'])
unavailable(f'/api/tx/{txid}/outspend/{vout}')  # Mempool spend remains UNKNOWN, never unspent.
setup_rpc('generatetoaddress', [1, address])
unavailable(f'/api/tx/{txid}/outspend/{vout}')  # Confirmed spent is likewise unavailable.
assert json.loads(reader.observe(f'/api/tx/{spend}/status'))['confirmed']
history = json.loads(reader.observe(f'/api/address/{destination}/txs'))
assert len(history) == 1 and history[0]['txid'] == txid and history[0]['status']['confirmed']
setup_rpc('invalidateblock', [mined])
assert json.loads(reader.observe(f'/api/tx/{txid}/status')) == {'confirmed': False}
unavailable(f'/api/tx/{txid}/outspend/{vout}')
print('Pinned Core authorization and confirmed/unconfirmed/spent/reorg observations passed.')
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
        result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        return result

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
            "-txindex=1",
            "-fallbackfee=0.0002",
            "-rpcbind=0.0.0.0",
            "-rpcallowip=0.0.0.0/0",
            *flags,
        )
        docker(
            "run",
            "--rm",
            "--network",
            name,
            "-v",
            f"{Path(__file__).parents[1] / 'chain_api.py'}:/check/chain_api.py:ro",
            "-v",
            f"{Path(__file__).parents[1] / 'broadcast_api.py'}:/check/broadcast_api.py:ro",
            "rillswap-dev:local",
            "python",
            "-c",
            CHECK,
            f"http://{name}:18443",
        )
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)
        docker("network", "rm", name)
