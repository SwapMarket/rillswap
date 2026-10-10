"""Opt-in read-only checks against the disposable running dev LND, never dispatches payments."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RILLSWAP_TEST_USER_NODE") != "1", reason="needs the explicit running dev stack"
)
ROOT = Path(__file__).resolve().parents[2]


def test_restricted_macaroon_and_read_only_browser_route_query():
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(ROOT / "dev/compose.yaml"),
            "exec",
            "-T",
            "user-node",
            "python",
            "-c",
            """
import sys,json
sys.path.insert(0,'/src/dev')
from user_node_api import UserNode
from http.client import HTTPSConnection
node=UserNode()
node.attest()
connection=HTTPSConnection('lnd-user',8080,context=node.context,timeout=10)
connection.request('GET','/v1/balance/channels',headers={'Grpc-Metadata-macaroon':node.macaroon})
response=connection.getresponse()
denial=json.loads(response.read())
# Pinned LND wraps the URI-permission error as gRPC UNKNOWN (HTTP 500).
assert response.status==500 and denial.get('code')==2 and denial.get('message')=='permission denied'
connection.close()
print('Native LND identity, regtest, verified TLS, and unrelated RPC denial passed.')
""",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # Read only a public destination already provisioned in the dev stack.
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(ROOT / "dev/compose.yaml"),
            "exec",
            "-T",
            "tools",
            "python",
            "-c",
            "import json; print(json.load(open('/state/info.json'))['lnd_pubkeys']['maker'])",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    destination = result.stdout.strip()
    headers = {"Origin": "http://127.0.0.1:5273"}
    with urlopen(
        Request("http://127.0.0.1:8093/configuration", headers=headers), timeout=10
    ) as response:
        config = json.load(response)
        assert response.headers["Cache-Control"] == "no-store"
    assert config["network_identity"]["name"] == "regtest"
    headers["Grpc-Metadata-macaroon"] = config["macaroon"]
    with urlopen(
        Request("http://127.0.0.1:8093/v1/getinfo", headers=headers), timeout=10
    ) as response:
        info = json.load(response)
    assert info["identity_pubkey"] == config["node_identity"]
    body = {
        "final_cltv_delta": 21,
        "fee_limit": {"fixed_msat": "10000"},
        "cltv_limit": 100,
        "route_hints": [],
        "dest_features": [8, 14],
    }
    with urlopen(
        Request(
            f"http://127.0.0.1:8093/v1/graph/routes/{destination}/1000",
            data=json.dumps(body).encode(),
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        ),
        timeout=10,
    ) as response:
        routes = json.load(response)
    assert len(routes["routes"]) == 1
    assert routes["routes"][0]["total_amt_msat"] == "1000000"
