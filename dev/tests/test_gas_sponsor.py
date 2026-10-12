"""Dev gas sponsor: request admission, response shapes, and the user operation packing."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("web3")
os.environ.setdefault("RILL_DEV_SRC", str(Path(__file__).parents[2]))
sys.path.insert(0, str(Path(__file__).parents[1]))
spec = importlib.util.spec_from_file_location(
    "gas_sponsor", Path(__file__).parents[1] / "gas_sponsor.py"
)
sponsor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sponsor)

VECTORS = json.loads(
    (Path(__file__).parents[2] / "rill-web/unit/fixtures/gasSponsorVectors.json").read_text()
)


def test_authorization_digest_matches_eth_account_vector() -> None:
    delegate = bytes.fromhex(VECTORS["delegate"][2:])
    digest = sponsor.keccak(
        b"\x05" + sponsor._rlp([VECTORS["chainId"], delegate, VECTORS["authorization"]["nonce"]])
    )
    assert "0x" + digest.hex() == VECTORS["authorization"]["digest"]


def test_packed_user_operation_hash_matches_browser_vector() -> None:
    packed = sponsor._packed(VECTORS["sponsoredUserOp"], b"")
    inner = sponsor.keccak(
        sponsor.encode(
            [
                "address",
                "uint256",
                "bytes32",
                "bytes32",
                "bytes32",
                "uint256",
                "bytes32",
                "bytes32",
            ],
            [
                packed[0],
                packed[1],
                sponsor.keccak(packed[2]),
                sponsor.keccak(packed[3]),
                packed[4],
                packed[5],
                packed[6],
                sponsor.keccak(packed[7]),
            ],
        )
    )
    outer = sponsor.keccak(
        sponsor.encode(
            ["bytes32", "address", "uint256"],
            [inner, sponsor.to_checksum_address(VECTORS["entryPoint"]), VECTORS["chainId"]],
        )
    )
    assert "0x" + outer.hex() == VECTORS["sponsoredUserOpHash"]


def test_signature_admission() -> None:
    assert len(sponsor._signature({"type": "secp256k1", "data": VECTORS["userOpSignature"]})) == 65
    with pytest.raises(sponsor.RpcError):
        sponsor._signature({"type": "secp256k1", "data": "0x" + "00" * 65})
    with pytest.raises(sponsor.RpcError):
        sponsor._signature({"type": "typed", "data": VECTORS["userOpSignature"]})


@pytest.fixture
def server():
    stub = SimpleNamespace(
        prepare=lambda request: {"echo": request},
        send=lambda signed: {"preparedCallIds": ["id-1"]},
        status=lambda call_id: {"status": 100},
    )
    instance = sponsor.SponsorServer(("127.0.0.1", 0), stub, 5273)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield instance
    instance.shutdown()


def rpc(
    server,
    method: str,
    params: list,
    origin: str | None = "http://127.0.0.1:5273",
    http_method: str = "POST",
) -> tuple[int, dict, dict]:
    connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    headers = {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = origin
    body = (
        json.dumps({"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
        if http_method == "POST"
        else None
    )
    connection.request(http_method, "/", body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    return response.status, dict(response.getheaders()), json.loads(raw) if raw else {}


def test_json_rpc_dispatch_and_cors(server) -> None:
    status, headers, body = rpc(server, "wallet_prepareCalls", [{"from": "0x1"}])
    assert status == 200 and body["result"] == {"echo": {"from": "0x1"}} and body["id"] == 7
    assert headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:5273"
    assert rpc(server, "wallet_sendPreparedCalls", [{}])[2]["result"] == {
        "preparedCallIds": ["id-1"]
    }
    assert rpc(server, "wallet_getCallsStatus", ["id-1"])[2]["result"] == {"status": 100}
    assert rpc(server, "eth_sendTransaction", [{}])[2]["error"]["code"] == -32601
    assert rpc(server, "wallet_getCallsStatus", [])[2]["error"]["code"] == -32602
    status, headers, _ = rpc(server, "", [], origin="http://evil.example", http_method="OPTIONS")
    assert status == 403 and "Access-Control-Allow-Origin" not in headers
    status, headers, _ = rpc(server, "", [], http_method="OPTIONS")
    assert status == 204 and headers["Access-Control-Allow-Methods"] == "POST"
