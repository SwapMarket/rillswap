"""Real recovery reader RPCs distinguish preflight refusal from lost broadcast replies."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx
import pytest
from test_recovery_core_observation import _context

from rill_cli import recovery_core_observation as observation
from rill_cli.claim_watcher import ClaimSubmission
from rill_cli.refund_watcher import core_claim_collaborators

if TYPE_CHECKING:
    from pathlib import Path

TXID = "ac" * 32


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("refused", ClaimSubmission.NOT_BROADCAST),
        ("preflight lost", ClaimSubmission.NOT_BROADCAST),
        ("send lost", ClaimSubmission.UNKNOWN),
        ("wrong txid", ClaimSubmission.UNKNOWN),
        ("accepted", ClaimSubmission.ACCEPTED),
    ],
)
def test_submission_rpc_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, expected: ClaimSubmission
) -> None:
    terms, binding, *_rest = _context()
    network = terms.network_identity
    methods: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body["method"]
        methods.append(method)
        if (method == "testmempoolaccept" and mode == "preflight lost") or (
            method == "sendrawtransaction" and mode == "send lost"
        ):
            raise httpx.ReadError("response lost")
        responses = {
            "getblockchaininfo": {
                "chain": "regtest",
                "bestblockhash": "ab" * 32,
                "initialblockdownload": False,
                "blocks": 120,
            },
            "getblockhash": network.genesis_hash,
            "testmempoolaccept": [{"allowed": mode != "refused", "txid": TXID}],
            "sendrawtransaction": "00" * 32 if mode == "wrong txid" else TXID,
        }
        encoded = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": responses[method]})
        return httpx.Response(200, stream=httpx.ByteStream(encoded.encode()))

    transport = httpx.MockTransport(handle)
    real_client = httpx.Client
    monkeypatch.setattr(
        observation.httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs)
    )
    cookie = tmp_path / "core.cookie"
    cookie.write_text("__cookie__:secret")
    cookie.chmod(0o600)
    reader = observation.RecoveryCoreReader(port=18443, cookie_path=cookie, network=network)
    _chain, _confirmations, submit = core_claim_collaborators(reader, binding=binding)
    assert submit(b"signed-claim", TXID) is expected
    assert ("sendrawtransaction" in methods) is (expected is not ClaimSubmission.NOT_BROADCAST)
