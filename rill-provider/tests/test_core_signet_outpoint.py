"""Both named-tip observation modes attest signet challenge at both boundaries."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.settlement import FundingBindingTransactionMatch
from rill_core.wire.hashes import contract_hash
from test_core_tx_bytes import _candidate_reply, _context, _cookie, _server
from test_network_adapters import _network

from rill_provider import core_tx_bytes

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("mode", ["candidate", "cooperative"])
@pytest.mark.parametrize("boundary", [1, 7])
@pytest.mark.parametrize("challenge", ["matching", "missing", "wrong"])
def test_signet_outpoint_checks_challenge_at_each_named_tip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    boundary: int,
    challenge: str,
) -> None:
    terms, binding, _ = _context()
    network = _network("signet")
    terms = terms.model_copy(update={"network_identity": network})
    binding = binding.model_copy(update={"contract_hash": contract_hash(terms).hex()})
    match = FundingBindingTransactionMatch(
        binding.funding_txid,
        binding.contract_vout,
        binding.lineage_anchor_txid,
        binding.lineage_anchor_vout,
    )
    monkeypatch.setattr(core_tx_bytes, "check_funding_binding_transaction", lambda *_a, **_k: match)

    def reply(payload: dict[str, Any]) -> tuple[int, bytes]:
        status, raw = _candidate_reply(payload, binding)
        body = json.loads(raw)
        if payload["method"] == "getblockchaininfo":
            body["result"]["chain"] = "signet"
            if payload["id"] != boundary or challenge == "matching":
                body["result"]["signet_challenge"] = network.signet_challenge
            elif challenge == "wrong":
                body["result"]["signet_challenge"] = "51"
        elif payload["method"] == "getblockhash" and payload["params"] == [0]:
            body["result"] = network.genesis_hash
        return status, json.dumps(body).encode()

    requests: list[dict[str, Any]] = []
    with _server(reply, requests) as port:
        reader = core_tx_bytes.CoreTransactionReader(
            port=port,
            cookie_path=_cookie(tmp_path),
            network=network,
        )
        observe = (
            reader.observe_candidate_outpoint
            if mode == "candidate"
            else reader.observe_cooperative_claim_outpoint
        )
        if challenge == "matching":
            sample = observe(binding, terms, keys=None)  # type: ignore[arg-type]
            assert sample.network_identity == network
            assert [request["method"] for request in requests].count("getblockchaininfo") == 2
        else:
            with pytest.raises(core_tx_bytes.CoreProtocolError, match="configured chain"):
                observe(binding, terms, keys=None)  # type: ignore[arg-type]
            assert requests[-1]["id"] == boundary


@pytest.mark.parametrize("challenge", ["matching", "missing", "wrong"])
def test_signet_informational_height_uses_same_challenge_guard(
    tmp_path: Path,
    challenge: str,
) -> None:
    network = _network("signet")

    def reply(payload: dict[str, Any]) -> tuple[int, bytes]:
        if payload["method"] == "getblockchaininfo":
            result: object = {
                "chain": "signet",
                "bestblockhash": "aa" * 32,
                "blocks": 105,
                "initialblockdownload": False,
            }
            if challenge != "missing":
                result["signet_challenge"] = (
                    network.signet_challenge if challenge == "matching" else "51"
                )
        else:
            result = network.genesis_hash
        return 200, json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode()

    requests: list[dict[str, Any]] = []
    with _server(reply, requests) as port:
        reader = core_tx_bytes.CoreTransactionReader(
            port=port,
            cookie_path=_cookie(tmp_path),
            network=network,
        )
        if challenge == "matching":
            assert reader.tip_height() == 105
        else:
            with pytest.raises(core_tx_bytes.CoreProtocolError):
                reader.tip_height()
            assert len(requests) == 1
