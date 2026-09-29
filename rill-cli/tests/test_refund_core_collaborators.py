"""Watcher reads and transaction submission must attest the actual Core network."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from rill_core.wire.types import NetworkIdentity

from rill_cli import recovery_core_observation as observation
from rill_cli.refund_watcher import ChainView, core_collaborators

if TYPE_CHECKING:
    from collections.abc import Callable

NETWORKS = Path(__file__).parents[2] / "rill-docs/networks"
TXID = "ac" * 32
FUNDING = "de" * 32


def _callbacks(  # noqa: PLR0913 - independent node identity fault knobs
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    network: NetworkIdentity,
    *,
    challenge: object,
    chain: str,
    genesis: str | None = None,
    outpoint: object = ...,
) -> tuple[
    tuple[
        Callable[[], ChainView | None], Callable[[str], int | None], Callable[[bytes, str], bool]
    ],
    list[str],
]:
    methods: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method, identifier = body["method"], body["id"]
        methods.append(method)
        info: dict[str, Any] = {
            "chain": chain,
            "bestblockhash": "ab" * 32,
            "initialblockdownload": False,
            "blocks": 120,
        }
        if challenge is not ...:
            info["signet_challenge"] = challenge
        result: object = {
            "getblockchaininfo": info,
            "getblockhash": network.genesis_hash if genesis is None else genesis,
            "gettxout": {"confirmations": 1} if outpoint is ... else outpoint,
            "getrawtransaction": {"txid": TXID, "confirmations": 2},
            "testmempoolaccept": [{"allowed": True, "txid": TXID}],
            "sendrawtransaction": TXID,
        }[method]
        return httpx.Response(
            200,
            stream=httpx.ByteStream(
                json.dumps({"jsonrpc": "2.0", "id": identifier, "result": result}).encode()
            ),
        )

    transport = httpx.MockTransport(handle)
    real_client = httpx.Client

    def client(**kwargs: object) -> httpx.Client:
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(observation.httpx, "Client", client)
    cookie = tmp_path / "core.cookie"
    cookie.write_text("__cookie__:secret")
    cookie.chmod(0o600)
    reader = observation.RecoveryCoreReader(port=18443, cookie_path=cookie, network=network)
    return core_collaborators(reader, funding_txid=FUNDING, contract_vout=0), methods


@pytest.mark.parametrize(
    ("challenge", "chain", "genesis", "last_method"),
    [
        (..., "signet", None, "getblockchaininfo"),
        (None, "signet", None, "getblockchaininfo"),
        (False, "signet", None, "getblockchaininfo"),
        ("00", "signet", None, "getblockchaininfo"),
        ("SIGNET", "signet", None, "getblockchaininfo"),
        ("00", "main", None, "getblockchaininfo"),
        ("matching", "signet", "00" * 32, "getblockhash"),
    ],
)
def test_wrong_signet_node_never_reads_or_receives_spend_bytes(  # noqa: PLR0913, PLR0917 - fault matrix
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    challenge: object,
    chain: str,
    genesis: str | None,
    last_method: str,
) -> None:
    network = NetworkIdentity.model_validate_json((NETWORKS / "signet.json").read_bytes())
    (view, confirmations, submit), methods = _callbacks(
        tmp_path,
        monkeypatch,
        network,
        challenge=network.signet_challenge if challenge == "matching" else challenge,
        chain=chain,
        genesis=genesis,
    )
    assert view() is None
    assert confirmations(TXID) is None
    assert not submit(b"sensitive-tx-bytes", TXID)
    expected = ["getblockchaininfo"]
    if last_method == "getblockhash":
        expected.append("getblockhash")
    assert methods == expected * 3


@pytest.mark.parametrize(
    ("name", "chain"), [("signet", "signet"), ("regtest-rillswap-e2e-v1", "regtest")]
)
def test_watcher_attests_each_session_then_allows_expected_rpcs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, chain: str
) -> None:
    network = NetworkIdentity.model_validate_json((NETWORKS / f"{name}.json").read_bytes())
    challenge = network.signet_challenge if name == "signet" else ...
    (view, confirmations, submit), methods = _callbacks(
        tmp_path, monkeypatch, network, challenge=challenge, chain=chain
    )
    assert view() == ChainView(120, unspent_on_chain=True)
    assert confirmations(TXID) == 2
    assert submit(b"signed-tx", TXID)
    assert methods == [
        "getblockchaininfo",
        "getblockhash",
        "gettxout",
        "getblockchaininfo",
        "getblockhash",
        "getrawtransaction",
        "getblockchaininfo",
        "getblockhash",
        "testmempoolaccept",
        "sendrawtransaction",
    ]


@pytest.mark.parametrize("outpoint", [False, 0, "spent", [], ["unspent"]])
def test_malformed_utxo_response_is_not_evidence_of_a_foreign_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outpoint: object
) -> None:
    network = NetworkIdentity.model_validate_json(
        (NETWORKS / "regtest-rillswap-e2e-v1.json").read_bytes()
    )
    (view, _, _), methods = _callbacks(
        tmp_path, monkeypatch, network, challenge=..., chain="regtest", outpoint=outpoint
    )
    assert view() is None
    assert methods == ["getblockchaininfo", "getblockhash", "gettxout"]
