"""Core wallet funding calls: fixed methods, exact satoshi parsing."""

from __future__ import annotations

import json
import threading
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.wire.types import NetworkIdentity

from rill_cli.wallet_rpc import WALLET_EFFECTS, RegtestWalletRpc, WalletRpcError, _sats

if TYPE_CHECKING:
    from collections.abc import Iterator

CONTRACT = "5120" + "77" * 32
CHANGE = "5120" + "55" * 32
COIN = "0014" + "44" * 20
NETWORK = NetworkIdentity.model_validate(
    json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())[
        "network_identity"
    ]
)


def _answers() -> dict[str, Any]:
    return {
        "getblockchaininfo": {"chain": "regtest", "initialblockdownload": False, "blocks": 850},
        "getblockhash": NETWORK.genesis_hash,
        "decodescript": {"address": "bcrt1pcontract"},
        "walletcreatefundedpsbt": {"psbt": "P0"},
        "walletprocesspsbt": {"psbt": "P1"},
        "finalizepsbt": {"complete": True, "hex": "0200"},
        "decodepsbt": {
            "tx": {
                "vin": [{"txid": "41" * 32, "vout": 1}],
                "vout": [
                    {"value": "#0.00050000#", "scriptPubKey": {"hex": CONTRACT}},
                    {"value": "#0.00020000#", "scriptPubKey": {"hex": CHANGE}},
                ],
            },
            "inputs": [{"witness_utxo": {"amount": "#0.00070300#", "scriptPubKey": {"hex": COIN}}}],
            "fee": "#0.00000300#",
        },
    }


@pytest.fixture
def answers() -> dict[str, Any]:
    return _answers()


@pytest.fixture
def core(
    tmp_path: Path, answers: dict[str, Any]
) -> Iterator[tuple[RegtestWalletRpc, list[dict[str, Any]]]]:
    calls: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append({"path": self.path, **request})
            result = answers[request["method"]]
            # Core answers amounts as JSON numbers.
            body = json.dumps({"result": result, "error": None, "id": 1})
            body = body.replace('"#', "").replace('#"', "")
            payload = body.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cookie = tmp_path / ".cookie"
    cookie.write_text("__cookie__:secret")
    cookie.chmod(0o600)
    try:
        yield (
            RegtestWalletRpc(
                port=server.server_port, cookie_path=cookie, wallet="w", network=NETWORK
            ),
            calls,
        )
    finally:
        server.shutdown()


def test_fund_returns_exact_declared_parts(
    core: tuple[RegtestWalletRpc, list[dict[str, Any]]],
) -> None:
    wallet, calls = core
    funded = wallet.fund(bytes.fromhex(CONTRACT), 50_000, fee_rate_sat_vb=2)
    assert funded.raw_transaction == b"\x02\x00"
    ((coin),) = funded.inputs
    assert (coin.txid, coin.output_index, coin.value_sat) == (b"\x41" * 32, 1, 70_300)
    assert [(o.value_sat, o.script_pubkey.hex()) for o in funded.other_outputs] == [
        (20_000, CHANGE)
    ]
    assert funded.fee_sat == 300
    create = next(call for call in calls if call["method"] == "walletcreatefundedpsbt")
    assert create["path"] == "/wallet/w"
    assert create["params"][1] == [{"bcrt1pcontract": "0.00050000"}]
    assert create["params"][3]["change_type"] == "bech32m"


def test_amounts_must_be_whole_satoshis() -> None:
    assert _sats(Decimal("0.00000001")) == 1
    for bad in (Decimal("0.000000001"), 1.5, True, "1", Decimal(-1)):
        with pytest.raises(WalletRpcError):
            _sats(bad)


def test_only_fixed_methods_and_loopback_configuration(tmp_path: Path) -> None:
    wallet = RegtestWalletRpc(port=1, cookie_path=tmp_path / "c", wallet="w", network=NETWORK)
    with pytest.raises(WalletRpcError):
        wallet._call("dumpprivkey")  # noqa: SLF001 - the allowlist itself
    for port, name in ((0, "w"), (1, ""), (1, "a/b")):
        with pytest.raises(ValueError, match="unsupported"):
            RegtestWalletRpc(port=port, cookie_path=tmp_path / "c", wallet=name, network=NETWORK)


@pytest.mark.parametrize("method", sorted(WALLET_EFFECTS))
@pytest.mark.parametrize("chain", ["main", "signet", "test", "testnet4", None])
def test_wrong_chain_never_reaches_any_wallet_effect(
    core: tuple[RegtestWalletRpc, list[dict[str, Any]]],
    answers: dict[str, Any],
    method: str,
    chain: str | None,
) -> None:
    wallet, calls = core
    answers["getblockchaininfo"]["chain"] = chain
    with pytest.raises(WalletRpcError, match="wallet chain"):
        wallet._call(method)  # noqa: SLF001 - all mutation dispatch paths must enforce this guard
    assert [call["method"] for call in calls] == ["getblockchaininfo"]


def test_wrong_genesis_never_reaches_funding(
    core: tuple[RegtestWalletRpc, list[dict[str, Any]]], answers: dict[str, Any]
) -> None:
    wallet, calls = core
    answers["getblockhash"] = "00" * 32
    with pytest.raises(WalletRpcError, match="genesis"):
        wallet.fund(bytes.fromhex(CONTRACT), 50_000, fee_rate_sat_vb=2)
    assert not {call["method"] for call in calls} & WALLET_EFFECTS


@pytest.mark.parametrize("info", [{}, None, {"chain": "regtest", "blocks": True}])
def test_missing_or_partial_attestation_never_authorizes_broadcast(
    core: tuple[RegtestWalletRpc, list[dict[str, Any]]],
    answers: dict[str, Any],
    info: object,
) -> None:
    wallet, calls = core
    answers["getblockchaininfo"] = info
    with pytest.raises(WalletRpcError, match="wallet chain"):
        wallet.broadcast(b"\x02\x00")
    assert not {call["method"] for call in calls} & WALLET_EFFECTS


def test_network_attestation_is_not_cached_across_calls(
    core: tuple[RegtestWalletRpc, list[dict[str, Any]]], answers: dict[str, Any]
) -> None:
    wallet, calls = core
    assert wallet.tip_height() == 850
    answers["getblockchaininfo"]["chain"] = "main"
    with pytest.raises(WalletRpcError, match="wallet chain"):
        wallet.broadcast(b"\x02\x00")
    assert not {call["method"] for call in calls} & WALLET_EFFECTS
