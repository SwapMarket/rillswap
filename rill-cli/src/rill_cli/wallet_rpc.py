"""Loopback regtest Bitcoin Core wallet calls used by the live swap client.

The wallet funds and signs; the caller authorizes the exact result against
the signed terms (``authorize_funding_transaction``) before binding or
broadcasting it. Only the fixed methods below are callable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import httpx
from rill_core.settlement import FundingPrevout, PlannedFundingOutput
from rill_core.wire.types import NetworkIdentity

from rill_cli.recovery_core_observation import _cookie

SATS_PER_BTC = Decimal(100_000_000)
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_PORT = 65535
HTTP_OK = 200
METHODS = frozenset(
    {
        "decodepsbt",
        "decodescript",
        "finalizepsbt",
        "getaddressinfo",
        "getblockcount",
        "getblockchaininfo",
        "getblockhash",
        "getnewaddress",
        "sendrawtransaction",
        "walletcreatefundedpsbt",
        "walletprocesspsbt",
    }
)
WALLET_EFFECTS = frozenset(
    {
        "getnewaddress",
        "walletcreatefundedpsbt",
        "walletprocesspsbt",
        "finalizepsbt",
        "sendrawtransaction",
    }
)


class WalletRpcError(RuntimeError):
    """Core refused or returned something unusable; no detail is echoed."""


@dataclass(frozen=True, slots=True)
class WalletFunding:
    """A wallet-signed funding transaction and the exact parts it declared."""

    raw_transaction: bytes
    inputs: tuple[FundingPrevout, ...]
    other_outputs: tuple[PlannedFundingOutput, ...]
    fee_sat: int


def _sats(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise WalletRpcError("Core amount is not a number")
    sats = Decimal(value) * SATS_PER_BTC
    if sats != sats.to_integral_value() or sats < 0:
        raise WalletRpcError("Core amount is not whole satoshis")
    return int(sats)


class RegtestWalletRpc:
    """One named Core wallet on a loopback regtest node (cookie auth)."""

    def __init__(
        self, *, port: int, cookie_path: str | Path, wallet: str, network: NetworkIdentity
    ) -> None:
        """Configure only; no network or file access."""
        if type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("Core RPC port unsupported")
        if not wallet or "/" in wallet:
            raise ValueError("Core wallet name unsupported")
        if not isinstance(network, NetworkIdentity) or network.name != "regtest":
            raise ValueError("live wallet funding currently requires explicit regtest identity")
        self._url = f"http://127.0.0.1:{port}"
        self._cookie_path = Path(cookie_path)
        self._wallet = wallet
        self._network = network

    def _call(self, method: str, *params: object, wallet: bool = True) -> Any:  # noqa: ANN401
        if method not in METHODS:
            raise WalletRpcError("unsupported Core wallet method")
        if method in WALLET_EFFECTS:
            self._verify_network()
        username, password = _cookie(self._cookie_path)
        path = f"/wallet/{self._wallet}" if wallet else "/"
        try:
            response = httpx.post(
                self._url + path,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)},
                auth=(username, password),
                timeout=httpx.Timeout(30.0, connect=2.0),
                follow_redirects=False,
                trust_env=False,
            )
        except httpx.HTTPError:
            raise WalletRpcError("Core RPC unavailable") from None
        if response.status_code != HTTP_OK or len(response.content) > MAX_RESPONSE_BYTES:
            raise WalletRpcError(f"Core {method} failed")
        try:
            body = json.loads(response.content, parse_float=Decimal)
        except (ValueError, InvalidOperation):
            raise WalletRpcError("Core RPC response is not JSON") from None
        if not isinstance(body, dict) or body.get("error") is not None:
            raise WalletRpcError(f"Core {method} failed")
        return body.get("result")

    def tip_height(self) -> int:
        """Return the best height only after checking the actual wallet backend."""
        return self._verify_network()

    def _verify_network(self) -> int:
        info = self._call("getblockchaininfo", wallet=False)
        if (
            not isinstance(info, dict)
            or info.get("chain") != self._network.name
            or info.get("initialblockdownload") is not False
            or type(info.get("blocks")) is not int
            or info["blocks"] < 0
        ):
            raise WalletRpcError("Core wallet chain is unavailable or differs from configuration")
        if self._call("getblockhash", 0, wallet=False) != self._network.genesis_hash:
            raise WalletRpcError("Core wallet genesis differs from configuration")
        return int(info["blocks"])

    def new_destination_script(self) -> bytes:
        """Return a fresh wallet P2TR scriptPubKey (the refund destination)."""
        address = self._call("getnewaddress", "", "bech32m")
        info = self._call("getaddressinfo", address)
        if not isinstance(info, dict) or not isinstance(info.get("scriptPubKey"), str):
            raise WalletRpcError("Core address info unusable")
        return bytes.fromhex(info["scriptPubKey"])

    def fund(self, script_pubkey: bytes, amount_sat: int, *, fee_rate_sat_vb: int) -> WalletFunding:
        """Create, fund, and sign (not broadcast) a v2 transaction paying the script."""
        decoded = self._call("decodescript", script_pubkey.hex(), wallet=False)
        address = decoded.get("address") if isinstance(decoded, dict) else None
        if not isinstance(address, str):
            raise WalletRpcError("contract script has no address")
        amount = format(Decimal(amount_sat) / SATS_PER_BTC, ".8f")
        created = self._call(
            "walletcreatefundedpsbt",
            [],
            [{address: amount}],
            0,
            {"change_type": "bech32m", "fee_rate": fee_rate_sat_vb, "replaceable": False},
        )
        processed = self._call(
            "walletprocesspsbt",
            created["psbt"],
            True,  # noqa: FBT003 - Core sign flag
        )
        final = self._call(
            "finalizepsbt",
            processed["psbt"],
            True,  # noqa: FBT003 - Core extract flag
        )
        if not isinstance(final, dict) or final.get("complete") is not True:
            raise WalletRpcError("wallet could not sign every funding input")
        described = self._call("decodepsbt", processed["psbt"], wallet=False)
        try:
            inputs = tuple(
                FundingPrevout(
                    txid=bytes.fromhex(vin["txid"]),
                    output_index=vin["vout"],
                    value_sat=_sats(detail["witness_utxo"]["amount"]),
                    script_pubkey=bytes.fromhex(detail["witness_utxo"]["scriptPubKey"]["hex"]),
                )
                for vin, detail in zip(described["tx"]["vin"], described["inputs"], strict=True)
            )
            others = tuple(
                PlannedFundingOutput(_sats(out["value"]), bytes.fromhex(out["scriptPubKey"]["hex"]))
                for out in described["tx"]["vout"]
                if bytes.fromhex(out["scriptPubKey"]["hex"]) != script_pubkey
            )
            fee = _sats(described["fee"])
        except (KeyError, TypeError, ValueError):
            raise WalletRpcError("wallet funding description unusable") from None
        return WalletFunding(bytes.fromhex(final["hex"]), inputs, others, fee)

    def broadcast(self, raw: bytes) -> str:
        """Submit exact bytes; return Core's txid."""
        txid = self._call("sendrawtransaction", raw.hex(), wallet=False)
        if not isinstance(txid, str):
            raise WalletRpcError("Core broadcast result unusable")
        return txid
