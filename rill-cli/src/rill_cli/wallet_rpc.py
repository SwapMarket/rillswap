"""Loopback Bitcoin Core wallet calls used by the live swap client.

The wallet funds and signs; the caller authorizes the exact result against
the signed terms (``authorize_funding_transaction``) before binding or
broadcasting it. Only the fixed methods below are callable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from rill_core.errors import ValidationError
from rill_core.networks import backend_names, require_funding_release
from rill_core.settlement import FundingPrevout, PlannedFundingOutput
from rill_provider.core_tx_bytes import (
    CooperativeClaimOutpoint,
    CooperativeFeePolicy,
    CoreTransactionReader,
)

from rill_cli.recovery_core_observation import _cookie, _matches_signet_challenge

if TYPE_CHECKING:
    from rill_core.settlement import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms, FundingBinding
    from rill_core.wire.types import NetworkIdentity

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
        "gettransaction",
        "gettxout",
        "listunspent",
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


@dataclass(frozen=True, slots=True)
class ConfirmedOutput:
    """One outpoint's value, script, and depth (0 in the mempool) per Core."""

    value_sat: int
    script_pubkey: bytes
    confirmations: int


@dataclass(frozen=True, slots=True)
class CooperativeClaimEvidence:
    """Matching named-tip own-node observations, not nonce or signing authority."""

    outpoint: CooperativeClaimOutpoint
    fee_policy: CooperativeFeePolicy


def _sats(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise WalletRpcError("Core amount is not a number")
    sats = Decimal(value) * SATS_PER_BTC
    if sats != sats.to_integral_value() or sats < 0:
        raise WalletRpcError("Core amount is not whole satoshis")
    return int(sats)


class WalletRpc:
    """One named Core wallet on a loopback node of the configured network (cookie auth)."""

    def __init__(
        self, *, port: int, cookie_path: str | Path, wallet: str, network: NetworkIdentity
    ) -> None:
        """Configure only; no network or file access."""
        if type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("Core RPC port unsupported")
        if not wallet or "/" in wallet:
            raise ValueError("Core wallet name unsupported")
        try:
            # Funding moves money: mainnet needs release acceptance in code.
            require_funding_release(network)
            self._chain = backend_names(network).core_chain
        except ValidationError:
            raise ValueError("live wallet funding requires a release-accepted network") from None
        self._url = f"http://127.0.0.1:{port}"
        self._cookie_path = Path(cookie_path)
        self._wallet = wallet
        self._network = network
        self._transactions = CoreTransactionReader(
            port=port, cookie_path=cookie_path, network=network
        )

    def observe_cooperative_claim_evidence(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
        allow_regtest_fixed_fee: bool = False,
    ) -> CooperativeClaimEvidence:
        """Join strict outpoint and fee samples, with no wallet RPC or effects.

        The original-session handler must bound the entire acquisition and
        native-effect age, check confirmations/deadlines and the exact plan's
        fee, and recheck after durable reservation publication. The two reads
        are non-atomic; a matching tip does not freeze mempool or chain policy.
        """
        try:
            outpoint = self._transactions.observe_cooperative_claim_outpoint(
                binding, terms, keys=keys
            )
            policy = self._transactions.observe_cooperative_fee_policy(
                terms.timing_policy.claim_confirmation_blocks,
                allow_regtest_fixed_fee=allow_regtest_fixed_fee,
            )
            if (
                type(outpoint) is not CooperativeClaimOutpoint
                or type(policy) is not CooperativeFeePolicy
                or outpoint.network_identity != self._network
                or policy.network_identity != self._network
                or policy.confirmation_blocks != terms.timing_policy.claim_confirmation_blocks
                or (outpoint.tip_hash, outpoint.tip_height) != (policy.tip_hash, policy.tip_height)
            ):
                raise WalletRpcError("cooperative Core view changed")  # noqa: TRY301
        except Exception:  # noqa: BLE001 - failed acquisition grants no signing evidence
            raise WalletRpcError("cooperative Core evidence unavailable") from None
        return CooperativeClaimEvidence(outpoint, policy)

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
            or info.get("chain") != self._chain
            or info.get("initialblockdownload") is not False
            or type(info.get("blocks")) is not int
            or info["blocks"] < 0
            or not _matches_signet_challenge(info, self._network)
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
        """Fund from one confirmed witness coin, never silently combine origins.

        One P2WPKH input and two P2TR outputs fit within 165 virtual bytes;
        reserve that conservative fee amount before asking Core to fund.
        The caller still enforces the signed absolute funding-fee cap.
        """
        if type(fee_rate_sat_vb) is not int or fee_rate_sat_vb <= 0:
            raise WalletRpcError("funding fee rate must be a positive integer")
        coin = self._select_coin(amount_sat + 165 * fee_rate_sat_vb)
        decoded = self._call("decodescript", script_pubkey.hex(), wallet=False)
        address = decoded.get("address") if isinstance(decoded, dict) else None
        if not isinstance(address, str):
            raise WalletRpcError("contract script has no address")
        amount = format(Decimal(amount_sat) / SATS_PER_BTC, ".8f")
        created = self._call(
            "walletcreatefundedpsbt",
            [{"txid": coin.txid.hex(), "vout": coin.output_index}],
            [{address: amount}],
            0,
            {
                "change_type": "bech32m",
                "fee_rate": fee_rate_sat_vb,
                "replaceable": False,
                "add_inputs": False,
            },
        )
        if not isinstance(created, dict) or not isinstance(created.get("psbt"), str):
            raise WalletRpcError("Core funding PSBT unusable")
        before_signing = self._call("decodepsbt", created["psbt"], wallet=False)
        try:
            actual = tuple((vin["txid"], vin["vout"]) for vin in before_signing["tx"]["vin"])
        except (KeyError, TypeError):
            raise WalletRpcError("wallet funding input description unusable") from None
        if actual != ((coin.txid.hex(), coin.output_index),):
            raise WalletRpcError("Core changed the approved funding input")
        processed = self._call(
            "walletprocesspsbt",
            created["psbt"],
            True,  # noqa: FBT003 - Core sign flag
        )
        if not isinstance(processed, dict) or not isinstance(processed.get("psbt"), str):
            raise WalletRpcError("Core signed PSBT unusable")
        final = self._call(
            "finalizepsbt",
            processed["psbt"],
            True,  # noqa: FBT003 - Core extract flag
        )
        if not isinstance(final, dict) or final.get("complete") is not True:
            raise WalletRpcError("wallet could not sign every funding input")
        described = self._call("decodepsbt", processed["psbt"], wallet=False)
        try:
            raw = bytes.fromhex(final["hex"])
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
        if inputs != (coin,):
            raise WalletRpcError("Core changed the approved funding input details")
        return WalletFunding(raw, inputs, others, fee)

    def _select_coin(self, required_sat: int) -> FundingPrevout:
        available = self._call("listunspent", 1)
        if not isinstance(available, list):
            raise WalletRpcError("Core coin list unusable")
        candidates: list[FundingPrevout] = []
        for item in available:
            if not isinstance(item, dict) or not all(
                item.get(field) is True for field in ("safe", "spendable", "solvable")
            ):
                continue
            if type(item.get("confirmations")) is not int or item["confirmations"] < 1:
                continue
            try:
                script = bytes.fromhex(item["scriptPubKey"])
                witness_coin = (
                    script[:2] in (b"\x00\x14", b"\x51\x20") and len(script) == script[1] + 2
                )
                value = _sats(item["amount"])
                if witness_coin and value >= required_sat:
                    candidates.append(
                        FundingPrevout(bytes.fromhex(item["txid"]), item["vout"], value, script)
                    )
            except (KeyError, TypeError, ValueError):
                raise WalletRpcError("Core coin description unusable") from None
        if not candidates:
            raise WalletRpcError("no single confirmed coin covers funding and its fee reserve")
        return min(candidates, key=lambda coin: (coin.value_sat, coin.txid, coin.output_index))

    def confirmed_output(self, txid: str, vout: int) -> ConfirmedOutput | None:
        """Return the unspent output as Core sees it (mempool included), or None.

        ``None`` means unknown or spent; it is never evidence about which.
        """
        result = self._call("gettxout", txid, vout, True, wallet=False)  # noqa: FBT003 - include_mempool
        if result is None:
            return None
        script = result.get("scriptPubKey", {}).get("hex") if isinstance(result, dict) else None
        depth = result.get("confirmations") if isinstance(result, dict) else None
        if not isinstance(script, str) or type(depth) is not int or depth < 0:
            raise WalletRpcError("Core gettxout result unusable")
        return ConfirmedOutput(_sats(result.get("value")), bytes.fromhex(script), depth)

    def unspent_on_chain(self, txid: str, vout: int) -> bool:
        """Whether the output is unspent in the active chain, ignoring the mempool.

        Our own unconfirmed spend must not look like a spend.
        """
        return self._call("gettxout", txid, vout, False, wallet=False) is not None  # noqa: FBT003

    def wallet_confirmations(self, txid: str) -> int | None:
        """Depth of a wallet transaction; ``None`` when unknown to the wallet."""
        try:
            result = self._call("gettransaction", txid)
        except WalletRpcError:
            return None
        depth = result.get("confirmations") if isinstance(result, dict) else None
        return depth if type(depth) is int and result.get("txid") == txid else None

    def broadcast(self, raw: bytes) -> str:
        """Submit exact bytes; return Core's txid."""
        txid = self._call("sendrawtransaction", raw.hex(), wallet=False)
        if not isinstance(txid, str):
            raise WalletRpcError("Core broadcast result unusable")
        return txid
