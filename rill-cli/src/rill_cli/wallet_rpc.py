"""Loopback Bitcoin Core wallet calls used by the live swap client.

The wallet funds and signs; the caller authorizes the exact result against
the signed terms (``authorize_funding_transaction``) before binding or
broadcasting it. Only the fixed methods below are callable.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from rill_core.errors import ValidationError
from rill_core.networks import backend_names, require_supported_network
from rill_core.settlement import FundingPrevout, PlannedFundingOutput, inspect_transaction_outputs
from rill_provider.core_tx_bytes import (
    CooperativeClaimOutpoint,
    CooperativeFeePolicy,
    CoreReadError,
    CoreTransactionReader,
    CoreUnavailableError,
    NextBlockFee,
)

from rill_cli.recovery_core_observation import _cookie, _matches_signet_challenge

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.settlement import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms, FundingBinding
    from rill_core.wire.types import NetworkIdentity

SATS_PER_BTC = Decimal(100_000_000)
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_PORT = 65535
MAX_HISTORICAL_DEADLINE_SECONDS = 30
MAX_HISTORICAL_HEX_BYTES = 200_000
MAX_BLOCK_HEIGHT = 499_999_999
TAPROOT_SCRIPT_BYTES = 34
MAX_ADDRESS_BYTES = 128
HTTP_OK = 200
COOPERATIVE_SAMPLE_ATTEMPTS = 3  # a block may arrive during one; each retake is as strict
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
        "gettxspendingprevout",
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
class HistoricalWalletOutput:
    """Confirmed historical script recognition, NEVER spending-key custody.

    ismine in Core v30 is script-map membership, even for public-only imports.
    Spent historical outputs establish receipt, not current inventory. The
    configured profile/namespace and trusted Core host are operator premises;
    sampled chain consistency is not an atomic snapshot or finality guarantee.
    """

    network: NetworkIdentity
    txid: str
    vout: int
    value_sat: int
    script_pubkey: bytes
    confirmations: int
    block_height: int
    block_hash: str
    started_at: float
    completed_at: float


def _strict_rpc_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Core response field")
        result[key] = value
    return result


def _reject_rpc_constant(_value: str) -> object:
    raise ValueError("Core response must contain JSON values")


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
        self,
        *,
        port: int,
        cookie_path: str | Path,
        wallet: str,
        network: NetworkIdentity,
        max_fee_estimate_sat_vb: int | None = None,
    ) -> None:
        """Configure only; no network or file access.

        ``max_fee_estimate_sat_vb`` caps only Core's estimate, in cooperative
        fee evidence and the LN to BTC claim reserve, for chains with a skewed
        estimator; ``None`` keeps it.
        """
        if type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("Core RPC port unsupported")
        if not wallet or "/" in wallet:
            raise ValueError("Core wallet name unsupported")
        try:
            require_supported_network(network)
            self._chain = backend_names(network).core_chain
        except ValidationError:
            raise ValueError("live wallet funding requires a supported network") from None
        self._url = f"http://127.0.0.1:{port}"
        self._cookie_path = Path(cookie_path)
        self._wallet = wallet
        self._network = network
        if max_fee_estimate_sat_vb is None:
            self._transactions = CoreTransactionReader(
                port=port, cookie_path=cookie_path, network=network
            )
        else:
            self._transactions = CoreTransactionReader(
                port=port,
                cookie_path=cookie_path,
                network=network,
                max_fee_estimate_sat_vb=max_fee_estimate_sat_vb,
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

        A block arriving during or between the reads only makes one sample
        inconsistent, so up to ``COOPERATIVE_SAMPLE_ATTEMPTS`` samples are
        taken, each as strict as the first, before reporting evidence
        unavailable; any other refusal stops at once. The caller's elapsed
        time bound covers every attempt.
        """
        for _attempt in range(COOPERATIVE_SAMPLE_ATTEMPTS):
            try:
                outpoint = self._transactions.observe_cooperative_claim_outpoint(
                    binding, terms, keys=keys
                )
                policy = self._transactions.observe_cooperative_fee_policy(
                    terms.timing_policy.claim_confirmation_blocks,
                    allow_regtest_fixed_fee=allow_regtest_fixed_fee,
                )
            except CoreUnavailableError:
                continue  # transient, such as the tip moving within one read
            except Exception:  # noqa: BLE001 - failed acquisition grants no signing evidence
                raise WalletRpcError("cooperative Core evidence unavailable") from None
            if (
                type(outpoint) is not CooperativeClaimOutpoint
                or type(policy) is not CooperativeFeePolicy
                or outpoint.network_identity != self._network
                or policy.network_identity != self._network
                or policy.confirmation_blocks != terms.timing_policy.claim_confirmation_blocks
            ):
                raise WalletRpcError("cooperative Core evidence unavailable")
            if (outpoint.tip_hash, outpoint.tip_height) == (policy.tip_hash, policy.tip_height):
                return CooperativeClaimEvidence(outpoint, policy)
            # The tip moved between the two reads: take both again.
        raise WalletRpcError("cooperative Core evidence unavailable")

    def _call(  # noqa: PLR0912 - opt-in strict observation preserves legacy RPC responses
        self,
        method: str,
        *params: object,
        wallet: bool = True,
        deadline: float | None = None,
        effect_allowed: Callable[[], bool] | None = None,
        strict_response: bool = False,
    ) -> Any:  # noqa: ANN401 - exact Core JSON response
        if method not in METHODS:
            raise WalletRpcError("unsupported Core wallet method")
        guarded = deadline is not None or effect_allowed is not None
        if guarded:
            _request_budget(deadline, effect_allowed)
        if method in WALLET_EFFECTS:
            if guarded:
                self._verify_network(deadline=deadline, effect_allowed=effect_allowed)
            else:
                self._verify_network()
        username, password = _cookie(self._cookie_path)
        path = f"/wallet/{self._wallet}" if wallet else "/"
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}
        try:
            if guarded:

                def authorize(request: httpx.Request) -> None:
                    # Auth and request construction precede this hook. Handoff
                    # is potentially irreversible, not a socket-write cutoff.
                    remaining = _request_budget(deadline, effect_allowed)
                    request.extensions["timeout"] = httpx.Timeout(
                        remaining,
                        connect=min(2.0, remaining),
                    ).as_dict()

                remaining = _request_budget(deadline, effect_allowed)
                with httpx.Client(
                    auth=(username, password),
                    timeout=httpx.Timeout(remaining, connect=min(2.0, remaining)),
                    follow_redirects=False,
                    trust_env=False,
                    event_hooks={"request": [authorize]},
                ) as client:
                    response = client.post(self._url + path, json=body)
            else:
                response = httpx.post(
                    self._url + path,
                    json=body,
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
            if strict_response:
                body = json.loads(
                    response.content,
                    parse_float=Decimal,
                    object_pairs_hook=_strict_rpc_object,
                    parse_constant=_reject_rpc_constant,
                )
            else:
                body = json.loads(response.content, parse_float=Decimal)
        except (ValueError, InvalidOperation):
            raise WalletRpcError("Core RPC response is not JSON") from None
        if not isinstance(body, dict) or body.get("error") is not None:
            raise WalletRpcError(f"Core {method} failed")
        if strict_response and (
            body.get("jsonrpc") != "2.0"
            or type(body.get("id")) is not int
            or body["id"] != 1
            or "result" not in body
        ):
            raise WalletRpcError("Core response envelope differs")
        return body.get("result")

    def tip_height(self) -> int:
        """Return the best height only after checking the actual wallet backend."""
        return self._verify_network()

    def next_block_fee(self) -> NextBlockFee:
        """Core's economical two-block advice with this node's relay and mempool floors.

        Capped by ``max_fee_estimate_sat_vb``. Public networks refuse without
        an estimate (the cap is never a fallback); regtest uses the floors.
        """
        try:
            fee = self._transactions.next_block_fee()
        except CoreReadError:
            raise WalletRpcError("Core next-block fee estimate unavailable") from None
        if type(fee) is not NextBlockFee:
            raise WalletRpcError("Core next-block fee estimate unavailable")
        return fee

    def _verify_network(
        self,
        *,
        deadline: float | None = None,
        effect_allowed: Callable[[], bool] | None = None,
    ) -> int:
        info = self._call(
            "getblockchaininfo", wallet=False, deadline=deadline, effect_allowed=effect_allowed
        )
        if (
            not isinstance(info, dict)
            or info.get("chain") != self._chain
            or info.get("initialblockdownload") is not False
            or type(info.get("blocks")) is not int
            or info["blocks"] < 0
            or not _matches_signet_challenge(info, self._network)
        ):
            raise WalletRpcError("Core wallet chain is unavailable or differs from configuration")
        if (
            self._call(
                "getblockhash", 0, wallet=False, deadline=deadline, effect_allowed=effect_allowed
            )
            != self._network.genesis_hash
        ):
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

    def mempool_spender(self, txid: str, vout: int) -> str | None:
        """Return the txid of a mempool transaction spending ``txid:vout``, or None.

        Needs Core 24 or later; a failed call raises rather than claiming absence.
        """
        result = self._call("gettxspendingprevout", [{"txid": txid, "vout": vout}], wallet=False)
        entry = result[0] if isinstance(result, list) and len(result) == 1 else None
        if not isinstance(entry, dict) or entry.get("txid") != txid or entry.get("vout") != vout:
            raise WalletRpcError("Core gettxspendingprevout result unusable")
        spender = entry.get("spendingtxid")
        if spender is None:
            return None
        if type(spender) is not str or len(spender) != 64:  # noqa: PLR2004 - txid hex
            raise WalletRpcError("Core gettxspendingprevout result unusable")
        return spender

    def wallet_confirmations(self, txid: str) -> int | None:
        """Depth of a wallet transaction; ``None`` when unknown to the wallet."""
        try:
            result = self._call("gettransaction", txid)
        except WalletRpcError:
            return None
        depth = result.get("confirmations") if isinstance(result, dict) else None
        return depth if type(depth) is int and result.get("txid") == txid else None

    def observe_historical_wallet_output(
        self,
        txid: str,
        treasury_script: bytes,
        *,
        deadline_seconds: float = 10,
    ) -> HistoricalWalletOutput:
        """Read one uniquely matching confirmed historical Taproot wallet output.

        Strict response envelopes, network and active-block correspondence
        bracket two identical historical transaction byte records. Depth is the
        minimum sampled wallet/chain depth. Core ismine proves recognition only.
        Unknown/spent-record loss never grants permission to repeat a swap.
        Acceptance includes client cleanup, not a hard execution bound or
        protection against later reorgs. No custody or completion is authorized.
        Existing unspent/depth methods and their behavior are unchanged.
        """
        result = None
        try:  # noqa: SIM105 - explicit private-error detachment boundary
            result = self._historical_wallet_output(txid, treasury_script, deadline_seconds)
        except Exception:  # noqa: BLE001, S110 - detach private cookie/RPC/transaction diagnostics
            pass
        if result is None:
            raise WalletRpcError("historical Core wallet output unavailable")
        return result

    def _historical_wallet_output(
        self,
        txid: str,
        script: bytes,
        deadline_seconds: float,
    ) -> HistoricalWalletOutput:
        if (
            type(txid) is not str
            or re.fullmatch(r"[0-9a-f]{64}", txid) is None
            or type(script) is not bytes
            or len(script) != TAPROOT_SCRIPT_BYTES
            or script[:2] != b"\x51\x20"
            or type(deadline_seconds) not in (int, float)
            or not math.isfinite(deadline_seconds)
            or not 0 < deadline_seconds <= MAX_HISTORICAL_DEADLINE_SECONDS
        ):
            raise WalletRpcError("historical output observation configuration differs")
        started_at = time.time()
        if not math.isfinite(started_at):
            raise WalletRpcError("historical output acquisition time unavailable")
        deadline = time.monotonic() + deadline_seconds

        def read(method: str, *params: object, wallet: bool = True) -> Any:  # noqa: ANN401 - strict result narrowed below
            return self._call(
                method, *params, wallet=wallet, deadline=deadline, strict_response=True
            )

        def snapshot() -> tuple[int, str]:
            info = read("getblockchaininfo", wallet=False)
            if (
                not isinstance(info, dict)
                or info.get("chain") != self._chain
                or info.get("initialblockdownload") is not False
                or not _matches_signet_challenge(info, self._network)
                or type(info.get("blocks")) is not int
                or not 0 < info["blocks"] <= MAX_BLOCK_HEIGHT
                or not isinstance(info.get("bestblockhash"), str)
                or re.fullmatch(r"[0-9a-f]{64}", info["bestblockhash"]) is None
                or read("getblockhash", 0, wallet=False) != self._network.genesis_hash
                or read("getblockhash", info["blocks"], wallet=False) != info["bestblockhash"]
            ):
                raise WalletRpcError("historical output Core chain unavailable")
            return info["blocks"], info["bestblockhash"]

        def record() -> tuple[bytes, int, str, int]:
            value = read("gettransaction", txid)
            if (
                not isinstance(value, dict)
                or value.get("txid") != txid
                or type(value.get("confirmations")) is not int
                or not 0 < value["confirmations"] <= MAX_BLOCK_HEIGHT
                or type(value.get("blockheight")) is not int
                or not 0 < value["blockheight"] <= MAX_BLOCK_HEIGHT
                or not isinstance(value.get("blockhash"), str)
                or re.fullmatch(r"[0-9a-f]{64}", value["blockhash"]) is None
                or not isinstance(value.get("hex"), str)
                or len(value["hex"]) > MAX_HISTORICAL_HEX_BYTES
                or re.fullmatch(r"(?:[0-9a-f]{2})+", value["hex"]) is None
            ):
                raise WalletRpcError("historical wallet transaction unavailable")
            return (
                bytes.fromhex(value["hex"]),
                value["blockheight"],
                value["blockhash"],
                value["confirmations"],
            )

        before_height, before_hash = snapshot()
        raw, height, block_hash, first_depth = record()
        inspected = inspect_transaction_outputs(raw)
        matches = [
            (index, output)
            for index, output in enumerate(inspected.outputs)
            if output.script_pubkey == script
        ]
        if inspected.txid != txid or len(matches) != 1 or matches[0][1].value_sat <= 0:
            raise WalletRpcError("historical transaction output bytes differ")
        if read("getblockhash", height, wallet=False) != block_hash:
            raise WalletRpcError("historical transaction block is not active")
        decoded = read("decodescript", script.hex(), wallet=False)
        if (
            not isinstance(decoded, dict)
            or decoded.get("type") != "witness_v1_taproot"
            or not isinstance(decoded.get("address"), str)
            or not 0 < len(decoded["address"]) <= MAX_ADDRESS_BYTES
        ):
            raise WalletRpcError("historical script address unavailable")
        recognized = read("getaddressinfo", decoded["address"])
        if (
            not isinstance(recognized, dict)
            or recognized.get("ismine") is not True
            or recognized.get("scriptPubKey") != script.hex()
        ):
            raise WalletRpcError("historical script not recognized by configured wallet")
        repeated, second_height, second_hash, second_depth = record()
        after_height, after_hash = snapshot()
        if (
            repeated != raw
            or (second_height, second_hash) != (height, block_hash)
            or after_height < before_height
            or (after_height == before_height and after_hash != before_hash)
            or read("getblockhash", before_height, wallet=False) != before_hash
            or read("getblockhash", height, wallet=False) != block_hash
        ):
            raise WalletRpcError("historical output observations contradict")
        depth = min(
            first_depth, second_depth, before_height - height + 1, after_height - height + 1
        )
        completed_at = time.time()
        if depth <= 0 or not math.isfinite(completed_at) or completed_at < started_at:
            raise WalletRpcError("historical output completion interval unavailable")
        _request_budget(deadline, None)
        vout, output = matches[0]
        return HistoricalWalletOutput(
            self._network,
            txid,
            vout,
            output.value_sat,
            script,
            depth,
            height,
            block_hash,
            started_at,
            completed_at,
        )

    def broadcast(
        self,
        raw: bytes,
        *,
        deadline: float | None = None,
        effect_allowed: Callable[[], bool] | None = None,
    ) -> str:
        """Submit exact bytes; optionally authorize transport handoff, not transmission.

        The original deadline covers attestation and final request setup.
        Once handed off, witness transmission or Core completion may occur
        after expiry. Errors and timeouts never establish preimage privacy.
        """
        txid = self._call(
            "sendrawtransaction",
            raw.hex(),
            wallet=False,
            deadline=deadline,
            effect_allowed=effect_allowed,
        )
        if not isinstance(txid, str):
            raise WalletRpcError("Core broadcast result unusable")
        return txid


def _request_budget(deadline: float | None, effect_allowed: Callable[[], bool] | None) -> float:
    """Sample the final time after the trusted local permission observation."""
    if deadline is not None and (
        type(deadline) not in (int, float)
        or not math.isfinite(deadline)
        or time.monotonic() >= deadline
    ):
        raise WalletRpcError("Core request authority expired or invalid")
    if effect_allowed is not None:
        try:
            allowed = effect_allowed() is True
        except Exception:  # noqa: BLE001 - caller details may contain secrets
            allowed = False
        if not allowed:
            raise WalletRpcError("Core request authority unavailable")
    remaining = 30.0 if deadline is None else min(30.0, deadline - time.monotonic())
    if remaining <= 0:
        raise WalletRpcError("Core request authority expired")
    return remaining
