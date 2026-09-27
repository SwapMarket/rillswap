"""Explicit read-only local Core RPC transaction-byte and UTXO observations.

No wallet, ledger, mempool, funding, or payment action. Named-tip UTXO
samples cannot establish persistent confirmation or live action authority.
The operator supplies the full network identity; Core attests only chain label
and genesis, NOT the deployment namespace or consensus policy identifier.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from rill_core.errors import ValidationError
from rill_core.networks import backend_names
from rill_core.settlement import FundingBindingTransactionMatch, check_funding_binding_transaction
from rill_core.wire.messages import FundingBinding
from rill_core.wire.types import NetworkIdentity

if TYPE_CHECKING:
    from rill_core.settlement import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms

RPC_VERIFY_ALREADY_IN_CHAIN = -27
RPC_INVALID_ADDRESS_OR_KEY = -5  # getrawtransaction: not in mempool or txindex
MAX_COOKIE_BYTES = 512
MAX_RESPONSE_BYTES = 256 * 1024
MAX_BLOCK_RESPONSE_BYTES = 32 * 1024 * 1024  # a decoded block (getblock verbosity 2)
MAX_SPEND_SCAN_BLOCKS = 12  # blocks decoded per find_spender call
FUNDING_ESTIMATE_TARGET = 6
MAX_SCRIPT_BYTES = 40
_WALLET_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
SATS_PER_BTC = Decimal(100_000_000)
MAX_TRANSACTION_HEX_BYTES = 200_000
MAX_PORT = 65535
HTTP_OK = 200
CONNECT_SECONDS = 2.0
READ_SECONDS = 5.0
HASH_HEX_LENGTH = 64
MAX_ESTIMATE_TARGET = 1008  # Core's estimatesmartfee bound
SATS_PER_BTC = Decimal(100_000_000)
MAX_SATS = 21_000_000 * 100_000_000


@dataclass(frozen=True, slots=True)
class FundedOutput:
    """A signed, not yet broadcast wallet transaction paying the contract at index 0."""

    txid: str
    vout: int
    raw: bytes
    fee_sat: int


@dataclass(frozen=True, slots=True)
class SpendObservation:
    """The transaction spending a contract output and the witness of that input."""

    txid: str
    witness: tuple[bytes, ...]
    height: int | None  # None while only in the mempool


@dataclass(frozen=True, slots=True)
class SpendScan:
    """Result of one bounded ``find_spender`` call."""

    spender: SpendObservation | None
    scanned_to: int  # last block height searched (resume from the next one)


@dataclass(frozen=True, slots=True)
class CandidateFundingOutpoint:
    """Named-tip read-only candidate inclusion, not lineage or permission.

    A succeeding RPC is immediately staleable. It cannot authenticate the
    binding, rule out mempool spends, or prove durable funding after restart.
    """

    network_identity: NetworkIdentity
    static_match: FundingBindingTransactionMatch
    tip_hash: str
    tip_height: int
    chain_only_confirmations: int
    inclusion_height: int
    inclusion_block_hash: str


class CoreReadError(Exception):
    """No usable requested evidence was established; never absence proof."""


class CoreAuthError(CoreReadError):
    """RPC authentication failed or a protected cookie was not readable."""


class CoreProtocolError(CoreReadError):
    """Core RPC response or network preflight was malformed or inconsistent."""


class CoreUnavailableError(CoreReadError):
    """The requested transaction or node was unavailable, not known absent."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == HASH_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _chain_tip(value: object, chain: str) -> tuple[str, int]:
    if (
        not isinstance(value, dict)
        or value.get("chain") != chain
        or not _hash(value.get("bestblockhash"))
        or type(value.get("blocks")) is not int
        or value["blocks"] < 0
        or value.get("initialblockdownload") is not False
    ):
        raise CoreProtocolError("Core has no usable current tip on the configured chain")
    return value["bestblockhash"], value["blocks"]


def _exact_sats(value: object, expected: int) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        return False
    if not 0 <= expected <= MAX_SATS or not Decimal(value).is_finite():
        return False
    whole, fractional = divmod(expected, int(SATS_PER_BTC))
    # Decimal comparison is exact; arithmetic would use the ambient precision
    # and can round away a fractional satoshi or overflow on a huge exponent.
    return value == Decimal(f"{whole}.{fractional:08d}")


def _cookie(path: Path) -> tuple[str, str]:
    try:
        result = _read_cookie(path)
    except (OSError, ValueError, UnicodeError):
        raise CoreAuthError("Core cookie unavailable; no transaction check performed") from None
    return result


def _read_cookie(path: Path) -> tuple[str, str]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb", closefd=True) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("cookie must be a private regular file")
        value = stream.read(MAX_COOKIE_BYTES + 1)
    if len(value) > MAX_COOKIE_BYTES or not value:
        raise ValueError("cookie exceeds size limit")
    text = value.removesuffix(b"\n").decode("ascii")
    username, password = text.split(":", 1)
    if username != "__cookie__" or not password or any(char in text for char in "\r\n\x00"):
        raise ValueError("unsupported cookie contents")
    return username, password


class CoreTransactionReader:
    """Fetch static bytes or a named-tip UTXO from local Bitcoin Core v30.

    A matching result does not authenticate the funder's binding signature,
    wallet prevouts or terms; it does not imply durable chain/UTXO status.
    Construction makes no RPC call and does not open or migrate any ledger.
    """

    def __init__(
        self,
        *,
        port: int,
        cookie_path: str | os.PathLike[str],
        wallet: str | None = None,
        network: NetworkIdentity,
        host: str = "127.0.0.1",
    ) -> None:
        """Configure a numeric loopback endpoint without connecting to it."""
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("Core RPC must be a numeric loopback host and valid port")
        try:
            self._chain = backend_names(network).core_chain
        except ValidationError:
            raise ValueError("only a supported complete network identity is accepted") from None
        self._url = f"http://[{host}]:{port}/" if host == "::1" else f"http://{host}:{port}/"
        self._cookie_path = Path(cookie_path)
        self._network = network
        if wallet is not None and _WALLET_NAME.fullmatch(wallet) is None:
            raise ValueError("Core wallet name unsupported")
        self._wallet_path = "/" if wallet is None else f"/wallet/{wallet}"

    def tip_height(self) -> int:
        """Return the current tip height after checking chain and genesis.

        Informational only (e.g. an indicative quote's reference height); a
        height read here authorizes nothing.
        """
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                _, height = _chain_tip(self._rpc(client, "getblockchaininfo", [], 1), self._chain)
                if self._rpc(client, "getblockhash", [0], 2) != self._network.genesis_hash:
                    raise CoreProtocolError("Core genesis differs from configuration")
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        return height

    def fetch_binding_byte_match(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
    ) -> FundingBindingTransactionMatch:
        """Explicitly read bytes and run only the core static matcher.

        Synchronous operator-invoked diagnostic, not a service or
        watcher. Inactivity timeouts are NOT a total-duration bound: a
        configured listener that trickles incomplete HTTP can block this call
        indefinitely. Never use it to enforce funding/payment deadlines.
        """
        if not isinstance(terms.network_identity, NetworkIdentity) or (
            terms.network_identity != self._network
        ):
            raise ValueError("binding terms and configured full network identity differ")
        if not isinstance(binding, FundingBinding):
            raise TypeError("a parsed binding is required")
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                info = self._rpc(client, "getblockchaininfo", [], 1)
                if not isinstance(info, dict) or info.get("chain") != self._chain:
                    raise CoreProtocolError("Core network label differs from configuration")
                genesis = self._rpc(client, "getblockhash", [0], 2)
                if genesis != self._network.genesis_hash:
                    raise CoreProtocolError("Core genesis differs from configuration")
                raw_hex = self._rpc(client, "getrawtransaction", [binding.funding_txid, False], 3)
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        # Static mismatch remains an explicit core ValidationError, not an
        # assertion of missing/invalid live funding or a reason to retry.
        return check_funding_binding_transaction(
            _transaction_bytes(raw_hex), binding, terms, keys=keys
        )

    def observe_candidate_outpoint(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
    ) -> CandidateFundingOutpoint:
        """Sample chain-only UTXO and block-qualified bytes, with no action authority.

        This explicit synchronous diagnostic does not install a lineage view,
        rule out mempool spends, prove permanent confirmations, or satisfy
        restored-state reconciliation. It has no total-duration bound against
        a trickling local endpoint. Unknown/unstable facts fail closed without
        retry, wallet RPC, database updates, or automatic scans.
        """
        if not isinstance(binding, FundingBinding):
            raise TypeError("a parsed binding is required")
        if not isinstance(terms.network_identity, NetworkIdentity) or (
            terms.network_identity != self._network
        ):
            raise ValueError("binding terms and configured full network identity differ")
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                tip_hash, tip_height = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 1), self._chain
                )
                if self._rpc(client, "getblockhash", [0], 2) != self._network.genesis_hash:
                    raise CoreProtocolError("Core genesis differs from configuration")
                raw_hex = self._rpc(client, "getrawtransaction", [binding.funding_txid, False], 3)
                raw = _transaction_bytes(raw_hex)
                match = check_funding_binding_transaction(raw, binding, terms, keys=keys)
                output = self._rpc(
                    client, "gettxout", [binding.funding_txid, binding.contract_vout, False], 4
                )
                confirmations = _checked_outpoint(output, binding, tip_height)
                inclusion_height = tip_height - confirmations + 1
                inclusion_hash = self._rpc(client, "getblockhash", [inclusion_height], 5)
                if not _hash(inclusion_hash) or (
                    inclusion_height == tip_height and inclusion_hash != tip_hash
                ):
                    raise CoreProtocolError("Core inclusion-height block differs from sampled tip")
                block_raw = _transaction_bytes(
                    self._rpc(
                        client,
                        "getrawtransaction",
                        [binding.funding_txid, False, inclusion_hash],
                        6,
                    )
                )
                if block_raw != raw:
                    raise CoreProtocolError("Core block-qualified transaction bytes differ")
                end_hash, end_height = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 7), self._chain
                )
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if tip_hash != end_hash or tip_height != end_height or output["bestblock"] != tip_hash:
            raise CoreUnavailableError("Core chain view changed; no current outpoint proof")
        return CandidateFundingOutpoint(
            self._network,
            match,
            tip_hash,
            tip_height,
            confirmations,
            inclusion_height,
            inclusion_hash,
        )

    def _client(self) -> httpx.Client:
        username, password = _cookie(self._cookie_path)
        return httpx.Client(
            base_url=self._url,
            auth=httpx.BasicAuth(username, password),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
        )

    def broadcast(self, raw: bytes, txid: str) -> str:
        """Submit exact transaction bytes (the only mutating call); return the txid.

        ``txid`` comes from the caller's validated build. Idempotent: a
        transaction already in the chain counts as broadcast.
        The caller records the exact bytes durably before calling.
        """
        try:
            with self._client() as client:
                result = self._rpc(client, "sendrawtransaction", [raw.hex()], 1)
        except CoreRpcError as error:
            if error.code != RPC_VERIFY_ALREADY_IN_CHAIN:
                raise
            return txid
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if result != txid:
            raise CoreProtocolError("Core reported another transaction ID")
        return txid

    def fund_output(
        self, script_pubkey: bytes, value_sat: int, *, max_fee_sat: int
    ) -> FundedOutput:
        """Build and sign (never broadcast) a wallet transaction paying ``value_sat`` to the script.

        The paid output is always index 0 (change, if any, is index 1); inputs
        are locked in the wallet so a second build cannot double-spend them.
        The fee must not exceed ``max_fee_sat`` or nothing is signed. The
        caller records the exact bytes durably, then ``broadcast``s them.
        """
        if not (
            type(script_pubkey) is bytes
            and 0 < len(script_pubkey) <= MAX_SCRIPT_BYTES
            and type(value_sat) is int
            and value_sat > 0
            and type(max_fee_sat) is int
            and max_fee_sat >= 0
        ):
            raise ValueError("funding request unsupported")
        amount = f"{Decimal(value_sat) / SATS_PER_BTC:.8f}"
        options = {
            "changePosition": 1,
            "lockUnspents": True,
            "replaceable": False,
            "conf_target": FUNDING_ESTIMATE_TARGET,
            "estimate_mode": "economical",
        }
        try:
            with self._client() as client:
                described = self._rpc(client, "decodescript", [script_pubkey.hex()], 1)
                address = described.get("address") if isinstance(described, dict) else None
                if type(address) is not str:
                    raise CoreProtocolError("contract script has no address")
                created = self._rpc(
                    client, "walletcreatefundedpsbt", [[], [{address: amount}], 0, options], 2
                )
                fee = _fee_sat(created)
                if fee > max_fee_sat:
                    raise CoreProtocolError("funding fee exceeds the signed maximum")
                signed = self._rpc(client, "walletprocesspsbt", [created["psbt"], True], 3)
                if not isinstance(signed, dict) or type(signed.get("psbt")) is not str:
                    raise CoreProtocolError("Core wallet could not sign the funding")
                final = self._rpc(client, "finalizepsbt", [signed["psbt"], True], 4)
                if not isinstance(final, dict) or final.get("complete") is not True:
                    raise CoreProtocolError("Core wallet could not sign every funding input")
                raw = _transaction_bytes(final.get("hex"))
                decoded = self._rpc(client, "decoderawtransaction", [raw.hex()], 5)
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        txid = decoded.get("txid") if isinstance(decoded, dict) else None
        outputs = decoded.get("vout") if isinstance(decoded, dict) else None
        if (
            type(txid) is not str
            or len(txid) != HASH_HEX_LENGTH
            or not isinstance(outputs, list)
            or not outputs
            or not isinstance(outputs[0], dict)
            or outputs[0].get("scriptPubKey", {}).get("hex") != script_pubkey.hex()
            or _btc_to_sat(outputs[0].get("value")) != value_sat
        ):
            raise CoreProtocolError("Core wallet signed a different funding than requested")
        return FundedOutput(txid=txid, vout=0, raw=raw, fee_sat=fee)

    def find_spender(self, txid: str, vout: int, *, from_height: int, to_height: int) -> SpendScan:
        """Look for the transaction spending ``txid:vout``: mempool first, then blocks.

        Blocks ``from_height`` through ``to_height`` are decoded oldest first,
        at most ``MAX_SPEND_SCAN_BLOCKS`` per call; ``scanned_to`` tells the
        caller where to resume. A mempool spender has ``height`` ``None``.
        """
        if not (
            type(txid) is str
            and len(txid) == HASH_HEX_LENGTH
            and type(vout) is int
            and vout >= 0
            and type(from_height) is int
            and type(to_height) is int
            and from_height > 0
        ):
            raise ValueError("spend scan bounds unsupported")
        try:
            with self._client() as client:
                (entry,) = _list(
                    self._rpc(client, "gettxspendingprevout", [[{"txid": txid, "vout": vout}]], 1),
                    1,
                )
                spender = entry.get("spendingtxid") if isinstance(entry, dict) else None
                if type(spender) is str and len(spender) == HASH_HEX_LENGTH:
                    decoded = self._rpc(client, "getrawtransaction", [spender, True], 2)
                    witness = _spending_witness(decoded, txid, vout)
                    if witness is not None:
                        return SpendScan(SpendObservation(spender, witness, None), from_height - 1)
                scanned_to = from_height - 1
                last = min(to_height, from_height + MAX_SPEND_SCAN_BLOCKS - 1)
                for height in range(from_height, last + 1):
                    block_hash = self._rpc(client, "getblockhash", [height], 3)
                    block = self._rpc(client, "getblock", [block_hash, 2], 4)
                    transactions = block.get("tx") if isinstance(block, dict) else None
                    for transaction in _list(transactions):
                        witness = _spending_witness(transaction, txid, vout)
                        if witness is not None:
                            spender = transaction.get("txid")
                            if type(spender) is not str or len(spender) != HASH_HEX_LENGTH:
                                raise CoreProtocolError("Core reported a malformed spender")
                            return SpendScan(SpendObservation(spender, witness, height), height)
                    scanned_to = height
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        return SpendScan(None, scanned_to)

    def outpoint_unspent(self, txid: str, vout: int) -> bool:
        """Whether ``txid:vout`` is unspent on the confirmed chain (mempool ignored).

        ``False`` means Core answered that the confirmed chain has no such
        unspent output: spent, or never existed. Transport failure raises.
        """
        if not (type(txid) is str and len(txid) == HASH_HEX_LENGTH and type(vout) is int):
            raise ValueError("outpoint must be a txid and index")
        try:
            with self._client() as client:
                output = self._rpc(client, "gettxout", [txid, vout, False], 1)
        except CoreRpcError:
            raise CoreUnavailableError("Core outpoint status unavailable") from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if output is None:
            return False
        if not isinstance(output, dict):
            raise CoreProtocolError("Core outpoint status is inconsistent")
        return True

    def fee_rate_sat_vb(self, target_blocks: int) -> float | None:
        """Return Core's conservative feerate estimate in sat/vB, or ``None``.

        An estimate is advice, not evidence: any failure, an answer with
        ``errors``, or a non-positive rate yields ``None`` and the caller
        falls back to its configured fee.
        """
        if type(target_blocks) is not int or not 1 <= target_blocks <= MAX_ESTIMATE_TARGET:
            raise ValueError("estimate target out of range")
        try:
            with self._client() as client:
                result = self._rpc(client, "estimatesmartfee", [target_blocks, "CONSERVATIVE"], 1)
        except (CoreRpcError, httpx.HTTPError):
            return None
        if not isinstance(result, dict) or result.get("errors"):
            return None
        rate = result.get("feerate")
        if (
            not isinstance(rate, (int, float, Decimal))
            or isinstance(rate, bool)
            or not 0 < rate < 1
        ):
            return None  # BTC per kvB; anything at or above 1 BTC/kvB is nonsense
        return float(Decimal(str(rate)) * 100_000)  # 1e8 sat per BTC over 1000 vB per kvB

    def block_hash(self, height: int) -> str:
        """Return the active-chain block hash at ``height``; failures raise."""
        if type(height) is not int or height < 0:
            raise ValueError("block height must be a non-negative integer")
        try:
            with self._client() as client:
                result = self._rpc(client, "getblockhash", [height], 1)
        except CoreRpcError:
            raise CoreUnavailableError("Core block hash unavailable") from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if not _hash(result):
            raise CoreProtocolError("Core block hash is malformed")
        return str(result)

    def confirmations(self, txid: str) -> int:
        """Return best-chain confirmations of a transaction (0 in mempool).

        Needs ``txindex=1`` for confirmed transactions. Raises
        ``CoreTransactionUnknownError`` when Core has neither a mempool nor an
        indexed copy (e.g. never broadcast or evicted); other failures are not
        evidence about the transaction at all.
        """
        try:
            with self._client() as client:
                result = self._rpc(client, "getrawtransaction", [txid, True], 1)
        except CoreRpcError as error:
            if error.code != RPC_INVALID_ADDRESS_OR_KEY:
                raise
            # Only a synced txindex turns "not found" into usable absence
            # evidence; a disabled or catching-up index says nothing.
            try:
                with self._client() as client:
                    indexes = self._rpc(client, "getindexinfo", ["txindex"], 2)
            except (CoreRpcError, httpx.HTTPError):
                raise CoreUnavailableError("Core index status unavailable") from None
            index = indexes.get("txindex") if isinstance(indexes, dict) else None
            if not (isinstance(index, dict) and index.get("synced") is True):
                raise CoreUnavailableError("Core txindex is not synced; no absence claim") from None
            raise CoreTransactionUnknownError(error.code) from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        count = result.get("confirmations", 0) if isinstance(result, dict) else None
        if not isinstance(result, dict) or result.get("txid") != txid or type(count) is not int:
            raise CoreProtocolError("Core transaction status is inconsistent")
        return count

    def _rpc(
        self,
        client: httpx.Client,
        method: str,
        params: list[object],
        request_id: int,
    ) -> Any:  # noqa: ANN401
        if method not in (
            "getblockchaininfo",
            "estimatesmartfee",
            "getblockhash",
            "getindexinfo",
            "getrawtransaction",
            "gettxout",
            "sendrawtransaction",
            # LN to BTC (RS-004): the provider funds contracts from its Core
            # wallet and looks for the client's claim spending them.
            "decodescript",
            "walletcreatefundedpsbt",
            "walletprocesspsbt",
            "finalizepsbt",
            "decoderawtransaction",
            "gettxspendingprevout",
            "getblock",
        ):
            raise CoreProtocolError("unsupported Core RPC method")
        path = self._wallet_path if method.startswith("wallet") else "/"
        max_bytes = MAX_BLOCK_RESPONSE_BYTES if method == "getblock" else MAX_RESPONSE_BYTES
        try:
            with client.stream(
                "POST",
                path,
                headers={"Accept-Encoding": "identity"},
                json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as response:
                if response.status_code in (401, 403):
                    raise CoreAuthError("Core RPC authentication rejected")
                if response.status_code != HTTP_OK:
                    raise CoreUnavailableError(
                        "Core RPC failed without usable transaction evidence"
                    )
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise CoreProtocolError("compressed Core RPC responses are unsupported")
                chunks = bytearray()
                for part in response.iter_raw():
                    if len(chunks) + len(part) > max_bytes:
                        raise CoreProtocolError("Core RPC response exceeded resource limit")
                    chunks.extend(part)
            envelope = json.loads(
                chunks,
                object_pairs_hook=_unique_pairs,
                parse_float=Decimal,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-JSON number")),
            )
        except (ValueError, UnicodeError, InvalidOperation):
            raise CoreProtocolError("Core RPC response is not strict JSON") from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if (
            not isinstance(envelope, dict)
            or envelope.get("jsonrpc") != "2.0"
            or type(envelope.get("id")) is not int
            or envelope["id"] != request_id
            or ("result" in envelope) == ("error" in envelope)
        ):
            raise CoreProtocolError("Core RPC response envelope is inconsistent")
        if "error" in envelope:
            error = envelope["error"]
            if (
                not isinstance(error, dict)
                or type(error.get("code")) is not int
                or not isinstance(error.get("message"), str)
            ):
                raise CoreProtocolError("Core RPC error envelope is malformed")
            raise CoreRpcError(error["code"])
        return envelope["result"]


class CoreRpcError(CoreUnavailableError):
    """Core answered with a JSON-RPC error; only the numeric code is kept."""

    def __init__(self, code: int) -> None:
        """Keep the code, never the (possibly data-bearing) message."""
        super().__init__("Core RPC result unavailable; no absence claim")
        self.code = code


class CoreTransactionUnknownError(CoreRpcError):
    """Core has no mempool or indexed copy of the transaction right now."""


def _transaction_bytes(raw_hex: object) -> bytes:
    if (
        not isinstance(raw_hex, str)
        or len(raw_hex) > MAX_TRANSACTION_HEX_BYTES
        or (len(raw_hex) % 2 or any(char not in "0123456789abcdef" for char in raw_hex))
    ):
        raise CoreProtocolError("Core transaction response is not bounded lowercase hex")
    return bytes.fromhex(raw_hex)


def _checked_outpoint(output: object, binding: FundingBinding, tip_height: int) -> int:
    if output is None:
        raise CoreUnavailableError("contract outpoint unavailable; not proof of absence")
    count = output.get("confirmations") if isinstance(output, dict) else None
    if (
        not isinstance(output, dict)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= tip_height
        or not _hash(output.get("bestblock"))
        or output.get("coinbase") is not False
        or not isinstance(output.get("scriptPubKey"), dict)
        or output["scriptPubKey"].get("hex") != binding.contract_script_pubkey
        or not _exact_sats(output.get("value"), int(binding.contract_value_sat))
    ):
        raise CoreProtocolError("Core contract outpoint evidence is inconsistent")
    return count


def _fee_sat(created: object) -> int:
    fee = created.get("fee") if isinstance(created, dict) else None
    if type(created) is not dict or type(created.get("psbt")) is not str:
        raise CoreProtocolError("Core wallet returned no PSBT")
    return _btc_to_sat(fee)


def _btc_to_sat(value: object) -> int:
    if not isinstance(value, Decimal):
        raise CoreProtocolError("Core reported a non-decimal amount")
    sats = value * SATS_PER_BTC
    if sats != sats.to_integral_value() or sats < 0:
        raise CoreProtocolError("Core reported a non-integral satoshi amount")
    return int(sats)


def _list(value: object, exact: int | None = None) -> list[Any]:
    if not isinstance(value, list) or (exact is not None and len(value) != exact):
        raise CoreProtocolError("Core reported a malformed list")
    return value


def _spending_witness(decoded: object, txid: str, vout: int) -> tuple[bytes, ...] | None:
    """Return the witness of the input of ``decoded`` spending ``txid:vout``, if any."""
    inputs = decoded.get("vin") if isinstance(decoded, dict) else None
    for entry in _list(inputs):
        if not isinstance(entry, dict) or entry.get("txid") != txid or entry.get("vout") != vout:
            continue
        items = entry.get("txinwitness", [])
        if not isinstance(items, list) or not all(type(item) is str for item in items):
            raise CoreProtocolError("Core reported a malformed witness")
        try:
            return tuple(bytes.fromhex(item) for item in items)
        except ValueError:
            raise CoreProtocolError("Core reported a malformed witness") from None
    return None
