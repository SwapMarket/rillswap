"""EVM HTLC chain backend for the RS-010 ERC20 profiles (Boltz ``ERC20Swap`` v6).

Synchronous like ``core_tx_bytes.CoreTransactionReader``; the settlement
engines call it from worker threads. The client only talks to the HTLC and
token contracts bound in signed terms and refuses an HTLC deployment whose
runtime bytecode does not match the vendored artifact.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from typing import TYPE_CHECKING, Any, Literal, cast

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_account.typed_transactions.typed_transaction import TypedTransaction
from eth_typing import HexStr
from hexbytes import HexBytes
from web3 import HTTPProvider, Web3

if TYPE_CHECKING:
    from rill_core.wire.messages import EvmContractTerms

ARTIFACT_RESOURCE = "erc20-swap-v6.json"
ERC20_ABI: list[dict[str, Any]] = [
    {
        "name": "allowance",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "name": "approve",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "name": "balanceOf",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "name": "decimals",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}],
    },
]
MAX_UINT256 = 2**256 - 1


class EvmBackendError(RuntimeError):
    """A chain read or write failed or returned something the terms forbid."""


def load_artifact() -> dict[str, Any]:
    """Load the vendored ERC20Swap v6 compile artifact."""
    text = resources.files("rill_provider.contracts").joinpath(ARTIFACT_RESOURCE).read_text()
    return cast("dict[str, Any]", json.loads(text))


def masked_runtime_sha256(code: bytes, ranges: list[dict[str, int]]) -> str:
    """Hash runtime bytecode with the immutable ranges zeroed, as the artifact does."""
    masked = bytearray(code)
    for item in ranges:
        start, length = item["start"], item["length"]
        masked[start : start + length] = b"\x00" * length
    return hashlib.sha256(masked).hexdigest()


@dataclass(frozen=True, slots=True)
class LockParams:
    """The six fields that key one HTLC lock (``hashValues`` argument order)."""

    preimage_hash: str
    amount: int
    token: str
    claim_address: str
    refund_address: str
    timelock: int

    @classmethod
    def from_terms(cls, terms: EvmContractTerms) -> LockParams:
        """Derive the exact lock every party must reproduce from signed terms."""
        return cls(
            preimage_hash=terms.invoice_binding.payment_hash,
            amount=terms.htlc_amount_token_base,
            token=terms.evm_asset.token_contract,
            claim_address=terms.htlc_claim_address,
            refund_address=terms.htlc_refund_address,
            timelock=terms.htlc_timelock_block,
        )

    def as_args(self) -> tuple[bytes, int, str, str, str, int]:
        """Return the fields as checksummed contract call arguments."""
        return (
            bytes.fromhex(self.preimage_hash),
            self.amount,
            Web3.to_checksum_address(self.token),
            Web3.to_checksum_address(self.claim_address),
            Web3.to_checksum_address(self.refund_address),
            self.timelock,
        )


@dataclass(frozen=True, slots=True)
class LockupEvent:
    """One ``Lockup`` log with the fields RS-010 compares against the terms."""

    tx_hash: str
    log_index: int
    block_number: int
    params: LockParams

    def matches(self, expected: LockParams) -> bool:
        """Whether this log is exactly the lock the terms describe."""
        return self.params == expected


@dataclass(frozen=True, slots=True)
class ClaimEvent:
    """One ``Claim`` log; the preimage settles the Lightning leg."""

    tx_hash: str
    block_number: int
    preimage: str


@dataclass(frozen=True, slots=True)
class TxReceipt:
    """Mined status of one transaction."""

    tx_hash: str
    block_number: int
    status: Literal["success", "reverted"]


@dataclass(frozen=True, slots=True)
class SignedTx:
    """A signed, not yet broadcast transaction: record it durably, then ``broadcast``."""

    tx_hash: str  # lowercase hex without 0x
    raw: bytes


class EvmHtlcClient:
    """Reads and writes against one verified ERC20Swap deployment on one chain."""

    def __init__(  # noqa: PLR0913 - explicit connection facts
        self,
        *,
        rpc_url: str,
        chain_id: int,
        htlc_contract: str,
        signer_private_key: str | None,
        request_timeout_seconds: float = 20.0,
        artifact: dict[str, Any] | None = None,
    ) -> None:
        """Connect to ``rpc_url``; ``signer_private_key`` is optional for read-only use."""
        self._artifact = artifact or load_artifact()
        self._web3 = Web3(
            HTTPProvider(rpc_url, request_kwargs={"timeout": request_timeout_seconds})
        )
        self.chain_id = chain_id
        self.htlc_contract = htlc_contract.lower()
        self._htlc = self._web3.eth.contract(
            address=Web3.to_checksum_address(htlc_contract), abi=self._artifact["abi"]
        )
        self._account = Account.from_key(signer_private_key) if signer_private_key else None
        self._verified = False

    @property
    def signer_address(self) -> str:
        """Lowercase address of the provider's EVM signer."""
        if self._account is None:
            raise EvmBackendError("no EVM signer configured")
        return cast("str", self._account.address).lower()

    def block_number(self) -> int:
        """Return the latest block number."""
        return int(self._web3.eth.block_number)

    def verify_deployment(self) -> None:
        """Refuse to use a chain or HTLC that differs from configuration and the artifact."""
        if self._verified:
            return
        if int(self._web3.eth.chain_id) != self.chain_id:
            raise EvmBackendError("EVM RPC chain id does not match configuration")
        code = bytes(self._web3.eth.get_code(Web3.to_checksum_address(self.htlc_contract)))
        if not code:
            raise EvmBackendError("no contract code at the configured HTLC address")
        digest = masked_runtime_sha256(code, self._artifact["immutableRanges"])
        if digest != self._artifact["maskedRuntimeSha256"]:
            raise EvmBackendError("HTLC runtime bytecode does not match the vendored artifact")
        version = int(self._htlc.functions.version().call())
        if version != int(self._artifact["contractVersion"]):
            raise EvmBackendError("HTLC contract version does not match the vendored artifact")
        self._verified = True

    def token_decimals(self, token: str) -> int:
        """Return ``decimals()`` of an ERC20 token."""
        contract = self._web3.eth.contract(address=Web3.to_checksum_address(token), abi=ERC20_ABI)
        return int(contract.functions.decimals().call())

    def token_balance(self, token: str, owner: str) -> int:
        """Return ``balanceOf(owner)`` of an ERC20 token."""
        contract = self._web3.eth.contract(address=Web3.to_checksum_address(token), abi=ERC20_ABI)
        return int(contract.functions.balanceOf(Web3.to_checksum_address(owner)).call())

    def lock_active(self, params: LockParams) -> bool:
        """Whether the HTLC currently holds this exact lock (``swaps[hashValues(...)]``)."""
        key = self._htlc.functions.hashValues(*params.as_args()).call()
        return bool(self._htlc.functions.swaps(key).call())

    def find_lockups(
        self, preimage_hash: str, *, from_block: int, to_block: int
    ) -> list[LockupEvent]:
        """Every ``Lockup`` log for this preimage hash in the block range, oldest first."""
        logs = self._htlc.events.Lockup().get_logs(
            argument_filters={"preimageHash": bytes.fromhex(preimage_hash)},
            from_block=from_block,
            to_block=to_block,
        )
        events = []
        for log in logs:
            args = log["args"]
            events.append(
                LockupEvent(
                    tx_hash=log["transactionHash"].hex().removeprefix("0x"),
                    log_index=int(log["logIndex"]),
                    block_number=int(log["blockNumber"]),
                    params=LockParams(
                        preimage_hash=bytes(args["preimageHash"]).hex(),
                        amount=int(args["amount"]),
                        token=str(args["tokenAddress"]).lower(),
                        claim_address=str(args["claimAddress"]).lower(),
                        refund_address=str(args["refundAddress"]).lower(),
                        timelock=int(args["timelock"]),
                    ),
                )
            )
        events.sort(key=lambda event: (event.block_number, event.log_index))
        return events

    def find_claim(
        self, preimage_hash: str, *, from_block: int, to_block: int
    ) -> ClaimEvent | None:
        """Return the ``Claim`` log for this preimage hash, if any."""
        logs = self._htlc.events.Claim().get_logs(
            argument_filters={"preimageHash": bytes.fromhex(preimage_hash)},
            from_block=from_block,
            to_block=to_block,
        )
        if not logs:
            return None
        log = logs[0]
        return ClaimEvent(
            tx_hash=log["transactionHash"].hex().removeprefix("0x"),
            block_number=int(log["blockNumber"]),
            preimage=bytes(log["args"]["preimage"]).hex(),
        )

    def receipt(self, tx_hash: str) -> TxReceipt | None:
        """Return the mined receipt for a transaction hash, or None while pending or unknown."""
        try:
            receipt = self._web3.eth.get_transaction_receipt(HexStr("0x" + tx_hash))
        except Exception:  # noqa: BLE001 - web3 raises TransactionNotFound and provider errors
            return None
        if receipt is None or receipt.get("blockNumber") is None:
            return None
        return TxReceipt(
            tx_hash=tx_hash,
            block_number=int(receipt["blockNumber"]),
            status="success" if int(receipt["status"]) == 1 else "reverted",
        )

    def confirmations(self, tx_hash: str) -> int:
        """Blocks on top of the mined block, zero while unmined."""
        receipt = self.receipt(tx_hash)
        if receipt is None:
            return 0
        return max(0, self.block_number() - receipt.block_number + 1)

    def ensure_allowance(self, token: str, amount: int) -> str | None:
        """Approve the HTLC for at least ``amount``; return the approval tx hash if one was sent."""
        contract = self._web3.eth.contract(address=Web3.to_checksum_address(token), abi=ERC20_ABI)
        owner = Web3.to_checksum_address(self.signer_address)
        spender = Web3.to_checksum_address(self.htlc_contract)
        if int(contract.functions.allowance(owner, spender).call()) >= amount:
            return None
        return self._send(contract.functions.approve(spender, MAX_UINT256))

    def prepare_lock(self, params: LockParams) -> SignedTx:
        """Sign ``lock(...)`` from the signer, which must already hold allowance and balance."""
        return self._prepare(self._htlc.functions.lock(*params.as_args()))

    def prepare_claim(self, params: LockParams, preimage: str) -> SignedTx:
        """Sign the six-argument ``claim``; it pays ``claim_address`` and is permissionless."""
        _hash, amount, token, claim_address, refund_address, timelock = params.as_args()
        return self._prepare(
            self._htlc.functions.claim(
                bytes.fromhex(preimage), amount, token, claim_address, refund_address, timelock
            )
        )

    def prepare_refund(self, params: LockParams) -> SignedTx:
        """Sign the six-argument timed ``refund``; valid once ``block.number >= timelock``."""
        return self._prepare(self._htlc.functions.refund(*params.as_args()))

    def broadcast(self, raw: bytes) -> str:
        """Submit signed bytes (idempotent for an already known transaction); return the hash."""
        try:
            return bytes(self._web3.eth.send_raw_transaction(raw)).hex()
        except ValueError as error:  # e.g. "already known" / nonce too low once mined
            tx_hash = bytes(Web3.keccak(raw)).hex()
            if self.receipt(tx_hash) is not None or "already known" in str(error).lower():
                return tx_hash
            raise EvmBackendError(f"broadcast refused: {error}") from error

    def superseded(self, raw: bytes, depth: int) -> bool:  # noqa: PLR0911 - one guard per proof step
        """Whether our recorded ``raw`` can no longer mine: its nonce went to another transaction.

        True only on affirmative evidence: ``raw`` is our own EIP-1559 transaction
        on this chain, it has no receipt (checked before and after the nonce read),
        and the signer's mined nonce count ``depth`` blocks deep (counting the tip
        as the first) is already above its nonce. Anything unexpected, including
        a node without that block's state, is False, so the caller keeps
        rebroadcasting. Receipt and nonce reads must come from one consistent node.
        """
        if depth < 1 or self._account is None:
            return False
        tx_hash = bytes(Web3.keccak(raw)).hex()
        try:
            fields = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
            sender = Account.recover_transaction(raw)
        except Exception:  # noqa: BLE001 - not a transaction we signed: never replace it
            return False
        if int(fields["chainId"]) != self.chain_id or sender.lower() != self.signer_address:
            return False
        if self.receipt(tx_hash) is not None:
            return False
        block = self.block_number() - depth + 1
        if block < 0:
            return False
        try:
            mined = int(self._web3.eth.get_transaction_count(sender, block))
        except Exception:  # noqa: BLE001 - e.g. a pruned node: unproven, keep rebroadcasting
            return False
        return mined > int(fields["nonce"]) and self.receipt(tx_hash) is None

    def lock(self, params: LockParams) -> str:
        """Sign and send ``lock(...)``."""
        return self.broadcast(self.prepare_lock(params).raw)

    def claim(self, params: LockParams, preimage: str) -> str:
        """Sign and send the six-argument ``claim``."""
        return self.broadcast(self.prepare_claim(params, preimage).raw)

    def refund(self, params: LockParams) -> str:
        """Sign and send the six-argument ``refund``."""
        return self.broadcast(self.prepare_refund(params).raw)

    def sign_cooperative_refund(self, params: LockParams) -> tuple[int, str, str]:
        """Sign the EIP-712 ``Refund`` message as ``claimAddress`` (cooperative refund)."""
        if self._account is None:
            raise EvmBackendError("no EVM signer configured")
        if params.claim_address != self.signer_address:
            raise EvmBackendError("cooperative refund must be signed by the claim address")
        message = encode_typed_data(
            domain_data={
                "name": "ERC20Swap",
                "version": "6",
                "chainId": self.chain_id,
                "verifyingContract": Web3.to_checksum_address(self.htlc_contract),
            },
            message_types={
                "Refund": [
                    {"name": "preimageHash", "type": "bytes32"},
                    {"name": "amount", "type": "uint256"},
                    {"name": "tokenAddress", "type": "address"},
                    {"name": "claimAddress", "type": "address"},
                    {"name": "timelock", "type": "uint256"},
                ]
            },
            message_data={
                "preimageHash": bytes.fromhex(params.preimage_hash),
                "amount": params.amount,
                "tokenAddress": Web3.to_checksum_address(params.token),
                "claimAddress": Web3.to_checksum_address(params.claim_address),
                "timelock": params.timelock,
            },
        )
        signed = self._account.sign_message(message)
        return int(signed.v), signed.r.to_bytes(32, "big").hex(), signed.s.to_bytes(32, "big").hex()

    def _send(self, call: Any) -> str:  # noqa: ANN401 - web3 ContractFunction is untyped
        return self.broadcast(self._prepare(call).raw)

    def _prepare(self, call: Any) -> SignedTx:  # noqa: ANN401 - web3 ContractFunction is untyped
        if self._account is None:
            raise EvmBackendError("no EVM signer configured")
        sender = Web3.to_checksum_address(self.signer_address)
        try:
            gas = int(call.estimate_gas({"from": sender}))
        except Exception as error:
            raise EvmBackendError(f"transaction would revert: {error}") from error
        transaction = call.build_transaction(
            {
                "from": sender,
                "chainId": self.chain_id,
                "nonce": self._web3.eth.get_transaction_count(sender, "pending"),
                "gas": gas + gas // 5,
            }
        )
        signed = self._account.sign_transaction(transaction)
        raw = bytes(signed.raw_transaction)
        return SignedTx(bytes(Web3.keccak(raw)).hex(), raw)
