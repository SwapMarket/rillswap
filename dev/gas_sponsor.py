"""Dev-only gas sponsor: the Alchemy wallet API subset RillSwap's browser client speaks
(``wallet_prepareCalls``, ``wallet_sendPreparedCalls``, ``wallet_getCallsStatus``), bundling
ERC-4337 v0.7 user operations for EIP-7702 accounts delegated to the Alchemy SMA7702 and
paying the gas from Anvil account 4.

This is NOT a production sponsor. It has no authentication, policy, rate limit, or paymaster;
it trusts its callers and only runs inside the dev stack. What it does share with production is
the on-chain path: the canonical EntryPoint, the canonical delegate, a type-4 (set-code)
transaction carrying the authorization list, and SMA7702's fallback-signer validation, so the
browser's independent verification is exercised against the genuine contracts.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from eth_abi import encode
from eth_utils import keccak, to_checksum_address
from web3 import Web3

sys.path.insert(0, str(Path(__file__).parent))
from evm_dev import ANVIL_KEYS, ANVIL_RPC, CHAIN_ID, SPONSOR, SRC  # noqa: E402

ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032"
DELEGATE = "0x77021100bd87b7008e5e1989d0eb38555d0d0000"
ENTRY_POINT_ABI = json.loads((SRC / "rill-contracts/artifacts/entry-point-v0.7.json").read_text())[
    "abi"
]
# SMA7702 fallback validation: ValidationLocatorLib.packNonce(0, isGlobal=True, deferred=False).
NONCE_KEY = 1
EXECUTE_BATCH = keccak(text="executeBatch((address,uint256,bytes)[])")[:4]
USER_OP_EVENT = keccak(
    text="UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"
)
GAS = {"callGasLimit": 1_000_000, "verificationGasLimit": 600_000, "preVerificationGas": 100_000}
MAX_BODY = 200_000
HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
QUANTITY = re.compile(r"0x[0-9a-fA-F]{1,64}")


class RpcError(Exception):
    def __init__(self, message: str, code: int = -32602) -> None:
        super().__init__(message)
        self.code = code


def _address(value: Any, what: str) -> str:
    if not isinstance(value, str) or not ADDRESS.fullmatch(value):
        raise RpcError(f"{what} is not an address")
    return value.lower()


def _quantity(value: Any, what: str) -> int:
    if not isinstance(value, str) or not QUANTITY.fullmatch(value):
        raise RpcError(f"{what} is not a hex quantity")
    return int(value, 16)


def _bytes(value: Any, what: str) -> bytes:
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise RpcError(f"{what} is not hex bytes")
    return bytes.fromhex(value[2:])


def _signature(value: Any) -> bytes:
    if not isinstance(value, dict) or value.get("type") not in ("secp256k1", "ecdsa"):
        raise RpcError("signature must be {type: secp256k1, data: hex}")
    signature = _bytes(value.get("data"), "signature")
    if len(signature) != 65 or signature[64] not in (27, 28):
        raise RpcError("signature must be 65 bytes r||s||v")
    return signature


class Sponsor:
    """Prepares, bundles, and tracks user operations. One instance per process."""

    def __init__(self, w3: Web3) -> None:
        self.w3 = w3
        self.entry_point = w3.eth.contract(
            address=to_checksum_address(ENTRY_POINT), abi=ENTRY_POINT_ABI
        )
        self.account = w3.eth.account.from_key(ANVIL_KEYS[SPONSOR])
        self.calls: dict[str, str] = {}
        self.lock = threading.Lock()

    def prepare(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise RpcError("prepareCalls expects one request object")
        sender = _address(request.get("from"), "from")
        if _quantity(request.get("chainId"), "chainId") != CHAIN_ID:
            raise RpcError(f"this sponsor serves chain {CHAIN_ID} only")
        calls = request.get("calls")
        if not isinstance(calls, list) or not calls:
            raise RpcError("calls must be a non-empty list")
        batch = []
        for call in calls:
            if not isinstance(call, dict) or _quantity(call.get("value", "0x0"), "value") != 0:
                raise RpcError("only zero-value calls are sponsored")
            batch.append(
                (
                    to_checksum_address(_address(call.get("to"), "to")),
                    0,
                    _bytes(call.get("data", "0x"), "data"),
                )
            )
        call_data = EXECUTE_BATCH + encode(["(address,uint256,bytes)[]"], [batch])
        checksum = to_checksum_address(sender)
        code = self.w3.eth.get_code(checksum)
        authorization = None
        if code != bytes.fromhex("ef0100" + DELEGATE[2:]):
            if code:
                raise RpcError("account is delegated to an unsupported contract")
            nonce = self.w3.eth.get_transaction_count(checksum, "pending")
            authorization = {
                "type": "authorization",
                "chainId": hex(CHAIN_ID),
                "data": {"address": DELEGATE, "nonce": hex(nonce)},
                "signatureRequest": {
                    "type": "eip7702Auth",
                    "rawPayload": "0x"
                    + keccak(b"\x05" + _rlp([CHAIN_ID, bytes.fromhex(DELEGATE[2:]), nonce])).hex(),
                },
            }
        user_op = {
            "sender": sender,
            "nonce": hex(self.entry_point.functions.getNonce(checksum, NONCE_KEY).call()),
            "callData": "0x" + call_data.hex(),
            **{name: hex(value) for name, value in GAS.items()},
            "maxFeePerGas": "0x0",
            "maxPriorityFeePerGas": "0x0",
        }
        op_hash = self.entry_point.functions.getUserOpHash(_packed(user_op, b"")).call()
        op_entry = {
            "type": "user-operation-v070",
            "chainId": hex(CHAIN_ID),
            "data": user_op,
            "signatureRequest": {"type": "personal_sign", "data": {"raw": "0x" + op_hash.hex()}},
            "feePayment": {"sponsored": True, "tokenAddress": "0x" + "00" * 20, "maxAmount": "0x0"},
        }
        return {"type": "array", "data": [authorization, op_entry]} if authorization else op_entry

    def send(self, signed: Any) -> dict[str, Any]:
        entries = (
            signed.get("data")
            if isinstance(signed, dict) and signed.get("type") == "array"
            else [signed]
        )
        if not isinstance(entries, list):
            raise RpcError("expected prepared entries")
        authorization_list = []
        packed = None
        for entry in entries:
            if not isinstance(entry, dict):
                raise RpcError("entry is not an object")
            if entry.get("type") == "authorization":
                data = entry.get("data") or {}
                signature = _signature(entry.get("signature"))
                authorization_list.append(
                    {
                        "chainId": _quantity(entry.get("chainId"), "chainId"),
                        "address": to_checksum_address(_address(data.get("address"), "delegate")),
                        "nonce": _quantity(data.get("nonce"), "nonce"),
                        "yParity": signature[64] - 27,
                        "r": int.from_bytes(signature[:32], "big"),
                        "s": int.from_bytes(signature[32:64], "big"),
                    }
                )
            elif entry.get("type") == "user-operation-v070":
                if packed is not None:
                    raise RpcError("one user operation per submission")
                # SMA7702 fallback signer: final-segment marker, SignatureType.EOA, then r||s||v.
                packed = _packed(
                    entry.get("data") or {}, b"\xff\x00" + _signature(entry.get("signature"))
                )
            else:
                raise RpcError("unsupported entry type")
        if packed is None:
            raise RpcError("missing user operation")
        with self.lock:
            transaction = self.entry_point.functions.handleOps(
                [packed], self.account.address
            ).build_transaction(
                {
                    "from": self.account.address,
                    "nonce": self.w3.eth.get_transaction_count(self.account.address, "pending"),
                    "chainId": CHAIN_ID,
                    "maxFeePerGas": 0,
                    "maxPriorityFeePerGas": 0,
                    "gas": 3_000_000,
                    **({"authorizationList": authorization_list} if authorization_list else {}),
                }
            )
            tx_hash = self.w3.eth.send_raw_transaction(
                self.account.sign_transaction(transaction).raw_transaction
            )
            call_id = uuid.uuid4().hex
            self.calls[call_id] = "0x" + tx_hash.hex()
        return {"id": call_id, "preparedCallIds": [call_id]}  # current and legacy Alchemy forms

    def status(self, call_id: Any) -> dict[str, Any]:
        tx_hash = self.calls.get(call_id) if isinstance(call_id, str) else None
        if tx_hash is None:
            raise RpcError("unknown call id", -32001)
        base = {"id": call_id, "chainId": hex(CHAIN_ID), "atomic": True}
        receipt = (
            self.w3.eth.get_transaction_receipt(tx_hash)
            if self.w3.eth.get_transaction(tx_hash).get("blockNumber")
            else None
        )
        if receipt is None:
            return {**base, "status": 100}
        # UserOperationEvent data words: nonce, success, actualGasCost, actualGasUsed.
        success = receipt["status"] == 1 and any(
            log["topics"][0] == USER_OP_EVENT and int.from_bytes(log["data"][32:64], "big") == 1
            for log in receipt["logs"]
        )
        return {
            **base,
            "status": 200 if success else 500,
            "receipts": [
                {
                    "transactionHash": tx_hash,
                    "blockNumber": hex(receipt["blockNumber"]),
                    "gasUsed": hex(receipt["gasUsed"]),
                    "status": hex(receipt["status"]),
                    "logs": [
                        {
                            "address": log["address"].lower(),
                            "topics": ["0x" + t.hex() for t in log["topics"]],
                            "data": "0x" + log["data"].hex(),
                        }
                        for log in receipt["logs"]
                    ],
                }
            ],
        }


def _rlp(items: list[Any]) -> bytes:
    def item(value: Any) -> bytes:
        if isinstance(value, int):
            value = b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
        if len(value) == 1 and value[0] < 0x80:
            return value
        return bytes([0x80 + len(value)]) + value

    body = b"".join(item(value) for value in items)
    return bytes([0xC0 + len(body)]) + body


def _packed(op: dict[str, Any], signature: bytes) -> tuple[Any, ...]:
    """Alchemy user-operation-v070 fields to the EntryPoint's PackedUserOperation tuple."""

    def u128(name: str) -> bytes:
        return _quantity(op.get(name, "0x0"), name).to_bytes(16, "big")

    paymaster = b""
    if op.get("paymaster") not in (None, "0x"):
        paymaster = (
            bytes.fromhex(_address(op["paymaster"], "paymaster")[2:])
            + u128("paymasterVerificationGasLimit")
            + u128("paymasterPostOpGasLimit")
            + _bytes(op.get("paymasterData", "0x"), "paymasterData")
        )
    init_code = b""
    if op.get("factory") not in (None, "0x"):
        init_code = bytes.fromhex(_address(op["factory"], "factory")[2:]) + _bytes(
            op.get("factoryData", "0x"), "factoryData"
        )
    return (
        to_checksum_address(_address(op.get("sender"), "sender")),
        _quantity(op.get("nonce"), "nonce"),
        init_code,
        _bytes(op.get("callData"), "callData"),
        u128("verificationGasLimit") + u128("callGasLimit"),
        _quantity(op.get("preVerificationGas"), "preVerificationGas"),
        u128("maxPriorityFeePerGas") + u128("maxFeePerGas"),
        paymaster,
        signature,
    )


class SponsorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], sponsor: Sponsor, web_port: int) -> None:
        super().__init__(address, SponsorHandler)
        self.sponsor = sponsor
        self.origins = {f"http://127.0.0.1:{web_port}", f"http://localhost:{web_port}"}


class SponsorHandler(BaseHTTPRequestHandler):
    """JSON-RPC over POST with the CORS preflight a browser needs for `application/json`."""

    protocol_version = "HTTP/1.1"
    server: SponsorServer

    def cors(self) -> str | None:
        origin = self.headers.get("Origin")
        return origin if origin in self.server.origins else None

    def reply(self, status: int, payload: dict[str, Any], origin: str | None) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        origin = self.cors()
        self.send_response(204 if origin else 403)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "POST")
            self.send_header("Access-Control-Allow-Headers", "content-type")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        origin = self.cors()
        request_id: Any = None
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise RpcError("bounded JSON body required", -32600)
            request = json.loads(self.rfile.read(length))
            request_id = request.get("id") if isinstance(request, dict) else None
            method, params = request.get("method"), request.get("params") or []
            if not isinstance(params, list) or len(params) != 1:
                raise RpcError("expected exactly one parameter")
            handler = {
                "wallet_prepareCalls": self.server.sponsor.prepare,
                "wallet_sendPreparedCalls": self.server.sponsor.send,
                "wallet_getCallsStatus": self.server.sponsor.status,
            }.get(method)
            if handler is None:
                raise RpcError(f"unsupported method {method}", -32601)
            self.reply(
                200, {"jsonrpc": "2.0", "id": request_id, "result": handler(params[0])}, origin
            )
        except RpcError as error:
            self.reply(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": error.code, "message": str(error)},
                },
                origin,
            )
        except (ValueError, KeyError, TypeError) as error:
            self.reply(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32600, "message": f"invalid request: {error}"},
                },
                origin,
            )
        except Exception as error:  # noqa: BLE001 - surfaced to the caller, dev only
            self.reply(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32000, "message": f"sponsor failed: {error}"},
                },
                origin,
            )

    def log_message(self, format: str, *args: Any) -> None:
        pass


def main() -> None:
    w3 = Web3(Web3.HTTPProvider(ANVIL_RPC, request_kwargs={"timeout": 30}))
    web_port = int(os.environ.get("RILL_DEV_WEB_PORT", "5273"))
    with SponsorServer(("0.0.0.0", 8094), Sponsor(w3), web_port) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
