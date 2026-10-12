"""Independent test vectors for src/swap/gasSponsor.ts, computed with eth-account and eth-abi.

Run with the provider's virtualenv (web3 7.x / eth-account 0.14):
    rill-provider/tmp/ci-venv/bin/python rill-web/scripts/gas-sponsor-vectors.py > rill-web/unit/fixtures/gasSponsorVectors.json
"""

from __future__ import annotations

import json

from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address

KEY = "0x" + "11" * 32
account = Account.from_key(KEY)
CHAIN_ID = 31337
ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032"
DELEGATE = "0x77021100bd87b7008e5e1989d0eb38555d0d0000"
CALLS = [
    ("0x84ea74d481ee0a5332c457a4d796187f6ba67feb", "0x" + "ab" * 196),
    ("0x9e545e3c0baab3e08cdfd552c960a1050f373042", "0xa9059cbb" + "00" * 12 + "70997970c51812dc3a010c7d01b50e0d17dc79c8" + "00" * 31 + "01"),
]


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


call_data = "0x" + (
    selector("executeBatch((address,uint256,bytes)[])")
    + encode(["(address,uint256,bytes)[]"], [[(to_checksum_address(to), 0, bytes.fromhex(data[2:])) for to, data in CALLS]])
).hex()

authorization = {"chainId": CHAIN_ID, "address": to_checksum_address(DELEGATE), "nonce": 7}
signed_auth = account.sign_authorization(authorization)

user_op = {
    "sender": account.address.lower(),
    "nonce": hex(1 << 64),
    "callData": call_data,
    "callGasLimit": hex(400_000),
    "verificationGasLimit": hex(300_000),
    "preVerificationGas": hex(60_000),
    "maxFeePerGas": "0x0",
    "maxPriorityFeePerGas": "0x0",
}
sponsored_op = {
    **user_op,
    "maxFeePerGas": hex(2_000_000_000),
    "maxPriorityFeePerGas": hex(1_000_000_000),
    "paymaster": "0x00000000000000000000000000000000000000aa",
    "paymasterVerificationGasLimit": hex(50_000),
    "paymasterPostOpGasLimit": hex(20_000),
    "paymasterData": "0xdeadbeef",
}


def pack(op: dict[str, str]) -> bytes:
    def u128(name: str) -> bytes:
        return int(op.get(name, "0x0"), 16).to_bytes(16, "big")

    paymaster = b""
    if "paymaster" in op:
        paymaster = bytes.fromhex(op["paymaster"][2:]) + u128("paymasterVerificationGasLimit") + u128("paymasterPostOpGasLimit") + bytes.fromhex(op["paymasterData"][2:])
    inner = keccak(
        encode(
            ["address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"],
            [
                to_checksum_address(op["sender"]),
                int(op["nonce"], 16),
                keccak(b""),
                keccak(bytes.fromhex(op["callData"][2:])),
                u128("verificationGasLimit") + u128("callGasLimit"),
                int(op["preVerificationGas"], 16),
                u128("maxPriorityFeePerGas") + u128("maxFeePerGas"),
                keccak(paymaster),
            ],
        )
    )
    return keccak(encode(["bytes32", "address", "uint256"], [inner, to_checksum_address(ENTRY_POINT), CHAIN_ID]))


op_hash = pack(user_op)
signed_op = account.sign_message(encode_defunct(op_hash))

print(
    json.dumps(
        {
            "secret": KEY,
            "address": account.address.lower(),
            "chainId": CHAIN_ID,
            "entryPoint": ENTRY_POINT,
            "delegate": DELEGATE,
            "calls": [{"to": to, "data": data} for to, data in CALLS],
            "callData": call_data,
            "authorization": {
                "nonce": 7,
                "digest": "0x" + signed_auth.authorization_hash.hex(),
                "signature": "0x" + signed_auth.r.to_bytes(32, "big").hex() + signed_auth.s.to_bytes(32, "big").hex() + f"{signed_auth.y_parity + 27:02x}",
            },
            "userOp": user_op,
            "userOpHash": "0x" + op_hash.hex(),
            "userOpSignature": "0x" + signed_op.signature.hex(),
            "sponsoredUserOp": sponsored_op,
            "sponsoredUserOpHash": "0x" + pack(sponsored_op).hex(),
        },
        indent=1,
    )
)
