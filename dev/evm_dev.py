"""Dev Anvil chain: deploy the Boltz ERC20Swap v6 HTLC and a fake stablecoin once.

Addresses are recorded in ``/state/evm/contracts.json``. Existing records are
reused while their code is still on the chain; a chain reset (Anvil volume
removed) redeploys. Accounts are Anvil's deterministic development keys:
0 deploys, 1 is the user (same as the demo shop's buyer), 3 is the maker's
HTLC signer. Nothing here holds real value.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from web3 import Web3

SRC = Path(os.environ.get("RILL_DEV_SRC", "/src"))
ANVIL_RPC = os.environ.get("RILL_DEV_ANVIL_RPC", "http://anvil:8545")
CHAIN_ID = 31337
HTLC_ARTIFACT = SRC / "rill-contracts/artifacts/erc20-swap-v6.json"
TOKEN_ARTIFACT = SRC / "rill-payments/examples/demo-shop/dev-stablecoin.json"
ANVIL_KEYS = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
)
DEPLOYER, USER, _SHOP, MAKER = range(4)
TOKEN = {"name": "Fake USD Coin", "symbol": "fUSDC", "decimals": 6}
GRANT = 1_000_000 * 10 ** TOKEN["decimals"]  # one million tokens each
# Fixed dev price: 1 BTC = 100,000 fUSDC, in base units per BTC.
RATE_TOKEN_BASE_PER_BTC = 100_000 * 10 ** TOKEN["decimals"]


def account_address(index: int) -> str:
    return Web3().eth.account.from_key(ANVIL_KEYS[index]).address.lower()


def _web3() -> Web3:
    w3 = Web3(Web3.HTTPProvider(ANVIL_RPC, request_kwargs={"timeout": 30}))
    deadline = time.monotonic() + 120
    while True:
        try:
            if w3.eth.chain_id == CHAIN_ID:
                return w3
            raise SystemExit(f"Anvil at {ANVIL_RPC} is not chain {CHAIN_ID}")
        except SystemExit:
            raise
        except Exception:  # noqa: BLE001 - not up yet
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def _send(w3: Web3, key: str, transaction: dict[str, Any]) -> str:
    account = w3.eth.account.from_key(key)
    transaction = {
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "chainId": CHAIN_ID,
        "gasPrice": 0,
        **transaction,
    }
    transaction["gas"] = w3.eth.estimate_gas(transaction)
    signed = account.sign_transaction(transaction)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt["status"] != 1:
        raise SystemExit(f"dev EVM transaction reverted: {tx_hash.hex()}")
    return receipt


def _deploy(w3: Web3, artifact_path: Path, *args: Any) -> str:
    artifact = json.loads(artifact_path.read_text())
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    data = contract.constructor(*args).build_transaction({"gasPrice": 0})["data"]
    receipt = _send(w3, ANVIL_KEYS[DEPLOYER], {"data": data})
    return receipt["contractAddress"].lower()


def _has_code(w3: Web3, address: str) -> bool:
    return len(w3.eth.get_code(Web3.to_checksum_address(address))) > 0


def ensure_evm(state: Path, log: Any) -> dict[str, Any]:
    """Deploy (once) and return the dev chain's contract record."""
    record_path = state / "evm" / "contracts.json"
    w3 = _web3()
    if record_path.exists():
        record = json.loads(record_path.read_text())
        if _has_code(w3, record["htlc_contract"]) and _has_code(w3, record["token_contract"]):
            return record
        log("dev EVM contracts missing from the chain (reset?): redeploying")
    record_path.parent.mkdir(parents=True, exist_ok=True)
    log("deploying ERC20Swap v6 and fUSDC on Anvil")
    htlc = _deploy(w3, HTLC_ARTIFACT)
    token = _deploy(w3, TOKEN_ARTIFACT, TOKEN["name"], TOKEN["symbol"])
    erc20 = w3.eth.contract(
        address=Web3.to_checksum_address(token),
        abi=json.loads(TOKEN_ARTIFACT.read_text())["abi"],
    )
    for index in (USER, MAKER):
        holder = Web3.to_checksum_address(account_address(index))
        data = erc20.functions.mint(holder, GRANT).build_transaction({"gasPrice": 0})["data"]
        _send(w3, ANVIL_KEYS[DEPLOYER], {"to": erc20.address, "data": data})
    record = {
        "chain_id": CHAIN_ID,
        "htlc_contract": htlc,
        "token_contract": token,
        "token_symbol": TOKEN["symbol"],
        "token_decimals": TOKEN["decimals"],
        "rate_token_base_per_btc": RATE_TOKEN_BASE_PER_BTC,
        "maker_address": account_address(MAKER),
        "user_address": account_address(USER),
    }
    record_path.write_text(json.dumps(record, indent=1) + "\n")
    return record
