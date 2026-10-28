"""EVM HTLC client: artifact pinning, lock parameter derivation, and an opt-in Anvil round trip."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from evm_fixtures import ANVIL_KEYS, PAYMENT_HASH, PREIMAGE, evm_terms

from rill_provider.evm_htlc import (
    EvmBackendError,
    EvmHtlcClient,
    LockParams,
    _gas_wei,
    load_artifact,
    masked_runtime_sha256,
)

ROOT = Path(__file__).resolve().parents[2]


def test_packaged_artifact_matches_rill_contracts() -> None:
    shared = json.loads((ROOT / "rill-contracts" / "artifacts" / "erc20-swap-v6.json").read_text())
    assert load_artifact() == shared
    runtime = bytes.fromhex(shared["runtimeBytecode"][2:])
    assert (
        masked_runtime_sha256(runtime, shared["immutableRanges"]) == shared["maskedRuntimeSha256"]
    )
    deployed = bytearray(runtime)  # a deployment patches the domain separator into those ranges
    for item in shared["immutableRanges"]:
        deployed[item["start"] : item["start"] + item["length"]] = b"\xab" * item["length"]
    assert (
        masked_runtime_sha256(bytes(deployed), shared["immutableRanges"])
        == shared["maskedRuntimeSha256"]
    )
    assert masked_runtime_sha256(bytes(deployed), []) != shared["maskedRuntimeSha256"]


def test_lock_params_follow_the_profile_roles() -> None:
    htlc, token = "0x" + "1a" * 20, "0x" + "2b" * 20
    client, provider = "0x" + "ac" * 20, "0x" + "bd" * 20
    forward = LockParams.from_terms(
        evm_terms(
            "erc20-to-ln/v1", htlc=htlc, token=token, client=client, provider=provider, timelock=500
        )
    )
    assert forward == LockParams(PAYMENT_HASH, 1_005_000, token, provider, client, 500)
    reverse = LockParams.from_terms(
        evm_terms(
            "ln-to-erc20/v1", htlc=htlc, token=token, client=client, provider=provider, timelock=500
        )
    )
    assert reverse == LockParams(PAYMENT_HASH, 1_000_000, token, client, provider, 500)
    assert forward.as_args()[0] == bytes.fromhex(PAYMENT_HASH)
    checksummed = forward.as_args()[2]
    assert checksummed != token
    assert checksummed.lower() == token


def test_client_without_signer_refuses_to_send() -> None:
    client = EvmHtlcClient(
        rpc_url="http://127.0.0.1:9",
        chain_id=31337,
        htlc_contract="0x" + "11" * 20,
        signer_private_key=None,
    )
    with pytest.raises(EvmBackendError, match="no EVM signer"):
        _ = client.signer_address


@pytest.fixture
def anvil() -> dict[str, Any]:
    if os.environ.get("RILLSWAP_RUN_ANVIL") != "1":
        pytest.skip("set RILLSWAP_RUN_ANVIL=1 with a local Anvil at RILLSWAP_ANVIL_RPC")
    from web3 import HTTPProvider, Web3  # noqa: PLC0415 - opt-in only

    web3 = Web3(HTTPProvider(os.environ.get("RILLSWAP_ANVIL_RPC", "http://127.0.0.1:8545")))
    assert web3.eth.chain_id == 31337
    token_artifact = json.loads(
        (ROOT / "rill-payments" / "examples" / "demo-shop" / "dev-stablecoin.json").read_text()
    )
    from eth_account import Account  # noqa: PLC0415

    deployer = Account.from_key(ANVIL_KEYS[0])

    def deploy(artifact: dict[str, Any], *args: Any) -> str:  # noqa: ANN401
        factory = web3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
        transaction = factory.constructor(*args).build_transaction(
            {"from": deployer.address, "nonce": web3.eth.get_transaction_count(deployer.address)}
        )
        tx_hash = web3.eth.send_raw_transaction(
            deployer.sign_transaction(transaction).raw_transaction
        )
        return str(web3.eth.wait_for_transaction_receipt(tx_hash)["contractAddress"]).lower()

    htlc = deploy(load_artifact())
    token = deploy(token_artifact, "Fake USDC", "fUSDC")
    return {"web3": web3, "htlc": htlc, "token": token, "token_abi": token_artifact["abi"]}


def _mined(client: EvmHtlcClient, tx_hash: str) -> None:
    """Wait for interval-mined Anvil to include the transaction."""
    import time  # noqa: PLC0415

    for _ in range(100):
        receipt = client.receipt(tx_hash)
        if receipt is not None:
            assert receipt.status == "success"
            return
        time.sleep(0.1)
    raise AssertionError("transaction was not mined")


@pytest.mark.anvil
def test_anvil_lock_claim_and_refund_round_trip(anvil: dict[str, Any]) -> None:  # noqa: PLR0915
    from eth_account import Account  # noqa: PLC0415
    from web3 import Web3  # noqa: PLC0415

    web3 = anvil["web3"]
    provider = EvmHtlcClient(
        rpc_url=web3.provider.endpoint_uri,
        chain_id=31337,
        htlc_contract=anvil["htlc"],
        signer_private_key=ANVIL_KEYS[1],
    )
    client = EvmHtlcClient(
        rpc_url=web3.provider.endpoint_uri,
        chain_id=31337,
        htlc_contract=anvil["htlc"],
        signer_private_key=ANVIL_KEYS[2],
    )
    provider.verify_deployment()
    with pytest.raises(EvmBackendError, match="chain id"):
        EvmHtlcClient(
            rpc_url=web3.provider.endpoint_uri,
            chain_id=1,
            htlc_contract=anvil["htlc"],
            signer_private_key=None,
        ).verify_deployment()
    with pytest.raises(EvmBackendError, match="no contract code"):
        EvmHtlcClient(
            rpc_url=web3.provider.endpoint_uri,
            chain_id=31337,
            htlc_contract="0x" + "33" * 20,
            signer_private_key=None,
        ).verify_deployment()

    token_contract = web3.eth.contract(
        address=Web3.to_checksum_address(anvil["token"]), abi=anvil["token_abi"]
    )
    minter = Account.from_key(ANVIL_KEYS[0])
    for owner in (provider.signer_address, client.signer_address):
        transaction = token_contract.functions.mint(
            Web3.to_checksum_address(owner), 10_000_000
        ).build_transaction(
            {"from": minter.address, "nonce": web3.eth.get_transaction_count(minter.address)}
        )
        web3.eth.wait_for_transaction_receipt(
            web3.eth.send_raw_transaction(minter.sign_transaction(transaction).raw_transaction)
        )
    assert provider.token_decimals(anvil["token"]) == 6

    # erc20-to-ln: the client locks to the provider, the provider claims with the preimage.
    start = provider.block_number()
    forward = evm_terms(
        "erc20-to-ln/v1",
        htlc=anvil["htlc"],
        token=anvil["token"],
        client=client.signer_address,
        provider=provider.signer_address,
        timelock=start + 1_000_000,
    )
    params = LockParams.from_terms(forward)
    approval = client.ensure_allowance(anvil["token"], params.amount)
    assert approval is not None
    _mined(client, approval)
    assert client.ensure_allowance(anvil["token"], params.amount) is None
    lock_tx = client.lock(params)
    _mined(provider, lock_tx)

    lockups = provider.find_lockups(
        PAYMENT_HASH, from_block=start, to_block=provider.block_number()
    )
    assert len(lockups) == 1
    assert lockups[0].matches(params)
    assert lockups[0].tx_hash == lock_tx
    assert provider.lock_active(params)
    assert provider.confirmations(lock_tx) >= 1
    before = provider.token_balance(anvil["token"], provider.signer_address)
    claim_tx = provider.claim(params, PREIMAGE)
    _mined(provider, claim_tx)
    claim = client.find_claim(PAYMENT_HASH, from_block=start, to_block=client.block_number())
    assert claim is not None
    assert claim.preimage == PREIMAGE
    assert claim.tx_hash == claim_tx
    assert provider.token_balance(anvil["token"], provider.signer_address) == before + params.amount
    assert not provider.lock_active(params)
    with pytest.raises(EvmBackendError, match="would revert"):
        provider.claim(params, PREIMAGE)

    # ln-to-erc20: the provider locks to the client and refunds after the timelock passes.
    reverse = evm_terms(
        "ln-to-erc20/v1",
        htlc=anvil["htlc"],
        token=anvil["token"],
        client=client.signer_address,
        provider=provider.signer_address,
        timelock=provider.block_number() + 3,
    )
    reverse_params = LockParams.from_terms(reverse)
    approval = provider.ensure_allowance(anvil["token"], reverse_params.amount)
    if approval is not None:
        _mined(provider, approval)
    _mined(provider, provider.lock(reverse_params))
    with pytest.raises(EvmBackendError, match="would revert"):
        provider.refund(reverse_params)  # SwapNotTimedOut
    web3.provider.make_request("anvil_mine", [hex(4)])
    _mined(provider, provider.refund(reverse_params))

    assert not provider.lock_active(reverse_params)
    v, r, s = provider.sign_cooperative_refund(
        params
    )  # provider is claimAddress of the forward lock
    assert v in (27, 28)
    assert len(r) == len(s) == 64


@pytest.mark.anvil
def test_anvil_superseded_needs_our_nonce_mined_by_another_transaction(
    anvil: dict[str, Any],
) -> None:
    """Only a mined other use of the nonce marks a recorded transaction as dead."""
    from web3 import Web3  # noqa: PLC0415

    web3 = anvil["web3"]
    key = "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e"  # Anvil #6
    client = EvmHtlcClient(
        rpc_url=web3.provider.endpoint_uri,
        chain_id=31337,
        htlc_contract=anvil["htlc"],
        signer_private_key=key,
    )
    token = web3.eth.contract(
        address=Web3.to_checksum_address(anvil["token"]), abi=anvil["token_abi"]
    )
    spender = Web3.to_checksum_address(anvil["htlc"])
    recorded = client._prepare(token.functions.approve(spender, 1))  # noqa: SLF001 - never sent
    assert not client.superseded(recorded.raw, 1)  # its nonce is still free
    other = client._send(token.functions.approve(spender, 2))  # noqa: SLF001 - same nonce
    _mined(client, other)
    assert client.superseded(recorded.raw, 1)
    mined_at = web3.eth.get_transaction_receipt(other)["blockNumber"]
    before = client.block_number() - mined_at + 5  # a few blocks before it was mined
    assert not client.superseded(recorded.raw, before)  # not that deep yet
    assert not client.superseded(recorded.raw, 10**9)  # no such block: unproven
    other_raw = bytes(web3.eth.get_raw_transaction(other))
    assert not client.superseded(other_raw, 1)  # mined itself
    stranger = EvmHtlcClient(
        rpc_url=web3.provider.endpoint_uri,
        chain_id=31337,
        htlc_contract=anvil["htlc"],
        signer_private_key=ANVIL_KEYS[2],
    )
    assert not stranger.superseded(recorded.raw, 1)  # not signed by this signer
    assert not client.superseded(b"\x02not a transaction", 1)


@pytest.mark.parametrize(
    ("receipt", "gas"),
    [
        ({"gasUsed": 21_000, "effectiveGasPrice": 3 * 10**9}, 63 * 10**12),
        ({"gasUsed": 21_000}, None),  # a node that omits the price
        ({"gasUsed": "bad", "effectiveGasPrice": 1}, None),
        ({"gasUsed": -1, "effectiveGasPrice": 1}, None),
    ],
)
def test_receipt_gas_is_used_gas_times_the_effective_price(
    receipt: dict[str, Any], gas: int | None
) -> None:
    assert _gas_wei(receipt) == gas
