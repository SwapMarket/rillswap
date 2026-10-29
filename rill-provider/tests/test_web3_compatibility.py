"""Web3 upgrades preserve transactions recorded by the previous runtime."""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

from eth_account import Account
from hexbytes import HexBytes
from web3 import Web3

from rill_provider.evm_htlc import EvmHtlcClient

if TYPE_CHECKING:
    import pytest

# Generated with Web3 7.16.0 and eth-account 0.14.0, before the Web3 8 upgrade.
# This is a public test key, never an account holding real funds.
KEY = "01" * 32
RECORDED_RAW = bytes.fromhex(
    "02f86e827a6907843b9aca008477359400825208941111111111111111111111111111111111111111"
    "82303980c080a0f01f3e1126c5a2996f60a9d6e34dc27bbdaedd04e7ade72d0862d8cda61b9527"
    "a004c4c73f6a21f4c841e15ea150be0ee9e0240975ce40b2569cd8e718a3b822d2"
)
RECORDED_HASH = "7298480b633274eb188ed64197f09e68ac22e4aabb9de0b0d307c42d8998deda"


def test_web3_import_does_not_load_deprecated_websockets() -> None:
    subprocess.run(
        [
            sys.executable,
            "-W",
            "error::DeprecationWarning",
            "-c",
            "from web3 import HTTPProvider, Web3",
        ],
        check=True,
        capture_output=True,
    )


def test_preupgrade_signed_transaction_is_replayed_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = EvmHtlcClient(
        rpc_url="http://127.0.0.1:9",
        chain_id=31337,
        htlc_contract="0x" + "11" * 20,
        signer_private_key=KEY,
    )
    assert bytes(Web3.keccak(RECORDED_RAW)).hex() == RECORDED_HASH
    assert Account.recover_transaction(RECORDED_RAW).lower() == client.signer_address
    submissions: list[bytes] = []

    def submit(raw: bytes) -> HexBytes:
        submissions.append(raw)
        return HexBytes(RECORDED_HASH)

    monkeypatch.setattr(client._web3.eth, "send_raw_transaction", submit)  # noqa: SLF001
    assert client.broadcast(RECORDED_RAW) == RECORDED_HASH
    assert submissions == [RECORDED_RAW]

    monkeypatch.setattr(client, "receipt", lambda _: None)
    monkeypatch.setattr(client, "block_number", lambda: 10)
    monkeypatch.setattr(client._web3.eth, "get_transaction_count", lambda *_: 7)  # noqa: SLF001
    assert not client.superseded(RECORDED_RAW, 1)
    monkeypatch.setattr(client._web3.eth, "get_transaction_count", lambda *_: 8)  # noqa: SLF001
    assert client.superseded(RECORDED_RAW, 1)
