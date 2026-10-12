"""The ``evm`` operator config section and the EVM-profile process wiring (RS-010)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from test_cli import _config

from rill_provider import cli
from rill_provider.operator_config import (
    OperatorConfigError,
    load_config,
    read_evm_signer_key,
)

if TYPE_CHECKING:
    from pathlib import Path

KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
EVM = {
    "rpc_url": "http://127.0.0.1:8545",
    "chain_id": 31337,
    "name": "anvil-dev",
    "htlc_contract": "0x" + "1a" * 20,
    "block_seconds": 2,
    "deployment_namespace": "dev",
    "signer_key_file": "evm-signer.key",
    "tokens": [
        {
            "token_contract": "0x" + "2b" * 20,
            "token_symbol": "fUSDC",
            "token_decimals": 6,
            "rate_token_base_per_btc": 100_000_000_000,
        }
    ],
    "forward_timelock_delay_blocks": 60_000,
    "reverse_timelock_delay_blocks": 600,
    "learn_and_claim_seconds": 600,
    "refund_and_ln_resolution_seconds": 600,
}


def _evm_config(tmp_path: Path, profile: str = "erc20-to-ln/v1", **evm: object) -> Path:
    key = tmp_path / "evm-signer.key"
    key.write_text(f"0x{KEY}\n")
    key.chmod(0o600)
    return _config(
        tmp_path,
        handshake={
            "profile": profile,
            "encryption_suites": ["noise-xk-secp256k1-chachapoly-sha256/v1"],
            "capabilities": ["core/v1", "recovery/v1"],
        },
        terms={
            "profiles": [profile],
            "amount_bands": [[1000, 100000]],
            "base_fee_sat": 50,
            "proportional_millionths": 1000,
            "slot": "regtest-main",
        },
        evm=EVM | evm,
    )


def test_evm_section_yields_assets_rates_schedule_and_a_resolved_key_path(tmp_path: Path) -> None:
    config = load_config(_evm_config(tmp_path))
    assert config.evm is not None
    assert config.evm.signer_key_file == tmp_path / "evm-signer.key"
    (asset,) = config.evm.assets()
    assert (asset.chain_id, asset.htlc_version, asset.token_symbol, asset.block_seconds) == (
        31337,
        6,
        "fUSDC",
        2,
    )
    assert config.evm.rates() == {"0x" + "2b" * 20: 100_000_000_000}
    assert config.evm.schedule().forward_timelock_delay_blocks == 60_000
    assert read_evm_signer_key(config.evm.signer_key_file) == "0x" + KEY


@pytest.mark.parametrize(
    "bad",
    [
        {"htlc_contract": "0x" + "1A" * 20},  # not lowercase
        {"tokens": []},
        {"forward_timelock_delay_blocks": 1},
        {"rpc_url": "ftp://x"},
        {"surprise": 1},
    ],
)
def test_evm_section_refuses_malformed_values(tmp_path: Path, bad: dict[str, object]) -> None:
    with pytest.raises(OperatorConfigError, match="config refused"):
        load_config(_evm_config(tmp_path, **bad))


def test_evm_profiles_never_negotiate_the_cooperative_claim_feature(tmp_path: Path) -> None:
    for profile in ("erc20-to-ln/v1", "ln-to-erc20/v1"):
        policy = load_config(_evm_config(tmp_path, profile)).handshake_policy()
        assert COOPERATIVE_CLAIM_FEATURE not in policy.features
    assert COOPERATIVE_CLAIM_FEATURE in load_config(_config(tmp_path)).handshake_policy().features


def test_signer_key_file_must_be_a_private_hex_key(tmp_path: Path) -> None:
    path = tmp_path / "k"
    path.write_text(KEY)
    path.chmod(0o640)
    with pytest.raises(OperatorConfigError, match="0600"):
        read_evm_signer_key(path)
    path.chmod(0o600)
    assert read_evm_signer_key(path) == "0x" + KEY
    path.write_text("zz" * 32)
    with pytest.raises(OperatorConfigError, match="hex key"):
        read_evm_signer_key(path)
    with pytest.raises(OperatorConfigError, match="unavailable"):
        read_evm_signer_key(tmp_path / "missing")


def test_evm_profile_process_needs_evm_core_and_the_matching_lnd_macaroon(tmp_path: Path) -> None:
    import asyncio  # noqa: PLC0415

    for profile, macaroon in (
        ("erc20-to-ln/v1", "payment_macaroon"),
        ("ln-to-erc20/v1", "invoices_macaroon"),
    ):
        config = load_config(_evm_config(tmp_path, profile))
        with pytest.raises(
            OperatorConfigError, match=f"needs evm, bitcoin_core and lnd.{macaroon}"
        ):
            asyncio.run(cli._serve(config, None, ""))  # noqa: SLF001
    assert cli._evm_settlement(load_config(_config(tmp_path)), None, None) is None  # type: ignore[arg-type]  # noqa: SLF001
