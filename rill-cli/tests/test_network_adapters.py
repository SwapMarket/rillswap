"""Client adapters use each network's labels; funding keeps the mainnet gate."""

from __future__ import annotations

from pathlib import Path

import pytest
from rill_core.wire.types import NetworkIdentity

from rill_cli import recovery_core_observation as observation
from rill_cli.wallet_rpc import WalletRpc

NETWORKS = Path(__file__).parents[2] / "rill-docs" / "networks"
CHAINS = {
    "mainnet": "main",
    "signet": "signet",
    "testnet4": "testnet4",
    "regtest-rillswap-e2e-v1": "regtest",
}


def _network(name: str) -> NetworkIdentity:
    return NetworkIdentity.model_validate_json((NETWORKS / f"{name}.json").read_bytes())


@pytest.mark.parametrize("name", CHAINS)
def test_wallet_funding_is_gated_only_on_mainnet(tmp_path: Path, name: str) -> None:
    if name == "mainnet":
        with pytest.raises(ValueError, match="release-accepted"):
            WalletRpc(port=1, cookie_path=tmp_path, wallet="w", network=_network(name))
        return
    wallet = WalletRpc(port=1, cookie_path=tmp_path, wallet="w", network=_network(name))
    assert wallet._chain == CHAINS[name]  # noqa: SLF001 - Core's label, not our name


@pytest.mark.parametrize("name", CHAINS)
def test_recovery_observation_works_on_every_network(tmp_path: Path, name: str) -> None:
    reader = observation.RecoveryCoreReader(port=1, cookie_path=tmp_path, network=_network(name))
    chain = CHAINS[name]
    tip = {"chain": chain, "bestblockhash": "ab" * 32, "blocks": 3, "initialblockdownload": False}
    assert observation._tip(tip, reader._chain) == ("ab" * 32, 3)  # noqa: SLF001
    for other in set(CHAINS.values()) - {chain}:
        with pytest.raises(observation.RecoveryCoreProtocolError):
            observation._tip(tip | {"chain": other}, reader._chain)  # noqa: SLF001


def test_unsupported_identities_are_refused(tmp_path: Path) -> None:
    legacy = _network("signet").model_copy(update={"name": "testnet3"})
    with pytest.raises(ValueError, match="supported"):
        observation.RecoveryCoreReader(port=1, cookie_path=tmp_path, network=legacy)
    with pytest.raises(ValueError, match="release-accepted"):
        WalletRpc(port=1, cookie_path=tmp_path, wallet="w", network=legacy)
