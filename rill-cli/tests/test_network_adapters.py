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


def _swap_argv(tmp_path: Path, network: str, *extra: str) -> list[str]:
    identity = tmp_path / "age-identity"
    identity.write_text("AGE-SECRET-KEY-1" + "Q" * 58 + "\n")
    identity.chmod(0o600)
    return [
        "swap", "btc-to-ln", "--network", str(NETWORKS / f"{network}.json"),
        "--crypto-library", str(tmp_path / "missing.so"), "--relay", "wss://relay.example/",
        "--provider", "11" * 32, "--invoice", "lntbs1", "--max-success-fee-sat", "1",
        "--core-port", "1", "--core-cookie", str(tmp_path / "c"), "--wallet", "w",
        "--lnd-port", "1", "--lnd-tls-cert", str(tmp_path / "t"),
        "--lnd-macaroon", str(tmp_path / "m"), "--recipient", "age1x",
        "--identity", str(identity), "--recovery-output", str(tmp_path / "r.age"), *extra,
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("extra", "refusal"),
    [
        ((), "need a relay proxy"),
        (("--relay-proxy", "http://10.0.0.1:9080"), "loopback"),
    ],
)
def test_public_swaps_refuse_direct_relays_before_anything_else(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], extra: tuple[str, ...], refusal: str
) -> None:
    from rill_cli import main  # noqa: PLC0415

    assert main.main(_swap_argv(tmp_path, "signet", *extra)) == 5
    assert refusal in capsys.readouterr().err
    assert not (tmp_path / "r.age").exists()


def test_provider_listing_refuses_direct_relays_on_public_networks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from rill_cli import main  # noqa: PLC0415

    argv = [
        "providers", "list", "--network", str(NETWORKS / "testnet4.json"),
        "--crypto-library", str(tmp_path / "missing.so"), "--relay", "wss://relay.example/",
    ]  # fmt: skip
    assert main.main(argv) == 5
    assert "need a relay proxy" in capsys.readouterr().err
