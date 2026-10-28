"""The Docker image's ``rill-provider-init`` setup command (docker/init.py)."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import re
import stat
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from rill_provider.core_tx_bytes import CORE_RPC_METHODS
from rill_provider.operator_config import OperatorConfigError, load_config

if TYPE_CHECKING:
    from types import ModuleType

NETWORKS = Path(__file__).parents[2] / "rill-docs" / "networks"
P2WPKH = "0014" + "11" * 20
XONLY = "ab" * 32
RECIPIENT = "age1" + "q" * 58


def _load_init() -> ModuleType:
    path = Path(__file__).parents[1] / "docker" / "init.py"
    spec = importlib.util.spec_from_file_location("rill_provider_docker_init", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


init = _load_init()


def _signet() -> dict[str, object]:
    network: dict[str, object] = json.loads((NETWORKS / "signet.json").read_text())
    return network


def _config(profile: str, **overrides: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "profile": profile,
        "network": _signet(),
        "xonly": XONLY,
        "recipient": RECIPIENT,
        "destination_script": P2WPKH,
        "core_wallet": "rillswap",
        "relays": init.DEFAULT_RELAYS,
        "affirm_store_authority": True,
    }
    config: dict[str, object] = init.maker_config(**(arguments | overrides))
    return config


def _write(tmp_path: Path, config: dict[str, object]) -> Path:
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(config))
    return path


def test_core_credential_writes_a_cookie_that_its_rpcauth_line_accepts(tmp_path: Path) -> None:
    out = tmp_path / "core.cookie"
    lines = init.core_credential(out, CORE_RPC_METHODS).splitlines()

    user, password = out.read_text().strip().split(":", 1)
    assert user == "__cookie__"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    (rpcauth,) = (line.removeprefix("rpcauth=") for line in lines if line.startswith("rpcauth="))
    auth_user, salted = rpcauth.split(":", 1)
    salt, digest = salted.split("$")
    # Core's HTTP auth check (src/httprpc.cpp CheckUserAuthorized).
    expected = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    assert auth_user == "__cookie__"
    assert hmac.compare_digest(digest, expected)
    assert f"rpcwhitelist=__cookie__:{','.join(CORE_RPC_METHODS)}" in lines
    assert "rpcwhitelistdefault=0" in lines


def test_core_credential_never_overwrites(tmp_path: Path) -> None:
    out = tmp_path / "core.cookie"
    out.write_text("__cookie__:existing\n")

    with pytest.raises(init.RefusedError, match="already exists"):
        init.core_credential(out, CORE_RPC_METHODS)
    assert out.read_text() == "__cookie__:existing\n"


@pytest.mark.parametrize("profile", ["btc-to-ln", "ln-to-btc"])
def test_bitcoin_maker_config_passes_the_provider_schema(tmp_path: Path, profile: str) -> None:
    config = load_config(_write(tmp_path, _config(profile)))

    assert config.terms.slot == f"signet-{profile}"
    assert config.handshake.profile == f"{profile}/v1"
    assert config.provider_destination_script == P2WPKH
    assert config.relay_proxy == init.RELAY_PROXY
    assert config.bitcoin_core is not None
    assert config.bitcoin_core.port == init.CORE_PORT
    assert config.lnd is not None
    assert config.lnd.port == init.LND_PORT
    assert config.lnd.payment_macaroon is not None
    assert (config.lnd.invoices_macaroon is not None) is (profile == "ln-to-btc")
    # Up to 10M sat, lowered to the maker's liquidity at each announcement.
    assert config.terms.amount_bands == ((10_000, 10_000_000),)
    assert config.terms.follow_liquidity is True


def test_default_relays_match_the_web_app_and_are_all_served(tmp_path: Path) -> None:
    web = Path(__file__).parents[2] / "rill-web" / "src" / "swap" / "publicRelays.ts"
    assert tuple(re.findall(r'"(wss?://[^"]+)"', web.read_text())) == init.DEFAULT_RELAYS
    config = load_config(_write(tmp_path, _config("btc-to-ln")))
    # The setup always configures the Tor proxy, so the onion relays are announced too.
    assert config.service_policy().relay_urls == init.DEFAULT_RELAYS
    assert any(url.startswith("ws://") for url in init.DEFAULT_RELAYS)


@pytest.mark.parametrize(("network", "ceiling"), [("signet", 2), ("mainnet", None)])
def test_only_signet_makers_cap_core_fee_estimates(
    tmp_path: Path, network: str, ceiling: int | None
) -> None:
    identity = json.loads((NETWORKS / f"{network}.json").read_text())
    config = load_config(_write(tmp_path, _config("ln-to-btc", network=identity)))

    assert config.bitcoin_core is not None
    assert config.bitcoin_core.max_fee_estimate_sat_vb == ceiling


@pytest.mark.parametrize("profile", ["erc20-to-ln", "ln-to-erc20"])
def test_erc20_maker_config_is_refused_until_the_operator_fills_it(
    tmp_path: Path, profile: str
) -> None:
    config = _config(profile, destination_script=None, core_wallet=None)

    with pytest.raises(OperatorConfigError):
        load_config(_write(tmp_path, config))

    evm = config["evm"]
    assert isinstance(evm, dict)
    evm |= {
        "rpc_url": "https://rpc.example",
        "chain_id": 11_155_111,
        "name": "sepolia",
        "htlc_contract": "0x" + "1a" * 20,
        "forward_timelock_delay_blocks": 7_200,
        "reverse_timelock_delay_blocks": 600,
        "learn_and_claim_seconds": 600,
        "refund_and_ln_resolution_seconds": 600,
    }
    evm["tokens"][0] |= {"token_contract": "0x" + "2b" * 20, "rate_token_base_per_btc": 10**11}
    loaded = load_config(_write(tmp_path, config))
    assert loaded.evm is not None
    assert loaded.evm.signer_key_file == tmp_path / "evm-signer.key"
    assert loaded.lnd is not None
    assert (loaded.lnd.invoices_macaroon is not None) is (profile == "ln-to-erc20")


@pytest.mark.parametrize(
    ("profile", "overrides", "message"),
    [
        ("btc-to-ln", {"destination_script": None}, "destination-script"),
        ("btc-to-ln", {"destination_script": "76a914" + "11" * 20 + "88ac"}, "P2WPKH or P2TR"),
        ("ln-to-btc", {"core_wallet": None}, "core-wallet"),
    ],
)
def test_maker_config_refuses_missing_bitcoin_inputs(
    profile: str, overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(init.RefusedError, match=message):
        _config(profile, **overrides)


def _args(profile: str, **overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "profile": profile,
        "network": "signet",
        "destination_script": P2WPKH,
        "core_wallet": "rillswap",
        "relay": None,
        "affirm_store_authority": True,
    }
    return argparse.Namespace(**(values | overrides))


@pytest.fixture
def networks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(init, "NETWORKS", NETWORKS)


def _fake_provision(out: Path, recipient: str) -> str:
    assert recipient.startswith("age1")
    out.write_text("identity")
    return XONLY


@pytest.mark.usefixtures("networks")
def test_init_maker_creates_private_files_once(tmp_path: Path) -> None:
    (tmp_path / "makers").mkdir()
    (tmp_path / "stores").mkdir()

    report = init.init_maker(tmp_path, _args("ln-to-erc20"), _fake_provision)

    home = tmp_path / "makers" / "ln-to-erc20"
    assert report[0] == f"provider identity: {XONLY}"
    assert report[1].startswith("EVM signer address (fund it with gas): 0x")
    for path in (home, tmp_path / "stores" / "ln-to-erc20"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    for name in ("custody.key", "evm-signer.key", "provider.json"):
        assert stat.S_IMODE((home / name).stat().st_mode) == 0o600
    assert (home / "custody.key").read_text().startswith("AGE-SECRET-KEY-")
    config = json.loads((home / "provider.json").read_text())
    assert config["provider_identity_xonly"] == XONLY
    assert config["relay_urls"] == list(init.DEFAULT_RELAYS)

    custody = (home / "custody.key").read_text()
    with pytest.raises(init.RefusedError, match="already exists"):
        init.init_maker(tmp_path, _args("ln-to-erc20"), _fake_provision)
    assert (home / "custody.key").read_text() == custody


@pytest.mark.usefixtures("networks")
def test_init_maker_validates_before_creating_anything(tmp_path: Path) -> None:
    (tmp_path / "makers").mkdir()
    (tmp_path / "stores").mkdir()

    with pytest.raises(init.RefusedError, match="core-wallet"):
        init.init_maker(tmp_path, _args("ln-to-btc", core_wallet=None), _fake_provision)

    assert not (tmp_path / "makers" / "ln-to-btc").exists()
    assert not (tmp_path / "stores" / "ln-to-btc").exists()


@pytest.mark.usefixtures("networks")
def test_init_maker_refuses_a_non_empty_store(tmp_path: Path) -> None:
    (tmp_path / "makers").mkdir()
    store = tmp_path / "stores" / "btc-to-ln"
    store.mkdir(parents=True)
    (store / "live.sqlite").write_text("")

    with pytest.raises(init.RefusedError, match="already exists"):
        init.init_maker(tmp_path, _args("btc-to-ln"), _fake_provision)
    assert not (tmp_path / "makers" / "btc-to-ln").exists()
