"""``--max-fee-estimate-sat-vb``: cap the own-node estimate in btc-to-ln cooperative checks."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock

import pytest
from rill_core.networks import DEFAULT_SIGNET_CHALLENGE, PUBLIC_CONSENSUS_PROFILE
from rill_core.wire.types import NetworkIdentity

from rill_cli import swap_command, wallet_rpc
from rill_cli.live_swap import SwapError
from rill_cli.wallet_rpc import WalletRpc

if TYPE_CHECKING:
    from pathlib import Path

REQUIRED = [
    "--network",
    "unused",
    "--crypto-library",
    "unused",
    "--relay",
    "ws://unused",
    "--provider",
    "00" * 32,
    "--max-success-fee-sat",
    "1",
    "--core-port",
    "1",
    "--core-cookie",
    "unused",
    "--lnd-port",
    "2",
    "--lnd-tls-cert",
    "unused",
    "--recipient",
    "unused",
    "--identity",
    "unused",
    "--recovery-output",
    "unused",
    "--wallet",
    "unused",
    "--lnd-macaroon",
    "unused",
]


def _parse(*extra: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    swap_command.add_parser(parser.add_subparsers(dest="category"))
    return parser.parse_args(["swap", "btc-to-ln", *REQUIRED, "--invoice", "lnbc1x", *extra])


def _signet() -> NetworkIdentity:
    return NetworkIdentity(
        family="bitcoin",
        name="signet",
        genesis_hash="00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
        signet_challenge=DEFAULT_SIGNET_CHALLENGE,
        consensus_profile=PUBLIC_CONSENSUS_PROFILE,
        deployment_namespace=None,
    )


def test_flag_is_optional_and_forward_only() -> None:
    assert _parse().max_fee_estimate_sat_vb is None
    assert _parse("--max-fee-estimate-sat-vb", "2").max_fee_estimate_sat_vb == 2
    parser = argparse.ArgumentParser()
    swap_command.add_parser(parser.add_subparsers(dest="category"))
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["swap", "ln-to-btc", *REQUIRED, "--payout-sat", "1", "--max-fee-estimate-sat-vb", "2"]
        )


@pytest.mark.parametrize("value", [0, -1, 10_001])
def test_out_of_range_ceiling_fails_before_native_and_relay_setup(
    monkeypatch: pytest.MonkeyPatch, value: int
) -> None:
    relay, crypto = (
        Mock(side_effect=AssertionError("no relay")),
        Mock(side_effect=AssertionError("no native")),
    )
    monkeypatch.setattr(swap_command, "RelayConnection", relay)
    monkeypatch.setattr(swap_command, "Context", crypto)
    with pytest.raises(SwapError, match="fee estimate ceiling"):
        swap_command.run(_parse("--max-fee-estimate-sat-vb", str(value)), Mock(), "unused")
    relay.assert_not_called()
    crypto.assert_not_called()


@pytest.mark.parametrize(
    ("extra", "expected"), [((), None), (("--max-fee-estimate-sat-vb", "3"), 3)]
)
def test_run_hands_the_ceiling_to_the_wallet(
    monkeypatch: pytest.MonkeyPatch, extra: tuple[str, ...], expected: int | None
) -> None:
    class StopError(Exception):
        pass

    for name in (
        "X25519Credentials",
        "require_relay_route",
        "RelayConnection",
        "LndInvoiceDecoder",
    ):
        monkeypatch.setattr(swap_command, name, Mock())
    monkeypatch.setattr(swap_command, "Context", MagicMock())
    wallet = Mock(side_effect=StopError)
    monkeypatch.setattr(swap_command, "WalletRpc", wallet)
    with pytest.raises(StopError):
        swap_command.run(_parse(*extra), Mock(), "unused")
    assert wallet.call_args.kwargs["max_fee_estimate_sat_vb"] == expected


def test_wallet_passes_the_ceiling_only_when_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    constructor = Mock()
    monkeypatch.setattr(wallet_rpc, "CoreTransactionReader", constructor)
    cookie = tmp_path / "absent.cookie"
    network = _signet()
    WalletRpc(port=38332, cookie_path=cookie, wallet="savings", network=network)
    constructor.assert_called_once_with(port=38332, cookie_path=cookie, network=network)
    constructor.reset_mock()
    WalletRpc(
        port=38332,
        cookie_path=cookie,
        wallet="savings",
        network=network,
        max_fee_estimate_sat_vb=2,
    )
    constructor.assert_called_once_with(
        port=38332, cookie_path=cookie, network=network, max_fee_estimate_sat_vb=2
    )
    assert not cookie.exists()
