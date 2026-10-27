"""Only a regtest provider prices cooperative claims without a Core fee estimate."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.networks import DEFAULT_SIGNET_CHALLENGE, PUBLIC_CONSENSUS_PROFILE
from rill_core.wire.types import NetworkIdentity

from rill_provider import cli

if TYPE_CHECKING:
    from pathlib import Path

REGTEST = NetworkIdentity(
    family="bitcoin",
    name="regtest",
    genesis_hash="0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    signet_challenge=None,
    consensus_profile="bitcoin-core-v30.0-regtest-default",
    deployment_namespace="rillswap-e2e-v1",
)
SIGNET = NetworkIdentity(
    family="bitcoin",
    name="signet",
    genesis_hash="00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    signet_challenge=DEFAULT_SIGNET_CHALLENGE,
    consensus_profile=PUBLIC_CONSENSUS_PROFILE,
    deployment_namespace=None,
)


@pytest.mark.parametrize(("network", "fixed"), [(REGTEST, True), (SIGNET, False)])
def test_operator_settlement_allows_fixed_fee_only_on_regtest(
    tmp_path: Path, network: NetworkIdentity, *, fixed: bool
) -> None:
    config = SimpleNamespace(
        network=network,
        handshake=SimpleNamespace(profile="btc-to-ln/v1"),
        bitcoin_core=SimpleNamespace(
            port=18443,
            cookie_file=tmp_path / "cookie",
            wallet="w",
            max_fee_estimate_sat_vb=None,
        ),
        lnd=SimpleNamespace(
            port=10009,
            tls_certificate=tmp_path / "tls.cert",
            payment_macaroon=tmp_path / "payment.macaroon",
            invoices_macaroon=None,
        ),
    )
    store = Mock(network_identity=network)
    engine = cli._settlement(config, store, Mock())  # type: ignore[arg-type]  # noqa: SLF001
    assert engine is not None
    assert engine._settings.allow_regtest_fixed_fee is fixed  # noqa: SLF001
