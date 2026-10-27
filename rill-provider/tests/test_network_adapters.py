"""Live adapters accept every supported network and bind to its exact labels."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider import core_tx_bytes, lnd_payment_observation, lnd_payment_send
from rill_provider._lnd_proto import lightning_pb2
from rill_provider.lnd_invoice_observation import LndInvoiceObserver

NETWORKS = Path(__file__).parents[2] / "rill-docs" / "networks"
LABELS = {
    "mainnet": ("main", "mainnet"),
    "signet": ("signet", "signet"),
    "testnet4": ("testnet4", "testnet4"),
    "regtest-rillswap-e2e-v1": ("regtest", "regtest"),
}
PAYER = "02" + "11" * 32


def _network(name: str) -> NetworkIdentity:
    return NetworkIdentity.model_validate_json((NETWORKS / f"{name}.json").read_bytes())


def _endpoint(tmp_path: Path) -> dict[str, Any]:
    return {"host": "127.0.0.1", "port": 10009, "tls_certificate_path": tmp_path}


@pytest.mark.parametrize("name", LABELS)
def test_every_supported_network_configures_every_adapter(tmp_path: Path, name: str) -> None:
    network = _network(name)
    core_tx_bytes.CoreTransactionReader(port=18443, cookie_path=tmp_path, network=network)
    lnd_payment_send.LndPaymentSender(
        **_endpoint(tmp_path), macaroon_path=tmp_path, network=network
    )
    LndInvoiceObserver(**_endpoint(tmp_path), invoice_macaroon_path=tmp_path, network=network)
    lnd_payment_observation.LndPaymentObserver(
        **_endpoint(tmp_path), read_macaroon_path=tmp_path, network=network
    )
    lnd_payment_observation.LndInfoObserver(
        **_endpoint(tmp_path),
        info_macaroon_path=tmp_path,
        network=network,
        expected_node_pubkey=PAYER,
    )


@pytest.mark.parametrize("name", LABELS)
def test_core_tip_requires_this_networks_chain_label(name: str) -> None:
    chain = LABELS[name][0]
    network = _network(name)
    tip = {"chain": chain, "bestblockhash": "ab" * 32, "blocks": 7, "initialblockdownload": False}
    if name == "signet":
        tip["signet_challenge"] = network.signet_challenge
    assert core_tx_bytes._chain_tip(tip, network) == ("ab" * 32, 7)  # noqa: SLF001
    for other, _lnd in LABELS.values():
        if other != chain:
            with pytest.raises(core_tx_bytes.CoreProtocolError):
                core_tx_bytes._chain_tip(tip | {"chain": other}, network)  # noqa: SLF001


@pytest.mark.parametrize("challenge", ["missing", None, True, 1, "51", "uppercase", "whitespace"])
def test_signet_tip_requires_exact_affirmative_challenge(challenge: object) -> None:
    network = _network("signet")
    tip = {
        "chain": "signet",
        "bestblockhash": "ab" * 32,
        "blocks": 7,
        "initialblockdownload": False,
    }
    if challenge != "missing":
        tip["signet_challenge"] = (
            network.signet_challenge.upper()
            if challenge == "uppercase"
            else network.signet_challenge + " "
            if challenge == "whitespace"
            else challenge
        )
    with pytest.raises(core_tx_bytes.CoreProtocolError):
        core_tx_bytes._chain_tip(tip, network)  # noqa: SLF001


def test_custom_signet_does_not_gain_execution_support(tmp_path: Path) -> None:
    network = _network("signet").model_copy(update={"signet_challenge": "51"})
    with pytest.raises(ValueError, match="supported complete network"):
        core_tx_bytes.CoreTransactionReader(port=18443, cookie_path=tmp_path, network=network)


class _Calls:
    def __init__(self, network: str) -> None:
        self.info = lightning_pb2.GetInfoResponse(
            block_height=100,
            synced_to_chain=True,
            chains=[{"chain": "bitcoin", "network": network}],
            identity_pubkey=PAYER,
        )

    def unary(self, *_args: object) -> lightning_pb2.GetInfoResponse:
        return self.info


@pytest.mark.parametrize("name", LABELS)
def test_lnd_payer_attestation_requires_this_networks_label(tmp_path: Path, name: str) -> None:
    network = _network(name)
    payer = lnd_payment_send.LndPaymentSender(
        **_endpoint(tmp_path), macaroon_path=tmp_path, network=network
    )
    deadline = time.monotonic() + 5
    height, authority = payer._attest(_Calls(LABELS[name][1]), deadline, expected=None)  # type: ignore[arg-type]  # noqa: SLF001
    assert (height, authority.network) == (100, network)
    for _core, other in LABELS.values():
        if other != LABELS[name][1]:
            with pytest.raises(lnd_payment_send.LndProtocolError, match="configured network"):
                payer._attest(_Calls(other), deadline, expected=None)  # type: ignore[arg-type]  # noqa: SLF001
    with pytest.raises(lnd_payment_send.LndProtocolError):  # testnet3 is not testnet4
        payer._attest(_Calls("testnet"), deadline, expected=None)  # type: ignore[arg-type]  # noqa: SLF001


def test_invoice_prefix_is_bound_before_any_lnd_call(tmp_path: Path) -> None:
    payer = lnd_payment_send.LndPaymentSender(
        **_endpoint(tmp_path), macaroon_path=tmp_path, network=_network("signet")
    )
    with pytest.raises(ValueError, match="bounds unsupported"):
        payer.prepare(
            "lntb500u1pexample",  # testnet prefix on a signet provider
            invoice_binding=None,  # type: ignore[arg-type]
            fee_limit_sat=1,
            max_expiry_height=10,
        )


@pytest.mark.parametrize("name", LABELS)
def test_serving_admits_each_pinned_network_before_loading_operator_state(name: str) -> None:
    import asyncio  # noqa: PLC0415
    from types import SimpleNamespace  # noqa: PLC0415

    from rill_provider import cli  # noqa: PLC0415

    config: Any = SimpleNamespace(network=_network(name), identity_file=None)
    with pytest.raises(AttributeError, match="lnd"):
        asyncio.run(cli._serve(config, None, ""))  # type: ignore[arg-type]  # noqa: SLF001


def test_serving_refuses_unpinned_mainnet_before_loading_operator_state() -> None:
    import asyncio  # noqa: PLC0415
    from types import SimpleNamespace  # noqa: PLC0415

    from rill_provider import cli  # noqa: PLC0415
    from rill_provider.operator_config import OperatorConfigError  # noqa: PLC0415

    network = _network("mainnet").model_copy(update={"genesis_hash": "00" * 32})
    config: Any = SimpleNamespace(network=network)
    with pytest.raises(OperatorConfigError, match="not supported"):
        asyncio.run(cli._serve(config, None, ""))  # type: ignore[arg-type]  # noqa: SLF001
