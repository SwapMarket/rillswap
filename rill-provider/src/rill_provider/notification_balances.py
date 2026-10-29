"""Read-only balance sources for operator summaries and pricing, never for authorization.

Construction does not read credentials or contact backends. The notifier runs
each source in a bounded worker thread only when a summary is due.
"""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

import grpc
from google.protobuf.message import Message  # type: ignore[import-untyped]

from rill_provider._lnd_proto import lightning_pb2
from rill_provider.core_tx_bytes import MAX_SATS, CoreTransactionReader
from rill_provider.evm_htlc import EvmHtlcClient
from rill_provider.lnd_payment_observation import (
    MAX_CERT_BYTES,
    MAX_MACAROON_BYTES,
    MAX_MESSAGE_BYTES,
    LndProtocolError,
    _read_file,
)
from rill_provider.operator_config import read_evm_signer_key

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_provider.operator_config import EvmSettings, EvmToken, Lnd, OperatorConfig

RPC_SECONDS = 5.0


def balance_readers(config: OperatorConfig) -> dict[str, Callable[[], str]]:
    """Return labeled current-balance reads for every configured backend."""
    readers: dict[str, Callable[[], str]] = {}
    core = config.bitcoin_core
    if core is not None:
        wallet = CoreTransactionReader(
            port=core.port,
            cookie_path=core.cookie_file,
            network=config.network,
            wallet=core.wallet,
        )
        readers["Bitcoin Core trusted"] = lambda: f"{wallet.trusted_balance_sat():,} sat"
        readers["Bitcoin Core UTXOs"] = lambda: f"{wallet.wallet_utxo_count():,}"
    lnd = config.lnd
    if lnd is not None:
        readers["Lightning channels"] = partial(_channel_balances, lnd)
        readers["LND on-chain (default account)"] = partial(_lnd_wallet_balance, lnd)
    evm = config.evm
    if evm is not None:
        chain = f"EVM chain {evm.chain_id}"
        readers[f"{chain} gas"] = partial(_evm_balance, evm, None)
        for token in evm.tokens:
            # Addresses distinguish configured tokens with the same symbol.
            readers[f"{chain} {token.token_symbol} ({token.token_contract})"] = partial(
                _evm_balance, evm, token
            )
    return readers


def _lnd_read[Response: Message](
    settings: Lnd, method: str, request: Message, response: type[Response]
) -> Response:
    certificate = _read_file(settings.tls_certificate, MAX_CERT_BYTES, private=False)
    macaroon = _read_file(settings.macaroon, MAX_MACAROON_BYTES, private=True)
    with grpc.secure_channel(
        f"127.0.0.1:{settings.port}",
        grpc.ssl_channel_credentials(root_certificates=certificate),
        options=(
            ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
            ("grpc.max_send_message_length", 1024),
            ("grpc.enable_retries", 0),
        ),
    ) as channel:
        rpc = channel.unary_unary(
            f"/lnrpc.Lightning/{method}",
            request_serializer=type(request).SerializeToString,
            response_deserializer=response.FromString,
        )
        result = rpc(
            request,
            timeout=RPC_SECONDS,
            metadata=(("macaroon", macaroon.hex()),),
            wait_for_ready=False,
        )
    if not isinstance(result, response):
        raise LndProtocolError("LND balance response invalid")
    return result


def lnd_channel_balance(settings: Lnd) -> lightning_pb2.ChannelBalanceResponse:
    """Read LND's channel totals; validate each field used with ``channel_amount_msat``."""
    response = _lnd_read(
        settings,
        "ChannelBalance",
        lightning_pb2.ChannelBalanceRequest(),
        lightning_pb2.ChannelBalanceResponse,
    )
    if response.custom_channel_data:
        raise LndProtocolError("LND custom channel balances unsupported")
    return response


def channel_amount_msat(response: lightning_pb2.ChannelBalanceResponse, field: str) -> int:
    """Return one present, self-consistent channel total in msat."""
    amount = getattr(response, field)
    if not (
        response.HasField(field)
        and amount.msat <= MAX_SATS * 1000
        and amount.sat == amount.msat // 1000
    ):
        raise LndProtocolError("LND channel balance invalid")
    return int(amount.msat)


def _channel_balances(settings: Lnd) -> str:
    response = lnd_channel_balance(settings)
    local, remote, unsettled, pending = (
        f"{_units(channel_amount_msat(response, field), 3)} sat"
        for field in (
            "local_balance",
            "remote_balance",
            "unsettled_local_balance",
            "pending_open_local_balance",
        )
    )
    return (
        f"local {local}, remote {remote} (peer-owned), "
        f"unsettled local {unsettled}, pending local {pending}"
    )


def _lnd_wallet_balance(settings: Lnd) -> str:
    response = _lnd_read(
        settings,
        "WalletBalance",
        lightning_pb2.WalletBalanceRequest(),
        lightning_pb2.WalletBalanceResponse,
    )
    amounts = (response.total_balance, response.confirmed_balance, response.unconfirmed_balance)
    if not all(0 <= value <= MAX_SATS for value in amounts) or amounts[0] != sum(amounts[1:]):
        raise LndProtocolError("LND wallet balance invalid")
    total, confirmed, pending = amounts
    return f"{total:,} sat ({confirmed:,} confirmed, {pending:,} unconfirmed)"


def _evm_client(settings: EvmSettings) -> EvmHtlcClient:
    client = EvmHtlcClient(
        rpc_url=settings.rpc_url,
        chain_id=settings.chain_id,
        htlc_contract=settings.htlc_contract,
        signer_private_key=read_evm_signer_key(settings.signer_key_file),
        request_timeout_seconds=RPC_SECONDS,
    )
    client.verify_deployment()
    return client


def evm_token_balances(settings: EvmSettings) -> dict[str, int]:
    """Return the reserve's base-unit balance of every configured token, by contract."""
    client = _evm_client(settings)
    owner = settings.claim_address or client.signer_address
    return {
        token.token_contract: client.token_balance(token.token_contract, owner)
        for token in settings.tokens
    }


def _evm_balance(settings: EvmSettings, token: EvmToken | None) -> str:
    client = _evm_client(settings)
    if token is None:
        return f"{_units(client.native_balance(client.signer_address), 0)} wei"
    return _units(
        client.token_balance(token.token_contract, settings.claim_address or client.signer_address),
        token.token_decimals,
    )


def _units(value: int, decimals: int) -> str:
    """Format base units exactly, without float or Decimal context rounding."""
    if type(value) is not int or value < 0:
        raise ValueError("balance must be a nonnegative integer")
    whole, fraction = divmod(value, 10**decimals)
    suffix = f".{fraction:0{decimals}d}".rstrip("0") if fraction else ""
    return f"{whole:,}{suffix}"
