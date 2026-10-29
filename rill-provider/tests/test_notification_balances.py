"""Read-only balance adapters and exact formatting for operator summaries."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import grpc
import pytest
from test_cli import _config
from test_evm_operator_config import EVM, _evm_config
from test_lnd_payment_tls import OPENSSL, _certificate
from web3 import Web3

from rill_provider import notification_balances as balances
from rill_provider._lnd_proto import lightning_pb2 as pb
from rill_provider.evm_htlc import EvmBackendError, EvmHtlcClient
from rill_provider.lnd_payment_observation import LndProtocolError
from rill_provider.operator_config import Lnd, load_config

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("value", "decimals", "expected"),
    [
        (0, 36, "0"),
        (1234, 0, "1,234"),
        (1_234_567, 6, "1.234567"),
        (1000, 3, "1"),
        (1, 36, "0." + "0" * 35 + "1"),
        (10**60 + 123, 36, "1,000,000,000,000,000,000,000,000." + "0" * 33 + "123"),
    ],
)
def test_balance_formatting_is_exact(value: int, decimals: int, expected: str) -> None:
    assert balances._units(value, decimals) == expected  # noqa: SLF001


def test_configured_balance_readers_are_lazy_and_include_all_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = MagicMock()
    core.trusted_balance_sat.return_value = 123_456
    core.wallet_utxo_count.return_value = 7
    monkeypatch.setattr(balances, "CoreTransactionReader", MagicMock(return_value=core))
    evm = MagicMock()
    evm.signer_address = "0x" + "ab" * 20
    evm.native_balance.return_value = 123
    evm.token_balance.side_effect = [1_234_567, 1]
    factory = MagicMock(return_value=evm)
    monkeypatch.setattr(balances, "EvmHtlcClient", factory)
    key = MagicMock(return_value="synthetic-key")
    monkeypatch.setattr(balances, "read_evm_signer_key", key)
    config = load_config(
        _config(
            tmp_path,
            bitcoin_core={"port": 18443, "cookie_file": "cookie", "wallet": "maker"},
            lnd={"port": 10009, "tls_certificate": "tls.cert", "macaroon": "read.mac"},
            evm=EVM
            | {
                "tokens": [
                    *EVM["tokens"],  # type: ignore[misc]
                    {
                        "token_contract": "0x" + "3c" * 20,
                        "token_symbol": "fUSDC",
                        "token_decimals": 36,
                        "rate_token_base_per_btc": 1,
                    },
                ]
            },
        )
    )
    readers = balances.balance_readers(config)
    assert len(readers) == 7
    key.assert_not_called()
    factory.assert_not_called()
    core.trusted_balance_sat.assert_not_called()
    assert readers["Bitcoin Core trusted"]() == "123,456 sat"
    assert readers["Bitcoin Core UTXOs"]() == "7"
    assert readers["EVM chain 31337 gas"]() == "123 wei"
    tokens = [read for label, read in readers.items() if "fUSDC" in label]
    assert [read() for read in tokens] == ["1.234567", "0." + "0" * 35 + "1"]
    assert evm.verify_deployment.call_count == 3
    assert factory.call_args.kwargs["request_timeout_seconds"] == balances.RPC_SECONDS
    evm.token_balance.assert_called_with("0x" + "3c" * 20, evm.signer_address)
    evm.verify_deployment.side_effect = EvmBackendError("wrong chain")
    evm.token_balance.reset_mock()
    with pytest.raises(EvmBackendError, match="wrong chain"):
        tokens[0]()
    evm.token_balance.assert_not_called()
    assert balances.balance_readers(load_config(_config(tmp_path))) == {}


def test_token_pools_are_read_once_per_token_after_verifying_the_deployment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evm = MagicMock()
    evm.signer_address = "0x" + "ab" * 20
    evm.token_balance.return_value = 42
    monkeypatch.setattr(balances, "EvmHtlcClient", MagicMock(return_value=evm))
    monkeypatch.setattr(balances, "read_evm_signer_key", MagicMock(return_value="key"))
    config = load_config(_config(tmp_path, evm=EVM))
    assert config.evm is not None
    assert balances.evm_token_balances(config.evm) == {"0x" + "2b" * 20: 42}
    evm.token_balance.assert_called_once_with("0x" + "2b" * 20, evm.signer_address)
    evm.verify_deployment.side_effect = EvmBackendError("wrong chain")
    with pytest.raises(EvmBackendError):
        balances.evm_token_balances(config.evm)
    assert evm.token_balance.call_count == 1  # nothing read from an unverified deployment


def test_forward_token_reserves_and_summaries_follow_the_claim_recipient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receiver = "0x" + "cd" * 20
    evm = MagicMock()
    evm.token_balance.return_value = 123
    monkeypatch.setattr(balances, "EvmHtlcClient", MagicMock(return_value=evm))
    monkeypatch.setattr(balances, "read_evm_signer_key", MagicMock(return_value="key"))
    config = load_config(_evm_config(tmp_path, claim_address=receiver))
    assert config.evm is not None
    assert balances.evm_token_balances(config.evm) == {"0x" + "2b" * 20: 123}
    token = config.evm.tokens[0]
    assert balances._evm_balance(config.evm, token) == "0.000123"  # noqa: SLF001
    assert evm.token_balance.call_count == 2
    evm.token_balance.assert_called_with(token.token_contract, receiver)


def _channels() -> pb.ChannelBalanceResponse:
    return pb.ChannelBalanceResponse(
        local_balance=pb.Amount(sat=1234, msat=1_234_567),
        remote_balance=pb.Amount(sat=500, msat=500_000),
        unsettled_local_balance=pb.Amount(sat=0, msat=1),
        pending_open_local_balance=pb.Amount(sat=0, msat=0),
    )


@pytest.mark.parametrize(
    "custom_data",
    [
        pytest.param(b"", id="legacy-empty"),
        pytest.param(b"\x00\x00", id="no-channels"),
        pytest.param(b"\x01\x00\x00", id="one-open-channel"),
        pytest.param(b"\x0d" + b"\x00" * 14, id="ordinary-signet-node"),
        pytest.param(b"\x00\x01\x00", id="pending-channel"),
        pytest.param(b"\xfd\xfd\x00" + b"\x00" * 254, id="compactsize-16-bit"),
        pytest.param(b"\xfe\x00\x00\x01\x00" + b"\x00" * 65537, id="compactsize-32-bit"),
    ],
)
def test_channel_balances_accept_only_empty_lnd_commitment_envelopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, custom_data: bytes
) -> None:
    response = _channels()
    response.custom_channel_data = custom_data
    monkeypatch.setattr(balances, "_lnd_read", lambda *_: response)
    settings = Lnd(port=10009, tls_certificate=tmp_path / "tls", macaroon=tmp_path / "mac")
    assert balances.lnd_channel_balance(settings) is response
    assert balances._channel_balances(settings) == (  # noqa: SLF001
        "local 1,234.567 sat, remote 500 sat (peer-owned), "
        "unsettled local 0.001 sat, pending local 0 sat"
    )


@pytest.mark.parametrize(
    "custom_data",
    [
        pytest.param(b"\x01\x01\x00\x00", id="open-custom-blob"),
        pytest.param(b"\x00\x01\x01\x00", id="pending-custom-blob"),
        pytest.param(b"\x00", id="missing-pending-group"),
        pytest.param(b"\x01", id="missing-blob"),
        pytest.param(b"\x02\x00", id="truncated-blobs"),
        pytest.param(b"\x00\x00\x00", id="trailing-bytes"),
        pytest.param(b"\xfd", id="missing-wide-count"),
        pytest.param(b"\xfd\x00", id="truncated-16-bit-count"),
        pytest.param(b"\xfe\x00\x00", id="truncated-32-bit-count"),
        pytest.param(b"\xff\x00\x00\x00\x00", id="truncated-64-bit-count"),
        pytest.param(b"\xfd\x00\x00\x00", id="noncanonical-16-bit-count"),
        pytest.param(b"\xfe\xfd\x00\x00\x00\x00", id="noncanonical-32-bit-count"),
        pytest.param(b"\xff\x00\x00\x01\x00\x00\x00\x00\x00\x00", id="noncanonical-64-bit-count"),
        pytest.param(b"\xff" + b"\xff" * 8 + b"\x00", id="unbounded-count"),
        pytest.param(b"[]", id="aux-parser-array"),
        pytest.param(b"{}", id="aux-parser-object"),
        pytest.param(b"custom", id="unknown-format"),
    ],
)
def test_channel_balances_reject_custom_or_malformed_commitment_envelopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, custom_data: bytes
) -> None:
    response = _channels()
    response.custom_channel_data = custom_data
    monkeypatch.setattr(balances, "_lnd_read", lambda *_: response)
    settings = Lnd(port=10009, tls_certificate=tmp_path / "tls", macaroon=tmp_path / "mac")
    with pytest.raises(LndProtocolError, match="LND custom channel balances unsupported"):
        balances.lnd_channel_balance(settings)


@pytest.mark.parametrize("fault", ["missing", "inconsistent"])
def test_empty_commitment_envelope_does_not_relax_amount_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    response = _channels()
    response.custom_channel_data = b"\x01\x00\x00"
    if fault == "missing":
        response.ClearField("local_balance")
    else:
        response.local_balance.sat = 0
    monkeypatch.setattr(balances, "_lnd_read", lambda *_: response)
    settings = Lnd(port=10009, tls_certificate=tmp_path / "tls", macaroon=tmp_path / "mac")
    with pytest.raises(LndProtocolError, match="LND channel balance invalid"):
        balances._channel_balances(settings)  # noqa: SLF001


@pytest.mark.parametrize("fault", ["missing", "inconsistent", "custom"])
def test_channel_balances_reject_incomplete_or_inconsistent_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    response = _channels()
    if fault == "missing":
        response.ClearField("local_balance")
    elif fault == "inconsistent":
        response.local_balance.sat = 0
    else:
        response.custom_channel_data = b"custom"
    monkeypatch.setattr(balances, "_lnd_read", lambda *_: response)
    settings = Lnd(port=10009, tls_certificate=tmp_path / "tls", macaroon=tmp_path / "mac")
    with pytest.raises(LndProtocolError):
        balances._channel_balances(settings)  # noqa: SLF001


@pytest.mark.skipif(OPENSSL is None, reason="openssl required for synthetic TLS test")
def test_lnd_balances_use_actual_tls_codecs_and_existing_read_credential(tmp_path: Path) -> None:
    certificate, key = _certificate(tmp_path)
    macaroon = tmp_path / "read.mac"
    macaroon.write_bytes(b"synthetic-read-credential")
    macaroon.chmod(0o600)
    methods: list[str] = []

    def channel_balance(
        _request: pb.ChannelBalanceRequest, context: grpc.ServicerContext
    ) -> pb.ChannelBalanceResponse:
        assert dict(context.invocation_metadata())["macaroon"] == macaroon.read_bytes().hex()
        methods.append("channels")
        return _channels()

    def wallet_balance(
        _request: pb.WalletBalanceRequest, context: grpc.ServicerContext
    ) -> pb.WalletBalanceResponse:
        assert dict(context.invocation_metadata())["macaroon"] == macaroon.read_bytes().hex()
        methods.append("wallet")
        return pb.WalletBalanceResponse(
            total_balance=1500, confirmed_balance=1000, unconfirmed_balance=500
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        server = grpc.server(pool)
        server.add_generic_rpc_handlers(
            (
                grpc.method_handlers_generic_handler(
                    "lnrpc.Lightning",
                    {
                        "ChannelBalance": grpc.unary_unary_rpc_method_handler(
                            channel_balance,
                            request_deserializer=pb.ChannelBalanceRequest.FromString,
                            response_serializer=pb.ChannelBalanceResponse.SerializeToString,
                        ),
                        "WalletBalance": grpc.unary_unary_rpc_method_handler(
                            wallet_balance,
                            request_deserializer=pb.WalletBalanceRequest.FromString,
                            response_serializer=pb.WalletBalanceResponse.SerializeToString,
                        ),
                    },
                ),
            )
        )
        port = server.add_secure_port(
            "127.0.0.1:0", grpc.ssl_server_credentials(((key, certificate.read_bytes()),))
        )
        server.start()
        try:
            settings = Lnd(port=port, tls_certificate=certificate, macaroon=macaroon)
            assert balances._channel_balances(settings) == (  # noqa: SLF001
                "local 1,234.567 sat, remote 500 sat (peer-owned), "
                "unsettled local 0.001 sat, pending local 0 sat"
            )
            assert balances._lnd_wallet_balance(settings) == (  # noqa: SLF001
                "1,500 sat (1,000 confirmed, 500 unconfirmed)"
            )
            assert methods == ["channels", "wallet"]
        finally:
            assert server.stop(0).wait(timeout=3)


def test_native_balance_uses_checksum_address_and_keeps_wei(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = EvmHtlcClient(
        rpc_url="http://127.0.0.1:9",
        chain_id=31337,
        htlc_contract="0x" + "ab" * 20,
        signer_private_key=None,
    )
    get_balance = MagicMock(return_value=10**18 + 1)
    monkeypatch.setattr(client._web3.eth, "get_balance", get_balance)  # noqa: SLF001
    assert client.native_balance("0x" + "ab" * 20) == 10**18 + 1
    get_balance.assert_called_once_with(Web3.to_checksum_address("0x" + "ab" * 20))
