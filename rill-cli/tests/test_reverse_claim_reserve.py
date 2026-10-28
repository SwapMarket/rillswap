"""LN to BTC: the claim fee reserve pays the next-block claim, and the claim pays the reserve."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    claim_vsizes,
    inspect_transaction_outputs,
    max_spendable_fee,
)
from rill_crypto import Context
from rill_provider.core_tx_bytes import CoreProtocolError, CoreUnavailableError, NextBlockFee
from test_fee_estimate_ceiling_cli import _signet
from test_reverse_sdk_lifetime import NATIVE_LIBRARY, NATIVE_ONLY, NativeSdk

from rill_cli import live_reverse_swap as reverse
from rill_cli import wallet_rpc
from rill_cli.live_swap import SwapError
from rill_cli.wallet_rpc import WalletRpc, WalletRpcError

if TYPE_CHECKING:
    from pathlib import Path

P2WPKH = bytes.fromhex("0014" + "11" * 20)
P2TR = bytes.fromhex("5120" + "11" * 32)


def _limits(minimum: int = 0, rate: int = 0) -> reverse.ReverseSwapLimits:
    return reverse.ReverseSwapLimits(1000, minimum, 5000, 72, 432, 100, rate)


def test_the_reserve_pays_the_script_path_claim_at_the_next_block_rate() -> None:
    assert claim_vsizes(P2WPKH) == (99, 143)
    assert claim_vsizes(P2TR) == (111, 155)
    busy = NextBlockFee(1000, 1000, 2500)
    assert reverse.minimum_claim_fee_reserve_sat(P2WPKH, busy, _limits()) == 358  # 143 * 2.5
    assert reverse.minimum_claim_fee_reserve_sat(P2TR, busy, _limits()) == 388  # 155 * 2.5
    assert (
        reverse.minimum_claim_fee_reserve_sat(P2TR, NextBlockFee(1000, 1000, 2001), _limits())
        == 311
    )


def test_a_low_relay_floor_never_prices_the_fallback_below_the_estimate() -> None:
    # A signet node: 0.1 sat/vB estimate, 0.01 sat/vB floor. Pricing the key path
    # at the estimate and the script path at the floor asked for 12 sat, so the
    # 155 vB fallback paid 0.078 sat/vB and default-policy peers dropped it.
    signet = NextBlockFee(10, 10, 100)
    assert reverse.minimum_claim_fee_reserve_sat(P2TR, signet, _limits()) == 16


def test_the_script_path_floor_user_rate_and_user_minimum_raise_it() -> None:
    quiet = NextBlockFee(1000, 1000, None)  # regtest without an estimate
    # Without an estimate (regtest), the node floor alone prices the 155 vB claim.
    assert reverse.minimum_claim_fee_reserve_sat(P2TR, quiet, _limits()) == 155
    assert (
        reverse.minimum_claim_fee_reserve_sat(P2TR, NextBlockFee(1000, 2000, 1000), _limits())
        == 310
    )
    assert reverse.minimum_claim_fee_reserve_sat(P2TR, quiet, _limits(rate=3)) == 465
    assert reverse.minimum_claim_fee_reserve_sat(P2TR, quiet, _limits(minimum=500)) == 500


@pytest.mark.parametrize(
    ("destination", "fee", "limits"),
    [
        (P2TR, Mock(rate_sat_kvb=1000, floor_sat_kvb=1000), _limits()),
        (P2TR, NextBlockFee(1000, 1000, 1000), _limits(rate=-1)),
        (bytes.fromhex("a914" + "11" * 20 + "87"), NextBlockFee(1000, 1000, 1000), _limits()),
    ],
    ids=["untyped-fee", "negative-rate", "p2sh-destination"],
)
def test_unsupported_inputs_refuse(destination: bytes, fee: object, limits: object) -> None:
    with pytest.raises(SwapError):
        reverse.minimum_claim_fee_reserve_sat(destination, fee, limits)  # type: ignore[arg-type]


def test_wallet_samples_its_own_core_and_hides_read_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    reader = Mock()
    monkeypatch.setattr(wallet_rpc, "CoreTransactionReader", Mock(return_value=reader))
    wallet = WalletRpc(
        port=38332, cookie_path=tmp_path / "cookie", wallet="savings", network=_signet()
    )
    reader.next_block_fee.return_value = NextBlockFee(1000, 1000, 4000)
    assert wallet.next_block_fee() == NextBlockFee(1000, 1000, 4000)
    for error in (CoreUnavailableError("secret detail"), CoreProtocolError("secret detail")):
        reader.next_block_fee.side_effect = error
        with pytest.raises(WalletRpcError, match="next-block fee estimate unavailable") as raised:
            wallet.next_block_fee()
        assert "secret" not in str(raised.value)
    reader.next_block_fee.side_effect, reader.next_block_fee.return_value = None, Mock()
    with pytest.raises(WalletRpcError, match="next-block fee estimate unavailable"):
        wallet.next_block_fee()


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_native_a_reserve_above_the_claim_fee_cap_is_refused_before_the_firm_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        fixture.wallet.next_block_fee.return_value = NextBlockFee(1000, 1000, 100_000)
        with pytest.raises(SwapError, match=r"exceeds your maximum claim fee \(5000 sat\)"):
            await fixture.run()
        fixture.session.send.assert_not_called()
        fixture.payer.pay.assert_not_called()
        assert fixture.documents == []
        assert fixture.contract_signatures == 0

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_native_the_request_asks_for_the_next_block_reserve_and_the_claim_pays_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        fixture.wallet.next_block_fee.return_value = NextBlockFee(1000, 1000, 3000)
        await fixture.run()
        destination = bytes.fromhex(fixture.terms.client_destination_script)
        request = fixture.session.send.call_args_list[0].args[0]
        assert request.message_type == "quote_request"
        assert request.payload["limits"]["min_claim_fee_reserve_sat"] == str(
            -(-claim_vsizes(destination)[1] * 3000 // 1000)
        )
        # The signed fixture reserve (500 sat) is above its signed 400-sat
        # claim cap, so the claim pays the cap: exactly what it may spend.
        reserve = int(fixture.terms.economics.claim_fee_reserve_sat)
        authorization = UnilateralAuthorization.from_terms(
            fixture.terms,
            FundingOutput(
                bytes.fromhex(fixture.binding.funding_txid),
                fixture.binding.contract_vout,
                int(fixture.binding.contract_value_sat),
                bytes.fromhex(fixture.binding.contract_script_pubkey),
            ),
            "claim",
            keys=crypto,
        )
        (claim,) = fixture.broadcasts
        (paid,) = inspect_transaction_outputs(claim).outputs
        fee = int(fixture.terms.economics.contract_amount_sat) - paid.value_sat
        assert fee == min(reserve, max_spendable_fee(authorization)) == 400

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))
