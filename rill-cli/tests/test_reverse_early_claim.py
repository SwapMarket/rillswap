"""LN to BTC claims below the signed funding depth: an explicit, warned client choice."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from test_fee_estimate_ceiling_cli import _parse

from rill_cli import swap_command
from rill_cli.live_reverse_swap import (
    ReverseSwapLimits,
    _chain_view,
    claim_depth,
    early_claim_warning,
    run_reverse_swap,
)
from rill_cli.live_swap import SwapError
from rill_cli.refund_watcher import ChainView

FUNDING = "51" * 32
CLAIM = "52" * 32


def _limits(claim_confirmations: Any = None) -> ReverseSwapLimits:  # noqa: ANN401
    return ReverseSwapLimits(
        max_success_fee_sat=1_000,
        min_claim_fee_reserve_sat=0,
        max_claim_fee_sat=5_000,
        min_refund_delay_blocks=72,
        max_incoming_htlc_delay_blocks=432,
        max_routing_fee_sat=100,
        claim_confirmations=claim_confirmations,
    )


@pytest.mark.parametrize(
    ("signed", "requested", "expected"),
    [(2, None, 2), (2, 0, 0), (3, 1, 1), (2, 2, 2), (1, 5, 1)],  # never deeper than signed
)
def test_claim_depth_lowers_but_never_raises_the_signed_depth(
    signed: int, requested: int | None, expected: int
) -> None:
    assert claim_depth(signed, requested) == expected


@pytest.mark.parametrize("requested", [-1, True, 1.0, "0"])
def test_malformed_claim_depth_is_refused(requested: object) -> None:
    with pytest.raises(SwapError, match="nonnegative integer"):
        claim_depth(2, requested)  # type: ignore[arg-type]


def test_early_claim_warning_names_the_depth_and_the_double_spend_risk() -> None:
    assert early_claim_warning(2, 2) is None
    assert early_claim_warning(3, 2) is None
    unconfirmed = early_claim_warning(0, 2)
    assert unconfirmed is not None
    assert "unconfirmed funding, below the provider's signed 2" in unconfirmed
    assert "double-spend" in unconfirmed
    shallow = early_claim_warning(1, 3)
    assert shallow is not None
    assert "funding at 1 confirmation(s), below the provider's signed 3" in shallow


def test_malformed_claim_depth_fails_before_any_relay_traffic() -> None:
    connection = Mock(side_effect=AssertionError("no relay traffic"))
    with pytest.raises(SwapError, match="nonnegative integer"):
        asyncio.run(
            run_reverse_swap(
                connection,
                identity="00" * 32,
                network=Mock(),
                payout_sat=50_000,
                decode_invoice=Mock(side_effect=AssertionError("no decode")),
                payer=Mock(),
                wallet=Mock(),
                write_recovery=Mock(side_effect=AssertionError("no recovery file")),
                limits=_limits(-1),
                crypto=Mock(),
                settle_timeout=1,
            )
        )
    assert connection.mock_calls == []


class _Wallet:
    """Core's three views of the funding output, recording which were read."""

    def __init__(
        self,
        *,
        on_chain: bool,
        with_mempool: object = None,
        spender: str | None = None,
        failing: str | None = None,
    ) -> None:
        self.calls: list[str] = []
        self._on_chain, self._with_mempool, self._spender = on_chain, with_mempool, spender
        self._failing = failing

    def _read(self, name: str) -> None:
        self.calls.append(name)
        if name == self._failing:
            raise RuntimeError(name)

    def tip_height(self) -> int:
        self._read("tip_height")
        return 120

    def unspent_on_chain(self, txid: str, vout: int) -> bool:
        assert (txid, vout) == (FUNDING, 1)
        self._read("unspent_on_chain")
        return self._on_chain

    def confirmed_output(self, txid: str, vout: int) -> object:
        assert (txid, vout) == (FUNDING, 1)
        self._read("confirmed_output")
        return self._with_mempool

    def mempool_spender(self, txid: str, vout: int) -> str | None:
        assert (txid, vout) == (FUNDING, 1)
        self._read("mempool_spender")
        return self._spender


BINDING = SimpleNamespace(funding_txid=FUNDING, contract_vout=1)


@pytest.mark.parametrize("on_chain", [True, False])
def test_the_signed_depth_reads_the_chain_only(on_chain: bool) -> None:  # noqa: FBT001 - parametrized
    wallet = _Wallet(on_chain=on_chain, with_mempool=object(), spender=CLAIM)
    assert _chain_view(wallet, BINDING) == ChainView(120, on_chain)  # type: ignore[arg-type]
    assert wallet.calls == ["tip_height", "unspent_on_chain"]


@pytest.mark.parametrize(
    ("wallet", "unspent", "reads"),
    [
        # Confirmed and unspent: the chain alone answers.
        (_Wallet(on_chain=True), True, ["unspent_on_chain"]),
        # Still unconfirmed and unspent: only the mempool view holds it.
        (
            _Wallet(on_chain=False, with_mempool=object()),
            True,
            ["unspent_on_chain", "confirmed_output"],
        ),
        # Spent by a mempool transaction (normally our claim): nothing confirmed spent it.
        (
            _Wallet(on_chain=False, spender=CLAIM),
            True,
            ["unspent_on_chain", "confirmed_output", "mempool_spender"],
        ),
        # Gone from every view: confirmed spent (maybe by our claim) or double-spent.
        (
            _Wallet(on_chain=False),
            False,
            ["unspent_on_chain", "confirmed_output", "mempool_spender"],
        ),
    ],
)
def test_an_early_claim_also_reads_the_mempool(
    wallet: _Wallet,
    unspent: bool,  # noqa: FBT001 - parametrized
    reads: list[str],
) -> None:
    view = _chain_view(wallet, BINDING, unconfirmed_funding=True)  # type: ignore[arg-type]
    assert view == ChainView(120, unspent)
    assert wallet.calls == ["tip_height", *reads]


@pytest.mark.parametrize(
    "failing", ["tip_height", "unspent_on_chain", "confirmed_output", "mempool_spender"]
)
def test_a_failed_read_is_no_evidence(failing: str) -> None:
    wallet = _Wallet(on_chain=False, failing=failing)
    assert _chain_view(wallet, BINDING, unconfirmed_funding=True) is None  # type: ignore[arg-type]


def test_claim_confirmations_flag_is_optional() -> None:
    assert _parse(command="ln-to-btc").claim_confirmations is None
    assert _parse("--claim-confirmations", "0", command="ln-to-btc").claim_confirmations == 0


@pytest.mark.parametrize(("extra", "expected"), [((), None), (("--claim-confirmations", "0"), 0)])
def test_run_hands_claim_confirmations_to_the_swap_limits(
    monkeypatch: pytest.MonkeyPatch, extra: tuple[str, ...], expected: int | None
) -> None:
    class StopError(Exception):
        pass

    for name in (
        "X25519Credentials",
        "require_relay_route",
        "RelayConnection",
        "LndInvoiceDecoder",
        "LndHoldPayer",
        "WalletRpc",
    ):
        monkeypatch.setattr(swap_command, name, MagicMock())
    monkeypatch.setattr(swap_command, "Context", MagicMock())
    limits = Mock(side_effect=StopError)
    monkeypatch.setattr(swap_command, "ReverseSwapLimits", limits)
    with pytest.raises(StopError):
        swap_command.run(_parse(*extra, command="ln-to-btc"), Mock(), "unused")
    assert limits.call_args.kwargs["claim_confirmations"] == expected
