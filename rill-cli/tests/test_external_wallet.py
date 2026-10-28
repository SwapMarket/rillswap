"""``rill swap ln-to-btc --pay-with external``: show the hold invoice for any wallet."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from rill_core.wire.messages import InvoiceBinding
from rill_core.wire.types import NetworkIdentity

from rill_cli import swap_command
from rill_cli.external_wallet import (
    DO_NOT_PAY_AGAIN,
    ExternalWalletPayer,
    invoice_qr,
    offline_invoice_decoder,
)
from rill_cli.live_swap import SwapError

DOCS = Path(__file__).parents[2] / "rill-docs"
VECTORS = {
    case["name"]: case
    for case in json.loads((DOCS / "vectors/bolt11/cases-v1.json").read_text())["cases"]
}
REGTEST = NetworkIdentity.model_validate_json(
    (DOCS / "networks/regtest-rillswap-e2e-v1.json").read_bytes()
)
HOLD = VECTORS["regtest hold invoice"]
BINDING = InvoiceBinding.model_validate(HOLD["bindings"]["regtest"])
QR_CHARACTERS = frozenset("█▀▄ \n")
BASE = [
    "--network", "n", "--crypto-library", "l", "--relay", "ws://unused", "--provider", "00" * 32,
    "--max-success-fee-sat", "1", "--core-port", "1", "--core-cookie", "c",
    "--recipient", "r", "--identity", "i", "--recovery-output", "o", "--wallet", "w",
]  # fmt: skip
LND = ["--lnd-port", "2", "--lnd-tls-cert", "t", "--lnd-macaroon", "m"]


class PinnedAuthenticator:
    """Stands in for libsecp256k1 (the rill-core native test covers real signatures)."""

    def __init__(self, payee: str) -> None:
        self.payee = bytes.fromhex(payee)

    def ecdsa_recover(self, _message: bytes, _signature: bytes, _recovery_id: int) -> bytes:
        return self.payee

    def ecdsa_verify(self, _public_key: bytes, _message: bytes, _signature: bytes) -> None:
        return None


def _parse(*extra: str, command: str = "ln-to-btc") -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    swap_command.add_parser(parser.add_subparsers(dest="category"))
    specific = ["--payout-sat", "1"] if command == "ln-to-btc" else ["--invoice", "lnbc1x"]
    return parser.parse_args(["swap", command, *BASE, *specific, *extra])


def _shown(*, qr: bool = True) -> tuple[str, list[str]]:
    written: list[str] = []
    status = ExternalWalletPayer(write=written.append, qr=qr).pay(
        HOLD["invoice"],
        invoice_binding=BINDING,
        min_final_expiry_height=1234,
        max_expiry_height=2000,
        fee_limit_sat=10,
    )
    return status, written


def test_external_payment_needs_no_lnd_flags_and_lnd_stays_the_default() -> None:
    external = _parse("--pay-with", "external")
    assert (external.pay_with, external.lnd_port, external.lnd_macaroon) == ("external", None, None)
    assert _parse(*LND).pay_with == "lnd"
    with pytest.raises(SystemExit):
        _parse("--pay-with", "phone")
    with pytest.raises(SystemExit):  # btc-to-ln still decodes through LND
        _parse("--lnd-macaroon", "m", command="btc-to-ln")


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        (("--lnd-port", "2", "--lnd-tls-cert", "t"), "--pay-with lnd needs"),
        ((), "--pay-with lnd needs"),
        (("--pay-with", "external", "--lnd-port", "2"), "takes no LND credentials"),
        (("--pay-with", "external", "--lnd-macaroon", "m"), "takes no LND credentials"),
    ],
)
def test_payment_source_is_checked_before_native_relay_or_wallet_setup(
    monkeypatch: pytest.MonkeyPatch, extra: tuple[str, ...], error: str
) -> None:
    for name in ("Context", "RelayConnection", "X25519Credentials", "WalletRpc"):
        monkeypatch.setattr(swap_command, name, Mock(side_effect=AssertionError(name)))
    with pytest.raises(SwapError, match=error):
        swap_command.run(_parse(*extra), REGTEST, "unused")


@pytest.mark.parametrize("pay_with", ["external", "lnd"])
def test_run_selects_the_payer_and_invoice_decoder(
    monkeypatch: pytest.MonkeyPatch, pay_with: str
) -> None:
    for name in ("X25519Credentials", "require_relay_route", "WalletRpc"):
        monkeypatch.setattr(swap_command, name, Mock())
    monkeypatch.setattr(swap_command, "Context", MagicMock())
    monkeypatch.setattr(swap_command, "RelayConnection", MagicMock())
    lnd_decoder, lnd_payer = Mock(), Mock()
    monkeypatch.setattr(swap_command, "LndInvoiceDecoder", lnd_decoder)
    monkeypatch.setattr(swap_command, "LndHoldPayer", lnd_payer)
    swap = AsyncMock(side_effect=SwapError("stop"))
    monkeypatch.setattr(swap_command, "run_reverse_swap", swap)
    extra = ("--pay-with", "external") if pay_with == "external" else tuple(LND)
    with pytest.raises(SwapError, match="stop"):
        swap_command.run(_parse(*extra), REGTEST, "unused")
    payer, decode = swap.call_args.kwargs["payer"], swap.call_args.kwargs["decode_invoice"]
    if pay_with == "external":
        assert isinstance(payer, ExternalWalletPayer)
        lnd_decoder.assert_not_called()
        lnd_payer.assert_not_called()
        with pytest.raises(SwapError, match="nothing was paid"):
            decode("lnbcrt1notaninvoice")
    else:
        assert payer is lnd_payer.return_value
        assert decode is lnd_decoder.return_value.decode


def test_the_offline_decoder_admits_the_invoice_like_the_browser() -> None:
    decode = offline_invoice_decoder(REGTEST, PinnedAuthenticator(HOLD["decoded"]["payee"]))
    assert decode(HOLD["invoice"]) == BINDING


@pytest.mark.parametrize(
    "name", ["mainnet hold invoice", "feature 14 missing", "blinded path field", "upper case"]
)
def test_a_refused_invoice_stops_the_swap_before_anything_is_paid(name: str) -> None:
    case = VECTORS[name]
    decode = offline_invoice_decoder(REGTEST, PinnedAuthenticator("02" + "11" * 32))
    with pytest.raises(SwapError) as refused:
        decode(case["invoice"])
    assert str(refused.value) == f"{case['bindings']['regtest']['error']}; nothing was paid"


def test_the_payer_shows_amount_deadline_qr_text_and_guidance_once() -> None:
    status, written = _shown()
    assert status == "SHOWN"
    (text,) = written
    lines = text.splitlines()
    assert lines[0] == "Pay 50000 sat from your Lightning wallet before 2023-11-15 00:13:20 UTC:"
    assert HOLD["invoice"] in lines
    assert f"payment hash {BINDING.payment_hash}" in lines
    assert DO_NOT_PAY_AGAIN in text
    assert "only after your payment is held" in text
    assert "expires before block 1234" in text
    qr = invoice_qr(HOLD["invoice"])
    assert qr in text
    assert set(qr) <= QR_CHARACTERS
    assert len(qr.splitlines()) > 20  # a scannable size, not one line


def test_the_qr_code_can_be_left_out() -> None:
    _, (text,) = _shown(qr=False)
    assert invoice_qr(HOLD["invoice"]) not in text
    assert HOLD["invoice"] in text.splitlines()


@pytest.mark.parametrize(
    "bounds",
    [
        {"deadline": time.monotonic() - 1},
        {"submission_allowed": lambda: False},
        {"submission_allowed": Mock(side_effect=RuntimeError("private"))},
    ],
)
def test_nothing_is_shown_once_the_swap_lifetime_refuses_payment(bounds: dict[str, Any]) -> None:
    written: list[str] = []
    with pytest.raises(SwapError, match="payment window closed") as error:
        ExternalWalletPayer(write=written.append).pay(
            HOLD["invoice"],
            invoice_binding=BINDING,
            min_final_expiry_height=1,
            max_expiry_height=2,
            fee_limit_sat=1,
            **bounds,
        )
    assert written == []
    assert "private" not in str(error.value)
