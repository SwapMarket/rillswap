"""Public conversion opts into the original SDK's actual signed-depth observation."""

from __future__ import annotations

import ast
import os
from importlib import import_module
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

# Exact substitutions leave the accepted funded program's financial controls
# intact. The public adapter, not a private-backend test shim, supplies history.
# ruff: noqa: SLF001


def _replace(program: str, old: str, new: str) -> str:
    assert program.count(old) == 1, "public conversion settlement fixture contract changed"
    return program.replace(old, new)


def _program() -> str:
    program = import_module("test_merchant_sdk_settlement_pinned")._program()
    program = _replace(
        program,
        "kwargs['await_settlement']=True",
        "assert kwargs['await_settlement'] is True",
    )
    program = _replace(
        program,
        "history=wallet._wallet.observe_historical_wallet_output",
        "history=wallet.observe_historical_wallet_output",
    )
    program = _replace(
        program,
        "del wallet.observe_historical_wallet_output",
        "wallet.observe_historical_wallet_output=history",
    )
    program = _replace(
        program,
        "# Explicit test-owned capability exposes the actual pinned\n"
        "                        # operator backend; the legacy conversion wallet adapter\n"
        "                        # does not advertise terminal observation automatically.",
        "# Public conversion explicitly requests observation from its\n"
        "                        # original pinned operator wallet through the adapter.\n"
        "                        # No private-backend shim or replacement owner is used.",
    )
    program = _replace(
        program,
        "timeout=30,settle_timeout=150,**capture_options)",
        "timeout=30,settle_timeout=150,await_settlement=True,**capture_options)",
    )
    return _replace(
        program,
        "sdk_signed_depth_observed=True,",
        "sdk_signed_depth_observed=True,public_conversion_settlement=True,",
    )


def test_public_conversion_program_requires_real_adapter_and_original_owner() -> None:
    program = _program()
    ast.parse(program)
    assert "kwargs['await_settlement']=True" not in program
    assert "assert kwargs['await_settlement'] is True" in program
    assert "history=wallet._wallet.observe_historical_wallet_output" not in program
    assert "history=wallet.observe_historical_wallet_output" in program
    assert "settle_timeout=150,await_settlement=True,**capture_options)" in program
    assert "await asyncio.sleep(0.5)" in program
    assert "consumed==receipt.amount_msat+receipt.routing_fee_msat" in program
    assert "len(final_paid.payments)==1 and len(final_paid.payments[0].htlcs)==1" in program
    compile(program, "<public-original-conversion-settlement>", "exec")


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="explicit owned LND/Core/Bun public conversion settlement opt-ins",
)
def test_pinned_public_conversion_observes_signed_claim_depth_with_original_wallet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = import_module("test_merchant_conversion_pinned")
    program = _program()
    monkeypatch.setattr(fixture, "_program", lambda **_controls: program)
    evidence = fixture._funded_evidence(tmp_path, completion=True, retain_funding_inclusion=True)
    assert evidence["public_conversion_settlement"] is True
    assert evidence["sdk_signed_depth_observed"] is True
    assert evidence["sdk_settlement_depth"] >= 3
    assert evidence["verified_completion"] is True
    assert evidence["original_funding_hint_retained"] is True
    assert evidence["original_source_attempts"] == 1
