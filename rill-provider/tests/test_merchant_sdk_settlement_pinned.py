"""Explicit SDK completion uses actual block-revalidated Core observations.

The accepted original merchant fixture retains its funding hint, original
deadline, independent miner and financial checks. No backend evidence is faked.
"""

from __future__ import annotations

import ast
import os
from importlib import import_module
from textwrap import indent
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

# Embedded programs stay readable without reflowing accepted fixture controls.
# ruff: noqa: E501, SLF001

OBSERVE = """                    kwargs['await_settlement']=True
                    wallet=kwargs['wallet']
                    # Explicit test-owned capability exposes the actual pinned
                    # operator backend; the legacy conversion wallet adapter
                    # does not advertise terminal observation automatically.
                    history=wallet._wallet.observe_historical_wallet_output
                    broadcast=wallet.broadcast
                    broadcasts=[]
                    def counted(raw,**bounds):
                        result=broadcast(raw,**bounds)
                        broadcasts.append(result)
                        return result
                    def observe(txid,script,*,deadline_seconds):
                        before=len(broadcasts)
                        observation=history(txid,script,deadline_seconds=deadline_seconds)
                        assert len(broadcasts)==before
                        if settlement_observations:
                            assert before==settlement_broadcast_count[0]
                        else: settlement_broadcast_count.append(before)
                        settlement_observations.append(observation)
                        return observation
                    wallet.broadcast=counted
                    wallet.observe_historical_wallet_output=observe
                    try:
                        result=await native_runner(*args,**kwargs)
                        assert settlement_observations and len(settlement_broadcast_count)==1
                        assert len(broadcasts)==settlement_broadcast_count[0]>=1
                        assert result.claim_txid in broadcasts
                        assert all(record.txid==result.claim_txid and record.vout==0
                            and record.network==kwargs['network']
                            and record.confirmations>0 and record.block_height>0
                            and len(record.block_hash)==64
                            and record.started_at<=record.completed_at
                            for record in settlement_observations)
                        assert settlement_observations[-1].confirmations>=reservation.job.request.confirmation_blocks==3
                        return result
                    finally:
                        del wallet.observe_historical_wallet_output
                        wallet.broadcast=broadcast
"""


def _replace(program: str, old: str, new: str) -> str:
    assert program.count(old) == 1, "original settlement fixture contract changed"
    return program.replace(old, new)


def _program() -> str:
    program = import_module("test_merchant_conversion_pinned")._program(
        completion=True,
        retain_funding_inclusion=True,
    )
    program = _replace(
        program,
        "                async def traced_runner(*args,**kwargs):",
        "                settlement_observations=[]\n"
        "                settlement_broadcast_count=[]\n"
        "                async def traced_runner(*args,**kwargs):",
    )
    program = _replace(
        program,
        "                    try: return await native_runner(*args,**kwargs)\n",
        "                    try:\n" + indent(OBSERVE, "    "),
    )
    return _replace(
        program,
        "                    original_claim_path=claim_path)",
        "                    original_claim_path=claim_path,\n"
        "                    sdk_signed_depth_observed=True,\n"
        "                    sdk_settlement_depth=settlement_observations[-1].confirmations)",
    )


def test_strong_settlement_program_preserves_original_budget_and_financial_checks() -> None:
    program = _program()
    tree = ast.parse(program)
    assert "timeout=30,settle_timeout=150,**capture_options" in program
    assert "for _ in range(180):" in program
    assert "await asyncio.sleep(0.5)" in program
    assert "len(final_paid.payments)==1 and len(final_paid.payments[0].htlcs)==1" in program
    assert "consumed==receipt.amount_msat+receipt.routing_fee_msat" in program
    assert program.count("kwargs['await_settlement']=True") == 1
    assert (
        sum(isinstance(node, ast.FunctionDef) and node.name == "observe" for node in ast.walk(tree))
        == 1
    )
    compile(program, "<actual-sdk-signed-settlement>", "exec")


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="explicit owned LND/Core/Bun terminal SDK conformance opt-ins",
)
def test_pinned_original_sdk_awaits_actual_wallet_claim_depth_three(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = import_module("test_merchant_conversion_pinned")
    program = _program()
    monkeypatch.setattr(fixture, "_program", lambda **_controls: program)
    evidence = fixture._funded_evidence(tmp_path, completion=True, retain_funding_inclusion=True)
    assert evidence["sdk_signed_depth_observed"] is True
    assert evidence["sdk_settlement_depth"] >= 3
    assert evidence["verified_completion"] is True
    assert evidence["original_funding_hint_retained"] is True
    assert evidence["original_source_attempts"] == 1
