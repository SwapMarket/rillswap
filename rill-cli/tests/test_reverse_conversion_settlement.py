"""Explicit conversion wiring, not chain provenance or receipt completion.

Reuse the existing original-right harness without modifying its contracts. The
fake SDK exercises durable ownership and keyword forwarding only; Core and
native SDK conformance are independently covered by the terminal SDK tests.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import Mock

import pytest
from test_reverse_conversion import CREDENTIALS, LIMITS, PACKAGE, Harness
from test_reverse_conversion import (
    harness as harness,  # noqa: PLC0414 - expose the existing pytest fixture in this module
)

from rill_cli import reverse_conversion as module
from rill_cli.live_reverse_swap import ReverseSwapOutcome


def _run(harness: Harness, **options: object) -> ReverseSwapOutcome:
    return asyncio.run(
        module.run_reserved_conversion(
            harness.journal,
            harness.reservation,
            Mock(),
            config=harness.config,
            limits=LIMITS,
            credentials=CREDENTIALS,
            crypto=Mock(),
            **options,
        )
    )


def _dispatch(harness: Harness, owner: module._Invocation) -> None:
    assert harness.journal.status(harness.request.operation_id).state == "invoked"
    # The original SDK samples the wallet tip before publishing its initial
    # recovery checkpoint. The owner requires that original admission fact.
    assert owner.wallet.tip_height() == 900
    harness.checkpoint(owner)
    assert harness.journal.status(harness.request.operation_id).state == "prepared"
    harness.payer.pay.side_effect = lambda *_args, **_kwargs: (
        "IN_FLIGHT"
        if harness.journal.status(harness.request.operation_id).state == "dispatched"
        else "FAILED"
    )
    assert harness.pay(owner) == "IN_FLIGHT"


@pytest.mark.parametrize("await_settlement", [False, True])
@pytest.mark.parametrize("retain_funding_inclusion", [False, True])
def test_explicit_settlement_uses_same_wallet_sdk_and_original_dispatch(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    *,
    await_settlement: bool,
    retain_funding_inclusion: bool,
) -> None:
    monkeypatch.setattr(module, "CoreTransactionReader", Mock())
    outcome = ReverseSwapOutcome(
        "session", PACKAGE["contract_hash"], "e" * 64, "f" * 64, 100500, 500
    )
    observed = object()  # Identity forwarding only, never admitted as chain evidence.
    harness.wallet.observe_historical_wallet_output.return_value = observed
    captured: list[dict[str, Any]] = []

    async def runner(_connection: object, **kwargs: Any) -> ReverseSwapOutcome:  # noqa: ANN401 - synthetic SDK boundary
        captured.append(kwargs)
        if await_settlement:
            assert kwargs["await_settlement"] is True
            wallet = kwargs["wallet"]
            script = wallet.new_destination_script()
            assert (
                wallet.observe_historical_wallet_output(
                    outcome.claim_txid,
                    script,
                    deadline_seconds=7.5,
                )
                is observed
            )
            harness.wallet.observe_historical_wallet_output.assert_called_once_with(
                outcome.claim_txid,
                script,
                deadline_seconds=7.5,
            )
        else:
            assert "await_settlement" not in kwargs
        assert ("funding_inclusion_observer" in kwargs) is retain_funding_inclusion
        _dispatch(harness, kwargs["payer"])
        return outcome

    monkeypatch.setattr(module, "run_reverse_swap", runner)
    result = _run(
        harness,
        await_settlement=await_settlement,
        retain_funding_inclusion=retain_funding_inclusion,
    )
    assert result is outcome
    assert len(captured) == 1
    assert harness.journal.status(harness.request.operation_id).state == "dispatched"
    harness.payer.pay.assert_called_once()
    assert harness.payer.pay.call_args.kwargs["deadline"] == 3700
    if not await_settlement:
        harness.wallet.observe_historical_wallet_output.assert_not_called()


def test_default_preserves_exact_sdk_keyword_shape(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, Any]] = []
    outcome = ReverseSwapOutcome(
        "session", PACKAGE["contract_hash"], "e" * 64, "f" * 64, 100500, 500
    )

    async def runner(_connection: object, **kwargs: Any) -> ReverseSwapOutcome:  # noqa: ANN401 - exact synthetic boundary keywords
        captured.append(kwargs)
        _dispatch(harness, kwargs["payer"])
        return outcome

    monkeypatch.setattr(module, "run_reverse_swap", runner)
    assert _run(harness) is outcome
    assert set(captured[0]) == {
        "identity",
        "network",
        "payout_sat",
        "decode_invoice",
        "payer",
        "wallet",
        "write_recovery",
        "limits",
        "crypto",
        "timeout",
        "settle_timeout",
    }
    harness.wallet.observe_historical_wallet_output.assert_not_called()


@pytest.mark.parametrize("invalid", [None, 0, 1, "true", [], {}])
def test_nonboolean_mode_refuses_before_consuming_the_original_right(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    invalid: object,
) -> None:
    sdk = Mock()
    monkeypatch.setattr(module, "run_reverse_swap", sdk)
    with pytest.raises(module.ReverseConversionError):
        _run(harness, await_settlement=invalid)
    sdk.assert_not_called()
    harness.payer.pay.assert_not_called()
    assert harness.journal.status(harness.request.operation_id).state == "reserved"

    # Correcting locally rejected input retains the SAME original live right;
    # this is not a retry of an invoked SDK or restored ownership after reopen.
    outcome = ReverseSwapOutcome(
        "session", PACKAGE["contract_hash"], "e" * 64, "f" * 64, 100500, 500
    )

    async def runner(_connection: object, **kwargs: Any) -> ReverseSwapOutcome:  # noqa: ANN401 - synthetic SDK boundary
        _dispatch(harness, kwargs["payer"])
        return outcome

    monkeypatch.setattr(module, "run_reverse_swap", runner)
    assert _run(harness, await_settlement=True) is outcome
    assert harness.journal.status(harness.request.operation_id).state == "dispatched"
    harness.payer.pay.assert_called_once()


def test_terminal_observation_failure_preserves_dispatched_liability_and_no_replay(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    async def runner(_connection: object, **kwargs: Any) -> ReverseSwapOutcome:  # noqa: ANN401 - synthetic SDK failure after durable dispatch
        calls.append(kwargs)
        assert kwargs["await_settlement"] is True
        _dispatch(harness, kwargs["payer"])
        raise RuntimeError("PRIVATE_OBSERVATION_CANARY")

    monkeypatch.setattr(module, "run_reverse_swap", runner)
    with pytest.raises(module.ReverseConversionError) as captured:
        _run(harness, await_settlement=True)
    assert "PRIVATE_OBSERVATION_CANARY" not in str(captured.value)
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None
    assert harness.journal.status(harness.request.operation_id).state == "dispatched"
    harness.payer.pay.assert_called_once()
    with pytest.raises(module.ReverseConversionError):
        _run(harness, await_settlement=True)
    assert len(calls) == 1
    harness.payer.pay.assert_called_once()
