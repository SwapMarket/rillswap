"""Explicit signed-depth observation, with legacy SDK behavior kept intact."""

from __future__ import annotations

import asyncio
import dataclasses
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    validate_cooperative_claim,
    validate_unilateral_spend,
)
from rill_crypto import Context
from test_reverse_cooperative_claim import _reply
from test_reverse_fallback_publication import _featured
from test_reverse_sdk_lifetime import NATIVE_LIBRARY, NATIVE_ONLY, NativeSdk
from test_wallet_rpc import NETWORK

from rill_cli import live_reverse_swap as reverse
from rill_cli.claim_watcher import ClaimAttempt
from rill_cli.wallet_rpc import HistoricalWalletOutput

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from rill_core.wire.messages import Envelope

# Unit records below represent trusted-backend behavior, not RPC provenance.
# Existing Core historical-observation tests prove that backend independently.
# ruff: noqa: SLF001

DESTINATION = b"\x51\x20" + b"\x55" * 32
SELECTED = ClaimAttempt("01" * 32, b"placeholder", 300, 150, 100)


def _record(depth: int = 3) -> HistoricalWalletOutput:
    return HistoricalWalletOutput(
        NETWORK,
        SELECTED.txid,
        0,
        9700,
        DESTINATION,
        depth,
        100,
        "02" * 32,
        time.time(),
        time.time(),
    )


def test_default_never_probes_a_stronger_wallet_capability() -> None:
    class Wallet:
        def __getattr__(self, _name: str) -> object:
            raise AssertionError("legacy wallet must not be probed")

    assert reverse._settlement_capability(Wallet(), await_settlement=False) is None


@pytest.mark.parametrize("mode", [None, 1, "true"])
def test_terminal_mode_rejects_nonboolean_requests(mode: object) -> None:
    with pytest.raises(reverse.SwapError, match="must be a boolean"):
        reverse._settlement_capability(Mock(), await_settlement=mode)


def test_missing_async_or_incompatible_capability_refuses_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def asynchronous(*_args: object, **_kwargs: object) -> None:
        return None

    def no_budget(_txid: str, _script: bytes) -> None:
        return None

    class AsyncObserver:
        async def __call__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("asynchronous observer must not execute")

    secrets = Mock(side_effect=AssertionError("must not create secrets"))
    discover = AsyncMock(side_effect=AssertionError("must not dispatch"))
    monkeypatch.setattr(reverse.secrets, "token_bytes", secrets)
    monkeypatch.setattr(reverse, "discover", discover)
    for capability in (None, False, asynchronous, AsyncObserver(), no_budget):
        with pytest.raises(reverse.SwapError, match="requires a synchronous"):
            asyncio.run(
                reverse.run_reverse_swap(
                    Mock(),
                    identity="00" * 32,
                    network=NETWORK,
                    payout_sat=10000,
                    decode_invoice=Mock(),
                    payer=Mock(),
                    wallet=SimpleNamespace(observe_historical_wallet_output=capability),
                    write_recovery=Mock(),
                    crypto=Mock(),
                    await_settlement=True,
                    limits=reverse.ReverseSwapLimits(5000, 0, 5000, 1, 1000, 100, 2),
                )
            )
    secrets.assert_not_called()
    discover.assert_not_called()


def _observe(observer: Mock, *, duration: float = 20) -> None:
    async def exercise() -> None:
        async with reverse._ReverseLifetime(duration) as lifetime:
            lifetime.start()
            await reverse._await_claim_settlement(
                lifetime,
                observer,
                SELECTED,
                network=NETWORK,
                destination=DESTINATION,
                value_sat=10000,
                depth=3,
                report=lambda _line: None,
            )

    asyncio.run(exercise())


def test_signed_target_is_pending_at_one_and_two_and_observed_at_three(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reverse, "POLL_SECONDS", 0)
    observer = Mock(side_effect=[_record(1), _record(2), _record(3)])
    _observe(observer)
    assert observer.call_count == 3
    for call in observer.call_args_list:
        assert call.args == (SELECTED.txid, DESTINATION)
        assert 0 < call.kwargs["deadline_seconds"] <= 10


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("txid", "03" * 32),
        ("network", None),
        ("vout", 1),
        ("vout", True),
        ("value_sat", 8200),
        ("value_sat", True),
        ("script_pubkey", b"foreign"),
        ("confirmations", -1),
        ("confirmations", 0),
        ("confirmations", True),
        ("block_height", 0),
        ("block_height", True),
        ("block_hash", "AB" * 32),
        ("block_hash", "orphan"),
        ("started_at", float("nan")),
        ("completed_at", float("inf")),
        ("completed_at", -1.0),
    ],
)
def test_contradictory_or_malformed_evidence_never_returns_terminal_success(
    field: str,
    value: object,
) -> None:
    observer = Mock(return_value=dataclasses.replace(_record(), **{field: value}))
    with pytest.raises(reverse.SwapError, match="observation differs"):
        _observe(observer)
    observer.assert_called_once()


@pytest.mark.parametrize(
    "error", [RuntimeError("PRIVATE_CALLBACK_CANARY"), TimeoutError("PRIVATE_CALLBACK_CANARY")]
)
def test_unknown_backend_errors_expose_no_upstream_context_or_retry(error: Exception) -> None:
    observer = Mock(side_effect=error)
    with pytest.raises((reverse.SwapError, TimeoutError)) as captured:
        _observe(observer)
    assert "PRIVATE_CALLBACK_CANARY" not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    observer.assert_called_once()


def test_unknown_record_never_returns_terminal_success() -> None:
    observer = Mock(return_value=None)
    with pytest.raises(reverse.SwapError, match="observation differs"):
        _observe(observer)
    observer.assert_called_once()


@pytest.mark.parametrize("delayed", [False, True])
def test_coroutine_returned_by_synchronous_observer_is_closed_without_execution(
    recwarn: pytest.WarningsRecorder,
    *,
    delayed: bool,
) -> None:
    executed = Mock()

    async def unsupported() -> None:
        executed()

    coroutine = unsupported()

    def observe(*_args: object, **_kwargs: object) -> object:
        if delayed:
            time.sleep(0.07)
        return coroutine

    observer = Mock(side_effect=observe)
    try:
        expected = TimeoutError if delayed else reverse.SwapError
        with pytest.raises(expected):
            _observe(observer, duration=0.03 if delayed else 20)
        assert coroutine.cr_frame is None
        executed.assert_not_called()
        assert not recwarn.list
    finally:
        # Keep the regression's deliberately malformed backend warning-free
        # even when exercising an implementation that does not yet close it.
        coroutine.close()


def test_queued_expiry_never_invokes_a_terminal_observer() -> None:
    entered, release = threading.Event(), threading.Event()
    observer = Mock(return_value=_record())

    async def exercise() -> None:
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        admitted = asyncio.Event()

        def occupy() -> None:
            entered.set()
            loop.call_soon_threadsafe(admitted.set)
            assert release.wait(2)

        occupied = loop.run_in_executor(None, occupy)

        async def owned() -> None:
            async with reverse._ReverseLifetime(0.03) as lifetime:
                lifetime.start()
                await reverse._await_claim_settlement(
                    lifetime,
                    observer,
                    SELECTED,
                    network=NETWORK,
                    destination=DESTINATION,
                    value_sat=10000,
                    depth=3,
                    report=lambda _line: None,
                )

        task = None
        try:
            await asyncio.wait_for(admitted.wait(), timeout=2)
            task = asyncio.create_task(owned())
            await asyncio.sleep(0.08)
            assert not task.done()  # Expired work is still owned until drainage.
        finally:
            release.set()
            await occupied
            if task is not None:
                with pytest.raises(TimeoutError):
                    await task

    asyncio.run(exercise())
    observer.assert_not_called()


def test_late_terminal_evidence_is_drained_but_never_accepted() -> None:
    finished = threading.Event()

    def observe(*_args: object, **_kwargs: object) -> HistoricalWalletOutput:
        time.sleep(0.07)
        finished.set()
        return _record()

    observer = Mock(side_effect=observe)

    async def exercise() -> None:
        async with reverse._ReverseLifetime(0.03) as lifetime:
            lifetime.start()
            await reverse._await_claim_settlement(
                lifetime,
                observer,
                SELECTED,
                network=NETWORK,
                destination=DESTINATION,
                value_sat=10000,
                depth=3,
                report=lambda _line: None,
            )

    with pytest.raises(TimeoutError):
        asyncio.run(exercise())
    assert finished.is_set()
    observer.assert_called_once()


def test_cancelled_terminal_observation_retains_its_running_worker() -> None:
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    admitted = asyncio.Event()
    loops: list[asyncio.AbstractEventLoop] = []

    def observe(*_args: object, **_kwargs: object) -> HistoricalWalletOutput:
        entered.set()
        loops[0].call_soon_threadsafe(admitted.set)
        assert release.wait(2)
        finished.set()
        return _record()

    observer = Mock(side_effect=observe)

    async def exercise() -> None:
        loops.append(asyncio.get_running_loop())

        async def owned() -> None:
            async with reverse._ReverseLifetime(20) as lifetime:
                lifetime.start()
                await reverse._await_claim_settlement(
                    lifetime,
                    observer,
                    SELECTED,
                    network=NETWORK,
                    destination=DESTINATION,
                    value_sat=10000,
                    depth=3,
                    report=lambda _line: None,
                )

        task = asyncio.create_task(owned())
        try:
            await asyncio.wait_for(admitted.wait(), timeout=2)
            task.cancel()
            await asyncio.sleep(0.02)
            assert not task.done()
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(exercise())
    assert finished.is_set()
    observer.assert_called_once()


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("claim_path", ["unilateral", "cooperative", "older-unilateral"])
def test_native_sdk_explicit_terminal_mode_uses_original_claim_and_lifetime(  # noqa: PLR0915 - one original native invocation and its read-only observations
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    claim_path: str,
) -> None:
    async def exercise(crypto: Context) -> None:  # noqa: PLR0915 - retain the original crypto lifetime across both claim paths
        sdk = NativeSdk(crypto, tmp_path, monkeypatch)
        older = claim_path == "older-unilateral"
        if older:
            sdk.wallet.tip_height.side_effect = lambda: (
                sdk.terms.refund_lock_height - sdk.terms.timing_policy.claim_confirmation_blocks
                if sdk.broadcasts
                else 1000
            )
            sdk.wallet.unspent_on_chain.side_effect = lambda *_args: len(sdk.broadcasts) < 2

            def old_depth(txid: str) -> int | None:
                if len(sdk.broadcasts) < 2:
                    return None
                authorization = UnilateralAuthorization.from_terms(
                    sdk.terms,
                    FundingOutput(
                        bytes.fromhex(sdk.binding.funding_txid),
                        sdk.binding.contract_vout,
                        int(sdk.binding.contract_value_sat),
                        bytes.fromhex(sdk.binding.contract_script_pubkey),
                    ),
                    "claim",
                    keys=crypto,
                )
                checked = validate_unilateral_spend(
                    sdk.broadcasts[0], authorization, verifier=crypto
                )
                return 1 if txid == checked.txid else -1

            sdk.wallet.wallet_confirmations.side_effect = old_depth
        if claim_path == "cooperative":
            _featured(sdk, monkeypatch)
            monkeypatch.setattr(reverse.time, "time", time.time)

            async def receive(
                wanted: Callable[[Envelope], bool],
                *,
                timeout: float | None = None,  # noqa: ASYNC109 - match the existing session's bounded receive interface
            ) -> Envelope:
                assert timeout is None or timeout > 0
                reply = _reply(sdk, "signed")
                assert wanted(reply)
                return reply

            sdk.session.receive = receive
        depths = iter((1, 2, 3))
        counts: list[tuple[int, int, int]] = []
        original = reverse.run_reverse_swap

        def observe(txid: str, script: bytes, *, deadline_seconds: float) -> HistoricalWalletOutput:
            counts.append((len(sdk.bounds), len(sdk.broadcasts), sdk.contract_signatures))
            assert 0 < deadline_seconds <= min(10, sdk.bounds[0]["deadline"] - sdk.now())
            assert len(sdk.bounds) == 1
            assert len(sdk.broadcasts) == (2 if older else 1)
            assert sdk.contract_signatures == (2 if older else 1)
            authorization = UnilateralAuthorization.from_terms(
                sdk.terms,
                FundingOutput(
                    bytes.fromhex(sdk.binding.funding_txid),
                    sdk.binding.contract_vout,
                    int(sdk.binding.contract_value_sat),
                    bytes.fromhex(sdk.binding.contract_script_pubkey),
                ),
                "claim",
                keys=crypto,
            )
            validator = (
                validate_cooperative_claim
                if claim_path == "cooperative"
                else validate_unilateral_spend
            )
            checked = validator(sdk.broadcasts[0], authorization, verifier=crypto)
            assert checked.txid == txid
            return HistoricalWalletOutput(
                sdk.terms.network_identity,
                txid,
                0,
                int(sdk.terms.economics.contract_amount_sat) - checked.fee_sat,
                script,
                next(depths),
                1000,
                "55" * 32,
                time.time(),
                time.time(),
            )

        sdk.wallet.observe_historical_wallet_output = Mock(side_effect=observe)

        if older:
            # The claim pays the signed 500-sat reserve, clamped to the signed
            # 400-sat ceiling, so it cannot be bumped by its 143-vB relay
            # increment. Starting at 143 sat creates replacement headroom
            # without changing signed terms.
            watcher = reverse.ClaimWatcher
            monkeypatch.setattr(
                reverse,
                "ClaimWatcher",
                lambda **kwargs: watcher(**{**kwargs, "initial_fee_sat": 143}),
            )

        async def stronger(*args: object, **kwargs: object) -> reverse.ReverseSwapOutcome:
            return await original(*args, **kwargs, await_settlement=True)

        monkeypatch.setattr(reverse, "run_reverse_swap", stronger)

        def acknowledged(candidate: bytes, previous: bytes | None) -> bytes:
            sdk.write(candidate, previous)
            return candidate

        try:
            result = await sdk.run(acknowledged, settle_timeout=120)
        finally:
            assert all(count == (1, 2 if older else 1, 2 if older else 1) for count in counts), (
                counts
            )
        assert (
            (result.claim_txid != sdk.claim_txid)
            if older
            else (result.claim_txid == sdk.claim_txid)
        )
        assert sdk.wallet.observe_historical_wallet_output.call_count == 3
        assert len(dataclasses.fields(result)) == 5
        assert len(sdk.bounds) == 1
        assert len(sdk.broadcasts) == (2 if older else 1)
        if older:
            authorization = UnilateralAuthorization.from_terms(
                sdk.terms,
                FundingOutput(
                    bytes.fromhex(sdk.binding.funding_txid),
                    sdk.binding.contract_vout,
                    int(sdk.binding.contract_value_sat),
                    bytes.fromhex(sdk.binding.contract_script_pubkey),
                ),
                "claim",
                keys=crypto,
            )
            first, second = [
                validate_unilateral_spend(raw, authorization, verifier=crypto)
                for raw in sdk.broadcasts
            ]
            assert first.txid == result.claim_txid != second.txid
            assert first.fee_sat < second.fee_sat
        assert any("signed settlement depth 3" in line for line in sdk.reports)

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))
