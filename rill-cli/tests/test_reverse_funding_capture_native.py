"""The original SDK awaits capture before signing and drains canceled workers."""

from __future__ import annotations

import asyncio
import gc
import threading
import warnings
from importlib import import_module
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.wire.hashes import contract_hash
from rill_crypto import Context
from test_reverse_sdk_lifetime import NATIVE_LIBRARY, NATIVE_ONLY, NativeSdk

from rill_cli import live_reverse_swap as reverse

if TYPE_CHECKING:
    from pathlib import Path

    from rill_core.wire.messages import ContractTerms, FundingBinding


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("mode", ["success", "error", "cancel", "expiry"])
def test_native_capture_order_original_deadline_and_drained_owner(  # noqa: PLR0915 - one native owner with coordinated worker cancellation
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    async def exercise(crypto: Context) -> None:  # noqa: PLR0915 - coordinate the complete original lifetime and worker drainage
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        sdk = reverse.run_reverse_swap
        signer = reverse._claim_signer  # noqa: SLF001 - assert pre-signing hook ordering
        acquired = []
        captured = []
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()

        def sign(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401 - delegate actual native signer unchanged
            assert finished.is_set()
            acquired.append(True)
            return signer(*args, **kwargs)

        monkeypatch.setattr(reverse, "_claim_signer", sign)

        def capture(binding: FundingBinding, terms: ContractTerms, deadline: float) -> None:
            try:
                assert len(fixture.documents) == 2
                assert binding == fixture.binding
                assert terms == fixture.terms
                assert deadline == fixture.bounds[0]["deadline"]
                assert acquired == []
                assert fixture.contract_signatures == 0
                captured.append((binding, terms, deadline))
                if mode == "error":
                    raise RuntimeError("PRIVATE_CANARY")
                if mode in ("cancel", "expiry"):
                    entered.set()
                    assert release.wait(3)
                # Native access remains valid until this owned worker finishes.
                assert (
                    crypto.public_key(fixture.contract_secret).hex()
                    == terms.client_contract_compressed_key
                )
            finally:
                finished.set()

        async def observed(*args: Any, **kwargs: Any) -> reverse.ReverseSwapOutcome:  # noqa: ANN401 - preserve complete original call contract
            return await sdk(*args, **kwargs, funding_inclusion_observer=capture)

        monkeypatch.setattr(reverse, "run_reverse_swap", observed)
        running = asyncio.create_task(fixture.run())
        try:
            if mode in ("cancel", "expiry"):
                assert await asyncio.to_thread(entered.wait, 1)
                if mode == "cancel":
                    for _ in range(3):
                        running.cancel()
                        await asyncio.sleep(0)
                        assert not running.done()
                else:
                    fixture.offset = 30
                    await asyncio.sleep(0.01)
                    assert not running.done()
                assert not finished.is_set()
                release.set()
            if mode == "success":
                outcome = await running
                assert outcome.claim_txid == fixture.claim_txid
                assert acquired == [True]
                assert fixture.broadcasts
            elif mode == "cancel":
                with pytest.raises(asyncio.CancelledError):
                    await running
            elif mode == "error":
                with pytest.raises(RuntimeError, match="PRIVATE_CANARY"):
                    await running
            else:
                with pytest.raises(reverse.SwapError):
                    await running
            assert finished.is_set()
            assert len(captured) == 1
            fixture.payer.pay.assert_called_once()
            if mode != "success":
                assert acquired == []
                assert fixture.contract_signatures == 0
                assert fixture.broadcasts == []
                assert (tmp_path / "reverse.age.funded").is_file()
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_authentic_native_relay_capture_after_funded_ack_before_signer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = import_module("test_live_reverse_swap")
    original = old.run_reverse_swap
    signer = reverse._claim_signer  # noqa: SLF001 - assert authentic relay's pre-signing hook
    acknowledged = []
    captured = []
    signed = []

    def sign(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401 - actual native signing unchanged
        assert len(captured) == 1
        signed.append(True)
        return signer(*args, **kwargs)

    async def observed(*args: Any, **kwargs: Any) -> reverse.ReverseSwapOutcome:  # noqa: ANN401 - existing relay fixture wrapper
        writer = kwargs["write_recovery"]

        def write(document: bytes, predecessor: bytes | None) -> object:
            result = writer(document, predecessor)
            acknowledged.append(document)
            return result

        def capture(binding: FundingBinding, terms: ContractTerms, deadline: float) -> None:
            assert len(acknowledged) == 2
            assert signed == []
            assert binding.contract_hash == contract_hash(terms).hex()
            assert deadline > reverse.time.monotonic()
            captured.append(binding)

        kwargs["write_recovery"] = write
        return await original(*args, **kwargs, funding_inclusion_observer=capture)

    monkeypatch.setattr(old, "run_reverse_swap", observed)
    monkeypatch.setattr(reverse, "_claim_signer", sign)
    old.test_native_ln_to_btc_swap_claims_and_settles_through_the_provider(tmp_path)
    assert len(captured) == 1
    assert signed == [True]


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize(
    "fault",
    [
        "async_function",
        "async_callable",
        "noncallable",
        "wrapped_coroutine",
        "late_coroutine",
        "value",
    ],
)
def test_capture_must_be_synchronous_and_acknowledge_with_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    with Context(library_path=NATIVE_LIBRARY) as crypto:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        original = reverse.run_reverse_swap
        calls = []

        async def asynchronous(*_args: object) -> None:
            calls.append("not synchronous")

        class AsyncObserver:
            async def __call__(self, *_args: object) -> None:
                calls.append("not synchronous")

        def wrapped(*_args: object) -> object:
            if fault == "late_coroutine":
                fixture.offset = 30
            return asynchronous()

        def value(*_args: object) -> object:
            return True

        observers = {
            "async_function": asynchronous,
            "async_callable": AsyncObserver(),
            "noncallable": False,
            "wrapped_coroutine": wrapped,
            "late_coroutine": wrapped,
            "value": value,
        }

        async def observed(*args: Any, **kwargs: Any) -> reverse.ReverseSwapOutcome:  # noqa: ANN401 - invalid callback types exercise public runtime checks
            return await original(*args, **kwargs, funding_inclusion_observer=observers[fault])

        monkeypatch.setattr(reverse, "run_reverse_swap", observed)
        with warnings.catch_warnings(record=True) as emitted:
            warnings.simplefilter("always")
            with pytest.raises(
                reverse.SwapError, match=r"funding inclusion observer must|lifetime expired"
            ):
                asyncio.run(fixture.run())
            gc.collect()
        assert emitted == []
        assert calls == []
        assert fixture.contract_signatures == 0
        assert fixture.broadcasts == []
        if fault in ("wrapped_coroutine", "late_coroutine", "value"):
            fixture.payer.pay.assert_called_once()
            assert len(fixture.documents) == 2
        else:
            fixture.payer.pay.assert_not_called()
            assert fixture.documents == []
