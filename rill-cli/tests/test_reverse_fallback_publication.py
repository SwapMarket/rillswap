"""Native reverse fallback publication is a private, explicit acknowledgment gate."""

from __future__ import annotations

import asyncio
import json
import threading
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest
from rill_core.recovery import REVERSE_FALLBACK_EXTENSION, inspect_recovery_successor
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    contract_hash,
    funding_binding_hash,
    handshake_accept_hash,
    handshake_hash,
    handshake_init_hash,
    provider_terms_hash,
)
from rill_core.wire.messages import ProviderTerms
from rill_crypto import Context
from test_recovery_cli import NATIVE_LIBRARY, NATIVE_ONLY
from test_reverse_sdk_lifetime import NativeSdk

from rill_cli import live_reverse_swap as reverse
from rill_cli.live_swap import SwapError

if TYPE_CHECKING:
    from pathlib import Path


def _featured(fixture: NativeSdk, monkeypatch: pytest.MonkeyPatch) -> None:
    """Authentic synthetic featured transcript; discovery/negotiation remain stubbed."""
    feature = (COOPERATIVE_CLAIM_FEATURE,)
    fixture.init = fixture.init.model_copy(update={"required_features": feature})
    fixture.accept = fixture.accept.model_copy(
        update={
            "required_features": feature,
            "handshake_init_hash": handshake_init_hash(fixture.init).hex(),
        }
    )
    fixture.terms = fixture.terms.model_copy(update={"required_features": feature})
    transcript = handshake_hash(fixture.init, fixture.accept).hex()
    provider_terms = ProviderTerms(
        contract_hash=contract_hash(fixture.terms).hex(),
        contract_terms=fixture.terms,
        handshake_hash=transcript,
    )
    fixture.offer = fixture.offer.model_copy(
        update={
            "terms": provider_terms,
            "provider_terms_signature": fixture.crypto.schnorr_sign(
                (1).to_bytes(32, "big"), provider_terms_hash(provider_terms), b"\x88" * 32
            ).hex(),
        }
    )
    identity_signature = fixture.crypto.schnorr_sign(
        (1).to_bytes(32, "big"), handshake_accept_hash(fixture.accept), b"\x99" * 32
    ).hex()
    fixture.session.reply_to = AsyncMock(
        side_effect=[
            SimpleNamespace(payload=fixture.offer.model_dump(mode="json"), message_id="55" * 32),
            object(),
        ]
    )
    fixture.binding = fixture.binding.model_copy(
        update={"contract_hash": provider_terms.contract_hash}
    )
    fixture.binding_signature = fixture.crypto.schnorr_sign(
        (9).to_bytes(32, "big"), funding_binding_hash(fixture.binding), b"\x77" * 32
    ).hex()
    fixture.funding.return_value = (
        fixture.binding,
        fixture.binding_signature,
        b"signed funding receive fixture",
    )
    monkeypatch.setattr(
        reverse,
        "_handshake",
        AsyncMock(
            return_value=(
                fixture.init,
                fixture.accept,
                identity_signature,
                transcript,
            )
        ),
    )


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_featured_reverse_fallback_is_published_read_back_without_implicit_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        _featured(fixture, monkeypatch)

        def write(candidate: bytes, previous: bytes | None) -> bytes:
            fixture.write(candidate, previous)
            return candidate

        cooperative = AsyncMock(side_effect=SwapError("cooperative stop"))
        monkeypatch.setattr(reverse, "_cooperative_claim", cooperative)
        with pytest.raises(SwapError, match="cooperative stop"):
            await fixture.run(write)
        assert len(fixture.documents) == 3
        # The consumer receives exactly the acknowledged fallback snapshot.
        assert cooperative.await_args.kwargs["acknowledged_fallback"] == fixture.documents[2]
        initial, funded, prepared = map(json.loads, fixture.documents)
        assert (tmp_path / "reverse.age").exists()
        assert (tmp_path / "reverse.age.funded").exists()
        assert (tmp_path / "reverse.age.fallback").exists()
        marker = prepared["extensions"][REVERSE_FALLBACK_EXTENSION]
        assert bytes.fromhex(marker["transaction"])
        assert marker["funding_binding_hash"] == funding_binding_hash(fixture.binding).hex()
        assert prepared["funding_history"] == funded["funding_history"]
        assert prepared["monotonic_knowledge"] == funded["monotonic_knowledge"]
        assert initial["monotonic_knowledge"]["dangerous_signature_issued"] is False
        inspect_recovery_successor(
            fixture.documents[1],
            fixture.documents[2],
            fixture.terms.network_identity,
            crypto=crypto,
        )
        assert fixture.contract_signatures == 1  # the prepared fallback only
        assert fixture.broadcasts == []

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize(
    "result", ["None", "mismatch", "exception after publication", "late success"]
)
def test_unknown_or_late_fallback_acknowledgment_never_reaches_broadcast(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        _featured(fixture, monkeypatch)

        def write(candidate: bytes, previous: bytes | None) -> bytes | None:
            fixture.write(candidate, previous)
            if REVERSE_FALLBACK_EXTENSION not in json.loads(candidate)["extensions"]:
                return candidate
            if result == "None":
                return None
            if result == "mismatch":
                return previous
            if result == "exception after publication":
                raise RuntimeError("private writer details")
            fixture.offset += 30
            return candidate

        expected = {
            "None": "reverse fallback publication not acknowledged",
            "mismatch": "reverse fallback publication not acknowledged",
            "exception after publication": "reverse fallback publication uncertain",
            "late success": "original reverse settlement lifetime expired",
        }[result]
        with pytest.raises(SwapError, match=expected) as error:
            await fixture.run(write)
        assert "do not retry payment" in str(error.value)
        assert "private writer details" not in str(error.value)
        assert (tmp_path / "reverse.age.funded").exists()
        assert (tmp_path / "reverse.age.fallback").exists()
        assert len(fixture.documents) == 3
        assert fixture.broadcasts == []
        assert fixture.contract_signatures == 1  # the prepared fallback only
        assert len(fixture.bounds) == 1
        assert not any("snapshot acknowledged" in report for report in fixture.reports)

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("cancellation", ["caller", "global"])
def test_canceled_fallback_publication_drains_and_cannot_adopt_late_acknowledgment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cancellation: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        _featured(fixture, monkeypatch)
        entered, release = threading.Event(), threading.Event()

        def write(candidate: bytes, previous: bytes | None) -> bytes:
            if REVERSE_FALLBACK_EXTENSION in json.loads(candidate)["extensions"]:
                entered.set()
                assert release.wait(3)
            fixture.write(candidate, previous)
            return candidate

        running = asyncio.create_task(fixture.run(write))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            for _ in range(3):
                if cancellation == "caller":
                    running.cancel()
                else:
                    controller = asyncio.current_task()
                    for task in asyncio.all_tasks():
                        if task is not controller:
                            task.cancel()
                await asyncio.sleep(0)
                assert not running.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await running
            assert (tmp_path / "reverse.age.fallback").exists()
            assert fixture.broadcasts == []
            assert fixture.contract_signatures == 1  # the prepared fallback only
            assert len(fixture.documents) == 3
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_timed_out_fallback_publication_keeps_crypto_owned_until_actual_write_finishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        _featured(fixture, monkeypatch)
        entered, release = threading.Event(), threading.Event()

        def write(candidate: bytes, previous: bytes | None) -> bytes:
            if REVERSE_FALLBACK_EXTENSION in json.loads(candidate)["extensions"]:
                entered.set()
                assert release.wait(4)
            fixture.write(candidate, previous)
            return candidate

        running = asyncio.create_task(fixture.run(write, settle_timeout=2))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            await asyncio.sleep(2.1)
            assert not running.done()  # Deadline is not permission to release borrowed crypto.
            assert fixture.bounds[0]["submission_allowed"]() is False
            assert (
                crypto.public_key(fixture.contract_secret).hex()
                == fixture.terms.client_contract_compressed_key
            )
            release.set()
            with pytest.raises(SwapError, match="original reverse settlement lifetime expired"):
                await running
            assert (tmp_path / "reverse.age.fallback").exists()
            assert fixture.broadcasts == []
            assert fixture.contract_signatures == 1  # the prepared fallback only
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))
