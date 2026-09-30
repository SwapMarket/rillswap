"""Native proposal preflight never trades deadline recovery for Core evidence."""

from __future__ import annotations

import asyncio
import os
import threading
from contextlib import contextmanager
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.settlement.funding import FundingBindingTransactionMatch
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from rill_core.wire.messages import Envelope
from rill_core.wire.settlement_messages import FundingBindingPayload
from test_cooperation_burn import _featured_paid_swap
from test_live_session_store import Harness

from rill_provider import live_session_store as live
from rill_provider import settlement_engine as engine_module
from rill_provider.core_tx_bytes import CooperativeClaimOutpoint, CoreTransactionUnknownError
from rill_provider.live_session_store import LiveSessionStoreError, SettlementItem
from rill_provider.settlement_engine import EngineSettings, SettlementEngine
from rill_provider.settlement_policy import offered_terms

if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Iterator
    from pathlib import Path

    from rill_provider.live_session_store import LiveSessionStore

pytestmark = [
    pytest.mark.native_crypto,
    pytest.mark.skipif(
        os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
        reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
    ),
]


@pytest.fixture
def runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[SettlementEngine, LiveSessionStore, CooperativeClaimOutpoint]]:
    from rill_crypto import Context  # noqa: PLC0415 - explicit native test opt-in

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, _, _ = _featured_paid_swap(harness, store)
        store._public_keys = crypto  # noqa: SLF001 - bind real native custody
        store._crypto = crypto  # noqa: SLF001
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001
            store._contract_key(connection, session)  # noqa: SLF001
        offer, funded, preimage = store._connection.execute(  # noqa: SLF001 - synthetic PAID fixture
            "SELECT terms_offer,funding_binding,preimage FROM swaps WHERE session_id=?",
            (session,),
        ).fetchone()
        item = SettlementItem(
            session_id=session,
            state="PAID",
            blocked=False,
            terms_offer=offer,
            funding_binding=funded,
            invoice="",
            preimage=preimage,
            claim_tx=None,
            claim_txid=None,
        )
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        binding = parse_model_json(
            FundingBindingPayload,
            canonicalize(Envelope.model_validate_json(item.funding_binding, strict=True).payload),
        ).binding
        sample = CooperativeClaimOutpoint(
            terms.network_identity,
            FundingBindingTransactionMatch(
                binding.funding_txid,
                binding.contract_vout,
                binding.lineage_anchor_txid,
                binding.lineage_anchor_vout,
            ),
            binding.funding_txid,
            binding.contract_vout,
            int(binding.contract_value_sat),
            bytes.fromhex(binding.contract_script_pubkey),
            "aa" * 32,
            1090,
            terms.funding_confirmations,
            1091 - terms.funding_confirmations,
            "bb" * 32,
        )
        chain = Mock(observe_cooperative_claim_outpoint=Mock(return_value=sample))
        engine = SettlementEngine(store, chain, Mock(), crypto, EngineSettings(claim_fee_sat=300))
        fallback = engine._claim(item, terms, binding, 300)  # noqa: SLF001 - native stored fallback
        with store._connection as connection:  # noqa: SLF001 - fixture admitted featured contract
            connection.execute(
                "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
                "VALUES (?, ?, 1, 'ADMITTED')",
                (session, binding.contract_hash),
            )
        store.prepare_claim_window(
            session,
            fallback_raw=fallback.raw_transaction,
            fallback_txid=fallback.txid,
            fallback_fee_sat=fallback.fee_sat,
            started_at=1000,
            now=1000,
            deadline_at=1020,
            deadline_height=1094,
        )
        yield engine, store, sample


def _session(store: LiveSessionStore) -> str:
    (candidate,) = store.prepared_fallbacks()
    return candidate.session_id


def _assert_no_attempt(store: LiveSessionStore) -> None:
    assert store._connection.execute(  # noqa: SLF001 - durable no-attempt assertion
        "SELECT count(*) FROM cooperation_attempts"
    ).fetchone() == (0,)
    assert store.pending_outbox() == ()
    assert store._cooperation_handles == {}  # noqa: SLF001


def test_proposal_is_durable_before_its_message_id_is_returned(runtime: tuple) -> None:
    engine, store, sample = runtime
    proposal_id = asyncio.run(
        engine.initiate_cooperative_proposal(_session(store), now=lambda: 1001)
    )
    assert proposal_id is not None
    (message,) = store.pending_outbox()
    proposal = Envelope.model_validate_json(message.canonical_bytes, strict=True)
    assert proposal.message_id == proposal_id
    assert proposal.payload["action"] == "cooperative_claim_propose"
    assert proposal.payload["deadline_at"] == 1020
    assert proposal.payload["deadline_height"] == 1094
    assert store._connection.execute(  # noqa: SLF001
        "SELECT state FROM cooperation_attempts"
    ).fetchone() == ("NONCE_READY",)
    (fallback,) = store.prepared_fallbacks()
    assert fallback.state == "WAITING"
    assert proposal.payload["payment_preimage"] == fallback.preimage
    engine._chain.broadcast.assert_not_called()  # noqa: SLF001
    assert store.pending_sendable(proposal_id, now=1001, tip_height=sample.tip_height)


@pytest.mark.parametrize("change", ["clock delay", "revocation"])
def test_proposal_clock_return_is_fenced_before_burn(
    runtime: tuple,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    engine, store, _ = runtime
    monotonic_value = 0.0
    armed = False
    burn = store.burn_selected_cooperative_claim

    def armed_burn(*args: object, **kwargs: object) -> None:
        nonlocal armed
        armed = True
        burn(*args, **kwargs)

    def now() -> int:
        nonlocal monotonic_value
        if armed:
            if change == "clock delay":
                monotonic_value = 1.0
            else:
                engine.disable_new_exposure()
        return 1001

    monkeypatch.setattr(engine_module, "time", Mock(monotonic=lambda: monotonic_value))
    monkeypatch.setattr(store, "burn_selected_cooperative_claim", armed_burn)
    with pytest.raises(LiveSessionStoreError, match="clock unavailable"):
        asyncio.run(engine.initiate_cooperative_proposal(_session(store), now=now))
    _assert_no_attempt(store)


@pytest.mark.parametrize(
    "case",
    [
        "network",
        "outpoint",
        "value",
        "script",
        "static match",
        "underconfirmed",
        "height cutoff",
        "genesis tip",
        "bad tip hash",
        "inconsistent inclusion",
        "wrong type",
        "core spent",
        "wall cutoff",
        "floor exceeds fee",
        "revoked",
        "missing",
    ],
)
def test_unsafe_preflight_never_burns(runtime: tuple, case: str) -> None:
    engine, store, sample = runtime
    session = _session(store)
    replacements = {
        "network": {
            "network_identity": sample.network_identity.model_copy(
                update={"genesis_hash": "ff" * 32}
            )
        },
        "outpoint": {"funding_txid": "ff" * 32},
        "value": {"funding_value_sat": sample.funding_value_sat + 1},
        "script": {"funding_script_pubkey": b"wrong"},
        "static match": {"static_match": replace(sample.static_match, lineage_anchor_vout=9)},
        "underconfirmed": {"confirmations": 0},
        "height cutoff": {"tip_height": 1094},
        "genesis tip": {"tip_height": 0},
        "bad tip hash": {"tip_hash": "not a hash"},
        "inconsistent inclusion": {"inclusion_height": 1000},
    }
    if case in replacements:
        engine._chain.observe_cooperative_claim_outpoint.return_value = replace(  # noqa: SLF001
            sample, **replacements[case]
        )
    if case == "wrong type":
        engine._chain.observe_cooperative_claim_outpoint.return_value = Mock()  # noqa: SLF001
    if case == "core spent":
        engine._chain.observe_cooperative_claim_outpoint.side_effect = CoreTransactionUnknownError(  # noqa: SLF001
            "spent"
        )
    if case == "floor exceeds fee":
        engine._settings = EngineSettings(claim_fee_sat=301)  # noqa: SLF001
    if case == "revoked":
        engine.disable_new_exposure()
    if case == "missing":
        session = "ff" * 32
    assert (
        asyncio.run(
            engine.initiate_cooperative_proposal(
                session, now=lambda: 1020 if case == "wall cutoff" else 1001
            )
        )
        is None
    )
    _assert_no_attempt(store)


@pytest.mark.parametrize("case", ["selected", "revoked", "clock expired"])
def test_sampling_does_not_preserve_stale_initiation_authority(runtime: tuple, case: str) -> None:
    engine, store, _ = runtime
    clock_now = 1001
    original_sample = engine._sample_cooperative_outpoint  # noqa: SLF001

    async def sample_then_change(
        *args: object, **kwargs: object
    ) -> CooperativeClaimOutpoint | None:
        nonlocal clock_now
        result = await original_sample(*args, **kwargs)
        if case == "selected":
            (candidate,) = store.prepared_fallbacks()
            store.select_prepared_fallback(candidate, signer=store._crypto, now=1001, height=1094)  # noqa: SLF001
        elif case == "revoked":
            engine.disable_new_exposure()
        else:
            clock_now = 1020
        return result

    engine._sample_cooperative_outpoint = sample_then_change  # noqa: SLF001
    session = _session(store)
    if case == "selected":
        with pytest.raises(LiveSessionStoreError, match="window unavailable"):
            asyncio.run(engine.initiate_cooperative_proposal(session, now=lambda: clock_now))
        assert store._cooperation_handles == {}  # noqa: SLF001
    else:
        assert (
            asyncio.run(engine.initiate_cooperative_proposal(session, now=lambda: clock_now))
            is None
        )
        _assert_no_attempt(store)


def test_post_burn_failure_is_not_reported_as_effect_free_refusal(
    runtime: tuple,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, store, _ = runtime

    def refused_begin(*_args: object, **_kwargs: object) -> str:
        raise LiveSessionStoreError("test-only native initiation failure")

    monkeypatch.setattr(store, "begin_selected_cooperative_proposal", refused_begin)
    with pytest.raises(LiveSessionStoreError, match="initiation failure"):
        asyncio.run(engine.initiate_cooperative_proposal(_session(store), now=lambda: 1001))
    assert store._connection.execute(  # noqa: SLF001
        "SELECT state FROM cooperation_attempts"
    ).fetchone() == ("BURNED",)
    assert store.pending_outbox() == ()
    assert store._cooperation_handles == {}  # noqa: SLF001


def test_sqlite_wait_cannot_reuse_aged_height_evidence(
    runtime: tuple,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, store, sample = runtime
    original_write = store._write  # noqa: SLF001
    elapsed = 0.0
    sampling_done = False
    monkeypatch.setattr(engine_module.time, "monotonic", lambda: elapsed)

    def completed_sample(*_args: object, **_kwargs: object) -> CooperativeClaimOutpoint:
        nonlocal sampling_done
        sampling_done = True
        return sample

    engine._chain.observe_cooperative_claim_outpoint.side_effect = completed_sample  # noqa: SLF001

    @contextmanager
    def delayed_write() -> Iterator[sqlite3.Connection]:
        nonlocal elapsed
        with original_write() as connection:
            if sampling_done:
                elapsed = 2.0
            yield connection

    monkeypatch.setattr(store, "_write", delayed_write)
    with pytest.raises(LiveSessionStoreError, match="clock unavailable"):
        asyncio.run(engine.initiate_cooperative_proposal(_session(store), now=lambda: 1001))
    _assert_no_attempt(store)


@pytest.mark.parametrize("cancel_waiter", [False, True])
def test_timeout_and_cancellation_retain_singleflight_until_worker_finishes(
    runtime: tuple,
    monkeypatch: pytest.MonkeyPatch,
    *,
    cancel_waiter: bool,
) -> None:
    engine, store, _ = runtime
    entered, release = asyncio.Event(), threading.Event()
    loop: asyncio.AbstractEventLoop | None = None
    monkeypatch.setattr(engine_module, "COOPERATIVE_SAMPLE_SECONDS", 0.5 if cancel_waiter else 0.02)

    def stalled_sample(*_args: object, **_kwargs: object) -> CooperativeClaimOutpoint:
        assert loop is not None
        loop.call_soon_threadsafe(entered.set)
        if not release.wait(timeout=2):
            raise AssertionError("test worker was not released")
        raise CoreTransactionUnknownError("late worker failure")

    engine._chain.observe_cooperative_claim_outpoint.side_effect = stalled_sample  # noqa: SLF001

    async def exercise() -> None:
        nonlocal loop
        loop = asyncio.get_running_loop()
        session = _session(store)
        waiter = asyncio.create_task(
            engine.initiate_cooperative_proposal(session, now=lambda: 1001)
        )
        try:
            async with asyncio.timeout(1):
                await entered.wait()
            if cancel_waiter:
                waiter.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiter
            else:
                assert await waiter is None
            task = engine._cooperative_sample_task  # noqa: SLF001
            assert task is not None
            assert not task.done()
            assert await engine.initiate_cooperative_proposal(session, now=lambda: 1001) is None
            assert engine._chain.observe_cooperative_claim_outpoint.call_count == 1  # noqa: SLF001
            _assert_no_attempt(store)
        finally:
            release.set()
            await asyncio.gather(waiter, return_exceptions=True)
            task = engine._cooperative_sample_task  # noqa: SLF001
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)
            await asyncio.sleep(0)
        assert engine._cooperative_sample_task is None  # noqa: SLF001
        _assert_no_attempt(store)

    asyncio.run(exercise())


def test_unilateral_selection_does_not_wait_for_hung_or_late_positive_sample(
    runtime: tuple,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, store, sample = runtime
    release = threading.Event()
    monkeypatch.setattr(engine_module, "COOPERATIVE_SAMPLE_SECONDS", 0.02)

    async def exercise() -> None:
        entered = asyncio.Event()
        loop = asyncio.get_running_loop()

        def stalled_positive(*_args: object, **_kwargs: object) -> CooperativeClaimOutpoint:
            loop.call_soon_threadsafe(entered.set)
            if not release.wait(timeout=2):
                raise AssertionError("test worker was not released")
            return sample

        engine._chain.observe_cooperative_claim_outpoint.side_effect = stalled_positive  # noqa: SLF001
        waiter = asyncio.create_task(
            engine.initiate_cooperative_proposal(_session(store), now=lambda: 1001)
        )
        try:
            async with asyncio.timeout(1):
                await entered.wait()
            assert len(engine.select_due_fallbacks(1020)) == 1
            assert len(store.recorded_fallbacks()) == 1
            assert await waiter is None
            assert store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM cooperation_attempts"
            ).fetchone() == (0,)
        finally:
            release.set()
            await asyncio.gather(waiter, return_exceptions=True)
            task = engine._cooperative_sample_task  # noqa: SLF001
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)
            await asyncio.sleep(0)
        assert store._cooperation_handles == {}  # noqa: SLF001
        assert len(store.pending_outbox()) == 1  # unilateral observation, never a proposal

    asyncio.run(exercise())
