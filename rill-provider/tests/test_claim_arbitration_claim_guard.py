"""Prepared arbitration cannot fall through the ordinary PAID signing path."""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from rill_core.wire.messages import Envelope
from rill_core.wire.settlement_messages import FundingBindingPayload
from test_cooperation_burn import FixtureEnvelopeSigner, _featured_paid_swap
from test_live_session_store import Harness

from rill_provider import live_session_store as live
from rill_provider.live_session_store import LiveSessionStoreError, SettlementItem, StaleSwapError
from rill_provider.settlement_engine import SettlementEngine
from rill_provider.settlement_policy import offered_terms

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("state", [None, "ADMITTED", "WAITING", "CLOSED"])
def test_unselected_window_cannot_sign_or_record_an_immediate_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str | None
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, _, _ = _featured_paid_swap(harness, store)
        with store._connection as connection:  # noqa: SLF001 - synthetic arbitration fixture
            (digest,) = connection.execute(
                "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
            ).fetchone()
            if state == "ADMITTED":
                connection.execute(
                    "INSERT INTO claim_arbitration (session_id, contract_hash, version, state) "
                    "VALUES (?, ?, 1, ?)",
                    (session, digest, state),
                )
            elif state is not None:
                connection.execute(
                    "INSERT INTO claim_arbitration VALUES "
                    "(?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                    (
                        session,
                        digest,
                        state,
                        store.generation,
                        1000,
                        1020,
                        1100,
                        b"signed",
                        "ab" * 32,
                        300,
                    ),
                )
        assert store.immediate_claim_allowed(session) is (state in (None, "ADMITTED"))
        chain, crypto = Mock(), Mock()
        engine = SettlementEngine(store, chain, Mock(), crypto)
        offer, binding, preimage = store._connection.execute(  # noqa: SLF001
            "SELECT terms_offer,funding_binding,preimage FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        item = SettlementItem(
            session_id=session,
            state="PAID",
            blocked=False,
            terms_offer=offer,
            funding_binding=binding,
            invoice="",
            preimage=preimage,
            claim_tx=None,
            claim_txid=None,
            payment_dispatch="SUBMITTED",
        )
        if state in ("WAITING", "CLOSED"):
            assert asyncio.run(engine._advance(item, 1002)) == "PAID"  # noqa: SLF001
            chain.tip_height.assert_not_called()
            crypto.schnorr_sign.assert_not_called()
            signer = FixtureEnvelopeSigner(harness, store._public_keys)  # noqa: SLF001
            with pytest.raises(LiveSessionStoreError, match="requires transaction selection"):
                store.advance_swap(
                    session,
                    from_state="PAID",
                    to_state="CLAIMING",
                    signer=signer,
                    now=1002,
                    claim_tx=b"signed",
                    claim_txid="ab" * 32,
                    claim_fee_sat=300,
                    claim_height=1000,
                    observation={"kind": "claim_broadcast", "claim_txid": "ab" * 32},
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM swaps WHERE session_id=?", (session,)
            ).fetchone() == ("PAID",)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM claim_attempts WHERE session_id=?", (session,)
            ).fetchone() == (0,)
            assert store.pending_outbox() == ()


@pytest.mark.parametrize("scenario", ["expiry", "height", "restart"])
def test_exact_prepared_fallback_is_selected_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, _, _ = _featured_paid_swap(harness, store)
        (digest,) = store._connection.execute(  # noqa: SLF001
            "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        with store._connection as connection:  # noqa: SLF001 - synthetic window fixture
            connection.execute(
                "INSERT INTO claim_arbitration VALUES "
                "(?, ?, 1, 'WAITING', ?, 1000, 1020, 1100, ?, ?, 300, NULL, NULL)",
                (session, digest, store.generation, b"signed", "ab" * 32),
            )
    with harness.acquire() as store:
        assert store.prepared_fallbacks(closed_only=True)
        if scenario != "restart":
            # The acquisition above has already closed the old owner's window.
            # Open a new synthetic current-generation window to exercise expiry.
            with store._connection as connection:  # noqa: SLF001
                connection.execute(
                    "UPDATE claim_arbitration SET state='WAITING', owner_generation=? "
                    "WHERE session_id=?",
                    (store.generation, session),
                )
            assert store.prepared_fallbacks(closed_only=True) == ()
        candidate = store.prepared_fallbacks()[0]
        signer = FixtureEnvelopeSigner(harness, store._public_keys)  # noqa: SLF001
        if scenario != "restart":
            with pytest.raises(LiveSessionStoreError, match="not selectable"):
                store.select_prepared_fallback(candidate, signer=signer, now=1019, height=1099)
            assert store.prepared_fallbacks() == (candidate,)
        selected_at = 1019 if scenario == "height" else 1020
        selected_height = 1100 if scenario == "height" else None
        with pytest.raises(StaleSwapError, match="changed"):
            store.select_prepared_fallback(
                replace(candidate, raw=b"another claim"),
                signer=signer,
                now=selected_at,
                height=selected_height,
            )
        assert store.prepared_fallbacks() == (candidate,)
        broken_signer = Mock()
        broken_signer.schnorr_sign.side_effect = ValueError("signing failed")
        with pytest.raises(LiveSessionStoreError, match="selection refused"):
            store.select_prepared_fallback(
                candidate, signer=broken_signer, now=selected_at, height=selected_height
            )
        assert store.prepared_fallbacks() == (candidate,)
        assert store.recorded_fallbacks() == ()
        store.select_prepared_fallback(
            candidate, signer=signer, now=selected_at, height=selected_height
        )
        assert store.prepared_fallbacks() == ()
        assert store.recorded_fallbacks() == (replace(candidate, state="CLOSED"),)
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state,claim_tx,claim_txid FROM swaps WHERE session_id=?", (session,)
        ).fetchone() == ("CLAIMING", b"signed", "ab" * 32)
        assert store._connection.execute(  # noqa: SLF001
            "SELECT attempt,raw,txid,fee_sat,first_seen_height FROM claim_attempts "
            "WHERE session_id=?",
            (session,),
        ).fetchone() == (0, b"signed", "ab" * 32, 300, selected_height)
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
        ).fetchone() == ("CLOSED",)
        assert len(store.pending_outbox()) == 1
        with pytest.raises(StaleSwapError, match="changed"):
            store.select_prepared_fallback(candidate, signer=signer, now=1021, height=1100)


def test_preparation_refuses_absent_or_nonadmitted_arbitration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, _, _ = _featured_paid_swap(harness, store)
        parameters = {
            "fallback_raw": b"synthetic claim never verified",
            "fallback_txid": "ab" * 32,
            "fallback_fee_sat": 300,
            "started_at": 1000,
            "now": 1002,
            "deadline_at": 1020,
            "deadline_height": 1094,
        }
        with pytest.raises(LiveSessionStoreError, match="not admitted"):
            store.prepare_claim_window(session, **parameters)
        (digest,) = store._connection.execute(  # noqa: SLF001
            "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        with store._connection as connection:  # noqa: SLF001 - synthetic eligibility fixture
            connection.execute(
                "INSERT INTO claim_arbitration VALUES "
                "(?, ?, 1, 'WAITING', ?, 1000, 1020, 1100, ?, ?, 300, NULL, NULL)",
                (session, digest, store.generation, b"signed", "ab" * 32),
            )
        for state in ("WAITING", "CLOSED"):
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
            ).fetchone() == (state,)
            with pytest.raises(LiveSessionStoreError, match="not admitted"):
                store.prepare_claim_window(session, **parameters)
            with store._connection as connection:  # noqa: SLF001
                connection.execute(
                    "UPDATE claim_arbitration SET state='CLOSED' WHERE session_id=?", (session,)
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM swaps WHERE session_id=?", (session,)
            ).fetchone() == ("PAID",)
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM claim_attempts WHERE session_id=?", (session,)
        ).fetchone() == (0,)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize("damage", ["none", "fee", "raw"])
def test_restart_validates_signed_fallback_before_selecting(  # noqa: PLR0915 - one native lifecycle
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    """Synthetic featured admission; actual script signature and verifier are native."""
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, _, _ = _featured_paid_swap(harness, store)
        store._crypto = crypto  # noqa: SLF001 - native custody in isolated fixture
        store._public_keys = crypto  # noqa: SLF001
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001 - native key material for fixture
            store._contract_key(connection, session)  # noqa: SLF001
        offer, funded, preimage, digest = store._connection.execute(  # noqa: SLF001
            "SELECT terms_offer,funding_binding,preimage,contract_hash "
            "FROM swaps WHERE session_id=?",
            (session,),
        ).fetchone()
        terms = offered_terms(Envelope.model_validate_json(offer, strict=True))
        binding = parse_model_json(
            FundingBindingPayload,
            canonicalize(Envelope.model_validate_json(funded, strict=True).payload),
        ).binding
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
        engine = SettlementEngine(store, Mock(), Mock(), crypto)
        spend = engine._claim(item, terms, binding, 300)  # noqa: SLF001 - real script signature
        raw = spend.raw_transaction if damage != "raw" else b"corrupt"
        fee = spend.fee_sat if damage != "fee" else spend.fee_sat + 1
        with store._connection as connection:  # noqa: SLF001 - interrupted prior owner
            if damage == "none":
                connection.execute(
                    "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
                    "VALUES (?, ?, 1, 'ADMITTED')",
                    (session, digest),
                )
            else:
                connection.execute(
                    "INSERT INTO claim_arbitration VALUES "
                    "(?, ?, 1, 'WAITING', ?, 1000, 1020, 1100, ?, ?, ?, NULL, NULL)",
                    (session, digest, store.generation, raw, spend.txid, fee),
                )
        if damage == "none":
            for refused in (
                {"fallback_raw": b"corrupt"},
                {"fallback_fee_sat": spend.fee_sat + 1},
                {"fallback_txid": "cd" * 32},
                {"deadline_at": 1031},
                {"deadline_height": 1095},
            ):
                parameters = {
                    "fallback_raw": spend.raw_transaction,
                    "fallback_txid": spend.txid,
                    "fallback_fee_sat": spend.fee_sat,
                    "started_at": 1000,
                    "now": 1002,
                    "deadline_at": 1020,
                    "deadline_height": 1094,
                }
                with pytest.raises(LiveSessionStoreError):
                    store.prepare_claim_window(session, **(parameters | refused))
                assert store._connection.execute(  # noqa: SLF001
                    "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
                ).fetchone() == ("ADMITTED",)
            store.prepare_claim_window(session, **parameters)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state,deadline_at,owner_generation,fallback_raw "
                "FROM claim_arbitration WHERE session_id=?",
                (session,),
            ).fetchone() == ("WAITING", 1020, store.generation, spend.raw_transaction)
            with pytest.raises(LiveSessionStoreError, match="requires transaction selection"):
                store.sign_with_contract_key(session, b"\x19" * 32, crypto)
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as restarted,
    ):
        restarted._crypto = crypto  # noqa: SLF001
        restarted._public_keys = crypto  # noqa: SLF001
        chain = Mock()
        engine = SettlementEngine(restarted, chain, Mock(), crypto)
        with pytest.raises(LiveSessionStoreError, match="requires transaction selection"):
            restarted.sign_with_contract_key(session, b"\x19" * 32, crypto)
        selected = engine.select_due_fallbacks(1010, closed_only=True)
        if damage != "none":
            assert selected == ()
            assert restarted._connection.execute(  # noqa: SLF001
                "SELECT state FROM swaps WHERE session_id=?", (session,)
            ).fetchone() == ("PAID",)
            assert restarted.immediate_claim_allowed(session) is False
            chain.broadcast.assert_not_called()
        else:
            assert len(selected) == 1
            assert selected[0].txid == spend.txid
            assert engine.recorded_fallbacks() == (replace(selected[0], state="CLOSED"),)
            assert restarted._connection.execute(  # noqa: SLF001
                "SELECT state,claim_tx FROM swaps WHERE session_id=?", (session,)
            ).fetchone() == ("CLAIMING", spend.raw_transaction)
            crypto.schnorr_verify(
                bytes.fromhex(terms.provider_contract_compressed_key)[1:],
                b"\x19" * 32,
                restarted.sign_with_contract_key(session, b"\x19" * 32, crypto),
            )
            asyncio.run(engine.broadcast_selected_fallback(selected[0]))
            chain.broadcast.assert_called_once_with(spend.raw_transaction, spend.txid)
    if damage == "none":
        with harness.acquire() as resumed:
            assert resumed.prepared_fallbacks(closed_only=True) == ()
            assert len(resumed.recorded_fallbacks()) == 1
            assert resumed._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM claim_attempts WHERE session_id=?", (session,)
            ).fetchone() == (1,)
