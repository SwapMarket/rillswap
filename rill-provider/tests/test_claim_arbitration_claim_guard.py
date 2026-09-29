"""Prepared arbitration cannot fall through the ordinary PAID signing path."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from test_cooperation_burn import FixtureEnvelopeSigner, _featured_paid_swap
from test_live_session_store import Harness

from rill_provider.live_session_store import LiveSessionStoreError, SettlementItem
from rill_provider.settlement_engine import SettlementEngine

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
