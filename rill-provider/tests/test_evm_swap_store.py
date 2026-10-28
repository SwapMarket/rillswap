"""EVM-profile swap lifecycle in the live session store (RS-010)."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest
from evm_fixtures import PAYMENT_HASH, PREIMAGE, evm_terms
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE, contract_hash

from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path

    from rill_core.wire.messages import EvmContractTerms
    from test_live_session_store import Harness


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    from test_live_session_store import Harness  # noqa: PLC0415 - heavy fixture module

    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def _advancer(store: live.LiveSessionStore, session: str) -> Any:  # noqa: ANN401
    def advance(from_state: str, to_state: str, **evidence: Any) -> None:  # noqa: ANN401
        store.advance_evm_swap(
            session,
            from_state=from_state,
            to_state=to_state,
            signer=None,  # type: ignore[arg-type]
            now=2000,
            **evidence,
        )

    return advance


pytest.importorskip("rill_crypto")  # the harness signs real envelopes
LOCKUP = ("ab" * 32, 3, 120)
TX = "cd" * 32


def _accept_evm_swap(
    store: live.LiveSessionStore, harness: Harness, terms: EvmContractTerms
) -> str:
    """Seed one accepted EVM swap exactly as admission records it (database fixture)."""
    policy = store._policy  # noqa: SLF001
    store._policy = replace(policy, features=policy.features - {COOPERATIVE_CLAIM_FEATURE})  # noqa: SLF001
    try:
        reservation = store.reserve(harness.init, now=1000)
    finally:
        store._policy = policy  # noqa: SLF001
    digest = contract_hash(terms).hex()
    offer = copy.deepcopy(harness.envelopes[1])
    offer.update(
        message_type="terms_offer",
        profile_id=terms.profile_id,
        contract_hash=digest,
        payload={
            "terms": {
                "contract_hash": digest,
                "contract_terms": terms.model_dump(mode="json"),
                "handshake_hash": harness.source["verification_context"]["handshake_hash"],
            },
            "provider_terms_signature": "00" * 64,
            **({"hold_invoice": "lnbc1fakehold"} if terms.profile_id == "ln-to-erc20/v1" else {}),
        },
    )
    request = copy.deepcopy(harness.envelopes[1])
    forward = terms.profile_id == "erc20-to-ln/v1"
    request.update(
        message_type="quote_request",
        payload={"kind": "firm", "invoice": "lnbc1fake"}
        if forward
        else {"kind": "reverse_firm", "payment_hash": PAYMENT_HASH},
    )
    connection = store._connection  # noqa: SLF001
    session = reservation.session_id
    connection.execute(
        "INSERT INTO swaps VALUES (?, ?, ?, ?, 'ACCEPTED', NULL, NULL, NULL, NULL, 1000, NULL, "
        "NULL, NULL, NULL, NULL, NULL, NULL)",
        (session, digest, canonicalize(offer), b"accepted"),
    )
    connection.execute(
        "INSERT INTO evm_swaps VALUES (?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        (session,),
    )
    connection.execute("UPDATE sessions SET phase='ACCEPTED' WHERE session_id=?", (session,))
    connection.execute("INSERT INTO payment_hashes VALUES (?, ?, 1000)", (PAYMENT_HASH, session))
    connection.execute(
        "INSERT INTO economic_reservations VALUES (?, ?, 'UNSENT', NULL)", (PAYMENT_HASH, session)
    )
    connection.execute(
        "INSERT INTO inbox VALUES (?, ?, 'm2', ?, 'd2', ?, 1)",
        (
            session,
            harness.envelopes[0]["payload"]["client_session_xonly_key"],
            live.FIRST_REQUEST_SEQUENCE,
            canonicalize(request),
        ),
    )
    connection.commit()
    return session


def _reservation(store: live.LiveSessionStore) -> tuple[str, bytes | None]:
    return store._connection.execute(  # noqa: SLF001
        "SELECT state, release_evidence FROM economic_reservations WHERE payment_hash=?",
        (PAYMENT_HASH,),
    ).fetchone()


def test_forward_lifecycle_records_lock_payment_grant_and_claim(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, evm_terms("erc20-to-ln/v1"))
        assert store.settlement_work() == ()  # never Bitcoin work
        (item,) = store.evm_settlement_work()
        assert (item.session_id, item.state, item.invoice, item.lock_tx_hash) == (
            session,
            "ACCEPTED",
            "lnbc1fake",
            None,
        )
        assert item.terms().profile_id == "erc20-to-ln/v1"
        advance = _advancer(store, session)
        with pytest.raises(live.LiveSessionStoreError, match="exact lockup"):
            advance("ACCEPTED", "FUNDING_SEEN")
        advance("ACCEPTED", "FUNDING_SEEN", lockup=LOCKUP)
        (item,) = store.evm_settlement_work()
        assert (item.lock_tx_hash, item.lock_log_index, item.lock_block) == LOCKUP
        advance("FUNDING_SEEN", "PAYING")
        assert store.evm_settlement_work()[0].dispatch_state == "UNSENT"
        with pytest.raises(live.StaleSwapError):
            advance("FUNDING_SEEN", "PAYING")  # one grant only
        with pytest.raises(live.LiveSessionStoreError, match="preimage"):
            advance("PAYING", "PAID", preimage="22" * 32)
        advance("PAYING", "PAID", preimage=PREIMAGE)
        with pytest.raises(live.LiveSessionStoreError, match="signed transaction"):
            advance("PAID", "CLAIMING")
        advance("PAID", "CLAIMING", sent=(TX, b"raw"))
        (item,) = store.evm_settlement_work()
        assert (item.state, item.preimage, item.claim_tx_hash) == ("CLAIMING", PREIMAGE, TX)
        assert _reservation(store)[0] == "UNSENT"  # no dispatch was committed in this test
        advance("CLAIMING", "CLAIMED")
        assert store.evm_settlement_work() == ()
        state, evidence = _reservation(store)
        assert state == "UNSENT"  # CLAIMED releases only DISPATCHED/UNKNOWN reservations
        assert evidence is None


def test_forward_failure_before_dispatch_releases_the_reservation(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, evm_terms("erc20-to-ln/v1"))
        store.advance_evm_swap(
            session, from_state="ACCEPTED", to_state="FAILED", signer=None, now=5
        )  # type: ignore[arg-type]
        state, evidence = _reservation(store)
        assert state == "RELEASED"
        assert b"failed-before-dispatch" in (evidence or b"")
        with pytest.raises(live.LiveSessionStoreError, match="unsupported"):
            store.advance_evm_swap(
                session, from_state="FAILED", to_state="PAYING", signer=None, now=6
            )  # type: ignore[arg-type]


def test_reverse_lifecycle_grants_one_lock_and_settles_on_the_preimage(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, evm_terms("ln-to-erc20/v1"))
        advance = _advancer(store, session)
        advance("ACCEPTED", "LN_HELD")
        advance("LN_HELD", "FUNDING_SENT", sent=(TX, b"raw"))
        assert _reservation(store)[0] == "DISPATCHED"
        (item,) = store.evm_settlement_work()
        assert (item.state, item.provider_tx_hash, item.provider_tx, item.invoice) == (
            "FUNDING_SENT",
            TX,
            b"raw",
            "",
        )
        advance("FUNDING_SENT", "FUNDED")
        advance("FUNDED", "SETTLED", preimage=PREIMAGE, observed_claim="ef" * 32)
        state, evidence = _reservation(store)
        assert state == "RELEASED"
        assert b"hold-settled" in (evidence or b"")
        assert store.evm_settlement_work() == ()
        assert store._connection.execute(  # noqa: SLF001
            "SELECT claim_tx_hash, preimage FROM evm_swaps e "
            "JOIN swaps w ON w.session_id=e.session_id"
        ).fetchone() == ("ef" * 32, PREIMAGE)


def test_reverse_refund_releases_on_the_refund_hash(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, evm_terms("ln-to-erc20/v1"))
        advance = _advancer(store, session)
        advance("ACCEPTED", "LN_HELD")
        advance("LN_HELD", "FUNDING_SENT", sent=(TX, b"raw"))
        store._connection.execute("UPDATE swaps SET state='LN_HELD'")  # noqa: SLF001
        with pytest.raises(live.LiveSessionStoreError, match="funding grant refused"):
            advance(
                "LN_HELD", "FUNDING_SENT", sent=(TX, b"raw")
            )  # the reservation is already dispatched
        store._connection.execute("UPDATE swaps SET state='FUNDED'")  # noqa: SLF001
        advance("FUNDED", "REFUNDING", sent=("ef" * 32, b"refund"))
        advance("REFUNDING", "REFUNDED")
        state, evidence = _reservation(store)
        assert state == "RELEASED"
        assert b"evm-refund-confirmed" in (evidence or b"")


def test_abort_releases_an_undispatched_hold(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, evm_terms("ln-to-erc20/v1"))
        store.advance_evm_swap(
            session, from_state="ACCEPTED", to_state="ABORTED", signer=None, now=1
        )  # type: ignore[arg-type]
        assert _reservation(store)[0] == "RELEASED"


def test_bitcoin_transitions_refuse_evm_swaps(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, evm_terms("erc20-to-ln/v1"))
        with pytest.raises(live.LiveSessionStoreError):
            store.advance_swap(
                session, from_state="ACCEPTED", to_state="FAILED", signer=None, now=1
            )  # type: ignore[arg-type]
        assert store.evm_settlement_work()[0].state == "ACCEPTED"
