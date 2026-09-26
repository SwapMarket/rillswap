"""Economic reservations: capacity for exposure, released only with evidence."""

from __future__ import annotations

import os
import secrets
import sqlite3
from typing import TYPE_CHECKING, Any

import pytest
from test_live_session_store import Harness, _other_init
from test_payment_dispatch_store import _hash, _insert_funded_swap
from test_payment_reconciliation import _paying
from test_quote_policy import FIRM, _firm
from test_settlement_failure_authority import _binding

from rill_provider import live_session_store as live
from rill_provider.settlement_policy import answer_client_request

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    monkeypatch.setattr(live, "_new_challenge", lambda: secrets.token_hex(32))
    monkeypatch.setattr(live, "_new_session_scalar", lambda: secrets.token_bytes(32))
    result.provision()
    return result


def _ledger(store: live.LiveSessionStore) -> dict[str, tuple[str, str, bytes | None]]:
    rows = store._connection.execute(  # noqa: SLF001
        "SELECT payment_hash, session_id, state, release_evidence FROM economic_reservations"
    )
    return {row[0]: (row[1], row[2], row[3]) for row in rows}


def _foreign(store: live.LiveSessionStore, payment_hash: str, state: str = "UNKNOWN") -> None:
    store._connection.execute(  # noqa: SLF001
        "INSERT INTO economic_reservations VALUES (?, ?, ?, NULL)",
        (payment_hash, "ee" * 32, state),
    )


def test_accepted_sessions_no_longer_exhaust_protocol_capacity(harness: Harness) -> None:
    with harness.acquire_at(harness.path, max_sessions=1) as store:
        for index in range(1, 6):  # more lifetime swaps than max_sessions
            reservation = store.reserve(_other_init(harness, index), now=1000)
            with pytest.raises(live.SessionCapacityError, match="capacity reached"):
                store.reserve(_other_init(harness, 100 + index), now=1000)
            store._connection.execute(  # noqa: SLF001 - acceptance keeps the session forever
                "UPDATE sessions SET phase='ACCEPTED' WHERE session_id=?",
                (reservation.session_id,),
            )
        (retained,) = store._connection.execute("SELECT COUNT(*) FROM sessions").fetchone()  # noqa: SLF001
        assert retained == 5


def test_capacity_limit_is_validated(harness: Harness) -> None:
    with pytest.raises(live.LiveSessionStoreError, match="capacity unsupported"):
        harness.acquire_at(harness.path, max_active_reservations=0)


def test_policy_refuses_new_quotes_after_a_swap_and_when_capacity_is_full() -> None:
    full = _firm()
    assert full.message_type == "terms_offer"
    context = live.RequestContext(
        handshake_hash="00" * 32,
        provider_contract_key="02" + "00" * 32,
        is_payment_hash_reserved=lambda _digest: False,
        economic_capacity_available=False,
    )
    from test_quote_policy import FIRM_TERMS, _envelope  # noqa: PLC0415

    from rill_provider.quote_policy import answer_quote  # noqa: PLC0415

    refused = answer_quote(_envelope(FIRM), (), context, FIRM_TERMS)
    assert (refused.message_type, refused.payment_hash) == ("error", None)
    assert refused.payload["code"] == "capacity_unavailable"
    request: Any = type(
        "Request", (), {"message_type": "quote_request", "in_reply_to": None, "contract_hash": None}
    )()
    swap_context = live.RequestContext(
        handshake_hash="00" * 32,
        provider_contract_key="02" + "00" * 32,
        is_payment_hash_reserved=lambda _digest: False,
        swap=object(),  # type: ignore[arg-type]
    )
    answer = answer_client_request(request, (), swap_context, FIRM_TERMS, None)  # type: ignore[arg-type]
    assert (answer.message_type, answer.payment_hash) == ("error", None)
    assert answer.payload["code"] == "unsupported_request"


def test_dispatch_marks_its_reservation_atomically(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _paying(store, harness, "UNSENT")
        _binding(store, harness)
        assert store.commit_payment_dispatch(session, _hash(harness), b"request")
        assert _ledger(store)[_hash(harness)] == (session, "DISPATCHED", None)


@pytest.mark.parametrize("closed", ["RELEASED", "DISPATCHED", None])
def test_dispatch_without_an_open_reservation_keeps_the_grant(
    harness: Harness, closed: str | None
) -> None:
    with harness.acquire() as store:
        session = _paying(store, harness, "UNSENT")
        _binding(store, harness)
        connection = store._connection  # noqa: SLF001
        if closed is None:
            connection.execute("DELETE FROM economic_reservations")
        else:
            connection.execute(
                "UPDATE economic_reservations SET state=?, release_evidence=?",
                (closed, b"{}" if closed == "RELEASED" else None),
            )
        with pytest.raises(live.LiveSessionStoreError, match="reservation unavailable"):
            store.commit_payment_dispatch(session, _hash(harness), b"request")
        assert connection.execute("SELECT state, request FROM payment_dispatch").fetchall() == [
            ("UNSENT", None)
        ]


def _as_v7(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE claim_attempts")
        connection.execute("DROP TABLE economic_reservations")
        connection.execute("UPDATE meta SET schema_version=7")
        connection.execute("PRAGMA user_version=7")


def test_v7_upgrade_is_explicit_and_backfills_conservatively(harness: Harness) -> None:
    open_hash, tombstoned, untracked = "a1" * 32, "a2" * 32, "a3" * 32
    with harness.acquire() as store:
        swap = _insert_funded_swap(store, harness, "CLAIMED")
        offer = store.reserve(_other_init(harness, 1), now=1000).session_id
        connection = store._connection  # noqa: SLF001
        connection.execute("INSERT INTO expired VALUES (?, 900)", ("dd" * 32,))
        for digest, session in (
            (open_hash, offer),
            (tombstoned, "dd" * 32),
            (untracked, "cc" * 32),
        ):
            connection.execute("INSERT INTO payment_hashes VALUES (?, ?, 1000)", (digest, session))
    _as_v7(harness.path)
    with pytest.raises(live.LiveSessionStoreError, match="version unsupported"):
        harness.acquire()
    with harness.acquire_at(harness.path, upgrade_from_v5=True) as store:
        ledger = _ledger(store)
        assert ledger[_hash(harness)] == (swap, "UNKNOWN", None)  # even CLAIMED needs evidence
        assert ledger[open_hash] == (offer, "UNSENT", None)
        assert ledger[untracked] == ("cc" * 32, "UNKNOWN", None)  # absence proves nothing
        session, state, evidence = ledger[tombstoned]
        assert (session, state) == ("dd" * 32, "RELEASED")
        assert evidence == b'{"reason":"expired-offer","source":"migration","version":1}'
        assert store._connection.execute("PRAGMA user_version").fetchone() == (9,)  # noqa: SLF001
    with harness.acquire() as store:  # idempotent: no further migration
        assert len(_ledger(store)) == 4


def test_v7_upgrade_refuses_a_swap_without_its_reservation(harness: Harness) -> None:
    with harness.acquire() as store:
        _insert_funded_swap(store, harness, "PAYING")
        store._connection.execute("DELETE FROM payment_hashes")  # noqa: SLF001
    _as_v7(harness.path)
    with pytest.raises(live.LiveSessionStoreError):
        harness.acquire_at(harness.path, upgrade_from_v5=True)
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (7,)
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
        assert "economic_reservations" not in tables


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_offer_reservations_refuse_over_budget_and_release_on_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)  # fixed handshake challenge
    harness.provision()
    from rill_crypto import Context  # noqa: PLC0415
    from test_live_session_store import _signed_request  # noqa: PLC0415

    capacity: list[bool] = []
    offered = iter(["a1" * 32, "a2" * 32, "a3" * 32])

    def responder(_request: Any, _prior: Any, context: live.RequestContext) -> live.Answer:  # noqa: ANN401
        capacity.append(context.economic_capacity_available)
        payload = {"code": "capacity_unavailable", "message": "fixture"}
        return live.Answer("error", payload, payment_hash=next(offered))  # ignores capacity

    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(
            harness.path, crypto=crypto, public_keys=crypto, max_active_reservations=2
        ) as store,
    ):
        session = store.reserve(harness.init, now=1000).session_id
        store.commit_accept(harness.accept)
        store.admit_confirm(harness.confirm)
        _foreign(store, "cd" * 32)
        _foreign(store, "ce" * 32)

        def ask(sequence: int) -> live.RequestAnswer:
            request = _signed_request(harness, crypto, sequence, f"{0x20 + sequence:064x}")
            return store.answer_request(request, responder=responder, signer=crypto, now=1000)

        assert not store.firm_capacity_available()  # cheap global pre-check
        with pytest.raises(live.SessionCapacityError, match="economic capacity"):
            ask(2)  # full: the store refuses even a responder that ignores capacity
        assert not store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM payment_hashes WHERE payment_hash=?", ("a1" * 32,)
        ).fetchone()
        assert store.pending_outbox() == ()
        store._connection.execute(  # noqa: SLF001
            "UPDATE economic_reservations SET state='RELEASED', release_evidence=x'7b7d' "
            "WHERE payment_hash=?",
            ("ce" * 32,),
        )
        assert store.firm_capacity_available()
        ask(2)  # the same, still unconsumed request now fits
        assert not store.firm_capacity_available()
        assert _ledger(store)["a2" * 32] == (session, "UNSENT", None)
        with pytest.raises(live.LiveSessionStoreError, match="already has a firm offer"):
            ask(3)  # RS-003: one firm offer per session
        assert capacity == [False, True, False]
        assert "a3" * 32 not in _ledger(store)
        assert store.expire_idle(now=10_000, idle_timeout=100) == 1
        ledger = _ledger(store)
        assert ledger["a2" * 32][1] == "RELEASED"
        assert ledger["a2" * 32][2] == b'{"expired_at":10000,"reason":"expired-offer","version":1}'
        assert ledger["cd" * 32][1] == "UNKNOWN"
        assert store._connection.execute(  # noqa: SLF001 - the hash stays reserved forever
            "SELECT 1 FROM payment_hashes WHERE payment_hash=?", ("a2" * 32,)
        ).fetchone()


@pytest.mark.parametrize(
    ("state", "accepted"), [("UNSENT", True), ("UNKNOWN", True), ("RELEASED", False)]
)
def test_acceptance_requires_an_unreleased_offer_reservation(
    harness: Harness,
    state: str,
    accepted: bool,  # noqa: FBT001 - parametrized
) -> None:
    import copy  # noqa: PLC0415
    import json  # noqa: PLC0415

    from rill_core.wire.messages import Envelope  # noqa: PLC0415

    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "ACCEPTED")
        connection = store._connection  # noqa: SLF001
        (offer,) = connection.execute("SELECT terms_offer FROM swaps").fetchone()
        connection.execute("DELETE FROM swaps")
        connection.execute(
            "UPDATE economic_reservations SET state=?, release_evidence=?",
            (state, b"{}" if state == "RELEASED" else None),
        )
        request = copy.deepcopy(harness.envelopes[2])
        request.update(message_type="terms_accept", contract_hash=harness.source["contract_hash"])
        envelope = Envelope.model_validate_json(json.dumps(request))
        effect = live.AcceptSwap(harness.source["contract_hash"])
        if accepted:
            live._apply_effect(connection, envelope, effect, (offer,), 1000)  # noqa: SLF001
            assert connection.execute("SELECT session_id FROM swaps").fetchall() == [(session,)]
        else:
            with pytest.raises(live.LiveSessionStoreError, match="reservation is closed"):
                live._apply_effect(connection, envelope, effect, (offer,), 1000)  # noqa: SLF001


def test_v7_upgrade_requires_the_exact_accepted_hash(harness: Harness) -> None:
    with harness.acquire() as store:
        _insert_funded_swap(store, harness, "PAYING")
        store._connection.execute(  # noqa: SLF001 - an unrelated hash of the same session
            "UPDATE payment_hashes SET payment_hash=?", ("99" * 32,)
        )
    _as_v7(harness.path)
    with pytest.raises(live.LiveSessionStoreError):
        harness.acquire_at(harness.path, upgrade_from_v5=True)
    with sqlite3.connect(harness.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (7,)
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
        assert "economic_reservations" not in tables


@pytest.mark.parametrize(("expired", "state"), [(1, "RELEASED"), (0, "UNKNOWN")])
def test_v7_upgrade_uses_only_affirmative_epoch_tombstones(
    harness: Harness, expired: int, state: str
) -> None:
    with harness.acquire() as store:
        connection = store._connection  # noqa: SLF001
        connection.execute(
            "INSERT INTO epoch_admissions VALUES (?, ?, 5000, ?)",
            ("dd" * 32, "02" + "11" * 32, expired),
        )
        connection.execute("INSERT INTO payment_hashes VALUES (?, ?, 1000)", ("a2" * 32, "dd" * 32))
    _as_v7(harness.path)
    with harness.acquire_at(harness.path, upgrade_from_v5=True) as store:
        assert _ledger(store)["a2" * 32][1] == state


def test_upgraded_unknown_reservation_can_use_its_existing_grant(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _paying(store, harness, "UNSENT")
        _binding(store, harness)
    _as_v7(harness.path)
    with harness.acquire_at(harness.path, upgrade_from_v5=True) as store:
        assert _ledger(store)[_hash(harness)] == (session, "UNKNOWN", None)
        assert store.commit_payment_dispatch(session, _hash(harness), b"request")
        assert _ledger(store)[_hash(harness)][1] == "DISPATCHED"


def _advance(store: live.LiveSessionStore, session: str, from_state: str, to_state: str) -> None:
    store.advance_swap(session, from_state=from_state, to_state=to_state, signer=None, now=1500)  # type: ignore[arg-type]


def _set_reservation(store: live.LiveSessionStore, state: str) -> None:
    store._connection.execute(  # noqa: SLF001
        "UPDATE economic_reservations SET state=?", (state,)
    )


@pytest.mark.parametrize(
    ("before", "after"),
    [("UNSENT", "RELEASED"), ("DISPATCHED", "DISPATCHED"), ("UNKNOWN", "UNKNOWN")],
)
def test_failure_releases_only_a_never_dispatched_reservation(
    harness: Harness, before: str, after: str
) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "FUNDING_SEEN")
        _set_reservation(store, before)
        _advance(store, session, "FUNDING_SEEN", "FAILED")
        _session, state, evidence = _ledger(store)[_hash(harness)]
        assert state == after
        if after == "RELEASED":
            assert evidence == b'{"failed_at":1500,"reason":"failed-before-dispatch","version":1}'


@pytest.mark.parametrize(
    ("before", "after"),
    [("DISPATCHED", "RELEASED"), ("UNKNOWN", "RELEASED"), ("UNSENT", "UNSENT")],
)
def test_confirmed_claim_releases_the_dispatched_reservation(
    harness: Harness, before: str, after: str
) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "CLAIMING")
        store._connection.execute(  # noqa: SLF001
            "UPDATE swaps SET claim_tx=?, claim_txid=?", (b"claim", "77" * 32)
        )
        store._connection.execute(  # noqa: SLF001
            "INSERT INTO claim_attempts VALUES (?, 0, ?, ?, 100, 10)",
            (session, "77" * 32, b"claim"),
        )
        _set_reservation(store, before)
        store.advance_swap(
            session,
            from_state="CLAIMING",
            to_state="CLAIMED",
            signer=None,  # type: ignore[arg-type]
            now=1500,
            claim_tx=b"claim",
            claim_txid="77" * 32,
        )
        _session, state, evidence = _ledger(store)[_hash(harness)]
        assert state == after
        if after == "RELEASED":
            assert evidence is not None
            assert b'"reason":"claim-confirmed"' in evidence
            assert ("77" * 32).encode() in evidence


def test_historical_claims_release_only_on_fresh_sufficient_depth(harness: Harness) -> None:
    depth = int(harness.source["contract_terms"]["settlement_confirmations"])
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "CLAIMED")
        store._connection.execute("UPDATE swaps SET claim_txid=?", ("77" * 32,))  # noqa: SLF001
        _set_reservation(store, "UNKNOWN")  # a migrated, already claimed swap
        assert store.unreleased_claims() == [(session, "77" * 32, depth)]
        assert not store.release_claim(session, "77" * 32, confirmations=depth - 1)
        assert not store.release_claim(session, "78" * 32, confirmations=depth)
        assert _ledger(store)[_hash(harness)][1] == "UNKNOWN"
        with pytest.raises(live.LiveSessionStoreError):
            store.release_claim(session, "77" * 32, confirmations=-1)
        assert store.release_claim(session, "77" * 32, confirmations=depth)
        assert _ledger(store)[_hash(harness)][1] == "RELEASED"
        assert b'"observed_confirmations"' in (_ledger(store)[_hash(harness)][2] or b"")
        assert store.unreleased_claims() == []


def test_engine_releases_historical_claims_from_chain_depth(harness: Harness) -> None:
    import asyncio  # noqa: PLC0415
    from unittest.mock import Mock  # noqa: PLC0415

    from test_payment_reconciliation import Signer  # noqa: PLC0415

    from rill_provider.settlement_engine import SettlementEngine  # noqa: PLC0415

    with harness.acquire() as store:
        _insert_funded_swap(store, harness, "CLAIMED")
        store._connection.execute("UPDATE swaps SET claim_txid=?", ("77" * 32,))  # noqa: SLF001
        _set_reservation(store, "UNKNOWN")
        chain = Mock()
        chain.confirmations.return_value = 0
        engine = SettlementEngine(store, chain, Mock(), Signer(harness))
        assert asyncio.run(engine.tick(now=1500)) == {}
        assert _ledger(store)[_hash(harness)][1] == "UNKNOWN"
        chain.confirmations.return_value = 100
        asyncio.run(engine.tick(now=1500))
        chain.confirmations.assert_called_with("77" * 32)
        assert _ledger(store)[_hash(harness)][1] == "RELEASED"


@pytest.mark.parametrize(
    ("clock", "tip", "closed"),
    [
        ("before", 100, False),
        ("before", RuntimeError("no tip"), False),
        ("after", RuntimeError("no tip"), True),  # invoice expiry alone suffices
        ("before", "deadline", True),
    ],
)
def test_engine_fails_unfunded_swaps_only_past_the_payment_deadline(
    harness: Harness,
    clock: str,
    tip: object,
    closed: bool,  # noqa: FBT001 - parametrized
) -> None:
    import asyncio  # noqa: PLC0415
    from unittest.mock import Mock  # noqa: PLC0415

    from test_payment_reconciliation import Signer  # noqa: PLC0415

    from rill_provider.settlement_engine import SettlementEngine  # noqa: PLC0415

    terms = harness.source["contract_terms"]
    expires_at = int(terms["invoice_binding"]["expires_at"])
    now = expires_at if clock == "after" else expires_at - 1
    chain = Mock()
    if isinstance(tip, Exception):
        chain.tip_height.side_effect = tip
    elif tip == "deadline":
        chain.tip_height.return_value = int(
            terms["timing_policy"]["max_outgoing_htlc_expiry_height"]
        ) - int(terms["invoice_binding"]["min_final_cltv_delta"])
    else:
        chain.tip_height.return_value = tip
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "ACCEPTED")
        outbox = len(store.pending_outbox())
        engine = SettlementEngine(store, chain, Mock(), Signer(harness))
        result = asyncio.run(engine.tick(now=now))
        (state,) = store._connection.execute("SELECT state FROM swaps").fetchone()  # noqa: SLF001
        reservation = _ledger(store)[_hash(harness)][1]
        if closed:
            assert result == {session: "FAILED"}
            assert (state, reservation) == ("FAILED", "RELEASED")
            assert len(store.pending_outbox()) == outbox + 1  # signed payment_failed
        else:
            assert result == {}
            assert (state, reservation) == ("ACCEPTED", "UNSENT")
            assert len(store.pending_outbox()) == outbox


def test_claim_sweep_pages_fairly_past_unconfirmable_claims() -> None:
    import asyncio  # noqa: PLC0415
    from unittest.mock import Mock  # noqa: PLC0415

    from rill_provider.settlement_engine import CLAIM_PAGE, SettlementEngine  # noqa: PLC0415

    claims = [(f"{index:064x}", f"{index:064x}", 3) for index in range(CLAIM_PAGE + 1)]
    released: list[str] = []

    class Store:
        def settlement_work(self) -> list[object]:
            return []

        def unfunded_swaps(self) -> list[object]:
            return []

        def unreleased_claims(self, *, after: str, limit: int) -> list[tuple[str, str, int]]:
            return [claim for claim in claims if claim[0] > after][:limit]

        def release_claim(self, session_id: str, _txid: str, *, confirmations: int) -> bool:
            released.append(session_id)
            return confirmations >= 3

    chain = Mock()
    last = claims[-1][1]

    def confirmations(txid: str) -> int:
        if txid != last:
            raise RuntimeError("reorged or missing claim")
        return 3

    chain.confirmations.side_effect = confirmations
    engine = SettlementEngine(Store(), chain, Mock(), Mock())  # type: ignore[arg-type]
    asyncio.run(engine.tick(now=1))  # first page: all unconfirmable, none released
    assert released == []
    asyncio.run(engine.tick(now=1))  # the cursor reaches the seventeenth claim
    assert released == [claims[-1][0]]
    asyncio.run(engine.tick(now=1))  # short page wrapped: back to the start
    assert chain.confirmations.call_count == 2 * CLAIM_PAGE + 1


def test_store_claim_listing_honors_the_cursor(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "CLAIMED")
        store._connection.execute("UPDATE swaps SET claim_txid=?", ("77" * 32,))  # noqa: SLF001
        _set_reservation(store, "UNKNOWN")
        assert [row[0] for row in store.unreleased_claims(after="")] == [session]
        assert store.unreleased_claims(after=session) == []


def test_blocked_unfunded_swap_is_still_closed(harness: Harness) -> None:
    import asyncio  # noqa: PLC0415
    from unittest.mock import Mock  # noqa: PLC0415

    from test_payment_reconciliation import Signer  # noqa: PLC0415

    from rill_provider.settlement_engine import SettlementEngine  # noqa: PLC0415

    expires_at = int(harness.source["contract_terms"]["invoice_binding"]["expires_at"])
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "ACCEPTED")
        store._connection.execute("UPDATE sessions SET blocked=1")  # noqa: SLF001
        engine = SettlementEngine(store, Mock(), Mock(), Signer(harness))
        assert asyncio.run(engine.tick(now=expires_at)) == {session: "FAILED"}
        assert _ledger(store)[_hash(harness)][1] == "RELEASED"
        (conflicts,) = store._connection.execute(  # noqa: SLF001
            "SELECT blocked FROM sessions"
        ).fetchone()
        assert conflicts == 1  # conflict evidence and blocking are preserved
