"""Claim fee escalation: every attempt recorded, any may confirm, max fee before refund."""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import dataclass, replace
from itertools import pairwise
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from test_live_session_store import Harness, swaps_as_v9
from test_payment_dispatch_store import _insert_funded_swap
from test_settlement_engine import BINDING, ITEM, TERMS

from rill_provider import live_session_store as live
from rill_provider import settlement_engine
from rill_provider.core_tx_bytes import CoreTransactionUnknownError
from rill_provider.live_session_store import MAX_CLAIM_ATTEMPTS, ClaimAttempt
from rill_provider.settlement_engine import CLAIM_URGENCY_BLOCKS, SettlementEngine, claim_fee_target

if TYPE_CHECKING:
    from pathlib import Path

VSIZE = 150


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


DEADLINE = 1100
URGENT = DEADLINE - CLAIM_URGENCY_BLOCKS


def _target(**changes: Any) -> int | None:  # noqa: ANN401
    values: dict[str, Any] = {
        "initial": 1_000,
        "maximum": 10_000,
        "anchor": 1_000,
        "deadline": DEADLINE,
        "tip": 1_047,
        "latest_fee": 1_000,
        "latest_height": 1_000,
        "vsize": VSIZE,
        "attempts": 1,
    }
    return claim_fee_target(**(values | changes))


def test_fee_rises_linearly_to_the_maximum_before_the_refund_can_confirm() -> None:
    span = URGENT - 1_000
    assert _target() == 1_000 + 9_000 * 47 // span
    assert _target(tip=URGENT) == 10_000
    assert _target(tip=DEADLINE + 50) == 10_000  # never above the signed maximum


def test_a_bump_needs_a_new_block_and_the_incremental_relay_fee() -> None:
    assert _target(tip=1_000) is None  # anchor block, nothing due yet
    assert _target(latest_height=1_047) is None  # same block as the latest attempt
    assert _target(tip=1_001) is None  # below latest fee + vsize sat/vB
    assert _target(tip=URGENT, latest_height=URGENT) == 10_000  # urgency skips the wait
    assert _target(tip=URGENT, latest_fee=10_000 - VSIZE + 1) is None  # cannot replace


@pytest.mark.parametrize("unknown", ["initial", "anchor", "latest_fee", "latest_height"])
def test_unobserved_attempts_never_trigger_a_bump(unknown: str) -> None:
    assert _target(**{unknown: None, "tip": URGENT}) is None


def test_the_last_attempt_is_reserved_for_the_maximum() -> None:
    assert _target(attempts=MAX_CLAIM_ATTEMPTS - 1) is None
    assert _target(attempts=MAX_CLAIM_ATTEMPTS - 1, tip=URGENT) == 10_000
    assert _target(attempts=MAX_CLAIM_ATTEMPTS, tip=URGENT) is None


def _claiming(store: live.LiveSessionStore, harness: Harness, *, raw: bytes | None = b"c0") -> str:
    session = _insert_funded_swap(store, harness, "CLAIMING")
    store._connection.execute(  # noqa: SLF001
        "UPDATE swaps SET claim_tx=?, claim_txid=? WHERE session_id=?",
        (raw, None if raw is None else "a0" * 32, session),
    )
    return session


def _as_v8(path: Any) -> None:  # noqa: ANN401
    with sqlite3.connect(path) as connection:
        swaps_as_v9(connection)
        connection.execute("DROP TABLE claim_attempts")
        connection.execute("UPDATE meta SET schema_version=8")
        connection.execute("PRAGMA user_version=8")


def test_v8_upgrades_on_ordinary_acquire_with_unobserved_attempt_zero(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _claiming(store, harness)
    _as_v8(harness.path)
    with harness.acquire() as store:
        assert store._connection.execute("PRAGMA user_version").fetchone() == (11,)  # noqa: SLF001
        assert store.claim_attempts(session) == (ClaimAttempt(0, "a0" * 32, b"c0", None, None),)
        store.observe_claim_attempt(session, 0, fee_sat=300, height=990)
        store.observe_claim_attempt(session, 0, fee_sat=1, height=1)  # a restart cannot move it
        assert store.claim_attempts(session) == (ClaimAttempt(0, "a0" * 32, b"c0", 300, 990),)


def test_v9_upgrades_on_ordinary_acquire_keeping_every_swap_row(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _claiming(store, harness)
        store._connection.execute(  # noqa: SLF001
            "INSERT INTO claim_attempts VALUES (?, 0, ?, ?, 300, 990)", (session, "a0" * 32, b"c0")
        )
        before = store._connection.execute(  # noqa: SLF001
            "SELECT session_id, contract_hash, terms_offer, terms_accept, state, "
            "funding_binding, preimage, claim_txid, claim_tx, updated_at FROM swaps"
        ).fetchall()
    with sqlite3.connect(harness.path) as connection:
        swaps_as_v9(connection)
        connection.execute("UPDATE meta SET schema_version=9")
        connection.execute("PRAGMA user_version=9")
    with harness.acquire() as store:
        assert store._connection.execute("PRAGMA user_version").fetchone() == (11,)  # noqa: SLF001
        rows = store._connection.execute("SELECT * FROM swaps").fetchall()  # noqa: SLF001
        assert [row[:-8] for row in rows] == before
        assert [row[-8:] for row in rows] == [(None,) * 8]  # observation starts from scratch
        assert store.claim_attempts(session) == (ClaimAttempt(0, "a0" * 32, b"c0", 300, 990),)
        with pytest.raises(live.LiveSessionStoreError, match="loss evidence"):
            store.advance_swap(  # LOST is reachable only through an observed spend
                session,
                from_state="CLAIMING",
                to_state="LOST",
                signer=None,  # type: ignore[arg-type]
                now=1,
            )


def test_upgrade_isolates_a_claiming_swap_without_claim_bytes(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _claiming(store, harness, raw=None)
    _as_v8(harness.path)
    with harness.acquire() as store:  # other swaps keep settling
        assert store.claim_attempts(session) == ()


def test_attempts_append_in_order_and_mirror_the_latest(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _claiming(store, harness)
        store._connection.execute(  # noqa: SLF001
            "INSERT INTO claim_attempts VALUES (?, 0, ?, ?, 300, 990)", (session, "a0" * 32, b"c0")
        )
        store.record_claim_attempt(
            session, attempt=1, txid="a1" * 32, raw=b"c1", fee_sat=600, height=991
        )
        with pytest.raises(live.StaleSwapError):  # a repeated tick cannot fork history
            store.record_claim_attempt(
                session, attempt=1, txid="a9" * 32, raw=b"c9", fee_sat=900, height=991
            )
        with pytest.raises(live.LiveSessionStoreError, match="budget"):
            store.record_claim_attempt(
                session, attempt=MAX_CLAIM_ATTEMPTS, txid="a8" * 32, raw=b"c8", fee_sat=1, height=1
            )
        assert [a.txid for a in store.claim_attempts(session)] == ["a0" * 32, "a1" * 32]
        mirror = store._connection.execute(  # noqa: SLF001
            "SELECT claim_tx, claim_txid FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        assert mirror == (b"c1", "a1" * 32)


def _claimed(store: live.LiveSessionStore, session: str, raw: bytes, txid: str) -> None:
    store.advance_swap(
        session,
        from_state="CLAIMING",
        to_state="CLAIMED",
        signer=None,  # type: ignore[arg-type]
        now=1500,
        claim_tx=raw,
        claim_txid=txid,
    )


def test_claimed_names_a_recorded_attempt_and_mirrors_the_winner(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _claiming(store, harness)
        store._connection.execute(  # noqa: SLF001
            "INSERT INTO claim_attempts VALUES (?, 0, ?, ?, 300, 990)", (session, "a0" * 32, b"c0")
        )
        store.record_claim_attempt(
            session, attempt=1, txid="a1" * 32, raw=b"c1", fee_sat=600, height=991
        )
        with pytest.raises(live.LiveSessionStoreError, match="recorded attempt"):
            _claimed(store, session, b"c1", "a0" * 32)  # bytes of another attempt
        _claimed(store, session, b"c0", "a0" * 32)  # the older attempt confirmed
        row = store._connection.execute(  # noqa: SLF001
            "SELECT state, claim_tx, claim_txid FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        assert row == ("CLAIMED", b"c0", "a0" * 32)
        assert len(store._connection.execute("SELECT * FROM claim_attempts").fetchall()) == 2  # noqa: SLF001


@dataclass
class _Store:
    attempts: list[ClaimAttempt]
    moves: list[dict[str, Any]]

    def claim_attempts(self, _session: str) -> tuple[ClaimAttempt, ...]:
        return tuple(self.attempts)

    def observe_claim_attempt(self, _s: str, attempt: int, *, fee_sat: int, height: int) -> None:
        old = self.attempts[attempt]
        self.attempts[attempt] = replace(
            old,
            fee_sat=old.fee_sat if old.fee_sat is not None else fee_sat,
            first_seen_height=old.first_seen_height or height,
        )

    def record_claim_attempt(self, _s: str, **fields: Any) -> None:  # noqa: ANN401
        self.attempts.append(
            ClaimAttempt(
                fields["attempt"],
                fields["txid"],
                fields["raw"],
                fields["fee_sat"],
                fields["height"],
            )
        )

    def advance_swap(self, _s: str, **fields: Any) -> None:  # noqa: ANN401
        self.moves.append(fields)


def _engine(
    monkeypatch: pytest.MonkeyPatch,
    attempts: list[ClaimAttempt],
    depths: dict[str, int],
    tip: int,
) -> tuple[SettlementEngine, _Store, Mock]:
    store = _Store(attempts, [])
    chain = Mock()
    chain.tip_height.return_value = tip

    def confirmations(txid: str) -> int:
        if txid not in depths:
            raise CoreTransactionUnknownError(-5)
        return depths[txid]

    chain.confirmations.side_effect = confirmations
    engine = SettlementEngine(store, chain, Mock(), Mock())  # type: ignore[arg-type]
    by_raw = {a.raw: a for a in attempts}

    def validate(raw: bytes, _auth: object, **_kw: object) -> SimpleNamespace:
        fee = by_raw[raw].fee_sat if raw in by_raw else 0
        return SimpleNamespace(txid=by_raw[raw].txid, vsize=VSIZE, fee_sat=fee or 300)

    monkeypatch.setattr(settlement_engine, "validate_unilateral_spend", validate)
    monkeypatch.setattr(engine, "_authorization", lambda *_a: None)
    monkeypatch.setattr(
        settlement_engine, "max_spendable_fee", lambda _a: int(TERMS.max_claim_fee_sat)
    )

    def claim(_item: object, _terms: object, _binding: object, fee: int) -> SimpleNamespace:
        return SimpleNamespace(raw_transaction=b"c%d" % fee, txid=f"{fee:064x}", fee_sat=fee)

    monkeypatch.setattr(engine, "_claim", claim)
    return engine, store, chain


def _run(engine: SettlementEngine) -> str:
    item = replace(ITEM, state="CLAIMING")
    return asyncio.run(engine._claiming(item, TERMS, BINDING, 1500))  # noqa: SLF001


def test_an_older_attempt_that_confirms_is_the_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = [
        ClaimAttempt(0, "a0" * 32, b"c0", 300, 900),
        ClaimAttempt(1, "a1" * 32, b"c1", 400, 901),
    ]
    depth = TERMS.settlement_confirmations
    engine, store, _chain = _engine(monkeypatch, attempts, {"a0" * 32: depth}, 950)
    _run(engine)
    assert store.moves[0]["to_state"] == "CLAIMED"
    assert (store.moves[0]["claim_tx"], store.moves[0]["claim_txid"]) == (b"c0", "a0" * 32)


def test_a_mined_attempt_is_never_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = [ClaimAttempt(0, "a0" * 32, b"c0", 300, 900)]
    engine, store, _chain = _engine(monkeypatch, attempts, {"a0" * 32: 1}, URGENT)
    _run(engine)
    assert len(store.attempts) == 1
    assert store.moves == []


def test_an_unconfirmed_claim_is_recorded_before_the_bump_is_broadcast(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = [ClaimAttempt(0, "a0" * 32, b"c0", 100, 900)]
    engine, store, chain = _engine(monkeypatch, attempts, {"a0" * 32: 0}, URGENT)
    recorded_at_broadcast: list[int] = []
    chain.broadcast.side_effect = lambda _raw, _txid: recorded_at_broadcast.append(
        len(store.attempts)
    )
    _run(engine)
    maximum = int(TERMS.max_claim_fee_sat)
    assert store.attempts[-1].fee_sat == maximum
    assert store.attempts[-1].first_seen_height == URGENT
    assert recorded_at_broadcast == [1, 2]  # rebroadcast latest, then the recorded bump


def test_migrated_attempts_are_observed_first_and_never_bumped_that_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = [ClaimAttempt(0, "a0" * 32, b"c0", None, None)]
    engine, store, _chain = _engine(monkeypatch, attempts, {}, 1000)
    _run(engine)
    assert store.attempts == [ClaimAttempt(0, "a0" * 32, b"c0", 300, 1000)]


def test_an_invalid_recorded_claim_isolates_the_swap(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = [ClaimAttempt(0, "a0" * 32, b"c0", 300, 900)]
    engine, store, chain = _engine(monkeypatch, attempts, {}, URGENT)

    def invalid(*_a: object, **_k: object) -> None:
        raise ValueError("bad")

    monkeypatch.setattr(settlement_engine, "validate_unilateral_spend", invalid)
    _run(engine)
    chain.broadcast.assert_not_called()
    assert len(store.attempts) == 1


def test_a_core_failure_is_not_evidence_and_never_bumps(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = [ClaimAttempt(0, "a0" * 32, b"c0", 300, 900)]
    engine, store, chain = _engine(monkeypatch, attempts, {}, URGENT)
    chain.confirmations.side_effect = RuntimeError("transport")
    with pytest.raises(RuntimeError):
        _run(engine)
    assert len(store.attempts) == 1


def test_a_full_schedule_always_reaches_the_maximum() -> None:
    # Reviewed regression: with max 5_000 the old schedule reached 4_924 and
    # then could never afford the final replacement's 150 sat increment.
    fee, height, attempts, fees = 1_000, 1_000, 1, []
    for tip in range(1_001, 1_070):
        target = claim_fee_target(
            initial=1_000,
            maximum=5_000,
            anchor=1_000,
            deadline=1_059,
            tip=tip,
            latest_fee=fee,
            latest_height=height,
            vsize=150,
            attempts=attempts,
        )
        if target is not None:
            fees.append(target)
            fee, height, attempts = target, tip, attempts + 1
    assert fees[-1] == 5_000
    assert all(b - a >= 150 for a, b in pairwise(fees))
    assert attempts <= MAX_CLAIM_ATTEMPTS


def _lost_engine(  # noqa: PLR0913 - explicit chain facts
    monkeypatch: pytest.MonkeyPatch,
    tip: int,
    *,
    unspent: bool,
    depths: dict[str, int],
    funding_depth: int = 6,
    blocks: dict[int, str] | None = None,
) -> tuple[SettlementEngine, _Store, Mock]:
    attempts = [ClaimAttempt(0, "a0" * 32, b"c0", 300, 900)]
    if funding_depth:
        depths = depths | {BINDING.funding_txid: funding_depth}
    engine, store, chain = _engine(monkeypatch, attempts, depths, tip)
    chain.outpoint_unspent.return_value = unspent
    chain.block_hash.side_effect = lambda height: (blocks or {}).get(height, f"{height:064x}")
    store.spent: list[tuple[int, str] | None] = []  # type: ignore[attr-defined]
    store.observe_outpoint_spent = lambda _s, height, block=None: store.spent.append(  # type: ignore[attr-defined]
        None if height is None else (height, block)
    )
    return engine, store, chain


def _run_at(engine: SettlementEngine, anchor: tuple[int, str] | None) -> str:
    height, block = anchor if anchor is not None else (None, None)
    item = replace(ITEM, state="CLAIMING", outpoint_spent_height=height, outpoint_spent_block=block)
    return asyncio.run(engine._claiming(item, TERMS, BINDING, 1500))  # noqa: SLF001


ANCHOR = (1105, f"{1105:064x}")


def test_a_spent_output_is_lost_only_after_an_anchored_resolution_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, store, _chain = _lost_engine(monkeypatch, 1105, unspent=False, depths={})
    assert _run_at(engine, None) == "CLAIMING"  # first sighting: anchor to the tip block
    assert (store.spent, len(store.attempts), store.moves) == ([ANCHOR], 1, [])
    resolution = TERMS.refund_resolution_confirmations
    engine, store, _chain = _lost_engine(
        monkeypatch, 1105 + resolution - 2, unspent=False, depths={}
    )
    assert _run_at(engine, ANCHOR) == "CLAIMING"  # still within the resolution wait
    assert (store.spent, store.moves) == ([], [])
    engine, store, _chain = _lost_engine(
        monkeypatch, 1105 + resolution - 1, unspent=False, depths={}
    )
    _run_at(engine, ANCHOR)
    assert store.moves[0]["to_state"] == "LOST"
    assert len(store.attempts) == 1  # never bumped against a spent output


@pytest.mark.parametrize(
    ("tip", "funding_depth"),
    [(1105, 0), (1105, TERMS.funding_confirmations - 1), (TERMS.refund_lock_height, 6)],
)
def test_a_missing_output_is_not_a_refund_while_funding_is_unconfirmed_or_early(
    monkeypatch: pytest.MonkeyPatch, tip: int, funding_depth: int
) -> None:
    engine, store, _chain = _lost_engine(
        monkeypatch, tip, unspent=False, depths={}, funding_depth=funding_depth
    )
    assert _run_at(engine, None) == "CLAIMING"
    assert (store.spent, store.moves) == ([], [])  # no anchor, no loss
    assert _run_at(engine, ANCHOR) == "CLAIMING"
    assert (store.spent, store.moves) == ([None], [])  # an old anchor is dropped


def test_an_anchor_that_left_the_active_chain_restarts_the_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolution = TERMS.refund_resolution_confirmations
    engine, store, _chain = _lost_engine(
        monkeypatch, 1105 + resolution, unspent=False, depths={}, blocks={1105: "ee" * 32}
    )
    assert _run_at(engine, ANCHOR) == "CLAIMING"
    assert (store.spent, store.moves) == ([None], [])
    engine, store, _chain = _lost_engine(monkeypatch, 1104, unspent=False, depths={})
    assert _run_at(engine, ANCHOR) == "CLAIMING"  # tip behind the anchor
    assert (store.spent, store.moves) == ([None], [])


def test_a_sighting_is_cleared_when_the_output_returns_or_an_attempt_is_mined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, store, chain = _lost_engine(monkeypatch, 1110, unspent=True, depths={"a0" * 32: 0})
    assert _run_at(engine, ANCHOR) == "CLAIMING"
    assert (store.spent, store.moves) == ([None], [])  # unspent again: the wait restarts
    chain.broadcast.assert_called_once()  # and the claim keeps being pushed
    engine, store, _chain = _lost_engine(monkeypatch, 1110, unspent=False, depths={"a0" * 32: 1})
    assert _run_at(engine, ANCHOR) == "CLAIMING"
    assert (store.spent, store.moves) == ([None], [])  # our own mined claim spent it


@pytest.mark.parametrize(
    ("rate", "expected"),
    [(None, 300), (1.0, 300), (2.5, 375), (1_000.0, int(TERMS.max_claim_fee_sat))],
)
def test_the_first_claim_fee_follows_the_estimate_between_floor_and_ceiling(
    monkeypatch: pytest.MonkeyPatch, rate: float | None, expected: int
) -> None:
    engine, _store, chain = _engine(monkeypatch, [], {}, 1000)
    engine._settings = replace(engine._settings, claim_fee_sat=300)  # noqa: SLF001
    chain.fee_rate_sat_vb.return_value = rate
    built: list[int] = []

    def claim(_item: object, _terms: object, _binding: object, fee: int) -> SimpleNamespace:
        built.append(fee)
        return SimpleNamespace(raw_transaction=b"c", txid="a0" * 32, fee_sat=fee, vsize=VSIZE)

    monkeypatch.setattr(engine, "_claim", claim)
    spend = asyncio.run(engine._initial_claim(ITEM, TERMS, BINDING))  # noqa: SLF001
    assert spend.fee_sat == expected
    assert built == [300] if expected == 300 else [300, expected]
    chain.fee_rate_sat_vb.assert_called_once_with(settlement_engine.CLAIM_ESTIMATE_TARGET)


def test_an_unavailable_fee_estimate_never_defers_the_first_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _store, chain = _engine(monkeypatch, [], {}, 1000)
    engine._settings = replace(engine._settings, claim_fee_sat=300)  # noqa: SLF001
    chain.fee_rate_sat_vb.side_effect = RuntimeError("estimatesmartfee unavailable")
    monkeypatch.setattr(
        engine,
        "_claim",
        lambda *_a: SimpleNamespace(raw_transaction=b"c", txid="a0" * 32, fee_sat=300, vsize=VSIZE),
    )
    assert asyncio.run(engine._initial_claim(ITEM, TERMS, BINDING)).fee_sat == 300  # noqa: SLF001
