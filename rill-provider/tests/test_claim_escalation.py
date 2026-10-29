"""Claim fee escalation: every attempt recorded, any may confirm, max fee before refund."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, replace
from itertools import pairwise
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from rill_core.wire.settlement_messages import FundingBindingPayload
from test_live_session_store import Harness
from test_payment_dispatch_store import _insert_funded_swap
from test_settlement_engine import BINDING, ITEM, TERMS

from rill_provider import live_session_store as live
from rill_provider import settlement_engine
from rill_provider.core_tx_bytes import (
    CoreProtocolError,
    CoreTransactionUnknownError,
    CoreUnavailableError,
    SpendObservation,
    SpendScan,
)
from rill_provider.live_session_store import MAX_CLAIM_ATTEMPTS, ClaimAttempt, FundingConflict
from rill_provider.settlement_engine import (
    CLAIM_URGENCY_BLOCKS,
    CONFLICT_LOSS_CONFIRMATIONS,
    CONFLICT_SCAN_MARGIN_BLOCKS,
    SettlementEngine,
    claim_fee_target,
)

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


def test_unobserved_attempts_are_observed_first_and_never_bumped_that_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An arbitration winner is recorded before any tip observed it.
    attempts = [ClaimAttempt(0, "a0" * 32, b"c0", 300, None)]
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


def test_zero_conf_terms_still_need_a_mined_funding_before_a_loss_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Paying from the mempool never makes a missing output a refund: the funding
    # may have been double-spent or not yet mined, which proves nothing.
    zero = TERMS.model_copy(update={"funding_confirmations": 0})
    item = replace(ITEM, state="CLAIMING")
    engine, store, _chain = _lost_engine(
        monkeypatch, 1105, unspent=False, depths={}, funding_depth=0
    )
    assert asyncio.run(engine._claiming(item, zero, BINDING, 1500)) == "CLAIMING"  # noqa: SLF001
    assert (store.spent, store.moves) == ([], [])
    engine, store, _chain = _lost_engine(
        monkeypatch, 1105, unspent=False, depths={}, funding_depth=1
    )
    assert asyncio.run(engine._claiming(item, zero, BINDING, 1500)) == "CLAIMING"  # noqa: SLF001
    assert (store.spent, store.moves) == ([ANCHOR], [])  # mined once: the wait may start


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


# A paid zero-conf deposit that never confirmed: LOST only on a deep, canonical conflict.

ZERO = TERMS.model_copy(update={"funding_confirmations": 0})
DEPOSIT_INPUTS = (("61" * 32, 0), ("62" * 32, 1))
CONFLICT = "c1" * 32
G_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def _deposit_binding() -> bytes:
    payload = FundingBindingPayload(
        binding=BINDING, funding_binding_signature="00" * 64, funding_transaction="02" * 100
    )
    envelope = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": TERMS.profile_id,
        "network_identity": TERMS.network_identity.model_dump(mode="json"),
        "session_id": ITEM.session_id,
        "message_id": "12" * 32,
        "sender_session_key": G_X,
        "sequence": 3,
        "in_reply_to": None,
        "contract_hash": BINDING.contract_hash,
        "message_type": "funding_binding",
        "payload": payload.model_dump(mode="json"),
        "required_features": [],
        "extensions": {},
        "signature": None,
    }
    return json.dumps(envelope).encode()


DEPOSIT_ITEM = replace(ITEM, state="CLAIMING", funding_binding=_deposit_binding())


@dataclass
class _Deposit:
    """Core's view of the deposit's inputs; the contract output never existed."""

    unspent: set[tuple[str, int]]
    mined: dict[tuple[str, int], tuple[str, int]]  # input -> (spender txid, height)
    mempool: dict[tuple[str, int], str]
    blocks: dict[int, str]
    scans: list[tuple[str, int, int]]  # (input txid, vout, from_height)
    authenticated: bool = True

    def block_hash(self, height: int) -> str:
        return self.blocks.get(height, f"{height:064x}")

    def outpoint_unspent(self, txid: str, vout: int) -> bool:
        return (txid, vout) in self.unspent

    def find_spender(
        self, txid: str, vout: int, *, from_height: int, to_height: int, anchor_block: str
    ) -> SpendScan:
        self.scans.append((txid, vout, from_height))
        assert anchor_block == self.block_hash(from_height - 1)  # always an anchored scan
        if (txid, vout) in self.mempool:
            observation = SpendObservation(self.mempool[txid, vout], (), None)
            return SpendScan(observation, from_height - 1, anchor_block)
        last = min(to_height, from_height + 11)
        found = self.mined.get((txid, vout))
        if found is not None and from_height <= found[1] <= last:
            observation = SpendObservation(found[0], (), found[1])
            if not self.authenticated:
                return SpendScan(observation, from_height - 1, None)
            return SpendScan(observation, found[1], self.block_hash(found[1]))
        return SpendScan(None, last, self.block_hash(last))


def _conflict_engine(
    monkeypatch: pytest.MonkeyPatch,
    tip: int,
    *,
    depths: dict[str, int] | None = None,
    **chain: Any,  # noqa: ANN401
) -> tuple[SettlementEngine, _Store, Mock, _Deposit]:
    attempts = [ClaimAttempt(0, "a0" * 32, b"c0", 300, 900)]  # floor 900 - 144 = 756
    engine, store, mock = _engine(monkeypatch, attempts, {} if depths is None else depths, tip)
    deposit = _Deposit(
        unspent=chain.get("unspent", {DEPOSIT_INPUTS[0]}),  # the conflict is on input 1
        mined=chain.get("mined", {DEPOSIT_INPUTS[1]: (CONFLICT, 800)}),
        mempool=chain.get("mempool", {}),
        blocks=chain.get("blocks", {}),
        scans=[],
        authenticated=chain.get("authenticated", True),
    )
    mock.outpoint_unspent.side_effect = deposit.outpoint_unspent
    mock.block_hash.side_effect = deposit.block_hash
    mock.find_spender.side_effect = deposit.find_spender
    mock.transaction_inputs.return_value = (BINDING.funding_txid, DEPOSIT_INPUTS)
    return engine, store, mock, deposit


def _sweeps(engine: SettlementEngine, store: _Store, count: int, item: Any = DEPOSIT_ITEM) -> None:  # noqa: ANN401
    for _ in range(count):
        assert asyncio.run(engine._claiming(item, ZERO, BINDING, 1500)) in ("CLAIMING", "LOST")  # noqa: SLF001
        if store.moves:
            return


def _proof(tip: int, block: str = f"{800:064x}") -> FundingConflict:
    return FundingConflict(
        funding_txid=BINDING.funding_txid,
        conflict_txid=CONFLICT,
        conflict_input_txid=DEPOSIT_INPUTS[1][0],
        conflict_input_vout=1,
        conflict_height=800,
        conflict_block=block,
        tip_height=tip,
        required_confirmations=CONFLICT_LOSS_CONFIRMATIONS,
    )


def test_a_deposit_input_spent_six_deep_by_another_transaction_closes_the_claim_as_lost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (CONFLICT_LOSS_CONFIRMATIONS, CONFLICT_SCAN_MARGIN_BLOCKS) == (6, 144)
    engine, store, chain, deposit = _conflict_engine(monkeypatch, 804)
    _sweeps(engine, store, 10)
    assert store.moves == []  # found at 800, only five deep
    # One bounded range per sweep from the floor, the unspent input never scanned.
    input_txid, vout = DEPOSIT_INPUTS[1]
    assert deposit.scans == [(input_txid, vout, h) for h in (756, 768, 780, 792)]
    chain.tip_height.return_value = 805
    _sweeps(engine, store, 1)
    (move,) = store.moves
    assert (move["from_state"], move["to_state"]) == ("CLAIMING", "LOST")
    assert move["loss_evidence"] == _proof(805)
    assert len(deposit.scans) == 4  # the found spender is revalidated, not searched again
    chain.transaction_inputs.assert_called_once_with(b"\x02" * 100)
    assert engine._conflict_scans == {}  # noqa: SLF001 - the closed swap no longer searches


def test_a_restarted_provider_searches_again_from_the_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, store, _chain, deposit = _conflict_engine(monkeypatch, 805)
    _sweeps(engine, store, 10)
    assert deposit.scans[0][2] == 756
    assert store.moves[0]["loss_evidence"] == _proof(805)


@pytest.mark.parametrize(
    "chain",
    [
        {"mined": {}, "mempool": {DEPOSIT_INPUTS[1]: CONFLICT}},  # conflict still unconfirmed
        {"mined": {DEPOSIT_INPUTS[1]: (BINDING.funding_txid, 800)}},  # the deposit itself
        {"authenticated": False},  # its block could not be authenticated
        {"unspent": set(DEPOSIT_INPUTS)},  # every input confirmed and unspent
        {"mined": {DEPOSIT_INPUTS[1]: (CONFLICT, 755)}},  # below the search floor
    ],
)
def test_anything_short_of_a_canonical_mined_conflict_keeps_the_claim(
    monkeypatch: pytest.MonkeyPatch, chain: dict[str, Any]
) -> None:
    engine, store, _chain, deposit = _conflict_engine(monkeypatch, 900, **chain)
    _sweeps(engine, store, 20)
    assert store.moves == []
    if "unspent" in chain:
        assert deposit.scans == []


def test_a_deposit_core_still_knows_is_never_searched(monkeypatch: pytest.MonkeyPatch) -> None:
    depths = {BINDING.funding_txid: 0}  # in the mempool: paid from it, waiting to confirm
    engine, store, chain, deposit = _conflict_engine(monkeypatch, 900, depths=depths)
    _sweeps(engine, store, 3)
    assert (store.moves, deposit.scans) == ([], [])
    chain.transaction_inputs.assert_not_called()
    del depths[BINDING.funding_txid]  # gone: the search starts
    _sweeps(engine, store, 2)
    assert [scan[2] for scan in deposit.scans] == [756, 768]
    depths[BINDING.funding_txid] = 0  # back in the mempool: the search is dropped
    _sweeps(engine, store, 1)
    del depths[BINDING.funding_txid]
    _sweeps(engine, store, 1)
    assert deposit.scans[-1][2] == 756  # gone again: a fresh search from the floor
    assert chain.transaction_inputs.call_count == 2


def test_unreadable_or_mismatched_deposit_bytes_are_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, store, chain, deposit = _conflict_engine(monkeypatch, 900)
    _sweeps(engine, store, 3, item=replace(DEPOSIT_ITEM, funding_binding=b"{}"))
    chain.transaction_inputs.assert_not_called()
    chain.transaction_inputs.return_value = ("99" * 32, DEPOSIT_INPUTS)
    _sweeps(engine, store, 3)
    assert (store.moves, deposit.scans) == ([], [])


def test_a_reorged_conflict_block_restarts_the_search(monkeypatch: pytest.MonkeyPatch) -> None:
    engine, store, chain, deposit = _conflict_engine(monkeypatch, 803)
    _sweeps(engine, store, 6)  # found at 800, four deep
    assert store.moves == []
    deposit.blocks[800] = "ee" * 32  # the conflict's block left the active chain
    chain.tip_height.return_value = 805
    _sweeps(engine, store, 1)
    assert store.moves == []  # not on the stale block: the search restarts
    _sweeps(engine, store, 10)
    assert deposit.scans[4][2] == 756
    assert store.moves[0]["loss_evidence"] == _proof(805, "ee" * 32)


@pytest.mark.parametrize(
    ("error", "resume"), [(CoreUnavailableError("down"), 780), (CoreProtocolError("branch"), 756)]
)
def test_a_failed_scan_is_no_evidence(
    monkeypatch: pytest.MonkeyPatch, error: Exception, resume: int
) -> None:
    engine, store, chain, deposit = _conflict_engine(monkeypatch, 900)
    _sweeps(engine, store, 2)
    chain.find_spender.side_effect = error
    _sweeps(engine, store, 1)
    chain.find_spender.side_effect = deposit.find_spender
    _sweeps(engine, store, 1)
    assert store.moves == []
    assert deposit.scans[-1][2] == resume  # unavailable resumes; a changed branch restarts


def test_new_blocks_on_one_input_never_starve_the_search_of_another(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Input 0 was spent long before the floor, so its search never ends; a new
    # block every sweep (a fast regtest miner) must still let input 1's search run.
    engine, store, chain, deposit = _conflict_engine(monkeypatch, 800, unspent=set())
    for tip in range(800, 860):
        chain.tip_height.return_value = tip
        _sweeps(engine, store, 1)
        if store.moves:
            break
    assert store.moves[0]["loss_evidence"].conflict_input_txid == DEPOSIT_INPUTS[1][0]
    assert {scan[0] for scan in deposit.scans} == {DEPOSIT_INPUTS[0][0], DEPOSIT_INPUTS[1][0]}
