"""BTC to LN provider claims are priced from the node's own fee evidence."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.settlement.unilateral import claim_vsizes
from test_settlement_engine import BINDING, DOCUMENT, ITEM, TERMS, _backends

from rill_provider import settlement_engine
from rill_provider.core_tx_bytes import CooperativeFeePolicy, CoreUnavailableError
from rill_provider.live_session_store import MAX_CLAIM_ATTEMPTS
from rill_provider.lnd_payment_send import PaymentOutcome
from rill_provider.settlement_engine import (
    CLAIM_URGENCY_BLOCKS,
    EngineSettings,
    SettlementEngine,
    claim_fee_target,
)

if TYPE_CHECKING:
    from rill_core.wire.messages import ContractTerms, NetworkIdentity

DESTINATION = bytes.fromhex(TERMS.provider_destination_script)
KEY_PATH, SCRIPT_PATH = claim_vsizes(DESTINATION)
CEILING = int(TERMS.max_claim_fee_sat)
TARGET = TERMS.timing_policy.claim_confirmation_blocks


def _policy(  # noqa: PLR0913 - explicit fee evidence
    relay: int = 1_000,
    mempool: int = 1_000,
    estimate: int | None = 2_000,
    *,
    target: int = TARGET,
    estimate_blocks: int = 1,
    network: NetworkIdentity = TERMS.network_identity,
) -> CooperativeFeePolicy:
    return CooperativeFeePolicy(
        network, "aa" * 32, 1_000, target, relay, mempool, estimate, estimate_blocks
    )


def _with_target(blocks: int) -> ContractTerms:
    timing = TERMS.timing_policy.model_copy(update={"claim_confirmation_blocks": blocks})
    return TERMS.model_copy(update={"timing_policy": timing})


def _claim_engine(
    monkeypatch: pytest.MonkeyPatch, *, regtest_fixed_fee: bool = False
) -> tuple[SettlementEngine, Mock]:
    chain = Mock()
    settings = EngineSettings(allow_regtest_fixed_fee=regtest_fixed_fee)
    engine = SettlementEngine(Mock(), chain, Mock(), Mock(), settings)
    authorization = SimpleNamespace(destination_script=DESTINATION)
    monkeypatch.setattr(engine, "_authorization", lambda *_a: authorization)
    monkeypatch.setattr(settlement_engine, "max_spendable_fee", lambda _a: CEILING)

    def claim(_item: object, _terms: object, _binding: object, fee: int) -> SimpleNamespace:
        return SimpleNamespace(raw_transaction=b"c", txid="a0" * 32, fee_sat=fee)

    monkeypatch.setattr(engine, "_claim", claim)
    return engine, chain


def _first_fee(engine: SettlementEngine, *, fresh: bool, terms: ContractTerms = TERMS) -> int:
    spend = asyncio.run(engine._initial_claim(ITEM, terms, BINDING, fresh=fresh))  # noqa: SLF001
    return int(spend.fee_sat)


@pytest.mark.parametrize(
    ("relay", "mempool", "estimate", "expected"),
    [
        (1_000, 1_000, 2_000, 222),  # 2 sat/vB at the key-path size
        (100, 100, 1_500, 167),  # sub-sat/vB relay floors: the estimate binds
        (1_000, 1_000, 1_000, 155),  # the script path must still relay at 1 sat/vB
        (1_000, 2_000, 1_000, 310),  # a raised mempool minimum binds both paths
        (1_000, 1_000, 10_000, CEILING),  # never above the signed ceiling
    ],
)
def test_the_first_claim_pays_the_key_path_size_at_the_node_fee_evidence(
    monkeypatch: pytest.MonkeyPatch, relay: int, mempool: int, estimate: int, expected: int
) -> None:
    assert (KEY_PATH, SCRIPT_PATH) == (111, 155)  # the fixture pays a P2TR destination
    engine, chain = _claim_engine(monkeypatch)
    chain.observe_cooperative_fee_policy.return_value = _policy(relay, mempool, estimate)
    assert _first_fee(engine, fresh=True) == expected
    chain.observe_cooperative_fee_policy.assert_called_once_with(
        TARGET, allow_regtest_fixed_fee=False
    )
    chain.fee_rate_sat_vb.assert_not_called()


def test_the_estimate_target_is_the_signed_claim_confirmation_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, chain = _claim_engine(monkeypatch)
    chain.observe_cooperative_fee_policy.return_value = _policy(target=3, estimate_blocks=3)
    assert _first_fee(engine, fresh=True, terms=_with_target(3)) == 222
    chain.observe_cooperative_fee_policy.assert_called_once_with(3, allow_regtest_fixed_fee=False)


@pytest.mark.parametrize(
    "evidence",
    [
        CoreUnavailableError("estimatesmartfee unavailable"),
        RuntimeError("Core hung"),
        "not a policy",
        _policy(estimate=None, estimate_blocks=0),
        _policy(target=TARGET + 1),
        _policy(estimate_blocks=TARGET + 1),
        _policy(network=TERMS.network_identity.model_copy(update={"genesis_hash": "ff" * 32})),
        _policy(relay=-1),
    ],
    ids=[
        "unavailable",
        "failed",
        "wrong type",
        "public estimate missing",
        "other target",
        "estimate beyond budget",
        "other network",
        "negative relay",
    ],
)
def test_without_usable_evidence_the_first_claim_pays_the_signed_ceiling(
    monkeypatch: pytest.MonkeyPatch, evidence: object
) -> None:
    engine, chain = _claim_engine(monkeypatch)
    if isinstance(evidence, Exception):
        chain.observe_cooperative_fee_policy.side_effect = evidence
    else:
        chain.observe_cooperative_fee_policy.return_value = evidence
    assert _first_fee(engine, fresh=True) == CEILING  # never deferred, never underpaid
    assert engine._claim_fee_evidence == {}  # noqa: SLF001


def test_explicit_regtest_without_an_estimate_pays_the_relay_floors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, chain = _claim_engine(monkeypatch, regtest_fixed_fee=True)
    chain.observe_cooperative_fee_policy.return_value = _policy(estimate=None, estimate_blocks=0)
    assert _first_fee(engine, fresh=True) == SCRIPT_PATH  # 1 sat/vB on the larger claim
    chain.observe_cooperative_fee_policy.assert_called_once_with(
        TARGET, allow_regtest_fixed_fee=True
    )


def test_rpc_free_claims_use_remembered_evidence_or_the_signed_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, chain = _claim_engine(monkeypatch)
    assert _first_fee(engine, fresh=False) == CEILING  # nothing remembered yet
    chain.observe_cooperative_fee_policy.assert_not_called()
    chain.observe_cooperative_fee_policy.return_value = _policy()
    assert _first_fee(engine, fresh=True) == 222
    chain.observe_cooperative_fee_policy.side_effect = CoreUnavailableError("hung")
    assert _first_fee(engine, fresh=True) == 222  # a failed sample keeps the remembered one
    assert _first_fee(engine, fresh=False) == 222
    assert chain.observe_cooperative_fee_policy.call_count == 2
    assert _first_fee(engine, fresh=False, terms=_with_target(3)) == CEILING  # per target


def test_payment_first_remembers_claim_fee_evidence_for_a_cooperative_probe() -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    engine._new_featured_sessions[ITEM.session_id] = ("cc" * 32, 1)  # noqa: SLF001
    chain.observe_cooperative_fee_policy.return_value = _policy()
    asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    lightning.send.assert_called_once()
    chain.observe_cooperative_fee_policy.assert_called_once_with(
        TARGET, allow_regtest_fixed_fee=False
    )
    assert engine._claim_fee_evidence == {TARGET: _policy()}  # noqa: SLF001


@pytest.mark.parametrize("featured", [True, False])
def test_claim_fee_sampling_is_only_for_probe_candidates_and_never_blocks_payment(
    *, featured: bool
) -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    if featured:
        engine._new_featured_sessions[ITEM.session_id] = ("cc" * 32, 1)  # noqa: SLF001
    chain.observe_cooperative_fee_policy.side_effect = CoreUnavailableError("no fee evidence")
    asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    lightning.send.assert_called_once()
    assert chain.observe_cooperative_fee_policy.call_count == (1 if featured else 0)
    assert engine._claim_fee_evidence == {}  # noqa: SLF001


@pytest.mark.parametrize("initial", [SCRIPT_PATH, 222])
def test_escalation_from_an_efficient_first_claim_still_reaches_the_maximum(initial: int) -> None:
    deadline, maximum = 1_059, 5_000
    fee, height, attempts, reached = initial, 1_000, 1, None
    for tip in range(1_001, deadline):
        target = claim_fee_target(
            initial=initial,
            maximum=maximum,
            anchor=1_000,
            deadline=deadline,
            tip=tip,
            latest_fee=fee,
            latest_height=height,
            vsize=SCRIPT_PATH,
            attempts=attempts,
        )
        if target is not None:
            fee, height, attempts = target, tip, attempts + 1
            if fee == maximum and reached is None:
                reached = tip
    assert fee == maximum
    assert reached is not None
    assert reached <= deadline - CLAIM_URGENCY_BLOCKS
    assert attempts <= MAX_CLAIM_ATTEMPTS


def test_ln_to_btc_refunds_keep_their_own_fee_floor() -> None:
    assert EngineSettings().refund_fee_floor_sat == 1_000
    engine = SettlementEngine(Mock(), Mock(), Mock(), Mock(), hold_invoices=Mock())
    assert engine._reverse is not None  # noqa: SLF001
    assert engine._reverse._refund_fee_floor_sat == 1_000  # noqa: SLF001
