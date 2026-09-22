from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from rill_core.domain.funding_lineage import BestChainObservation, FundingLineage
from rill_core.errors import TransitionError, ValidationError
from rill_core.wire.messages import ContractTerms, FundingBinding

VECTORS = Path(__file__).parents[1] / "fixtures" / "settlement-v1" / "taproot-cases-v1.json"


class FixtureKeys:
    def __init__(self, case: dict[str, Any], terms: ContractTerms) -> None:
        self.artifacts = case["artifacts"]
        self.client = bytes.fromhex(terms.client_contract_compressed_key)
        self.provider = bytes.fromhex(terms.provider_contract_compressed_key)

    def musig_internal_key(self, client: bytes, provider: bytes) -> tuple[bytes, int]:
        assert (client, provider) == (self.client, self.provider)
        return (
            bytes.fromhex(self.artifacts["internal_key"]),
            self.artifacts["internal_parity"],
        )

    def musig_output_key(
        self, client: bytes, provider: bytes, tap_tweak: bytes
    ) -> tuple[bytes, int]:
        assert (client, provider) == (self.client, self.provider)
        assert tap_tweak == bytes.fromhex(self.artifacts["tap_tweak"])
        return bytes.fromhex(self.artifacts["output_key"]), self.artifacts["output_parity"]


def _new_lineage(case_index: int = 0) -> FundingLineage:
    case: dict[str, Any] = json.loads(VECTORS.read_text())["valid"][case_index]
    terms = ContractTerms.model_validate_json(json.dumps(case["contract_terms"]))
    lineage = FundingLineage.for_terms(terms, "bb" * 32, keys=FixtureKeys(case, terms))
    assert lineage.contract_script_pubkey == case["artifacts"]["script_pubkey"]
    assert lineage.contract_value_sat == terms.economics.contract_amount_sat
    assert lineage.network_identity == terms.network_identity
    return lineage


def _binding(
    lineage: FundingLineage,
    revision: int,
    **changes: object,
) -> FundingBinding:
    values: dict[str, object] = {
        "contract_hash": lineage.contract_hash,
        "funding_attempt_id": lineage.funding_attempt_id,
        "binding_revision": revision,
        "funder_role": lineage.funder_role,
        "lineage_anchor_txid": "ab" * 32,
        "lineage_anchor_vout": 1,
        "funding_txid": f"{revision + 17:02x}" * 32,
        "contract_vout": revision + 2,
        "contract_value_sat": lineage.contract_value_sat,
        "contract_script_pubkey": lineage.contract_script_pubkey,
        "replaces_txid": f"{revision + 16:02x}" * 32 if revision else None,
        "created_at": 1_700_000_000 + revision,
    }
    values.update(changes)
    return FundingBinding.model_validate(values)


def _observation(
    binding: FundingBinding,
    *,
    block_hash: str = "cd" * 32,
    block_height: int = 100,
    tip_hash: str = "ef" * 32,
    tip_height: int = 105,
) -> BestChainObservation:
    return BestChainObservation(
        binding.funding_txid,
        binding.contract_vout,
        block_hash,
        block_height,
        tip_hash,
        tip_height,
    )


@pytest.mark.parametrize(("case_index", "role"), [(0, "client"), (1, "provider")])
def test_append_replay_and_replacements_preserve_one_attempt(case_index: int, role: str) -> None:
    empty = _new_lineage(case_index)
    assert empty.funder_role == role
    assert not empty.bindings
    assert empty.best_chain is None
    first = _binding(empty, 0)
    one = empty.append_verified_binding(first)
    assert one.bindings == (first,)
    assert empty.bindings == ()
    assert one.append_verified_binding(first) is one
    second = _binding(empty, 1, contract_vout=7)
    two = one.append_verified_binding(second)
    assert two.bindings == (first, second)
    assert two.append_verified_binding(first) is two
    assert two.append_verified_binding(second) is two


def test_rejects_reordered_forked_or_cross_contract_binding_without_mutation() -> None:
    empty = _new_lineage()
    first = _binding(empty, 0)
    one = empty.append_verified_binding(first)
    for state, binding, expected in (
        (empty, _binding(empty, 1), "skips or forks"),
        (one, _binding(empty, 2), "skips or forks"),
        (one, _binding(empty, 0, funding_txid="99" * 32), "conflicting"),
        (one, _binding(empty, 0, created_at=123), "conflicting"),
        (one, _binding(empty, 1, replaces_txid="ff" * 32), "predecessor"),
        (one, _binding(empty, 1, lineage_anchor_txid="ee" * 32), "anchor"),
        (one, _binding(empty, 1, lineage_anchor_vout=0), "anchor"),
        (one, _binding(empty, 1, funding_txid=first.funding_txid), "repeats"),
        (one, _binding(empty, 1, funding_attempt_id="ee" * 32), "contract and attempt"),
        (one, _binding(empty, 1, contract_hash="ee" * 32), "contract and attempt"),
        (one, _binding(empty, 1, funder_role="provider"), "contract and attempt"),
        (one, _binding(empty, 1, contract_value_sat="1"), "contract and attempt"),
        (
            one,
            _binding(empty, 1, contract_script_pubkey=_new_lineage(1).contract_script_pubkey),
            "contract and attempt",
        ),
        (one, _binding(empty, 1, contract_vout=2**32), "exceeds uint32"),
        (one, _binding(empty, 1, lineage_anchor_vout=2**32), "exceeds uint32"),
    ):
        before = state
        with pytest.raises(TransitionError, match=expected):
            state.append_verified_binding(binding)
        assert state == before


def test_best_chain_may_select_earlier_revision_and_cannot_be_displaced() -> None:
    empty = _new_lineage()
    first, second = _binding(empty, 0), _binding(empty, 1)
    state = empty.append_verified_binding(first)
    with pytest.raises(TransitionError, match="not an accepted binding"):
        state.observe_verified_best_chain(_observation(second))
    confirmed_first = _observation(first)
    state = state.observe_verified_best_chain(confirmed_first)
    assert state.best_chain == confirmed_first
    assert state.best_chain.depth == 6
    assert state.observe_verified_best_chain(confirmed_first) is state
    state = state.append_verified_binding(second)
    assert state.best_chain == confirmed_first
    with pytest.raises(TransitionError, match="remove the prior"):
        state.observe_verified_best_chain(_observation(second))
    with pytest.raises(TransitionError, match="remove the prior"):
        state.observe_verified_best_chain(_observation(first, tip_hash="ca" * 32))


def test_reorg_removes_exact_view_without_rewriting_accepted_bindings() -> None:
    empty = _new_lineage()
    first, second = _binding(empty, 0), _binding(empty, 1)
    state = empty.append_verified_binding(first).append_verified_binding(second)
    first_view = _observation(first)
    state = state.observe_verified_best_chain(first_view)
    with pytest.raises(TransitionError, match="different or absent"):
        state.remove_verified_best_chain(_observation(first, tip_hash="ca" * 32))
    cleared = state.remove_verified_best_chain(first_view)
    assert cleared.best_chain is None
    assert cleared.bindings == state.bindings
    new_view = _observation(second, block_hash="ba" * 32, tip_hash="ba" * 32, tip_height=100)
    restored = cleared.observe_verified_best_chain(new_view)
    assert restored.best_chain == new_view
    assert new_view.depth == 1
    with pytest.raises(TransitionError, match="different or absent"):
        restored.remove_verified_best_chain(first_view)
    with pytest.raises(TransitionError, match="different or absent"):
        cleared.remove_verified_best_chain(first_view)


def test_invalid_or_independent_outpoints_never_become_lineage_evidence() -> None:
    empty = _new_lineage()
    first = _binding(empty, 0)
    state = empty.append_verified_binding(first)
    for observation in (
        BestChainObservation("99" * 32, first.contract_vout, "cd" * 32, 100, "ef" * 32, 105),
        BestChainObservation(first.funding_txid, 10, "cd" * 32, 100, "ef" * 32, 105),
    ):
        with pytest.raises(TransitionError, match="not an accepted binding"):
            state.observe_verified_best_chain(observation)
    with pytest.raises(TransitionError, match="anchor"):
        state.append_verified_binding(_binding(empty, 1, lineage_anchor_txid="99" * 32))
    assert state.bindings == (first,)
    assert state.best_chain is None


def test_rejects_malformed_context_and_chain_view() -> None:
    case: dict[str, Any] = json.loads(VECTORS.read_text())["valid"][0]
    terms = ContractTerms.model_validate_json(json.dumps(case["contract_terms"]))
    for attempt in ("abc", "GG" * 32):
        with pytest.raises(ValidationError, match="funding_attempt_id"):
            FundingLineage.for_terms(terms, attempt, keys=FixtureKeys(case, terms))
    for changes in (
        {"contract_vout": -1},
        {"contract_vout": 2**32},
        {"block_height": 105, "tip_height": 100},
        {"block_height": 100, "tip_height": 100, "block_hash": "cd" * 32},
        {"tip_hash": "xx" * 32},
    ):
        values: dict[str, object] = {
            "funding_txid": "11" * 32,
            "contract_vout": 0,
            "block_hash": "cd" * 32,
            "block_height": 100,
            "tip_hash": "ef" * 32,
            "tip_height": 105,
        }
        values.update(changes)
        with pytest.raises(ValidationError):
            BestChainObservation(**values)  # type: ignore[arg-type]
