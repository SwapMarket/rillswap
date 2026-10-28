"""Wallet cooperation reuses shared read-only Core validation, never wallet effects."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from rill_core.settlement import FundingBindingTransactionMatch
from rill_core.wire.messages import ContractTerms, FundingBinding
from rill_provider.core_tx_bytes import (
    CooperativeClaimOutpoint,
    CooperativeFeePolicy,
    CoreProtocolError,
    CoreUnavailableError,
)

from rill_cli import wallet_rpc
from rill_cli.wallet_rpc import WalletRpc, WalletRpcError


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple:
    document = json.loads(
        (Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text()
    )
    terms = ContractTerms.model_validate_json(json.dumps(document["contract_terms"]))
    binding = FundingBinding.model_validate(
        {
            "contract_hash": document["contract_hash"],
            "funding_attempt_id": "11" * 32,
            "binding_revision": 0,
            "funder_role": "client",
            "lineage_anchor_txid": "33" * 32,
            "lineage_anchor_vout": 0,
            "funding_txid": "22" * 32,
            "contract_vout": 1,
            "contract_value_sat": terms.economics.contract_amount_sat,
            "contract_script_pubkey": document["taproot_contract"]["script_pubkey"],
            "replaces_txid": None,
            "created_at": 1_700_000_000,
        }
    )
    outpoint = CooperativeClaimOutpoint(
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
        105,
        3,
        103,
        "bb" * 32,
    )
    policy = CooperativeFeePolicy(
        terms.network_identity,
        "aa" * 32,
        105,
        terms.timing_policy.claim_confirmation_blocks,
        100,
        1000,
        3000,
        terms.timing_policy.claim_confirmation_blocks,
    )
    reader = Mock()
    reader.observe_cooperative_claim_outpoint.return_value = outpoint
    reader.observe_cooperative_fee_policy.return_value = policy
    constructor = Mock(return_value=reader)
    monkeypatch.setattr(wallet_rpc, "CoreTransactionReader", constructor)
    cookie = tmp_path / "absent.cookie"
    wallet = WalletRpc(
        port=18443, cookie_path=cookie, wallet="savings", network=terms.network_identity
    )
    constructor.assert_called_once_with(
        port=18443, cookie_path=cookie, network=terms.network_identity
    )
    assert not cookie.exists()
    monkeypatch.setattr(wallet, "_call", Mock(side_effect=AssertionError("wallet RPC forbidden")))
    return wallet, reader, terms, binding, outpoint, policy


@pytest.mark.parametrize("fixed", [False, True])
def test_wallet_joins_shared_named_tip_evidence(evidence: tuple, *, fixed: bool) -> None:
    wallet, reader, terms, binding, outpoint, policy = evidence
    keys = Mock()
    sample = wallet.observe_cooperative_claim_evidence(
        binding,
        terms,
        keys=keys,
        allow_regtest_fixed_fee=fixed,
    )
    assert sample.outpoint is outpoint
    assert sample.fee_policy is policy
    reader.observe_cooperative_claim_outpoint.assert_called_once_with(binding, terms, keys=keys)
    reader.observe_cooperative_fee_policy.assert_called_once_with(
        terms.timing_policy.claim_confirmation_blocks,
        allow_regtest_fixed_fee=fixed,
    )


@pytest.mark.parametrize(
    "case",
    [
        "outpoint type",
        "policy type",
        "outpoint network",
        "policy network",
        "tip hash",
        "tip height",
        "confirmation budget",
        "spent",
        "fees unavailable",
    ],
)
def test_failed_or_changed_wallet_evidence_never_returns_a_sample(
    evidence: tuple, case: str
) -> None:
    wallet, reader, terms, binding, outpoint, policy = evidence
    wrong_network = terms.network_identity.model_copy(update={"genesis_hash": "ff" * 32})
    if case == "outpoint type":
        reader.observe_cooperative_claim_outpoint.return_value = Mock()
    elif case == "policy type":
        reader.observe_cooperative_fee_policy.return_value = Mock()
    elif case == "outpoint network":
        reader.observe_cooperative_claim_outpoint.return_value = replace(
            outpoint, network_identity=wrong_network
        )
    elif case == "policy network":
        reader.observe_cooperative_fee_policy.return_value = replace(
            policy, network_identity=wrong_network
        )
    elif case == "tip hash":
        reader.observe_cooperative_fee_policy.return_value = replace(policy, tip_hash="ff" * 32)
    elif case == "tip height":
        reader.observe_cooperative_fee_policy.return_value = replace(policy, tip_height=106)
    elif case == "confirmation budget":
        reader.observe_cooperative_fee_policy.return_value = replace(
            policy, confirmation_blocks=999
        )
    else:
        failure = CoreUnavailableError("sensitive local backend details")
        if case == "spent":
            reader.observe_cooperative_claim_outpoint.side_effect = failure
        else:
            reader.observe_cooperative_fee_policy.side_effect = failure
    with pytest.raises(WalletRpcError, match="Core evidence unavailable") as error:
        wallet.observe_cooperative_claim_evidence(binding, terms, keys=Mock())
    assert "sensitive" not in str(error.value)
    assert error.value.__cause__ is None


def test_a_block_between_the_two_reads_retakes_the_whole_sample(evidence: tuple) -> None:
    wallet, reader, terms, binding, outpoint, policy = evidence
    moved = replace(outpoint, tip_hash="cc" * 32, tip_height=104)
    reader.observe_cooperative_claim_outpoint.side_effect = [moved, outpoint]
    sample = wallet.observe_cooperative_claim_evidence(binding, terms, keys=Mock())
    assert (sample.outpoint, sample.fee_policy) == (outpoint, policy)
    assert reader.observe_cooperative_claim_outpoint.call_count == 2
    assert reader.observe_cooperative_fee_policy.call_count == 2


@pytest.mark.parametrize("read", ["outpoint", "fee"])
def test_a_transient_core_refusal_retakes_the_sample(evidence: tuple, read: str) -> None:
    # Each reader raises CoreUnavailableError when the tip moves within its own read.
    wallet, reader, terms, binding, outpoint, policy = evidence
    changed = CoreUnavailableError("Core chain view changed")
    if read == "outpoint":
        reader.observe_cooperative_claim_outpoint.side_effect = [changed, outpoint]
    else:
        reader.observe_cooperative_fee_policy.side_effect = [changed, policy]
    sample = wallet.observe_cooperative_claim_evidence(binding, terms, keys=Mock())
    assert (sample.outpoint, sample.fee_policy) == (outpoint, policy)
    assert reader.observe_cooperative_claim_outpoint.call_count == 2


@pytest.mark.parametrize("case", ["unavailable", "tip keeps moving"])
def test_a_persistent_transient_failure_stops_after_the_bounded_attempts(
    evidence: tuple, case: str
) -> None:
    wallet, reader, terms, binding, _outpoint, policy = evidence
    if case == "unavailable":
        reader.observe_cooperative_claim_outpoint.side_effect = CoreUnavailableError("detail")
    else:
        reader.observe_cooperative_fee_policy.return_value = replace(policy, tip_height=106)
    with pytest.raises(WalletRpcError, match="Core evidence unavailable") as error:
        wallet.observe_cooperative_claim_evidence(binding, terms, keys=Mock())
    assert error.value.__cause__ is None
    attempts = wallet_rpc.COOPERATIVE_SAMPLE_ATTEMPTS
    assert attempts == 3
    assert reader.observe_cooperative_claim_outpoint.call_count == attempts


@pytest.mark.parametrize("case", ["protocol", "outpoint type", "policy network"])
def test_other_refusals_are_never_retried(evidence: tuple, case: str) -> None:
    wallet, reader, terms, binding, _outpoint, policy = evidence
    if case == "protocol":
        reader.observe_cooperative_claim_outpoint.side_effect = CoreProtocolError("inconsistent")
    elif case == "outpoint type":
        reader.observe_cooperative_claim_outpoint.return_value = Mock()
    else:
        wrong = terms.network_identity.model_copy(update={"genesis_hash": "ff" * 32})
        reader.observe_cooperative_fee_policy.return_value = replace(policy, network_identity=wrong)
    with pytest.raises(WalletRpcError, match="Core evidence unavailable"):
        wallet.observe_cooperative_claim_evidence(binding, terms, keys=Mock())
    assert reader.observe_cooperative_claim_outpoint.call_count == 1
