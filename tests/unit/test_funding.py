from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from rill_core.errors import ValidationError
from rill_core.settlement import (
    FundingPlan,
    FundingPrevout,
    PlannedFundingOutput,
    authorize_funding_transaction,
)
from rill_core.wire.messages import ContractTerms

TAPROOT_FIXTURE = Path(__file__).parents[1] / "fixtures" / "settlement-v1" / "taproot-cases-v1.json"
P2WPKH = b"\x00\x14" + b"\x55" * 20
P2WSH = b"\x00\x20" + b"\x66" * 32
P2TR = b"\x51\x20" + b"\x77" * 32


@dataclass
class FixtureKeyOperations:
    internal_key: bytes
    internal_parity: int
    output_key: bytes
    output_parity: int
    tap_tweak: bytes
    client_key: bytes
    provider_key: bytes

    def musig_internal_key(self, client: bytes, provider: bytes) -> tuple[bytes, int]:
        assert (client, provider) == (self.client_key, self.provider_key)
        return self.internal_key, self.internal_parity

    def musig_output_key(self, client: bytes, provider: bytes, tweak: bytes) -> tuple[bytes, int]:
        assert (client, provider, tweak) == (
            self.client_key,
            self.provider_key,
            self.tap_tweak,
        )
        return self.output_key, self.output_parity


def _terms_and_keys(case_index: int = 0) -> tuple[ContractTerms, FixtureKeyOperations, int, bytes]:
    case: dict[str, Any] = json.loads(TAPROOT_FIXTURE.read_text())["valid"][case_index]
    terms = ContractTerms.model_validate_json(json.dumps(case["contract_terms"]))
    artifacts = case["artifacts"]
    return (
        terms,
        FixtureKeyOperations(
            internal_key=bytes.fromhex(artifacts["internal_key"]),
            internal_parity=artifacts["internal_parity"],
            output_key=bytes.fromhex(artifacts["output_key"]),
            output_parity=artifacts["output_parity"],
            tap_tweak=bytes.fromhex(artifacts["tap_tweak"]),
            client_key=bytes.fromhex(terms.client_contract_compressed_key),
            provider_key=bytes.fromhex(terms.provider_contract_compressed_key),
        ),
        int(terms.economics.contract_amount_sat),
        bytes.fromhex(artifacts["script_pubkey"]),
    )


def _contract_script() -> bytes:
    return _terms_and_keys()[3]


def _string(value: bytes) -> bytes:
    assert len(value) < 253
    return bytes([len(value)]) + value


def _raw(
    inputs: tuple[tuple[bytes, int, bytes, int], ...],
    outputs: tuple[tuple[int, bytes], ...],
    *,
    version: int = 2,
    lock_time: int = 0,
    witness: tuple[tuple[bytes, ...], ...] | None = None,
) -> bytes:
    assert len(inputs) < 253
    assert len(outputs) < 253
    encoded = version.to_bytes(4, "little", signed=True)
    if witness is not None:
        assert len(witness) == len(inputs)
        encoded += b"\x00\x01"
    encoded += bytes([len(inputs)])
    for txid, index, script_sig, sequence in inputs:
        encoded += (
            txid[::-1]
            + index.to_bytes(4, "little")
            + _string(script_sig)
            + sequence.to_bytes(4, "little")
        )
    encoded += bytes([len(outputs)])
    for value, script in outputs:
        encoded += value.to_bytes(8, "little") + _string(script)
    if witness is not None:
        for stack in witness:
            encoded += bytes([len(stack)]) + b"".join(_string(item) for item in stack)
    return encoded + lock_time.to_bytes(4, "little")


def _candidate(  # noqa: PLR0913
    *,
    case_index: int = 0,
    second_script: bytes = P2WSH,
    inputs_override: tuple[tuple[bytes, int, bytes, int], ...] | None = None,
    outputs_override: tuple[tuple[int, bytes], ...] | None = None,
    witness: tuple[tuple[bytes, ...], ...] | None = None,
    version: int = 2,
    lock_time: int = 0,
) -> tuple[bytes, FundingPlan, ContractTerms, FixtureKeyOperations]:
    terms, keys, amount, contract_script = _terms_and_keys(case_index)
    anchor = FundingPrevout(b"\x11" * 32, 2, 90_000, P2WPKH)
    other = FundingPrevout(b"\x22" * 32, 1, amount + 10_000 - 90_000, second_script)
    change = PlannedFundingOutput(9_500, P2TR)
    plan = FundingPlan((anchor, other), anchor, (change,))
    inputs = inputs_override or (
        (anchor.txid, anchor.output_index, b"", 0xFFFFFFFD),
        (other.txid, other.output_index, b"", 0xFFFFFFFF),
    )
    outputs = outputs_override or (
        (change.value_sat, change.script_pubkey),
        (amount, contract_script),
    )
    return (
        _raw(inputs, outputs, witness=witness, version=version, lock_time=lock_time),
        plan,
        terms,
        keys,
    )


@pytest.mark.parametrize("case_index", [0, 1])
@pytest.mark.parametrize("second_script", [P2WSH, P2TR])
def test_authorizes_exact_plan_and_preserves_txid_with_witness(
    case_index: int,
    second_script: bytes,
) -> None:
    unsigned, plan, terms, keys = _candidate(case_index=case_index, second_script=second_script)
    result = authorize_funding_transaction(unsigned, terms, plan, keys=keys)
    assert result.raw_transaction == unsigned
    assert result.txid == hashlib.sha256(hashlib.sha256(unsigned).digest()).digest()[::-1].hex()
    assert result.contract_vout == 1
    assert result.contract_value_sat == int(terms.economics.contract_amount_sat)
    assert result.contract_script_pubkey != result.outputs[0].script_pubkey
    assert result.fee_sat == 500
    assert result.input_sequences == (0xFFFFFFFD, 0xFFFFFFFF)
    assert result.lock_time == 0
    assert not result.has_witness_serialization

    witness = ((b"\x30" * 72, b"\x02" * 33), (b"\x01",))
    candidate, _, _, _ = _candidate(
        case_index=case_index,
        second_script=second_script,
        witness=witness,
    )
    observed = authorize_funding_transaction(candidate, terms, plan, keys=keys)
    assert observed.txid == result.txid
    assert observed.has_witness_serialization
    assert observed.raw_transaction != result.raw_transaction
    assert observed.fee_sat == result.fee_sat


def test_rejects_unapproved_inputs_script_sig_and_anchor() -> None:
    raw, plan, terms, keys = _candidate()
    inputs = (
        (plan.approved_inputs[0].txid, 2, b"", 0xFFFFFFFD),
        (plan.approved_inputs[1].txid, 1, b"", 0xFFFFFFFF),
    )
    duplicate = _raw((inputs[0], inputs[0]), ((9_500, P2TR), (101_000, _contract_script())))
    with pytest.raises(ValidationError, match="duplicate or unapproved"):
        authorize_funding_transaction(duplicate, terms, plan, keys=keys)
    with pytest.raises(ValidationError, match="duplicate or unapproved"):
        authorize_funding_transaction(
            raw.replace(plan.lineage_anchor.txid[::-1], b"\x99" * 32), terms, plan, keys=keys
        )
    with pytest.raises(ValidationError, match="scriptSig"):
        authorize_funding_transaction(
            raw.replace(b"\x00\xfd\xff\xff\xff", b"\x01\x51\xfd\xff\xff\xff", 1),
            terms,
            plan,
            keys=keys,
        )
    with pytest.raises(ValidationError, match="lineage anchor"):
        FundingPlan(
            plan.approved_inputs[1:], plan.lineage_anchor, plan.approved_noncontract_outputs
        )
    with pytest.raises(ValidationError, match="repeats"):
        FundingPlan((plan.lineage_anchor, plan.lineage_anchor), plan.lineage_anchor, ())


def test_rejects_output_substitution_and_fee_violations() -> None:
    raw, plan, terms, keys = _candidate()
    contract_script = _contract_script()
    scenarios = (
        (((9_500, P2TR), (100_999, contract_script)), "contract output value"),
        (((9_500, P2TR), (101_000, P2TR)), "exactly one contract"),
        (((9_500, P2TR), (101_000, contract_script), (1, contract_script)), "exactly one contract"),
        (((9_501, P2TR), (101_000, contract_script)), "unapproved or missing output"),
        (((9_500, P2WPKH), (101_000, contract_script)), "unapproved or missing output"),
        (((9_500, P2TR), (101_000, contract_script), (1, P2WPKH)), "unapproved or missing output"),
        (((9_500, P2TR), (101_000, contract_script), (1, P2WSH)), "unsupported change"),
        (((8_999, P2TR), (101_000, contract_script)), "unapproved or missing output"),
    )
    for outputs, expected_error in scenarios:
        changed, _, _, _ = _candidate(outputs_override=outputs)
        assert changed != raw
        with pytest.raises(ValidationError, match=expected_error):
            authorize_funding_transaction(changed, terms, plan, keys=keys)

    increased_change = (PlannedFundingOutput(10_001, P2TR),)
    changed_plan = FundingPlan(plan.approved_inputs, plan.lineage_anchor, increased_change)
    negative_fee, _, _, _ = _candidate(
        outputs_override=((10_001, P2TR), (101_000, contract_script))
    )
    with pytest.raises(ValidationError, match="fee is negative"):
        authorize_funding_transaction(negative_fee, terms, changed_plan, keys=keys)
    reduced_change = (PlannedFundingOutput(9_499, P2TR),)
    changed_plan = FundingPlan(plan.approved_inputs, plan.lineage_anchor, reduced_change)
    over_cap, _, _, _ = _candidate(outputs_override=((9_499, P2TR), (101_000, contract_script)))
    with pytest.raises(ValidationError, match="exceeds the signed cap"):
        authorize_funding_transaction(over_cap, terms, changed_plan, keys=keys)


def test_rejects_malformed_wire_encoding_and_unsupported_profile() -> None:
    raw, plan, terms, keys = _candidate()
    contract_script = _contract_script()
    inputs = tuple((item.txid, item.output_index, b"", 0xFFFFFFFF) for item in plan.approved_inputs)
    outputs = ((9_500, P2TR), (101_000, contract_script))
    for changed in (
        b"",
        raw[:-1],
        raw + b"\x00",
        raw[:4] + b"\xfd\x02\x00" + raw[5:],
        _raw(inputs, outputs, version=3),
        _raw(inputs, outputs, witness=((), ())),
        raw[:4] + b"\x00\x02" + raw[6:],
    ):
        with pytest.raises(ValidationError):
            authorize_funding_transaction(changed, terms, plan, keys=keys)
    unsupported_identity = terms.network_identity.model_copy(
        update={"consensus_profile": "bitcoin-core/v30"},
    )
    unsupported_terms = terms.model_copy(update={"network_identity": unsupported_identity})
    with pytest.raises(ValidationError, match="unsupported funding consensus profile"):
        authorize_funding_transaction(raw, unsupported_terms, plan, keys=keys)


def test_no_implicit_rbf_rule_and_input_order_is_not_a_plan_order() -> None:
    _, plan, terms, keys = _candidate()
    reordered = tuple(
        (item.txid, item.output_index, b"", 0xFFFFFFFF) for item in reversed(plan.approved_inputs)
    )
    candidate = _raw(
        reordered,
        ((9_500, P2TR), (101_000, _contract_script())),
        lock_time=123,
    )
    result = authorize_funding_transaction(candidate, terms, plan, keys=keys)
    assert result.input_sequences == (0xFFFFFFFF, 0xFFFFFFFF)
    assert result.lock_time == 123
    assert not result.has_witness_serialization


def test_nonpalindromic_prevout_is_serialized_in_wire_order() -> None:
    _, plan, terms, keys = _candidate()
    anchor = replace(plan.lineage_anchor, txid=bytes(range(32)))
    approved = FundingPlan(
        (anchor, plan.approved_inputs[1]),
        anchor,
        plan.approved_noncontract_outputs,
    )
    inputs = tuple(
        (item.txid, item.output_index, b"", 0xFFFFFFFD) for item in approved.approved_inputs
    )
    candidate = _raw(inputs, ((9_500, P2TR), (101_000, _contract_script())))
    assert candidate[5:37] == bytes(range(32))[::-1]
    result = authorize_funding_transaction(candidate, terms, approved, keys=keys)
    assert result.contract_vout == 1


def test_output_multiset_accepts_explicit_duplicates_only() -> None:
    _, plan, terms, keys = _candidate()
    duplicate = PlannedFundingOutput(4_750, P2TR)
    approved = FundingPlan(plan.approved_inputs, plan.lineage_anchor, (duplicate, duplicate))
    inputs = tuple(
        (item.txid, item.output_index, b"", 0xFFFFFFFD) for item in approved.approved_inputs
    )
    candidate = _raw(
        inputs,
        ((4_750, P2TR), (101_000, _contract_script()), (4_750, P2TR)),
    )
    result = authorize_funding_transaction(candidate, terms, approved, keys=keys)
    assert result.fee_sat == 500
    assert result.outputs.count(duplicate) == 2
    short_plan = FundingPlan(plan.approved_inputs, plan.lineage_anchor, (duplicate,))
    with pytest.raises(ValidationError, match="unapproved or missing output"):
        authorize_funding_transaction(candidate, terms, short_plan, keys=keys)


def test_compact_size_and_witness_resource_limits() -> None:
    raw, plan, terms, keys = _candidate()
    nonminimal_counts = (
        b"\xfd\x02\x00",
        b"\xfe\x02\x00\x00\x00",
        b"\xff\x02" + b"\x00" * 7,
    )
    for count in nonminimal_counts:
        with pytest.raises(ValidationError, match="noncanonical CompactSize"):
            authorize_funding_transaction(raw[:4] + count + raw[5:], terms, plan, keys=keys)
    with pytest.raises(ValidationError, match="truncated"):
        authorize_funding_transaction(raw[:4] + b"\xfe\x02", terms, plan, keys=keys)
    inputs = tuple((item.txid, item.output_index, b"", 0xFFFFFFFD) for item in plan.approved_inputs)
    candidate = _raw(
        inputs,
        ((9_500, P2TR), (101_000, _contract_script())),
        witness=((b"",) * 101, ()),
    )
    with pytest.raises(ValidationError, match="local item limit"):
        authorize_funding_transaction(candidate, terms, plan, keys=keys)


def test_aggregate_input_money_range_is_not_only_a_per_input_check() -> None:
    raw, plan, terms, keys = _candidate()
    enormous = tuple(
        replace(item, value_sat=21_000_000 * 100_000_000) for item in plan.approved_inputs
    )
    inflated = FundingPlan(enormous, enormous[0], plan.approved_noncontract_outputs)
    with pytest.raises(ValidationError, match="aggregate value"):
        authorize_funding_transaction(raw, terms, inflated, keys=keys)


@pytest.mark.parametrize(
    "script", [b"\xa9\x14" + b"\x00" * 20 + b"\x87", b"\x52\x20" + b"\x00" * 32]
)
def test_rejects_non_native_or_future_witness_input(script: bytes) -> None:
    with pytest.raises(ValidationError, match="native P2WPKH, P2WSH, or P2TR"):
        FundingPrevout(b"\x01" * 32, 0, 1_000, script)
