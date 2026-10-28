from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest

from rill_core.errors import ValidationError
from rill_core.settlement import (
    FundingOutput,
    TaprootContract,
    UnilateralAuthorization,
    build_cooperative_claim,
    build_unilateral_spend,
    finalize_cooperative_claim,
    finalize_unilateral_spend,
    max_spendable_fee,
    reconstruct_taproot_contract,
    validate_cooperative_claim,
    validate_unilateral_spend,
    verify_cooperative_claim_proposal,
)
from rill_core.settlement import unilateral as tx
from rill_core.wire.messages import ContractTerms

FIXTURES = Path(__file__).parents[1] / "fixtures" / "settlement-v1"


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


def _terms(case: dict[str, Any]) -> ContractTerms:
    return ContractTerms.model_validate_json(json.dumps(case["contract_terms"]))


def _taproot_contract(case: dict[str, Any]) -> TaprootContract:
    artifacts = case["artifacts"]
    return TaprootContract(
        internal_key=bytes.fromhex(artifacts["internal_key"]),
        internal_parity=artifacts["internal_parity"],
        claim_script=bytes.fromhex(artifacts["claim_script"]),
        refund_script=bytes.fromhex(artifacts["refund_script"]),
        claim_leaf_preimage=bytes.fromhex(artifacts["claim_leaf_preimage"]),
        refund_leaf_preimage=bytes.fromhex(artifacts["refund_leaf_preimage"]),
        claim_leaf_hash=bytes.fromhex(artifacts["claim_leaf_hash"]),
        refund_leaf_hash=bytes.fromhex(artifacts["refund_leaf_hash"]),
        branch_left_hash=bytes.fromhex(artifacts["branch_left_hash"]),
        branch_right_hash=bytes.fromhex(artifacts["branch_right_hash"]),
        merkle_root=bytes.fromhex(artifacts["merkle_root"]),
        tap_tweak=bytes.fromhex(artifacts["tap_tweak"]),
        output_key=bytes.fromhex(artifacts["output_key"]),
        output_parity=artifacts["output_parity"],
        script_pubkey=bytes.fromhex(artifacts["script_pubkey"]),
        claim_control_block=bytes.fromhex(artifacts["claim_control_block"]),
        refund_control_block=bytes.fromhex(artifacts["refund_control_block"]),
    )


@dataclass
class FixtureKeyOperations:
    terms: ContractTerms
    contract: TaprootContract

    def _require_order(self, client: bytes, provider: bytes) -> None:
        assert client == bytes.fromhex(self.terms.client_contract_compressed_key)
        assert provider == bytes.fromhex(self.terms.provider_contract_compressed_key)

    def musig_internal_key(self, client: bytes, provider: bytes) -> tuple[bytes, int]:
        self._require_order(client, provider)
        return self.contract.internal_key, self.contract.internal_parity

    def musig_output_key(
        self, client: bytes, provider: bytes, tap_tweak: bytes
    ) -> tuple[bytes, int]:
        self._require_order(client, provider)
        assert tap_tweak == self.contract.tap_tweak
        return self.contract.output_key, self.contract.output_parity


def _keys(terms: ContractTerms, case: dict[str, Any]) -> FixtureKeyOperations:
    return FixtureKeyOperations(terms, _taproot_contract(case))


def _funding(case: dict[str, Any]) -> FundingOutput:
    funding = case["synthetic_funding"]
    return FundingOutput(
        txid=bytes.fromhex(funding["txid"]),
        output_index=funding["vout"],
        value_sat=int(funding["value_sat"]),
        script_pubkey=bytes.fromhex(funding["script_pubkey"]),
    )


@dataclass
class ExpectedVerifier:
    public_key: bytes
    message: bytes
    signature: bytes
    calls: list[tuple[bytes, bytes, bytes]] = field(default_factory=list)

    def schnorr_verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> None:
        self.calls.append((public_key, message, signature))
        if (public_key, message, signature) != (
            self.public_key,
            self.message,
            self.signature,
        ):
            raise ValueError("unexpected or invalid signature")


def _role_key(terms: ContractTerms, path: str) -> bytes:
    role = terms.claimant if path == "claim" else terms.refund_party
    compressed = (
        terms.client_contract_compressed_key
        if role == "client"
        else terms.provider_contract_compressed_key
    )
    return bytes.fromhex(compressed)[1:]


def test_fixture_copies_are_pinned_by_source_commit_and_hash() -> None:
    manifest = _load("manifest.json")
    assert manifest["fixture_set"] == "rillswap-unilateral-settlement-v1-pre.1"
    assert manifest["sources"]["taproot-cases-v1.json"]["commit"] == "60c6068"
    assert manifest["sources"]["settlement-cases-v1.json"]["commit"] == "369f02a"
    for name, source in manifest["sources"].items():
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == source["sha256"]


def test_reproduces_all_unilateral_settlement_vectors() -> None:
    taproot_vectors = _load("taproot-cases-v1.json")
    settlement_vectors = _load("settlement-cases-v1.json")
    taproot_by_id = {case["id"]: case for case in taproot_vectors["valid"]}

    for case in settlement_vectors["valid"]:
        taproot_case = taproot_by_id[case["taproot_vector"]]
        terms = _terms(taproot_case)
        keys = _keys(terms, taproot_case)
        assert reconstruct_taproot_contract(terms, keys=keys) == keys.contract
        funding = _funding(case)
        for path in ("claim", "refund"):
            artifact = case[path]
            authorization = UnilateralAuthorization.from_terms(
                terms,
                funding,
                path,
                keys=keys,
            )
            plan = build_unilateral_spend(
                authorization,
                fee_sat=int(artifact["fee_sat"]),
                claim_preimage=(
                    bytes.fromhex(taproot_case["claim_preimage"]) if path == "claim" else None
                ),
            )
            assert plan.base_transaction.hex() == artifact["base_transaction"]
            assert plan.signature_hash.hex() == artifact["signature_hash"]
            assert plan.output_value_sat == int(artifact["output_value_sat"])
            signature = bytes.fromhex(artifact["signature"])
            verifier = ExpectedVerifier(
                _role_key(terms, path),
                plan.signature_hash,
                signature,
            )
            validated = finalize_unilateral_spend(plan, signature, verifier=verifier)
            assert validated.raw_transaction.hex() == artifact["raw_transaction"]
            assert validated.signature_hash.hex() == artifact["signature_hash"]
            assert validated.fee_sat == int(artifact["fee_sat"])
            assert validated.txid == artifact["txid"]
            assert validated.wtxid == artifact["wtxid"]
            assert validated.weight == artifact["weight"]
            assert validated.vsize == artifact["vsize"]
            assert len(verifier.calls) == 2


def _first_context() -> tuple[
    dict[str, Any],
    ContractTerms,
    FundingOutput,
]:
    taproot_case = _load("taproot-cases-v1.json")["valid"][0]
    settlement_case = _load("settlement-cases-v1.json")["valid"][0]
    return (
        taproot_case,
        _terms(taproot_case),
        _funding(settlement_case),
    )


def test_cooperative_claim_binds_exact_key_path_transaction_and_output_key() -> None:
    case, terms, funding = _first_context()
    authorization = UnilateralAuthorization.from_terms(
        terms, funding, "claim", keys=_keys(terms, case)
    )
    plan = build_cooperative_claim(authorization, fee_sat=300)
    # This synthetic verifier tests the policy boundary; the native/Bitcoin
    # Core tests separately establish actual BIP340/MuSig consensus validity.
    signature = b"\x11" * 64
    verifier = ExpectedVerifier(funding.script_pubkey[2:], plan.signature_hash, signature)
    validated = finalize_cooperative_claim(plan, signature, verifier=verifier)
    assert validated.signature_hash == plan.signature_hash
    assert validated.fee_sat == 300
    assert validated.raw_transaction[-69:] == b"\x40" + signature + b"\x00\x00\x00\x00"
    assert len(verifier.calls) == 1
    assert validate_cooperative_claim(validated.raw_transaction, authorization, verifier=verifier)
    assert len(verifier.calls) == 2
    internal_key_verifier = ExpectedVerifier(
        bytes.fromhex(case["artifacts"]["internal_key"]), plan.signature_hash, signature
    )
    with pytest.raises(ValidationError, match="signature is invalid"):
        validate_cooperative_claim(
            validated.raw_transaction, authorization, verifier=internal_key_verifier
        )


@pytest.mark.parametrize("profile", ["btc-to-ln/v1", "ln-to-btc/v1"])
def test_cooperative_proposal_reconstructs_fee_and_exact_sighash(profile: str) -> None:
    case = next(
        item
        for item in _load("taproot-cases-v1.json")["valid"]
        if item["contract_terms"]["profile_id"] == profile
    )
    settlement = next(
        item
        for item in _load("settlement-cases-v1.json")["valid"]
        if item["taproot_vector"] == case["id"]
    )
    terms, funding = _terms(case), _funding(settlement)
    authorization = UnilateralAuthorization.from_terms(
        terms, funding, "claim", keys=_keys(terms, case)
    )
    for fee in (0, 300, max_spendable_fee(authorization)):
        plan = build_cooperative_claim(authorization, fee_sat=fee)
        assert verify_cooperative_claim_proposal(plan.base_transaction, authorization) == plan
        assert len(plan.signature_hash) == 32


@pytest.mark.parametrize(
    ("destination", "expected"),
    [("0014" + "77" * 20, (99, 143)), ("5120" + "77" * 32, (111, 155))],
)
def test_claim_vsizes_match_the_built_claims(destination: str, expected: tuple[int, int]) -> None:
    case = next(
        item
        for item in _load("taproot-cases-v1.json")["valid"]
        if item["contract_terms"]["profile_id"] == "ln-to-btc/v1"
    )
    settlement = next(
        item
        for item in _load("settlement-cases-v1.json")["valid"]
        if item["taproot_vector"] == case["id"]
    )
    terms = _terms(case).model_copy(update={"client_destination_script": destination})
    funding = _funding(settlement)
    authorization = UnilateralAuthorization.from_terms(
        terms, funding, "claim", keys=_keys(terms, case)
    )
    signature = b"\x11" * 64
    cooperative = build_cooperative_claim(authorization, fee_sat=300)
    validated = finalize_cooperative_claim(
        cooperative,
        signature,
        verifier=ExpectedVerifier(funding.script_pubkey[2:], cooperative.signature_hash, signature),
    )
    unilateral = build_unilateral_spend(
        authorization, fee_sat=300, claim_preimage=bytes.fromhex(case["claim_preimage"])
    )
    fallback = finalize_unilateral_spend(
        unilateral,
        signature,
        verifier=ExpectedVerifier(_role_key(terms, "claim"), unilateral.signature_hash, signature),
    )
    assert tx.claim_vsizes(bytes.fromhex(destination)) == expected
    assert (validated.vsize, fallback.vsize) == expected


def test_claim_vsizes_refuse_unsupported_destinations() -> None:
    with pytest.raises(ValidationError, match="destination script"):
        tx.claim_vsizes(bytes.fromhex("0020" + "77" * 32))


def test_cooperative_proposal_refuses_base_encoding_and_policy_escapes() -> None:
    case, terms, funding = _first_context()
    authorization = UnilateralAuthorization.from_terms(
        terms, funding, "claim", keys=_keys(terms, case)
    )
    plan = build_cooperative_claim(authorization, fee_sat=300)
    raw = plan.base_transaction

    def changed(start: int, end: int, replacement: bytes) -> bytes:
        return raw[:start] + replacement + raw[end:]

    # One canonical input/output, no witness, exactly the selected funding
    # outpoint/destination and the locally enforced signed fee cap and dust.
    invalid: list[object] = [
        None,
        bytearray(raw),
        b"",
        raw[:-1],
        raw + b"\x00",
        b"\x00" * (tx.MAX_TRANSACTION_BYTES + 1),
        changed(0, 4, b"\x03\x00\x00\x00"),
        changed(4, 5, b"\x00"),
        changed(4, 5, b"\x02"),
        changed(4, 5, b"\xfd\x01\x00"),
        changed(4, 5, b"\x00\x01"),  # witness marker is not base serialization
        changed(5, 6, bytes([raw[5] ^ 1])),
        changed(37, 38, bytes([raw[37] ^ 1])),
        changed(41, 42, b"\x01\x00"),
        changed(41, 42, b"\xfd\x11\x27"),  # scriptSig > MAX_SCRIPT_BYTES
        changed(42, 43, bytes([raw[42] ^ 1])),
        changed(46, 47, b"\x00"),
        changed(46, 47, b"\x02"),
        changed(47, 55, (funding.value_sat + 1).to_bytes(8, "little")),
        changed(
            47, 55, (funding.value_sat - max_spendable_fee(authorization) - 1).to_bytes(8, "little")
        ),
        changed(47, 55, (0).to_bytes(8, "little")),
        changed(56, 57, bytes([raw[56] ^ 1])),
        changed(len(raw) - 4, len(raw), b"\x01\x00\x00\x00"),
    ]
    signature = b"\x11" * 64
    verifier = ExpectedVerifier(funding.script_pubkey[2:], plan.signature_hash, signature)
    invalid.append(finalize_cooperative_claim(plan, signature, verifier=verifier).raw_transaction)
    for candidate in invalid:
        with pytest.raises(ValidationError):
            verify_cooperative_claim_proposal(candidate, authorization)  # type: ignore[arg-type]
    refund = UnilateralAuthorization.from_terms(terms, funding, "refund", keys=_keys(terms, case))
    with pytest.raises(ValidationError, match="only for a claim"):
        verify_cooperative_claim_proposal(raw, refund)


def test_cooperative_claim_refuses_every_transaction_policy_escape() -> None:
    case, terms, funding = _first_context()
    authorization = UnilateralAuthorization.from_terms(
        terms, funding, "claim", keys=_keys(terms, case)
    )
    signature = b"\x11" * 64
    plan = build_cooperative_claim(authorization, fee_sat=300)
    verifier = ExpectedVerifier(funding.script_pubkey[2:], plan.signature_hash, signature)
    good = tx._parse_transaction(  # noqa: SLF001 - mutate parsed bytes for adversarial policy cases
        finalize_cooperative_claim(plan, signature, verifier=verifier).raw_transaction
    )
    incoming = good.inputs[0]
    outgoing = good.outputs[0]
    mutations = [
        replace(good, version=1),
        replace(good, lock_time=1),
        replace(good, inputs=(replace(incoming, sequence=0xFFFFFFFF),)),
        replace(good, inputs=(replace(incoming, script_sig=b"\x01"),)),
        replace(
            good, inputs=(replace(incoming, prevout=replace(incoming.prevout, txid=b"\xff" * 32)),)
        ),
        replace(good, inputs=(incoming, incoming), witnesses=((signature,), (signature,))),
        replace(good, outputs=(outgoing, outgoing)),
        replace(good, outputs=(replace(outgoing, script_pubkey=b"\x51\x20" + b"\xff" * 32),)),
        replace(good, outputs=(replace(outgoing, value_sat=funding.value_sat + 1),)),
        replace(
            good,
            outputs=(
                replace(outgoing, value_sat=funding.value_sat - authorization.fee_cap_sat - 1),
            ),
        ),
        replace(good, witnesses=((signature, b"\x50"),)),  # annex
        replace(good, witnesses=((signature + b"\x00",),)),  # explicit default sighash
        replace(good, witnesses=((b"\x00" * 64,),)),
    ]
    for candidate in mutations:
        with pytest.raises(ValidationError):
            validate_cooperative_claim(candidate.serialize(), authorization, verifier=verifier)
    refund = UnilateralAuthorization.from_terms(terms, funding, "refund", keys=_keys(terms, case))
    with pytest.raises(ValidationError, match="only for a claim"):
        build_cooperative_claim(refund, fee_sat=300)
    with pytest.raises(ValidationError, match="internally inconsistent"):
        finalize_cooperative_claim(
            replace(plan, signature_hash=b"\x00" * 32), signature, verifier=verifier
        )


def test_authorization_rejects_unsupported_profile_and_wrong_funding() -> None:
    case, terms, funding = _first_context()
    keys = _keys(terms, case)
    unsupported_identity = terms.network_identity.model_copy(
        update={"consensus_profile": "bitcoin-core/v30"},
    )
    unsupported_terms = terms.model_copy(update={"network_identity": unsupported_identity})

    with pytest.raises(ValidationError, match="unsupported settlement consensus profile"):
        UnilateralAuthorization.from_terms(unsupported_terms, funding, "claim", keys=keys)
    with pytest.raises(ValidationError, match="funding value"):
        UnilateralAuthorization.from_terms(
            terms,
            replace(funding, value_sat=funding.value_sat + 1),
            "claim",
            keys=keys,
        )
    with pytest.raises(ValidationError, match="funding scriptPubKey"):
        UnilateralAuthorization.from_terms(
            terms,
            replace(funding, script_pubkey=b"\x51\x20" + b"\x00" * 32),
            "claim",
            keys=keys,
        )


def test_authorization_reconstructs_control_parity_and_binds_terms() -> None:
    case, terms, funding = _first_context()
    keys = _keys(terms, case)
    corrupted = replace(
        keys.contract,
        claim_control_block=bytes([keys.contract.claim_control_block[0] ^ 1])
        + keys.contract.claim_control_block[1:],
    )
    expected_control = keys.contract.claim_control_block
    assert corrupted.claim_control_block != expected_control
    keys.contract = corrupted
    authorization = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=keys)
    assert authorization.control_block == expected_control
    assert authorization.control_block != corrupted.claim_control_block
    with pytest.raises(TypeError):
        UnilateralAuthorization()
    with pytest.raises(TypeError):
        UnilateralAuthorization(
            path="claim", funding=funding, destination_script=b"", fee_cap_sat=0
        )
    with pytest.raises(TypeError):
        replace(authorization, control_block=corrupted.claim_control_block)

    changed_data = copy.deepcopy(case["contract_terms"])
    changed_data["invoice_binding"]["payment_hash"] = "00" * 32
    changed_terms = ContractTerms.model_validate_json(json.dumps(changed_data))

    class ChangedKeyOperations(FixtureKeyOperations):
        def musig_output_key(
            self, client: bytes, provider: bytes, _tap_tweak: bytes
        ) -> tuple[bytes, int]:
            self._require_order(client, provider)
            return b"\x11" * 32, 0

    with pytest.raises(ValidationError, match="funding scriptPubKey"):
        UnilateralAuthorization.from_terms(
            changed_terms, funding, "claim", keys=ChangedKeyOperations(changed_terms, keys.contract)
        )


def test_builder_rejects_fee_and_preimage_policy_violations() -> None:
    taproot_case, terms, funding = _first_context()
    keys = _keys(terms, taproot_case)
    claim = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=keys)
    refund = UnilateralAuthorization.from_terms(terms, funding, "refund", keys=keys)
    valid_preimage = bytes.fromhex(taproot_case["claim_preimage"])

    with pytest.raises(ValidationError, match="fee exceeds"):
        build_unilateral_spend(
            claim,
            fee_sat=claim.fee_cap_sat + 1,
            claim_preimage=valid_preimage,
        )
    for preimage in (b"\x42" * 31, b"\x42" * 33, b"\x00" * 32):
        with pytest.raises(ValidationError):
            build_unilateral_spend(claim, fee_sat=0, claim_preimage=preimage)
    with pytest.raises(ValidationError, match="does not accept"):
        build_unilateral_spend(refund, fee_sat=0, claim_preimage=valid_preimage)


@pytest.mark.parametrize(
    ("case_index", "below", "accepted"),
    [(0, 329, 330), (1, 293, 294)],
)
def test_pinned_core_v30_dust_boundaries(
    case_index: int,
    below: int,
    accepted: int,
) -> None:
    taproot_case = _load("taproot-cases-v1.json")["valid"][case_index]
    settlement_case = _load("settlement-cases-v1.json")["valid"][case_index]
    terms_data = copy.deepcopy(taproot_case["contract_terms"])
    economics = terms_data["economics"]
    if case_index == 0:
        economics.update(
            lightning_principal_sat="1000", success_fee_sat="0", contract_amount_sat="1000"
        )
    else:
        economics.update(
            contract_amount_sat="1000",
            nominal_payout_sat="1000",
            claim_fee_reserve_sat="0",
            success_fee_sat="0",
            mining_prepayment_sat="0",
            hold_invoice_sat="1000",
        )
    terms_data["invoice_binding"]["amount_msat"] = "1000000"
    terms_data["max_claim_fee_sat"] = "1000"
    terms = ContractTerms.model_validate_json(json.dumps(terms_data))
    funding = replace(_funding(settlement_case), value_sat=1000)
    keys = _keys(terms, taproot_case)
    authorization = UnilateralAuthorization.from_terms(
        terms,
        funding,
        "claim",
        keys=keys,
    )
    preimage = bytes.fromhex(taproot_case["claim_preimage"])

    with pytest.raises(ValidationError, match="dust"):
        build_unilateral_spend(
            authorization,
            fee_sat=1_000 - below,
            claim_preimage=preimage,
        )
    plan = build_unilateral_spend(
        authorization,
        fee_sat=1_000 - accepted,
        claim_preimage=preimage,
    )
    assert plan.output_value_sat == accepted


def test_finalization_rejects_unverified_or_nondefault_signature() -> None:
    taproot_case, terms, funding = _first_context()
    authorization = UnilateralAuthorization.from_terms(
        terms, funding, "claim", keys=_keys(terms, taproot_case)
    )
    plan = build_unilateral_spend(
        authorization,
        fee_sat=0,
        claim_preimage=bytes.fromhex(taproot_case["claim_preimage"]),
    )
    signature = b"\x11" * 64
    verifier = ExpectedVerifier(authorization.signer_public_key, plan.signature_hash, b"\x22" * 64)

    with pytest.raises(ValidationError, match="signature is invalid"):
        finalize_unilateral_spend(plan, signature, verifier=verifier)
    with pytest.raises(ValidationError, match="must contain 64 bytes"):
        finalize_unilateral_spend(plan, signature + b"\x00", verifier=verifier)

    with pytest.raises(TypeError):
        replace(authorization, consensus_profile="unrecognized-core-policy")

    inconsistent_plan = replace(plan, signature_hash=b"\x00" * 32)
    verifier = ExpectedVerifier(
        authorization.signer_public_key,
        inconsistent_plan.signature_hash,
        signature,
    )
    with pytest.raises(ValidationError, match="internally inconsistent"):
        finalize_unilateral_spend(inconsistent_plan, signature, verifier=verifier)


def test_raw_validation_is_strict_and_rechecks_authorization() -> None:
    taproot_case = _load("taproot-cases-v1.json")["valid"][0]
    settlement_case = _load("settlement-cases-v1.json")["valid"][0]
    artifact = settlement_case["claim"]
    terms = _terms(taproot_case)
    authorization = UnilateralAuthorization.from_terms(
        terms,
        _funding(settlement_case),
        "claim",
        keys=_keys(terms, taproot_case),
    )
    signature = bytes.fromhex(artifact["signature"])
    verifier = ExpectedVerifier(
        authorization.signer_public_key,
        bytes.fromhex(artifact["signature_hash"]),
        signature,
    )
    raw = bytes.fromhex(artifact["raw_transaction"])

    validate_unilateral_spend(raw, authorization, verifier=verifier)
    assert raw[6] == 1
    assert raw[43] == 0
    assert raw[48] == 1
    assert raw[57] == 34
    assert raw[92] == 4
    assert raw[93] == 64

    wrong_outpoint = bytearray(raw)
    wrong_outpoint[7] ^= 1
    wrong_sequence = bytearray(raw)
    wrong_sequence[44:48] = (0xFFFFFFFE).to_bytes(4, "little")
    wrong_destination = bytearray(raw)
    wrong_destination[58] = 0
    over_cap_fee = bytearray(raw)
    over_cap_fee[49:57] = (
        authorization.funding.value_sat - authorization.fee_cap_sat - 1
    ).to_bytes(8, "little")
    signature = bytes.fromhex(artifact["signature"])
    signature_start = raw.index(signature)
    explicit_default = bytearray(raw)
    explicit_default[signature_start - 1] = 65
    explicit_default[signature_start + 64 : signature_start + 64] = b"\x00"
    annex = bytearray(raw)
    annex[92] = 5
    annex[-4:-4] = b"\x01\x50"
    extra_output = bytearray(raw)
    extra_output[48] = 2
    extra_output[92:92] = (1_000).to_bytes(8, "little") + b"\x16\x00\x14" + b"\x77" * 20
    extra_input = bytearray(raw)
    extra_input[6] = 2
    extra_input[48:48] = (
        b"\xaa" * 32 + (1).to_bytes(4, "little") + b"\x00" + (0xFFFFFFFD).to_bytes(4, "little")
    )
    extra_input[-4:-4] = b"\x00"
    preimage = bytes.fromhex(taproot_case["claim_preimage"])
    wrong_preimage = raw.replace(preimage, b"\x00" * 32)
    control_block = bytes.fromhex(taproot_case["artifacts"]["claim_control_block"])
    wrong_control = raw.replace(control_block, bytes([control_block[0] ^ 1]) + control_block[1:])
    mutations = {
        "wrong version": ((3).to_bytes(4, "little", signed=True) + raw[4:], "version"),
        "non-witness encoding": (bytes.fromhex(artifact["base_transaction"]), "witness"),
        "extra input": (bytes(extra_input), "exactly one input"),
        "extra output": (bytes(extra_output), "exactly one output"),
        "wrong outpoint": (bytes(wrong_outpoint), "wrong outpoint"),
        "wrong sequence": (bytes(wrong_sequence), "sequence"),
        "wrong destination": (bytes(wrong_destination), "wrong role destination"),
        "over-cap fee": (bytes(over_cap_fee), "fee exceeds"),
        "explicit default sighash byte": (bytes(explicit_default), "64 bytes"),
        "annex": (bytes(annex), "exactly four items"),
        "wrong preimage": (wrong_preimage, "payment hash"),
        "wrong control block": (wrong_control, "control block"),
        "wrong locktime": (raw[:-4] + (1).to_bytes(4, "little"), "locktime"),
        "trailing bytes": (raw + b"\x00", "trailing bytes"),
        "truncated": (raw[:-1], "truncated"),
    }
    valid_verifications = len(verifier.calls)
    for case_name, (changed, rejection) in mutations.items():
        assert changed != raw, case_name
        with pytest.raises(ValidationError, match=rejection):
            validate_unilateral_spend(changed, authorization, verifier=verifier)
        assert len(verifier.calls) == valid_verifications, case_name


def test_max_spendable_fee_is_the_signed_cap_or_the_dust_floor() -> None:
    taproot_case, terms, funding = _first_context()
    keys = _keys(terms, taproot_case)
    claim = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=keys)
    valid_preimage = bytes.fromhex(taproot_case["claim_preimage"])
    assert max_spendable_fee(claim) == claim.fee_cap_sat
    build_unilateral_spend(claim, fee_sat=max_spendable_fee(claim), claim_preimage=valid_preimage)

    data = copy.deepcopy(taproot_case["contract_terms"])
    amount = 2_000  # below cap + dust floor: the signed cap is unreachable
    data["economics"]["lightning_principal_sat"] = str(amount - 1_000)
    data["economics"]["contract_amount_sat"] = str(amount)
    data["invoice_binding"]["amount_msat"] = str((amount - 1_000) * 1_000)
    data["max_claim_fee_sat"] = str(amount - 100)
    small_terms = ContractTerms.model_validate_json(json.dumps(data))
    small = replace(funding, value_sat=amount)
    tight = UnilateralAuthorization.from_terms(
        small_terms, small, "claim", keys=_keys(small_terms, taproot_case)
    )
    ceiling = max_spendable_fee(tight)
    assert ceiling < tight.fee_cap_sat
    build_unilateral_spend(tight, fee_sat=ceiling, claim_preimage=valid_preimage)
    with pytest.raises(ValidationError, match="dust"):
        build_unilateral_spend(tight, fee_sat=ceiling + 1, claim_preimage=valid_preimage)
