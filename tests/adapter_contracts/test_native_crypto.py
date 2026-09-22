"""Opt-in real-crypto interoperability with pinned Taproot and settlement vectors."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from rill_core.errors import ValidationError
from rill_core.recovery import inspect_recovery_plaintext
from rill_core.settlement import (
    FundingOutput,
    TaprootContract,
    UnilateralAuthorization,
    build_unilateral_spend,
    finalize_unilateral_spend,
    reconstruct_taproot_contract,
    validate_unilateral_spend,
)
from rill_core.wire.canonical import canonicalize, parse_json_strict
from rill_core.wire.hashes import funding_binding_hash
from rill_core.wire.messages import ContractTerms, FundingBinding
from rill_core.wire.types import NetworkIdentity

FIXTURES = Path(__file__).parents[1] / "fixtures" / "settlement-v1"
RECOVERY = Path(__file__).parents[1] / "fixtures" / "recovery-v1" / "initial-btc-to-ln-v1.json"


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 to run pinned native interoperability",
)
def test_pinned_native_crypto_reproduces_every_signed_unilateral_vector() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    library = os.environ["RILL_CRYPTO_LIBRARY"]
    taproot_vectors: dict[str, Any] = json.loads(
        (FIXTURES / "taproot-cases-v1.json").read_text(),
    )
    settlement_vectors: dict[str, Any] = json.loads(
        (FIXTURES / "settlement-cases-v1.json").read_text(),
    )
    by_id = {case["id"]: case for case in taproot_vectors["valid"]}
    assert {case["id"] for case in settlement_vectors["valid"]} == set(by_id)

    with Context(library_path=library) as crypto:
        for settlement_case in settlement_vectors["valid"]:
            taproot_case = by_id[settlement_case["taproot_vector"]]
            terms = ContractTerms.model_validate_json(
                json.dumps(taproot_case["contract_terms"]),
            )
            contract = reconstruct_taproot_contract(terms, keys=crypto)
            for field in fields(TaprootContract):
                actual = getattr(contract, field.name)
                expected = taproot_case["artifacts"][field.name]
                assert actual == (expected if isinstance(actual, int) else bytes.fromhex(expected))

            funding_case = settlement_case["synthetic_funding"]
            funding = FundingOutput(
                txid=bytes.fromhex(funding_case["txid"]),
                output_index=funding_case["vout"],
                value_sat=int(funding_case["value_sat"]),
                script_pubkey=bytes.fromhex(funding_case["script_pubkey"]),
            )
            for path in ("claim", "refund"):
                artifact = settlement_case[path]
                role = terms.claimant if path == "claim" else terms.refund_party
                authorization = UnilateralAuthorization.from_terms(
                    terms,
                    funding,
                    path,
                    keys=crypto,
                )
                plan = build_unilateral_spend(
                    authorization,
                    fee_sat=int(artifact["fee_sat"]),
                    claim_preimage=(
                        bytes.fromhex(taproot_case["claim_preimage"]) if path == "claim" else None
                    ),
                )
                assert plan.signature_hash.hex() == artifact["signature_hash"]
                fixture_signature = bytes.fromhex(artifact["signature"])
                crypto.schnorr_verify(
                    authorization.signer_public_key,
                    plan.signature_hash,
                    fixture_signature,
                )
                secret = bytes.fromhex(
                    taproot_case["fixture_keys"][f"{role}_contract_secret_key"],
                )
                assert crypto.public_key(secret)[1:] == authorization.signer_public_key
                signature = crypto.schnorr_sign(
                    secret,
                    plan.signature_hash,
                    bytes.fromhex(artifact["auxiliary_random"]),
                )
                assert signature == fixture_signature
                validated = finalize_unilateral_spend(plan, signature, verifier=crypto)
                assert validated.raw_transaction.hex() == artifact["raw_transaction"]
                assert validated.txid == artifact["txid"]
                assert validated.wtxid == artifact["wtxid"]
                assert validated.weight == artifact["weight"]
                assert validated.vsize == artifact["vsize"]
                assert (
                    validate_unilateral_spend(
                        validated.raw_transaction,
                        authorization,
                        verifier=crypto,
                    )
                    == validated
                )


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 to run pinned native interoperability",
)
def test_initial_recovery_static_commitments_with_native_crypto() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    record = json.loads(RECOVERY.read_bytes())
    expected_network = NetworkIdentity.model_validate(record["network_identity"])
    canonical = canonicalize(parse_json_strict(RECOVERY.read_bytes()))
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        report = inspect_recovery_plaintext(canonical, expected_network, crypto=crypto)
    assert report.recorded_binding_count == 0
    assert report.first_refund_eligible_height == 1101
    assert "export durability, age decryptability, and snapshot freshness" in report.unproven


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 to run pinned native interoperability",
)
def test_native_signatures_check_static_replacement_history_without_chain_claim() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    package = json.loads(RECOVERY.read_bytes())
    context = package["verification_context"]
    network = NetworkIdentity.model_validate(package["network_identity"])
    client_secret = (2).to_bytes(32, "big")
    provider_secret = (3).to_bytes(32, "big")
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        assert crypto.public_key(client_secret)[1:].hex() == context["client_session_xonly_key"]
        assert crypto.public_key(provider_secret)[1:].hex() == context["provider_session_xonly_key"]
        for revision, txid, predecessor in ((0, "aa" * 32, None), (1, "bb" * 32, "aa" * 32)):
            binding = {
                "contract_hash": package["contract_hash"],
                "funding_attempt_id": "cc" * 32,
                "binding_revision": revision,
                "funder_role": "client",
                "lineage_anchor_txid": "dd" * 32,
                "lineage_anchor_vout": 1,
                "funding_txid": txid,
                "contract_vout": revision,
                "contract_value_sat": package["contract_terms"]["economics"]["contract_amount_sat"],
                "contract_script_pubkey": package["taproot_contract"]["script_pubkey"],
                "replaces_txid": predecessor,
                "created_at": 1700000200 + revision,
            }
            digest = funding_binding_hash(FundingBinding.model_validate(binding))
            signature = crypto.schnorr_sign(client_secret, digest, b"\x33" * 32)
            package["funding_history"].append(
                {
                    "binding": binding,
                    "funder_session_signature": signature.hex(),
                }
            )
        plaintext = canonicalize(parse_json_strict(json.dumps(package).encode()))
        report = inspect_recovery_plaintext(plaintext, network, crypto=crypto)
        assert report.recorded_binding_count == 2
        assert "funding transactions, conflicts, UTXOs, and chain maturity" in report.unproven
        wrong_signer = copy.deepcopy(package)
        second = wrong_signer["funding_history"][1]
        digest = funding_binding_hash(FundingBinding.model_validate(second["binding"]))
        second["funder_session_signature"] = crypto.schnorr_sign(
            provider_secret, digest, b"\x33" * 32
        ).hex()
        with pytest.raises(ValidationError):
            inspect_recovery_plaintext(
                canonicalize(parse_json_strict(json.dumps(wrong_signer).encode())),
                network,
                crypto=crypto,
            )
