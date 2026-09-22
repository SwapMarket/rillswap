"""Opt-in real-crypto interoperability with pinned Taproot and settlement vectors."""

from __future__ import annotations

import json
import os
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from rill_core.settlement import (
    FundingOutput,
    TaprootContract,
    UnilateralAuthorization,
    build_unilateral_spend,
    finalize_unilateral_spend,
    reconstruct_taproot_contract,
    validate_unilateral_spend,
)
from rill_core.wire.messages import ContractTerms

FIXTURES = Path(__file__).parents[1] / "fixtures" / "settlement-v1"


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
