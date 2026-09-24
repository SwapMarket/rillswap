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
from rill_core.recovery import (
    construct_selected_recovery_claim,
    construct_selected_recovery_refund,
    inspect_recovery_plaintext,
    inspect_recovery_selected_funding_binding,
)
from rill_core.settlement import (
    FundingOutput,
    SignedFundingBinding,
    TaprootContract,
    UnilateralAuthorization,
    build_unilateral_spend,
    finalize_unilateral_spend,
    reconstruct_taproot_contract,
    validate_unilateral_spend,
    verify_static_signed_funding_binding_history,
)
from rill_core.wire.canonical import canonicalize, parse_json_strict
from rill_core.wire.envelope_authentication import verify_static_signed_envelope
from rill_core.wire.handshake_authentication import verify_static_handshake_transcript
from rill_core.wire.hashes import funding_binding_hash, unsigned_envelope_hash
from rill_core.wire.messages import (
    ContractTerms,
    Envelope,
    FundingBinding,
    HandshakeAccept,
    HandshakeInit,
)
from rill_core.wire.types import NetworkIdentity

FIXTURES = Path(__file__).parents[1] / "fixtures" / "settlement-v1"
RECOVERY = Path(__file__).parents[1] / "fixtures" / "recovery-v1" / "initial-btc-to-ln-v1.json"
LN_RECOVERY = (
    Path(__file__).parents[1]
    / "fixtures"
    / "recovery-v1"
    / "initial-ln-to-btc-no-prepayment-v1.json"
)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 to run pinned native interoperability",
)
def test_pinned_rs001_client_confirm_envelope_signature_with_native_crypto() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    # RS-001 authentication/cases-v1.json regtest-btc-to-ln confirmed envelope.
    network = NetworkIdentity.model_validate_json(
        json.dumps(
            {
                "family": "bitcoin",
                "name": "regtest",
                "genesis_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                "signet_challenge": None,
                "consensus_profile": "bitcoin-core-v30.0-regtest-default",
                "deployment_namespace": "rillswap-e2e-v1",
            }
        )
    )
    sender = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    signed: dict[str, Any] = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": "btc-to-ln/v1",
        "network_identity": network.model_dump(mode="json"),
        "session_id": "10" * 32,
        "message_id": "13" * 32,
        "sender_session_key": sender,
        "sequence": 1,
        "in_reply_to": "14" * 32,
        "contract_hash": None,
        "message_type": "handshake_confirm",
        "payload": {
            "handshake_hash": "5fbb869c7f2df70b939d7c370478c06f5819f287351c1d19b4921fe95aa156c8",
            "session_id": "10" * 32,
            "client_session_xonly_key": sender,
            "provider_session_xonly_key": (
                "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
            ),
        },
        "required_features": [],
        "extensions": {},
        "signature": (
            "d8a7339977e4673e215e61339386e8208b0c6d1ecbe01621e985fe3d6c1399"
            "384f7b321a32c9ddf5363cb484e78561b3fb6aa65e686a076fcf95c7263a13c3bb"
        ),
    }
    envelope = Envelope.model_validate_json(json.dumps(signed))
    expected_digest = bytes.fromhex(
        "eef562447f6afa99cc8e9c949c72b37613488e1b061a01207fa51bca349eb20b"
    )
    assert unsigned_envelope_hash(envelope) == expected_digest
    context = json.loads(RECOVERY.read_text())["verification_context"]
    initiation = context["handshake_init"]
    acceptance = context["handshake_accept"]
    common: dict[str, Any] = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": "btc-to-ln/v1",
        "network_identity": network.model_dump(mode="json"),
        "session_id": initiation["session_id"],
        "contract_hash": None,
        "required_features": [],
        "extensions": {},
        "signature": None,
    }
    init_envelope = {
        **common,
        "message_type": "handshake_init",
        "sequence": 0,
        "message_id": "12" * 32,
        "in_reply_to": None,
        "sender_session_key": initiation["client_session_xonly_key"],
        "payload": initiation,
    }
    accept_envelope = {
        **common,
        "message_type": "handshake_accept",
        "sequence": 0,
        "message_id": "14" * 32,
        "in_reply_to": "12" * 32,
        "sender_session_key": acceptance["provider_session_xonly_key"],
        "payload": {
            "accept": acceptance,
            "provider_identity_signature": context["provider_identity_signature"],
        },
    }

    def check() -> bytes:
        return verify_static_signed_envelope(
            json.dumps(signed).encode(),
            expected_session_id="10" * 32,
            expected_profile="btc-to-ln/v1",
            expected_network=network,
            expected_sender_key=sender,
            supported_features=frozenset(),
            crypto=crypto,
        )

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        assert check() == expected_digest
        assert verify_static_handshake_transcript(
            json.dumps(init_envelope).encode(),
            json.dumps(accept_envelope).encode(),
            json.dumps(signed).encode(),
            expected_provider_identity=initiation["expected_provider_identity_xonly_key"],
            expected_profile="btc-to-ln/v1",
            expected_network=network,
            supported_features=frozenset(),
            supported_encryption_suites=frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
            supported_capabilities=frozenset({"core/v1", "recovery/v1"}),
            crypto=crypto,
        ) == bytes.fromhex(context["handshake_hash"])
        signed["payload"]["session_id"] = "20" * 32
        with pytest.raises(ValidationError, match="invalid static signed envelope"):
            check()
        signed["payload"]["session_id"] = "10" * 32
        signed["signature"] = "00" * 64
        with pytest.raises(ValidationError, match="invalid static signed envelope"):
            check()


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
def test_initial_ln_recovery_preimage_and_signatures_with_native_crypto() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    original = json.loads(LN_RECOVERY.read_bytes())
    network = NetworkIdentity.model_validate(original["network_identity"])
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        report = inspect_recovery_plaintext(
            canonicalize(parse_json_strict(LN_RECOVERY.read_bytes())), network, crypto=crypto
        )
        assert report.profile_id == "ln-to-btc/v1"
        assert report.recorded_binding_count == 0
        assert "export durability, age decryptability, and snapshot freshness" in report.unproven

        for area, field, bad in (
            ("monotonic_knowledge", "preimage", "00" * 32),
            ("verification_context", "provider_identity_signature", "00" * 64),
            ("verification_context", "provider_terms_signature", "00" * 64),
            ("verification_context", "client_acceptance_signature", "00" * 64),
        ):
            altered = copy.deepcopy(original)
            altered[area][field] = bad
            with pytest.raises(ValidationError):
                inspect_recovery_plaintext(
                    canonicalize(parse_json_strict(json.dumps(altered).encode())),
                    network,
                    crypto=crypto,
                )


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
        selected = inspect_recovery_selected_funding_binding(
            plaintext,
            network,
            funding_attempt_id="cc" * 32,
            binding_revision=1,
            crypto=crypto,
        )
        assert selected.funding_txid == "bb" * 32
        assert selected.contract_vout == 1
        assert package["user_secret"]["contract_secret_key"] not in repr(selected)
        terms = ContractTerms.model_validate_json(json.dumps(package["contract_terms"]))
        funding = FundingOutput(
            bytes.fromhex(selected.funding_txid),
            selected.contract_vout,
            int(selected.contract_value_sat),
            bytes.fromhex(selected.contract_script_pubkey),
        )
        raw_refund = construct_selected_recovery_refund(
            plaintext,
            network,
            funding_attempt_id="cc" * 32,
            binding_revision=1,
            live_funding=funding,
            sampled_tip_height=terms.refund_lock_height + 1,
            fee_sat=200,
            auxiliary_random=b"\x55" * 32,
            crypto=crypto,
        )
        refund_authorization = UnilateralAuthorization.from_terms(
            terms,
            funding,
            "refund",
            keys=crypto,
        )
        parsed_refund = validate_unilateral_spend(raw_refund, refund_authorization, verifier=crypto)
        assert parsed_refund.fee_sat == 200
        assert parsed_refund.raw_transaction == raw_refund
        with pytest.raises(ValidationError, match="recovery claim preparation refused"):
            construct_selected_recovery_claim(
                plaintext,
                network,
                funding_attempt_id="cc" * 32,
                binding_revision=1,
                live_funding=funding,
                sampled_tip_height=100,
                sampled_confirmations=2,
                fee_sat=200,
                auxiliary_random=b"\x55" * 32,
                crypto=crypto,
            )
        with pytest.raises(ValidationError, match="recovery refund construction refused"):
            construct_selected_recovery_refund(
                plaintext,
                network,
                funding_attempt_id="cc" * 32,
                binding_revision=1,
                live_funding=funding,
                sampled_tip_height=terms.refund_lock_height,
                fee_sat=200,
                auxiliary_random=b"\x55" * 32,
                crypto=crypto,
            )
        verify_static_signed_funding_binding_history(
            terms=terms,
            handshake_init=HandshakeInit.model_validate_json(json.dumps(context["handshake_init"])),
            handshake_accept=HandshakeAccept.model_validate_json(
                json.dumps(context["handshake_accept"])
            ),
            provider_identity_signature=context["provider_identity_signature"],
            provider_terms_signature=context["provider_terms_signature"],
            client_acceptance_signature=context["client_acceptance_signature"],
            signed_bindings=tuple(
                SignedFundingBinding(
                    FundingBinding.model_validate_json(json.dumps(item["binding"])),
                    item["funder_session_signature"],
                )
                for item in package["funding_history"]
            ),
            expected_provider_identity=terms.provider_identity_key,
            expected_network=network,
            crypto=crypto,
        )
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


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 to run pinned native interoperability",
)
def test_real_crypto_provider_funder_signed_context_stays_static_only() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    document = json.loads(LN_RECOVERY.read_bytes())
    context = document["verification_context"]
    terms = ContractTerms.model_validate_json(json.dumps(document["contract_terms"]))
    network = NetworkIdentity.model_validate(document["network_identity"])
    provider_secret = (9).to_bytes(32, "big")  # Pinned synthetic test-only session key.
    wrong_secret = (2).to_bytes(32, "big")
    binding = FundingBinding.model_validate_json(
        json.dumps(
            {
                "contract_hash": document["contract_hash"],
                "funding_attempt_id": "cc" * 32,
                "binding_revision": 0,
                "funder_role": "provider",
                "lineage_anchor_txid": "dd" * 32,
                "lineage_anchor_vout": 1,
                "funding_txid": "aa" * 32,
                "contract_vout": 0,
                "contract_value_sat": terms.economics.contract_amount_sat,
                "contract_script_pubkey": document["taproot_contract"]["script_pubkey"],
                "replaces_txid": None,
                "created_at": 1_700_000_200,
            }
        )
    )
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        assert crypto.public_key(provider_secret)[1:].hex() == context["provider_session_xonly_key"]

        def verify(signer: bytes) -> None:
            signature = crypto.schnorr_sign(signer, funding_binding_hash(binding), b"\x31" * 32)
            verify_static_signed_funding_binding_history(
                terms=terms,
                handshake_init=HandshakeInit.model_validate_json(
                    json.dumps(context["handshake_init"])
                ),
                handshake_accept=HandshakeAccept.model_validate_json(
                    json.dumps(context["handshake_accept"])
                ),
                provider_identity_signature=context["provider_identity_signature"],
                provider_terms_signature=context["provider_terms_signature"],
                client_acceptance_signature=context["client_acceptance_signature"],
                signed_bindings=(SignedFundingBinding(binding, signature.hex()),),
                expected_provider_identity=terms.provider_identity_key,
                expected_network=network,
                crypto=crypto,
            )

        verify(provider_secret)
        document["funding_history"].append(
            {
                "binding": binding.model_dump(mode="json"),
                "funder_session_signature": crypto.schnorr_sign(
                    provider_secret,
                    funding_binding_hash(binding),
                    b"\x31" * 32,
                ).hex(),
            }
        )
        plaintext = canonicalize(parse_json_strict(json.dumps(document).encode()))
        funding = FundingOutput(
            bytes.fromhex(binding.funding_txid),
            binding.contract_vout,
            int(binding.contract_value_sat),
            bytes.fromhex(binding.contract_script_pubkey),
        )
        with pytest.raises(ValidationError, match="recovery refund construction refused"):
            construct_selected_recovery_refund(
                plaintext,
                network,
                funding_attempt_id="cc" * 32,
                binding_revision=0,
                live_funding=funding,
                sampled_tip_height=terms.refund_lock_height + 1,
                fee_sat=200,
                auxiliary_random=b"\x55" * 32,
                crypto=crypto,
            )
        claim = construct_selected_recovery_claim(
            plaintext,
            network,
            funding_attempt_id="cc" * 32,
            binding_revision=0,
            live_funding=funding,
            sampled_tip_height=100,
            sampled_confirmations=2,
            fee_sat=200,
            auxiliary_random=b"\x55" * 32,
            crypto=crypto,
        )
        preimage = bytes.fromhex(document["monotonic_knowledge"]["preimage"])
        assert preimage in claim
        claim_authorization = UnilateralAuthorization.from_terms(
            terms,
            funding,
            "claim",
            keys=crypto,
        )
        parsed = validate_unilateral_spend(claim, claim_authorization, verifier=crypto)
        assert parsed.fee_sat == 200
        assert parsed.raw_transaction == claim
        with pytest.raises(ValidationError, match="invalid static signed funding declaration"):
            verify(wrong_secret)
