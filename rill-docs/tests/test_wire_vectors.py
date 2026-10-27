from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
import rfc8785

from tests.test_schemas import load_json, schema_registry
from tests.vendor.bip340_reference import public_key, sign, tagged_hash, verify

ROOT = Path(__file__).parents[1]
AUTHENTICATION_PATH = ROOT / "vectors" / "authentication" / "cases-v1.json"
ECONOMICS_PATH = ROOT / "vectors" / "economics" / "cases-v1.json"
RUMOR_PATH = ROOT / "vectors" / "wire" / "nostr-rumor-experimental-1.json"
TRANSPORT_POW_PATH = ROOT / "vectors" / "wire" / "nostr-transport-pow-v1.json"


def test_private_regtest_nip59_rumor_binding_preserves_canonical_envelope() -> None:
    """Pin the experimental NIP-01 rumor ID without changing RS-001 bytes."""
    vector = load_json(RUMOR_PATH)
    assert vector["vector_version"] == "nostr-rumor-experimental-1"
    assert vector["source_envelope_vector"] == (
        "vectors/authentication/cases-v1.json#valid[0].confirm_envelope.object"
    )
    envelope = load_json(AUTHENTICATION_PATH)["valid"][0]["confirm_envelope"]["object"]
    content_bytes = rfc8785.dumps(envelope)
    assert len(content_bytes) == vector["content_utf8_length"]
    assert hashlib.sha256(content_bytes).hexdigest() == vector["content_utf8_sha256"]
    assert vector["pubkey"] == envelope["sender_session_key"]
    assert envelope["protocol"] == "rillswap"
    assert envelope["wire_version"] == "1"
    assert vector["kind"] == 21417
    assert vector["tags"] == [["rillswap", "nostr-experimental-1"]]
    rumor = {
        "id": vector["id"],
        "pubkey": vector["pubkey"],
        "created_at": vector["created_at"],
        "kind": vector["kind"],
        "tags": vector["tags"],
        "content": content_bytes.decode("utf-8"),
    }
    assert set(rumor) == {"id", "pubkey", "created_at", "kind", "tags", "content"}
    nip01_bytes = json.dumps(
        [
            0,
            rumor["pubkey"],
            rumor["created_at"],
            rumor["kind"],
            rumor["tags"],
            rumor["content"],
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert hashlib.sha256(nip01_bytes).hexdigest() == rumor["id"]
    altered = [
        0,
        rumor["pubkey"],
        rumor["created_at"],
        rumor["kind"],
        [],
        rumor["content"],
    ]
    assert (
        hashlib.sha256(json.dumps(altered, separators=(",", ":")).encode()).hexdigest()
        != (rumor["id"])
    )


def _artifact_is_valid(artifact: dict[str, Any]) -> bool:
    canonical = rfc8785.dumps(artifact["object"])
    if canonical.decode() != artifact["canonical_utf8"]:
        return False
    digest = tagged_hash(artifact["tag"], canonical)
    if digest.hex() != artifact["tagged_hash"]:
        return False
    if "signature" not in artifact:
        return True
    secret_key = bytes.fromhex(artifact["signer_secret_key"])
    signer = bytes.fromhex(artifact["signer_xonly_key"])
    auxiliary = bytes.fromhex(artifact["auxiliary_random"])
    signature = bytes.fromhex(artifact["signature"])
    return (
        public_key(secret_key) == signer
        and sign(digest, secret_key, auxiliary) == signature
        and verify(digest, signer, signature)
    )


def _confirm_envelope_is_valid(artifact: dict[str, Any]) -> bool:
    unsigned = dict(artifact["object"])
    signature_hex = unsigned.pop("signature")
    canonical = rfc8785.dumps(unsigned)
    digest = tagged_hash(artifact["tag"], canonical)
    signer = bytes.fromhex(artifact["signer_xonly_key"])
    signature = bytes.fromhex(artifact["signature"])
    secret_key = bytes.fromhex(artifact["signer_secret_key"])
    auxiliary = bytes.fromhex(artifact["auxiliary_random"])
    return (
        signature_hex == artifact["signature"]
        and canonical.decode() == artifact["canonical_unsigned_utf8"]
        and digest.hex() == artifact["tagged_hash"]
        and public_key(secret_key) == signer
        and sign(digest, secret_key, auxiliary) == signature
        and verify(digest, signer, signature)
    )


def _authentication_context_is_valid(case: dict[str, Any]) -> bool:
    initiation_artifact = case["handshake_init"]
    acceptance_artifact = case["handshake_accept"]
    transcript_artifact = case["transcript"]
    confirm = case["handshake_confirm"]["object"]
    envelope_artifact = case["confirm_envelope"]
    initiation = initiation_artifact["object"]
    acceptance = acceptance_artifact["object"]

    echoed_fields = (
        "protocol",
        "wire_version",
        "profile_id",
        "network_identity",
        "session_id",
        "client_challenge",
        "client_session_xonly_key",
    )
    if any(acceptance[field] != initiation[field] for field in echoed_fields):
        return False
    initiation_hash = tagged_hash(
        "RillSwap/handshake-init/v1",
        rfc8785.dumps(initiation),
    ).hex()
    if acceptance["handshake_init_hash"] != initiation_hash:
        return False
    if (
        acceptance["provider_identity_xonly_key"]
        != initiation["expected_provider_identity_xonly_key"]
    ):
        return False
    if (
        acceptance["selected_encryption_suite"]
        not in initiation["requested_encryption_suites"]
    ):
        return False
    if not set(acceptance["selected_capabilities"]).issubset(
        initiation["requested_capabilities"],
    ):
        return False
    if acceptance["required_features"] != initiation["required_features"]:
        return False

    expected_transcript = {"accept": acceptance, "init": initiation}
    transcript_canonical = rfc8785.dumps(expected_transcript)
    transcript_digest = tagged_hash(transcript_artifact["tag"], transcript_canonical)
    if (
        transcript_artifact["object"] != expected_transcript
        or transcript_artifact["canonical_utf8"] != transcript_canonical.decode()
        or transcript_artifact["tagged_hash"] != transcript_digest.hex()
    ):
        return False
    if confirm["handshake_hash"] != transcript_digest.hex():
        return False
    if any(
        confirm[field] != acceptance[field]
        for field in (
            "session_id",
            "client_session_xonly_key",
            "provider_session_xonly_key",
        )
    ):
        return False
    envelope = envelope_artifact["object"]
    return (
        envelope["payload"] == confirm
        and envelope["sender_session_key"] == confirm["client_session_xonly_key"]
        and envelope["session_id"] == initiation["session_id"]
        and envelope["profile_id"] == initiation["profile_id"]
        and envelope["network_identity"] == initiation["network_identity"]
        and envelope["message_type"] == "handshake_confirm"
        and envelope["sequence"] == 1
        and envelope["contract_hash"] is None
    )


def _authentication_case_is_valid(case: dict[str, Any]) -> bool:
    initiation_artifact = case["handshake_init"]
    acceptance_artifact = case["handshake_accept"]
    transcript_artifact = case["transcript"]
    envelope_artifact = case["confirm_envelope"]
    initiation = initiation_artifact["object"]
    acceptance = acceptance_artifact["object"]
    return (
        initiation_artifact["tag"] == "RillSwap/handshake-init/v1"
        and acceptance_artifact["tag"] == "RillSwap/handshake/v1"
        and transcript_artifact["tag"] == "RillSwap/transcript/v1"
        and envelope_artifact["tag"] == "RillSwap/envelope/v1"
        and acceptance_artifact["signer_xonly_key"]
        == initiation["expected_provider_identity_xonly_key"]
        == acceptance["provider_identity_xonly_key"]
        and envelope_artifact["signer_xonly_key"]
        == initiation["client_session_xonly_key"]
        and _artifact_is_valid(initiation_artifact)
        and _artifact_is_valid(acceptance_artifact)
        and _artifact_is_valid(transcript_artifact)
        and _confirm_envelope_is_valid(envelope_artifact)
        and _authentication_context_is_valid(case)
    )


def _economic_semantics_are_valid(terms: dict[str, Any]) -> bool:
    invoice_msat = int(terms["invoice_binding"]["amount_msat"])
    economics = terms["economics"]
    first_refund_block = terms["refund_lock_height"] + 1
    timing = terms["timing_policy"]
    if terms["profile_id"] == "btc-to-ln/v1":
        principal = int(economics["lightning_principal_sat"])
        fee = int(economics["success_fee_sat"])
        contract = int(economics["contract_amount_sat"])
        return (
            (terms["claimant"], terms["refund_party"]) == ("provider", "client")
            and principal > 0
            and contract > 0
            and principal + fee == contract
            and invoice_msat == principal * 1_000
            and timing["max_outgoing_htlc_expiry_height"]
            + timing["learn_and_claim_blocks"]
            < first_refund_block
        )
    contract = int(economics["contract_amount_sat"])
    payout = int(economics["nominal_payout_sat"])
    reserve = int(economics["claim_fee_reserve_sat"])
    fee = int(economics["success_fee_sat"])
    prepayment = int(economics["mining_prepayment_sat"])
    hold = int(economics["hold_invoice_sat"])
    feature_committed = (
        prepayment == 0
        or "org.rillswap/mining-prepayment/v1" in terms["required_features"]
    )
    return (
        (terms["claimant"], terms["refund_party"]) == ("client", "provider")
        and contract > 0
        and payout > 0
        and payout + reserve == contract
        and 0 <= prepayment <= fee
        and contract + fee - prepayment == hold
        and invoice_msat == hold * 1_000
        and feature_committed
        and first_refund_block + timing["refund_and_ln_resolution_blocks"]
        < timing["min_incoming_htlc_expiry_height"]
    )


def _economic_case_is_valid(
    case: dict[str, Any],
    authentication_by_profile: dict[str, dict[str, Any]],
) -> bool:
    terms_artifact = case["contract_terms"]
    provider_artifact = case["provider_terms"]
    acceptance_artifact = case["client_acceptance"]
    if not all(
        _artifact_is_valid(artifact)
        for artifact in (terms_artifact, provider_artifact, acceptance_artifact)
    ):
        return False
    terms = terms_artifact["object"]
    provider_terms = provider_artifact["object"]
    acceptance = acceptance_artifact["object"]
    authentication = authentication_by_profile[case["profile_id"]]
    transcript_hash = authentication["transcript"]["tagged_hash"]
    init = authentication["handshake_init"]["object"]
    accept = authentication["handshake_accept"]["object"]
    return (
        terms_artifact["tag"] == "RillSwap/contract/v1"
        and provider_artifact["tag"] == "RillSwap/provider-terms/v1"
        and acceptance_artifact["tag"] == "RillSwap/client-acceptance/v1"
        and provider_artifact["signer_xonly_key"] == terms["provider_identity_key"]
        and acceptance_artifact["signer_xonly_key"]
        == acceptance["client_session_xonly_key"]
        and _economic_semantics_are_valid(terms)
        and provider_terms["contract_terms"] == terms
        and provider_terms["contract_hash"] == terms_artifact["tagged_hash"]
        and acceptance["contract_hash"] == terms_artifact["tagged_hash"]
        and provider_terms["handshake_hash"] == transcript_hash
        and acceptance["handshake_hash"] == transcript_hash
        and acceptance["session_id"] == init["session_id"]
        and acceptance["client_session_xonly_key"] == init["client_session_xonly_key"]
        and acceptance["provider_session_xonly_key"]
        == accept["provider_session_xonly_key"]
        and terms["profile_id"] == init["profile_id"]
        and terms["network_identity"] == init["network_identity"]
        and terms["provider_identity_key"] == accept["provider_identity_xonly_key"]
        and set(terms["required_features"]).issubset(init["required_features"])
        and set(terms["required_features"]).issubset(accept["required_features"])
    )


def _apply_replacement(base: dict[str, Any], invalid: dict[str, Any]) -> dict[str, Any]:
    changed = copy.deepcopy(base)
    target: Any = changed
    components = invalid["path"].removeprefix("/").split("/")
    for component in components[:-1]:
        target = target[component]
    target[components[-1]] = invalid["replacement"]
    return changed


def _resign_with_unrelated_key(artifact: dict[str, Any]) -> None:
    secret_key = (99).to_bytes(32, "big")
    artifact["signer_secret_key"] = secret_key.hex()
    artifact["signer_xonly_key"] = public_key(secret_key).hex()
    artifact["signature"] = sign(
        bytes.fromhex(artifact["tagged_hash"]),
        secret_key,
        bytes.fromhex(artifact["auxiliary_random"]),
    ).hex()


def _validator(schema_name: str) -> jsonschema.Draft202012Validator:
    registry, schemas = schema_registry()
    schema = next(
        schema for path, schema in schemas.items() if path.name == schema_name
    )
    return jsonschema.Draft202012Validator(schema, registry=registry)


def test_authentication_vectors_have_valid_canonical_hashes_and_signatures() -> None:
    vectors = load_json(AUTHENTICATION_PATH)
    for case in vectors["valid"]:
        assert _authentication_case_is_valid(case), case["id"]


def test_authentication_vector_objects_match_wire_schemas() -> None:
    vectors = load_json(AUTHENTICATION_PATH)
    handshake_validator = _validator("handshake-v1.schema.json")
    envelope_validator = _validator("envelope-v1.schema.json")
    for case in vectors["valid"]:
        handshake_validator.validate(case["handshake_init"]["object"])
        handshake_validator.validate(
            {
                "accept": case["handshake_accept"]["object"],
                "provider_identity_signature": case["handshake_accept"]["signature"],
            },
        )
        handshake_validator.validate(case["handshake_confirm"]["object"])
        envelope_validator.validate(case["confirm_envelope"]["object"])


def test_authentication_invalid_mutations_are_rejected() -> None:
    vectors = load_json(AUTHENTICATION_PATH)
    by_id = {case["id"]: case for case in vectors["valid"]}
    for invalid in vectors["invalid"]:
        changed = _apply_replacement(by_id[invalid["base"]], invalid)
        assert not _authentication_case_is_valid(changed), invalid["id"]
        if invalid["reason"] in {
            "handshake-init-hash-mismatch",
            "unrequested-encryption-suite",
            "provider-identity-mismatch",
            "handshake-transcript-mismatch",
        }:
            assert not _authentication_context_is_valid(changed), invalid["id"]
        elif invalid["reason"] == "invalid-provider-signature":
            assert not _artifact_is_valid(changed["handshake_accept"]), invalid["id"]
        else:
            envelope = changed["confirm_envelope"]
            assert not _confirm_envelope_is_valid(envelope), invalid["id"]
            assert not verify(
                bytes.fromhex(envelope["tagged_hash"]),
                bytes.fromhex(envelope["signer_xonly_key"]),
                bytes.fromhex(envelope["signature"]),
            ), invalid["id"]


def test_authentication_rejects_valid_signature_from_unrelated_key() -> None:
    case = copy.deepcopy(load_json(AUTHENTICATION_PATH)["valid"][0])
    _resign_with_unrelated_key(case["handshake_accept"])
    assert _artifact_is_valid(case["handshake_accept"])
    assert not _authentication_case_is_valid(case)


def test_economic_vectors_have_valid_commitments_and_signatures() -> None:
    authentication = load_json(AUTHENTICATION_PATH)
    authentication_by_profile = {
        case["profile_id"]: case for case in authentication["valid"]
    }
    vectors = load_json(ECONOMICS_PATH)
    terms_validator = _validator("contract-terms-v1.schema.json")
    for case in vectors["valid"]:
        terms_validator.validate(case["contract_terms"]["object"])
        assert _economic_case_is_valid(case, authentication_by_profile), case["id"]


def test_economic_invalid_mutations_are_rejected() -> None:
    authentication = load_json(AUTHENTICATION_PATH)
    authentication_by_profile = {
        case["profile_id"]: case for case in authentication["valid"]
    }
    vectors = load_json(ECONOMICS_PATH)
    by_id = {case["id"]: case for case in vectors["valid"]}
    for invalid in vectors["invalid"]:
        changed = _apply_replacement(by_id[invalid["base"]], invalid)
        assert not _economic_case_is_valid(changed, authentication_by_profile), invalid[
            "id"
        ]
        if invalid["reason"] in {
            "contract-must-equal-principal-plus-success-fee",
            "invoice-must-equal-principal",
            "hold-invoice-equation-mismatch",
            "mining-prepayment-feature-not-committed",
            "profile-role-mismatch",
            "strict-refund-margin-required",
        }:
            assert not _economic_semantics_are_valid(
                changed["contract_terms"]["object"],
            ), invalid["id"]
        elif invalid["reason"] == "contract-hash-mismatch":
            provider_terms = changed["provider_terms"]["object"]
            terms = changed["contract_terms"]
            assert (
                provider_terms["contract_hash"]
                != tagged_hash(
                    "RillSwap/contract/v1",
                    rfc8785.dumps(terms["object"]),
                ).hex()
            )
        else:
            assert not _artifact_is_valid(changed["client_acceptance"]), invalid["id"]


def test_economics_rejects_valid_acceptance_from_unrelated_key() -> None:
    authentication = load_json(AUTHENTICATION_PATH)
    authentication_by_profile = {
        case["profile_id"]: case for case in authentication["valid"]
    }
    case = copy.deepcopy(load_json(ECONOMICS_PATH)["valid"][0])
    _resign_with_unrelated_key(case["client_acceptance"])
    assert _artifact_is_valid(case["client_acceptance"])
    assert not _economic_case_is_valid(case, authentication_by_profile)


def _transport_work(event: dict[str, Any]) -> int | None:
    """RS-006 transport work: recomputed-ID zero bits capped by one committed target."""
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    recomputed = hashlib.sha256(serialized).hexdigest()
    if recomputed != event["id"]:
        return None  # a claimed ID proves nothing
    nonces = [tag for tag in event["tags"] if tag[0] == "nonce"]
    if len(nonces) != 1 or len(nonces[0]) != 3:
        return 0
    target = nonces[0][2]
    if not target.isdigit() or str(int(target)) != target or int(target) > 256:
        return 0
    return min(256 - int(recomputed, 16).bit_length(), int(target))


def test_transport_work_counts_only_committed_recomputed_leading_zero_bits() -> None:
    vector = load_json(TRANSPORT_POW_PATH)
    assert vector["vector_version"] == "nostr-transport-pow-v1"
    required = vector["required_bits"]
    assert vector["announcement_extensions"] == {"rillswap/transport-pow": {"bits": required}}
    assert vector["init_extensions"] == vector["announcement_extensions"]
    secret = bytes.fromhex(vector["wrapper_secret_key_fixture_only"])
    names = set()
    for case in vector["cases"]:
        event = case["event"]
        names.add(case["name"])
        assert event["kind"] == 1059
        assert event["tags"][0] == ["p", vector["recipient_xonly_key"]]
        assert [tag for tag in event["tags"] if tag[0] == "p"] == [event["tags"][0]]
        assert event["pubkey"] == public_key(secret).hex()
        proven = _transport_work(event)
        assert proven == case["proven_work"], case["name"]
        assert (proven is not None and proven >= required) == case["accepted"], case["name"]
        if proven is not None:
            assert verify(bytes.fromhex(event["id"]), public_key(secret), bytes.fromhex(event["sig"]))
    assert [case["accepted"] for case in vector["cases"]].count(True) == 1
    assert {"lucky_hash_low_commitment", "claimed_id_not_recomputed"} <= names


def test_fixture_secrets_are_explicitly_test_only() -> None:
    for path in (AUTHENTICATION_PATH, ECONOMICS_PATH, TRANSPORT_POW_PATH):
        vectors = load_json(path)
        assert vectors["fixture_key_warning"] == (
            "public deterministic test keys; never use for funds"
        )
        assert "fixture" in vectors["scope"] or "separate" in vectors["scope"]
