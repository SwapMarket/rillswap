from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from rill_core.domain.amounts import MAX_SATS
from rill_core.errors import CanonicalizationError
from rill_core.wire import parse_model_json
from rill_core.wire.hashes import (
    canonical_model,
    contract_hash,
    funding_binding_hash,
    handshake_accept_hash,
    handshake_hash,
    handshake_init_hash,
    provider_terms_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import (
    ContractTerms,
    Envelope,
    FundingBinding,
    HandshakeAccept,
    HandshakeAcceptPayload,
    HandshakeInit,
    ProviderTerms,
)

if TYPE_CHECKING:
    from collections.abc import Callable

G = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
G2 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
G3 = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
G4 = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
G5 = "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
FIELD_PRIME = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"


def network() -> dict[str, object]:
    return {
        "family": "bitcoin",
        "name": "regtest",
        "genesis_hash": "01" * 32,
        "signet_challenge": None,
        "consensus_profile": "bitcoin-core/v30",
        "deployment_namespace": "test/rill-core",
    }


def invoice(amount_msat: str) -> dict[str, object]:
    return {
        "bolt11_sha256": "02" * 32,
        "payment_hash": "03" * 32,
        "amount_msat": amount_msat,
        "payee_compressed_pubkey": "02" + G5,
        "created_at": 1_000,
        "expires_at": 2_000,
        "min_final_cltv_delta": 18,
    }


def terms_data(profile_id: str = "btc-to-ln/v1") -> dict[str, object]:
    common: dict[str, object] = {
        "protocol": "rillswap",
        "contract_version": "1",
        "profile_id": profile_id,
        "network_identity": network(),
        "provider_identity_key": G,
        "client_contract_compressed_key": "02" + G2,
        "provider_contract_compressed_key": "03" + G3,
        "refund_lock_height": 500,
        "funding_confirmations": 1,
        "settlement_confirmations": 2,
        "refund_resolution_confirmations": 3,
        "max_funding_fee_sat": "10",
        "max_claim_fee_sat": "11",
        "max_refund_fee_sat": "12",
        "client_destination_script": "0014" + "11" * 20,
        "provider_destination_script": "5120" + G5,
        "recovery_authorization_xonly_key": G4,
        "terms_expiry": 3_000,
        "required_features": (),
        "extensions": {},
    }
    if profile_id == "btc-to-ln/v1":
        common.update(
            {
                "claimant": "provider",
                "refund_party": "client",
                "invoice_binding": invoice("100000"),
                "economics": {
                    "kind": "btc-to-ln",
                    "lightning_principal_sat": "100",
                    "success_fee_sat": "5",
                    "contract_amount_sat": "105",
                },
                "timing_policy": {
                    "kind": "btc-to-ln",
                    "max_outgoing_htlc_expiry_height": 491,
                    "learn_and_claim_blocks": 9,
                    "client_response_blocks": 2,
                    "claim_confirmation_blocks": 3,
                },
            },
        )
    else:
        common.update(
            {
                "claimant": "client",
                "refund_party": "provider",
                "invoice_binding": invoice("105000"),
                "economics": {
                    "kind": "ln-to-btc",
                    "contract_amount_sat": "100",
                    "nominal_payout_sat": "98",
                    "claim_fee_reserve_sat": "2",
                    "success_fee_sat": "5",
                    "mining_prepayment_sat": "0",
                    "hold_invoice_sat": "105",
                },
                "timing_policy": {
                    "kind": "ln-to-btc",
                    "min_incoming_htlc_expiry_height": 511,
                    "refund_and_ln_resolution_blocks": 9,
                    "client_response_blocks": 2,
                    "claim_confirmation_blocks": 3,
                },
            },
        )
    return common


def handshake_init_data() -> dict[str, object]:
    return {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": "btc-to-ln/v1",
        "network_identity": network(),
        "session_id": "10" * 32,
        "client_challenge": "11" * 32,
        "client_session_xonly_key": G2,
        "expected_provider_identity_xonly_key": G,
        "requested_encryption_suites": ("noise-xk/v1",),
        "requested_capabilities": ("core/v1", "recovery/v1"),
        "required_features": (),
        "extensions": {},
    }


def handshake_accept_data(initiation: HandshakeInit) -> dict[str, object]:
    return {
        "handshake_init_hash": handshake_init_hash(initiation).hex(),
        "protocol": initiation.protocol,
        "wire_version": initiation.wire_version,
        "profile_id": initiation.profile_id,
        "network_identity": initiation.network_identity,
        "session_id": initiation.session_id,
        "client_challenge": initiation.client_challenge,
        "provider_challenge": "12" * 32,
        "client_session_xonly_key": initiation.client_session_xonly_key,
        "provider_session_xonly_key": G3,
        "provider_identity_xonly_key": G,
        "selected_encryption_suite": "noise-xk/v1",
        "selected_capabilities": ("core/v1",),
        "transport_endpoints": ("wss://provider.invalid/rillswap",),
        "required_features": (),
        "extensions": {},
    }


@pytest.mark.parametrize("profile_id", ["btc-to-ln/v1", "ln-to-btc/v1"])
def test_contract_terms_accept_both_economic_directions(profile_id: str) -> None:
    terms = ContractTerms.model_validate(terms_data(profile_id))
    assert terms.profile_id == profile_id


@pytest.mark.parametrize(
    ("profile_id", "mutate"),
    [
        (
            "btc-to-ln/v1",
            lambda value: value["economics"].update(contract_amount_sat="106"),
        ),
        (
            "btc-to-ln/v1",
            lambda value: value["economics"].update(lightning_principal_sat="0"),
        ),
        (
            "btc-to-ln/v1",
            lambda value: value.update(claimant="client", refund_party="provider"),
        ),
        (
            "btc-to-ln/v1",
            lambda value: value["timing_policy"].update(max_outgoing_htlc_expiry_height=492),
        ),
        (
            "ln-to-btc/v1",
            lambda value: value["economics"].update(nominal_payout_sat="97"),
        ),
        (
            "ln-to-btc/v1",
            lambda value: value["economics"].update(mining_prepayment_sat="6"),
        ),
        (
            "ln-to-btc/v1",
            lambda value: value.update(claimant="provider", refund_party="client"),
        ),
        (
            "ln-to-btc/v1",
            lambda value: value["timing_policy"].update(min_incoming_htlc_expiry_height=510),
        ),
    ],
)
def test_contract_terms_reject_invalid_economics_roles_and_timing(
    profile_id: str,
    mutate: Callable[[dict[str, object]], object],
) -> None:
    value = terms_data(profile_id)
    mutate(value)
    with pytest.raises(ValidationError):
        ContractTerms.model_validate(value)


def test_invoice_binding_requires_whole_positive_sats_and_matching_amount() -> None:
    for amount in ("100001", "0", "99000"):
        value = terms_data()
        value["invoice_binding"] = invoice(amount)
        with pytest.raises(ValidationError):
            ContractTerms.model_validate(value)


def test_nonzero_mining_prepayment_requires_feature() -> None:
    value = terms_data("ln-to-btc/v1")
    economics = value["economics"]
    assert isinstance(economics, dict)
    economics.update(mining_prepayment_sat="2", hold_invoice_sat="103")
    value["invoice_binding"] = invoice("103000")
    with pytest.raises(ValidationError):
        ContractTerms.model_validate(value)
    value["required_features"] = ("org.rillswap/mining-prepayment/v1",)
    assert ContractTerms.model_validate(value).economics.mining_prepayment_sat == "2"


def test_ln_to_btc_total_payment_cannot_exceed_monetary_maximum() -> None:
    value = terms_data("ln-to-btc/v1")
    value["economics"] = {
        "kind": "ln-to-btc",
        "contract_amount_sat": str(MAX_SATS),
        "nominal_payout_sat": str(MAX_SATS - 1),
        "claim_fee_reserve_sat": "1",
        "success_fee_sat": "1",
        "mining_prepayment_sat": "1",
        "hold_invoice_sat": str(MAX_SATS),
    }
    value["invoice_binding"] = invoice(str(MAX_SATS * 1_000))
    value["required_features"] = ("org.rillswap/mining-prepayment/v1",)
    with pytest.raises(ValidationError, match="monetary maximum"):
        ContractTerms.model_validate(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_identity_key", FIELD_PRIME),
        ("client_contract_compressed_key", "02" + FIELD_PRIME),
        ("recovery_authorization_xonly_key", G),
        ("provider_contract_compressed_key", "03" + G2),
    ],
)
def test_contract_terms_reject_invalid_or_reused_purpose_keys(field: str, value: str) -> None:
    terms = terms_data()
    terms[field] = value
    with pytest.raises(ValidationError):
        ContractTerms.model_validate(terms)


def test_feature_and_extension_limits_are_enforced() -> None:
    terms = terms_data()
    terms["required_features"] = tuple(f"feature/{index:02d}" for index in range(65))
    with pytest.raises(ValidationError):
        ContractTerms.model_validate(terms)
    terms = terms_data()
    terms["extensions"] = {"not-namespaced": None}
    with pytest.raises(ValidationError):
        ContractTerms.model_validate(terms)


def test_provider_terms_recomputes_contract_hash() -> None:
    terms = ContractTerms.model_validate(terms_data())
    provider_terms = ProviderTerms(
        contract_hash=contract_hash(terms).hex(),
        contract_terms=terms,
        handshake_hash="04" * 32,
    )
    assert provider_terms_hash(provider_terms) != contract_hash(terms)
    with pytest.raises(ValidationError):
        ProviderTerms(
            contract_hash="05" * 32,
            contract_terms=terms,
            handshake_hash="04" * 32,
        )


def test_handshake_validates_selection_and_signed_payload_shape() -> None:
    initiation = HandshakeInit.model_validate(handshake_init_data())
    acceptance = HandshakeAccept.model_validate(handshake_accept_data(initiation))
    acceptance.validate_against(initiation, supported_features=set())
    payload = HandshakeAcceptPayload(
        accept=acceptance,
        provider_identity_signature="06" * 64,
    )
    assert payload.accept == acceptance
    assert handshake_accept_hash(acceptance) != handshake_hash(initiation, acceptance)


def test_handshake_preserves_preference_order_and_counts_endpoint_characters() -> None:
    initiation_data = handshake_init_data()
    initiation_data["requested_capabilities"] = ("recovery/v1", "core/v1")
    initiation_data["requested_encryption_suites"] = ("noise-xx/v1", "noise-xk/v1")
    initiation = HandshakeInit.model_validate(initiation_data)
    acceptance_data = handshake_accept_data(initiation)
    acceptance_data["selected_capabilities"] = ("recovery/v1", "core/v1")
    acceptance_data["transport_endpoints"] = ("é" * 1_100,)
    acceptance = HandshakeAccept.model_validate(acceptance_data)
    acceptance.validate_against(initiation, supported_features=set())
    assert acceptance.selected_capabilities == ("recovery/v1", "core/v1")
    assert b'"requested_encryption_suites":["noise-xx/v1","noise-xk/v1"]' in canonical_model(
        initiation
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("session_id", "20" * 32),
        ("selected_encryption_suite", "unoffered/v1"),
        ("selected_capabilities", ("unknown/v1",)),
        ("provider_identity_xonly_key", G4),
    ],
)
def test_handshake_rejects_mismatched_echo_or_selection(field: str, value: object) -> None:
    initiation = HandshakeInit.model_validate(handshake_init_data())
    acceptance_data = handshake_accept_data(initiation)
    acceptance_data[field] = value
    acceptance = HandshakeAccept.model_validate(acceptance_data)
    with pytest.raises(ValueError, match=r"handshake|provider"):
        acceptance.validate_against(initiation, supported_features=set())


def test_handshake_rejects_empty_oversized_and_invalid_collections() -> None:
    for field in ("requested_encryption_suites", "requested_capabilities"):
        value = handshake_init_data()
        value[field] = ()
        with pytest.raises(ValidationError):
            HandshakeInit.model_validate(value)
    value = handshake_init_data()
    value["required_features"] = tuple(f"feature/{index:02d}" for index in range(65))
    with pytest.raises(ValidationError):
        HandshakeInit.model_validate(value)
    value = handshake_init_data()
    value["extensions"] = {"invalid": None}
    with pytest.raises(ValidationError):
        HandshakeInit.model_validate(value)


def test_handshake_rejects_unknown_required_feature() -> None:
    initiation_data = handshake_init_data()
    initiation_data["required_features"] = ("required/v1",)
    initiation = HandshakeInit.model_validate(initiation_data)
    acceptance = HandshakeAccept.model_validate(handshake_accept_data(initiation))
    with pytest.raises(ValueError, match="unknown feature"):
        acceptance.validate_against(initiation, supported_features=set())
    acceptance.validate_against(initiation, supported_features={"required/v1"})


def funding_binding_data() -> dict[str, object]:
    return {
        "contract_hash": "30" * 32,
        "funding_attempt_id": "31" * 32,
        "binding_revision": 0,
        "funder_role": "client",
        "lineage_anchor_txid": "32" * 32,
        "lineage_anchor_vout": 1,
        "funding_txid": "33" * 32,
        "contract_vout": 2,
        "contract_value_sat": "105",
        "contract_script_pubkey": "5120" + G5,
        "replaces_txid": None,
        "created_at": 1_500,
    }


def test_funding_binding_requires_p2tr_and_coherent_revision() -> None:
    initial = FundingBinding.model_validate(funding_binding_data())
    assert len(funding_binding_hash(initial)) == 32
    replacement = funding_binding_data()
    replacement.update(binding_revision=1, replaces_txid="33" * 32, funding_txid="34" * 32)
    assert FundingBinding.model_validate(replacement).binding_revision == 1
    for changes in (
        {"binding_revision": 0, "replaces_txid": "33" * 32},
        {"binding_revision": 1, "replaces_txid": None},
        {"contract_script_pubkey": "0014" + "11" * 20},
        {"contract_script_pubkey": "5120" + FIELD_PRIME},
    ):
        invalid = funding_binding_data()
        invalid.update(changes)
        with pytest.raises(ValidationError):
            FundingBinding.model_validate(invalid)


def envelope_data() -> dict[str, object]:
    return {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": "btc-to-ln/v1",
        "network_identity": network(),
        "session_id": "40" * 32,
        "message_id": "41" * 32,
        "sender_session_key": G2,
        "sequence": 2,
        "in_reply_to": None,
        "contract_hash": "42" * 32,
        "message_type": "observation",
        "payload": {"height": 100},
        "required_features": (),
        "extensions": {},
        "signature": "43" * 64,
    }


def test_unsigned_envelope_hash_omits_signature_member() -> None:
    first = Envelope.model_validate(envelope_data())
    second_data = envelope_data()
    second_data["signature"] = "44" * 64
    second = Envelope.model_validate(second_data)
    assert unsigned_envelope_hash(first) == unsigned_envelope_hash(second)


def test_strict_json_model_parsing_rejects_duplicates_and_floats() -> None:
    encoded = json.dumps(handshake_init_data()).encode()
    parsed = parse_model_json(HandshakeInit, encoded)
    assert parsed.session_id == "10" * 32
    with pytest.raises(CanonicalizationError, match="duplicate"):
        parse_model_json(
            HandshakeInit,
            b'{"protocol":"rillswap","protocol":"rillswap"}',
        )
    float_document = encoded.replace(b'"extensions": {}', b'"extensions": {"org.test/x": 1.5}')
    with pytest.raises(CanonicalizationError, match="floating-point"):
        parse_model_json(HandshakeInit, float_document)


def test_model_collections_reject_non_json_extension_values() -> None:
    value = copy.deepcopy(handshake_init_data())
    value["extensions"] = {"org.test/value": object()}
    with pytest.raises(ValidationError):
        HandshakeInit.model_validate(value)
