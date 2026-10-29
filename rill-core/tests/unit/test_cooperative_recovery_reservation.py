"""An authenticated attempt reservation is historical evidence, not authority."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from test_recovery_inspection import (
    FixtureCrypto,
    _add_history,
    _canonical,
    _crypto,
    _network,
    _source,
    _successor,
)

from rill_core.errors import ValidationError
from rill_core.recovery import COOPERATIVE_RESERVATION_EXTENSION, inspect_recovery_plaintext
from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
)
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    contract_hash,
    handshake_hash,
    handshake_init_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import ContractTerms, Envelope, HandshakeAccept, HandshakeInit


def _paid() -> tuple[dict[str, Any], FixtureCrypto]:
    document = _source()
    artifacts = _crypto(document).artifacts
    context = document["verification_context"]
    feature = [COOPERATIVE_CLAIM_FEATURE]
    context["handshake_init"]["required_features"] = [
        COOPERATIVE_CLAIM_FEATURE,
        EPOCH_SESSION_FEATURE,
    ]
    context["handshake_accept"]["required_features"] = [
        COOPERATIVE_CLAIM_FEATURE,
        EPOCH_SESSION_FEATURE,
    ]
    init = HandshakeInit.model_validate_json(json.dumps(context["handshake_init"]))
    context["handshake_accept"]["handshake_init_hash"] = handshake_init_hash(init).hex()
    accept = HandshakeAccept.model_validate_json(json.dumps(context["handshake_accept"]))
    context["handshake_hash"] = handshake_hash(init, accept).hex()
    document["contract_terms"]["required_features"] = feature
    terms = ContractTerms.model_validate_json(json.dumps(document["contract_terms"]))
    document["contract_hash"] = contract_hash(terms).hex()
    for name in (
        "provider_identity_signature",
        "provider_terms_signature",
        "client_acceptance_signature",
    ):
        context[name] = "11" * 64
    crypto = FixtureCrypto(document, artifacts)
    _add_history(document, crypto, 1)
    document["monotonic_knowledge"].update(preimage_known=True, preimage="42" * 32)
    assert inspect_recovery_plaintext(_canonical(document), _network(document), crypto=crypto)
    return document, crypto


def _reserved(
    previous: dict[str, Any],
    crypto: FixtureCrypto,
    *,
    revision: int = -1,
) -> dict[str, Any]:
    candidate = copy.deepcopy(previous)
    binding = previous["funding_history"][revision]["binding"]
    terms = ContractTerms.model_validate_json(json.dumps(previous["contract_terms"]))
    funding = FundingOutput(
        txid=bytes.fromhex(binding["funding_txid"]),
        output_index=binding["contract_vout"],
        value_sat=int(binding["contract_value_sat"]),
        script_pubkey=bytes.fromhex(binding["contract_script_pubkey"]),
    )
    plan = build_cooperative_claim(
        UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto),
        fee_sat=300,
    )
    context = previous["verification_context"]
    envelope = {
        "protocol": "rillswap",
        "wire_version": "1",
        "network_identity": previous["network_identity"],
        "profile_id": previous["profile_id"],
        "required_features": [COOPERATIVE_CLAIM_FEATURE],
        "extensions": {},
        "session_id": context["handshake_init"]["session_id"],
        "sender_session_key": context["provider_session_xonly_key"],
        "sequence": 3,
        "message_id": "aa" * 32,
        "contract_hash": previous["contract_hash"],
        "message_type": "action_request",
        "in_reply_to": None,
        "payload": {
            "action": "cooperative_claim_propose",
            "cooperation_id": "bb" * 32,
            "unsigned_transaction": plan.base_transaction.hex(),
            "public_nonce": "11" * 66,
            "payment_preimage": previous["monotonic_knowledge"]["preimage"],
            "deadline_at": previous["updated_at"] + 20,
            "deadline_height": terms.refund_lock_height
            - terms.timing_policy.claim_confirmation_blocks,
        },
        "signature": "22" * 64,
    }
    candidate["extensions"][COOPERATIVE_RESERVATION_EXTENSION] = {
        "version": 1,
        "proposal": envelope,
        "signature_hash": plan.signature_hash.hex(),
    }
    _permit_proposal(candidate, crypto)
    return candidate


def _permit_proposal(document: dict[str, Any], crypto: FixtureCrypto) -> None:
    proposal = document["extensions"][COOPERATIVE_RESERVATION_EXTENSION]["proposal"]
    envelope = Envelope.model_validate_json(json.dumps(proposal), strict=True)
    crypto.allow(envelope.sender_session_key, unsigned_envelope_hash(envelope), envelope.signature)


@pytest.mark.parametrize("dangerous", [False, True])
def test_reservation_preserves_paid_knowledge_and_unrelated_extensions(*, dangerous: bool) -> None:
    previous, crypto = _paid()
    previous["monotonic_knowledge"]["dangerous_signature_issued"] = dangerous
    previous["extensions"]["example.invalid/nested"] = {"value": [True, 1]}
    candidate = _reserved(previous, crypto)
    assert _successor(previous, candidate, crypto).recorded_binding_count == 1
    assert candidate["monotonic_knowledge"] == previous["monotonic_knowledge"]
    assert _successor(candidate, candidate, crypto).recorded_binding_count == 1
    later = copy.deepcopy(candidate)
    later["updated_at"] += 1000  # expiry does not invalidate historical recovery
    later["funding_history"] = []
    _add_history(later, crypto, 2)
    assert _successor(candidate, later, crypto).recorded_binding_count == 2
    assert inspect_recovery_plaintext(_canonical(later), _network(later), crypto=crypto)


@pytest.mark.parametrize(
    "change",
    [
        "bool version",
        "unknown version",
        "extra member",
        "null marker",
        "signature",
        "sender",
        "session",
        "network",
        "reply",
        "features",
        "preimage",
        "transaction",
        "sighash",
        "wall zero",
        "height zero",
        "height too late",
        "not proposal",
    ],
)
def test_invalid_reservation_rejected_by_standalone_inspection(change: str) -> None:  # noqa: PLR0912 - closed tampering matrix
    previous, crypto = _paid()
    candidate = _reserved(previous, crypto)
    marker = candidate["extensions"][COOPERATIVE_RESERVATION_EXTENSION]
    proposal, payload = marker["proposal"], marker["proposal"]["payload"]
    if change == "bool version":
        marker["version"] = True
    elif change == "unknown version":
        marker["version"] = 2
    elif change == "extra member":
        marker["signed"] = True
    elif change == "null marker":
        candidate["extensions"][COOPERATIVE_RESERVATION_EXTENSION] = None
    elif change == "signature":
        proposal["signature"] = "33" * 64
    elif change == "sender":
        proposal["sender_session_key"] = previous["verification_context"][
            "client_session_xonly_key"
        ]
    elif change == "session":
        proposal["session_id"] = "ff" * 32
    elif change == "network":
        proposal["network_identity"]["genesis_hash"] = "ff" * 32
    elif change == "reply":
        proposal["in_reply_to"] = "cc" * 32
    elif change == "features":
        proposal["required_features"] = []
    elif change == "preimage":
        payload["payment_preimage"] = "22" * 32
    elif change == "transaction":
        payload["unsigned_transaction"] = "01" + payload["unsigned_transaction"][2:]
    elif change == "sighash":
        marker["signature_hash"] = "ff" * 32
    elif change == "wall zero":
        payload["deadline_at"] = 0
    elif change == "height zero":
        payload["deadline_height"] = 0
    elif change == "height too late":
        payload["deadline_height"] += 1
    else:
        payload.clear()
        payload.update(
            action="cooperative_claim_complete",
            cooperation_id="bb" * 32,
            partial_signature="11" * 32,
        )
    if change not in {"signature", "null marker"}:
        _permit_proposal(candidate, crypto)  # independently exercise each non-signature invariant
    with pytest.raises(ValidationError):
        inspect_recovery_plaintext(_canonical(candidate), _network(candidate), crypto=crypto)


@pytest.mark.parametrize(
    "change",
    [
        "old funding",
        "funding append",
        "payment learned",
        "dangerous changed",
        "too late",
        "extension added",
        "extension type changed",
        "unpaid",
        "unfunded",
    ],
)
def test_reservation_insertion_cannot_combine_other_state_changes(change: str) -> None:
    previous, crypto = _paid()
    previous["extensions"]["example.invalid/preserve"] = True
    if change == "old funding":
        previous["funding_history"] = []
        _add_history(previous, crypto, 2)
    candidate = _reserved(previous, crypto, revision=0 if change == "old funding" else -1)
    if change == "funding append":
        candidate["funding_history"] = []
        _add_history(candidate, crypto, 2)
    elif change == "payment learned":
        previous["monotonic_knowledge"].update(preimage_known=False, preimage=None)
    elif change == "dangerous changed":
        candidate["monotonic_knowledge"]["dangerous_signature_issued"] = True
    elif change == "too late":
        candidate["updated_at"] = candidate["extensions"][COOPERATIVE_RESERVATION_EXTENSION][
            "proposal"
        ]["payload"]["deadline_at"]
    elif change == "extension added":
        candidate["extensions"]["example.invalid/extra"] = 1
    elif change == "extension type changed":
        candidate["extensions"]["example.invalid/preserve"] = 1
    elif change == "unpaid":
        candidate["monotonic_knowledge"].update(preimage_known=False, preimage=None)
    elif change == "unfunded":
        candidate["funding_history"] = []
    with pytest.raises(ValidationError, match="invalid or nonmonotonic recovery successor"):
        _successor(previous, candidate, crypto)


@pytest.mark.parametrize("change", ["remove", "new id", "new proposal", "resigned"])
def test_existing_reservation_cannot_be_removed_or_replaced(change: str) -> None:
    paid, crypto = _paid()
    previous = _reserved(paid, crypto)
    candidate = copy.deepcopy(previous)
    marker = candidate["extensions"][COOPERATIVE_RESERVATION_EXTENSION]
    if change == "remove":
        del candidate["extensions"][COOPERATIVE_RESERVATION_EXTENSION]
    else:
        if change == "new id":
            marker["proposal"]["payload"]["cooperation_id"] = "cc" * 32
        elif change == "new proposal":
            marker["proposal"]["message_id"] = "dd" * 32
        else:
            marker["proposal"]["signature"] = "44" * 64
        _permit_proposal(candidate, crypto)
    # Even a different statically valid proposal cannot reopen a reservation.
    assert inspect_recovery_plaintext(_canonical(candidate), _network(candidate), crypto=crypto)
    with pytest.raises(ValidationError, match="invalid or nonmonotonic recovery successor"):
        _successor(previous, candidate, crypto)


def test_unfeatured_paid_recovery_cannot_reserve_cooperation() -> None:
    previous = _source()
    crypto = _crypto(previous)
    _add_history(previous, crypto, 1)
    previous["monotonic_knowledge"].update(preimage_known=True, preimage="42" * 32)
    candidate = _reserved(previous, crypto)
    with pytest.raises(ValidationError, match="invalid or nonmonotonic recovery successor"):
        _successor(previous, candidate, crypto)
    # An older snapshot remains usable; absence neither requests migration nor
    # supplies a new live cooperative session or one-shot signing authority.
    assert inspect_recovery_plaintext(_canonical(previous), _network(previous), crypto=crypto)
