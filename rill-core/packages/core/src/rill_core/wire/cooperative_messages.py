"""Closed cooperative-claim/v1 action payloads (not authentication or signing).

Receivers must verify the enclosing signed RS-001 envelope, signed feature
negotiation, role, reply correlation, chain state, transaction policy, and
one-shot durable burn separately. Parsing never grants permission to sign.
"""

from __future__ import annotations

from typing import Annotated, Literal, cast

from pydantic import StringConstraints

from rill_core.wire.canonical import canonicalize, parse_json_strict
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    contract_hash,
)
from rill_core.wire.messages import (
    ContractTerms,
    Envelope,
    HandshakeAccept,
    HandshakeInit,
    require_supported_contract_features,
)
from rill_core.wire.types import ExactInteger, Hex32, StrictModel

type PublicNonce = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{132}$")]
type PartialSignature = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
# RS-002 v1 has one input and one output; this is an intentionally tighter
# transport bound, not permission to sign a transaction without parsing it.
type UnsignedTransaction = Annotated[str, StringConstraints(pattern=r"^(?:[0-9a-f]{2}){60,1000}$")]


class CooperativeClaimPropose(StrictModel):
    """The claimant offers a frozen transaction and burns its own nonce first."""

    action: Literal["cooperative_claim_propose"]
    cooperation_id: Hex32
    unsigned_transaction: UnsignedTransaction
    payment_preimage: Hex32
    public_nonce: PublicNonce
    deadline_at: ExactInteger
    deadline_height: ExactInteger


class CooperativeClaimSigned(StrictModel):
    """The cosigner returns a nonce and one partial for that exact proposal."""

    action: Literal["cooperative_claim_propose"]
    cooperation_id: Hex32
    status: Literal["signed"]
    public_nonce: PublicNonce
    partial_signature: PartialSignature


class CooperativeClaimDeclined(StrictModel):
    """The cosigner declines without disclosing a nonce or partial."""

    action: Literal["cooperative_claim_propose"]
    cooperation_id: Hex32
    status: Literal["declined"]


class CooperativeClaimComplete(StrictModel):
    """The claimant discloses its partial after verifying the peer's partial."""

    action: Literal["cooperative_claim_complete"]
    cooperation_id: Hex32
    partial_signature: PartialSignature


class CooperativeClaimVerified(StrictModel):
    """Receipt only: the claimant never waits for this to broadcast."""

    action: Literal["cooperative_claim_complete"]
    cooperation_id: Hex32
    status: Literal["verified"]


type CooperativeAction = (
    CooperativeClaimPropose
    | CooperativeClaimSigned
    | CooperativeClaimDeclined
    | CooperativeClaimComplete
    | CooperativeClaimVerified
)


def parse_cooperative_payload(
    message_type: Literal["action_request", "action_result"], document: bytes
) -> CooperativeAction:
    """Parse only a closed payload shape, never infer signed feature authority."""
    parsed = parse_json_strict(document)
    if not isinstance(parsed, dict):
        raise ValueError("cooperative payload must be an object")  # noqa: TRY004 - wire refusal
    action = parsed.get("action")
    status = parsed.get("status")
    if message_type == "action_request":
        if action == "cooperative_claim_propose" and status is None:
            model: type[CooperativeAction] = CooperativeClaimPropose
        elif action == "cooperative_claim_complete" and status is None:
            model = CooperativeClaimComplete
        else:
            raise ValueError("cooperative action request unsupported")
    elif message_type == "action_result":
        if action == "cooperative_claim_propose" and status == "signed":
            model = CooperativeClaimSigned
        elif action == "cooperative_claim_propose" and status == "declined":
            model = CooperativeClaimDeclined
        elif action == "cooperative_claim_complete" and status == "verified":
            model = CooperativeClaimVerified
        else:
            raise ValueError("cooperative action result unsupported")
    else:
        raise ValueError("not a cooperative action envelope type")
    return model.model_validate_json(canonicalize(parsed), strict=True)


def check_cooperative_action_context(
    envelope: Envelope,
    terms: ContractTerms,
    initiation: HandshakeInit,
    acceptance: HandshakeAccept,
    *,
    prior_request: Envelope | None = None,
) -> CooperativeAction:
    """Check the feature, sender role, and exact request/reply association.

    This is NOT a signature, payment, transaction, nonce, deadline, attempt
    stage, or chain verifier. Both current and prior envelopes MUST first be
    authenticated by the receiver; a prior request must also be retained and
    admitted by the attempt ledger. The accepted contract and both handshake
    halves MUST come from its retained signed transcript, not the request.
    """
    require_supported_contract_features(terms, initiation, acceptance)
    acceptance.validate_against(
        initiation, supported_features={EPOCH_SESSION_FEATURE, COOPERATIVE_CLAIM_FEATURE}
    )
    if (
        COOPERATIVE_CLAIM_FEATURE not in terms.required_features
        or COOPERATIVE_CLAIM_FEATURE not in envelope.required_features
        or set(envelope.required_features) - {EPOCH_SESSION_FEATURE, COOPERATIVE_CLAIM_FEATURE}
        or envelope.session_id != initiation.session_id
        or envelope.session_id != acceptance.session_id
        or envelope.network_identity != terms.network_identity
        or initiation.network_identity != terms.network_identity
        or acceptance.network_identity != terms.network_identity
        or envelope.profile_id != terms.profile_id
        or initiation.profile_id != terms.profile_id
        or acceptance.profile_id != terms.profile_id
        or envelope.contract_hash != contract_hash(terms).hex()
    ):
        raise ValueError("cooperative action is not bound to signed feature and terms")
    message_type = envelope.message_type
    if message_type not in ("action_request", "action_result"):
        raise ValueError("not a cooperative action envelope type")
    payload = parse_cooperative_payload(
        cast('Literal["action_request", "action_result"]', message_type),
        canonicalize(envelope.payload),
    )
    claimant_key = (
        initiation.client_session_xonly_key
        if terms.claimant == "client"
        else acceptance.provider_session_xonly_key
    )
    cosigner_key = (
        acceptance.provider_session_xonly_key
        if terms.claimant == "client"
        else initiation.client_session_xonly_key
    )
    is_request = isinstance(payload, (CooperativeClaimPropose, CooperativeClaimComplete))
    expected_key = claimant_key if is_request else cosigner_key
    if envelope.sender_session_key != expected_key:
        raise ValueError("cooperative action sender role is incorrect")
    if isinstance(payload, CooperativeClaimPropose):
        if envelope.in_reply_to is not None or prior_request is not None:
            raise ValueError("cooperative proposal must start a new action")
        return payload
    if prior_request is None or prior_request.message_type != "action_request":
        raise ValueError("cooperative action has no prior proposal/request")
    if (
        prior_request.session_id != envelope.session_id
        or prior_request.contract_hash != envelope.contract_hash
        or prior_request.network_identity != envelope.network_identity
        or prior_request.profile_id != envelope.profile_id
        or prior_request.sender_session_key != claimant_key
        or prior_request.in_reply_to is not None
        or COOPERATIVE_CLAIM_FEATURE not in prior_request.required_features
        or set(prior_request.required_features) - {EPOCH_SESSION_FEATURE, COOPERATIVE_CLAIM_FEATURE}
    ):
        raise ValueError("cooperative action refers to a different signed request")
    previous = parse_cooperative_payload("action_request", canonicalize(prior_request.payload))
    if previous.cooperation_id != payload.cooperation_id:
        raise ValueError("cooperative action refers to a different attempt")
    if isinstance(payload, CooperativeClaimComplete):
        if not isinstance(previous, CooperativeClaimPropose) or envelope.in_reply_to is not None:
            raise ValueError("cooperative completion requires its prior proposal")
    elif envelope.in_reply_to != prior_request.message_id or (
        isinstance(payload, CooperativeClaimVerified)
    ) != isinstance(previous, CooperativeClaimComplete):
        raise ValueError("cooperative result does not answer its exact request")
    return payload
