"""Closed cooperative-claim/v1 action payloads (not authentication or signing).

Receivers must verify the enclosing signed RS-001 envelope, signed feature
negotiation, role, reply correlation, chain state, transaction policy, and
one-shot durable burn separately. Parsing never grants permission to sign.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import StringConstraints

from rill_core.wire.canonical import canonicalize, parse_json_strict
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
