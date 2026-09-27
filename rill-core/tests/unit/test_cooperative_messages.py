"""Structural safety for cooperative v1 action payloads, not signing authority."""

from __future__ import annotations

import json

import pytest

from rill_core.wire.canonical import canonicalize
from rill_core.wire.cooperative_messages import (
    CooperativeClaimComplete,
    CooperativeClaimDeclined,
    CooperativeClaimPropose,
    CooperativeClaimSigned,
    CooperativeClaimVerified,
    parse_cooperative_payload,
)

ID = "01" * 32
NONCE = "02" * 66
PARTIAL = "03" * 32
PROPOSE = {
    "action": "cooperative_claim_propose",
    "cooperation_id": ID,
    "unsigned_transaction": "00" * 100,
    "payment_preimage": "04" * 32,
    "public_nonce": NONCE,
    "deadline_at": 1700000000,
    "deadline_height": 1000,
}


@pytest.mark.parametrize(
    ("message_type", "payload", "model"),
    [
        ("action_request", PROPOSE, CooperativeClaimPropose),
        (
            "action_result",
            {
                "action": "cooperative_claim_propose",
                "cooperation_id": ID,
                "status": "signed",
                "public_nonce": NONCE,
                "partial_signature": PARTIAL,
            },
            CooperativeClaimSigned,
        ),
        (
            "action_result",
            {"action": "cooperative_claim_propose", "cooperation_id": ID, "status": "declined"},
            CooperativeClaimDeclined,
        ),
        (
            "action_request",
            {
                "action": "cooperative_claim_complete",
                "cooperation_id": ID,
                "partial_signature": PARTIAL,
            },
            CooperativeClaimComplete,
        ),
        (
            "action_result",
            {"action": "cooperative_claim_complete", "cooperation_id": ID, "status": "verified"},
            CooperativeClaimVerified,
        ),
    ],
)
def test_closed_cooperative_shapes_round_trip(
    message_type: str, payload: dict[str, object], model: type
) -> None:
    parsed = parse_cooperative_payload(message_type, canonicalize(payload))  # type: ignore[arg-type]
    assert isinstance(parsed, model)
    assert parsed.model_dump(mode="json") == payload


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("cooperation_id", "ff"),
        ("public_nonce", "02" * 65),
        ("public_nonce", "GG" * 66),
        ("unsigned_transaction", "00" * 59),
        ("unsigned_transaction", "00" * 1001),
        ("unsigned_transaction", "AA" * 100),
        ("deadline_at", True),
        ("deadline_height", -1),
        ("payment_preimage", "00" * 31),
        ("unexpected", "hidden"),
        ("status", "signed"),
    ],
)
def test_malformed_proposal_is_refused(key: str, value: object) -> None:
    payload = {**PROPOSE, key: value}
    with pytest.raises(ValueError, match=r"validation error|request unsupported"):
        parse_cooperative_payload("action_request", canonicalize(payload))


def test_role_of_request_and_result_and_replay_bytes_are_not_conflated() -> None:
    with pytest.raises(ValueError, match="request unsupported"):
        parse_cooperative_payload(
            "action_request",
            canonicalize(
                {"action": "cooperative_claim_propose", "cooperation_id": ID, "status": "declined"}
            ),
        )
    with pytest.raises(ValueError, match="result unsupported"):
        parse_cooperative_payload("action_result", canonicalize(PROPOSE))
    with pytest.raises(ValueError, match="must be an object"):
        parse_cooperative_payload("action_request", b"[]")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        parse_cooperative_payload(
            "action_request",
            b'{"action":"cooperative_claim_propose","action":"cooperative_claim_complete"}',
        )
    with pytest.raises(ValueError, match="validation error"):
        parse_cooperative_payload(
            "action_result",
            json.dumps(
                {
                    "action": "cooperative_claim_complete",
                    "cooperation_id": ID,
                    "status": "verified",
                    "partial_signature": PARTIAL,
                }
            ).encode(),
        )
