"""Schema checks the closed reservation shape, not semantic signing authority."""

from __future__ import annotations

import pytest

from tests.test_recovery_vectors import FIXTURE, _schema_validator
from tests.test_schemas import load_json

KEY = "rillswap/cooperative-claim-reservation"


@pytest.mark.parametrize(
    "variation",
    [
        "shape",
        "bool version",
        "unknown version",
        "extra member",
        "missing sighash",
        "unsigned",
        "not request",
        "null marker",
    ],
)
def test_cooperative_reservation_closed_shape(variation: str) -> None:
    package = load_json(FIXTURE)
    context = package["verification_context"]
    proposal = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": package["profile_id"],
        "network_identity": package["network_identity"],
        "session_id": context["handshake_init"]["session_id"],
        "message_id": "aa" * 32,
        "sender_session_key": context["provider_session_xonly_key"],
        "sequence": 3,
        "in_reply_to": None,
        "contract_hash": package["contract_hash"],
        "message_type": "action_request",
        "payload": {},
        "required_features": [],
        "extensions": {},
        "signature": "22" * 64,
    }
    marker = {"version": 1, "proposal": proposal, "signature_hash": "bb" * 32}
    package["extensions"][KEY] = marker
    if variation == "bool version":
        marker["version"] = True
    elif variation == "unknown version":
        marker["version"] = 2
    elif variation == "extra member":
        marker["signed"] = True
    elif variation == "missing sighash":
        del marker["signature_hash"]
    elif variation == "unsigned":
        proposal["signature"] = None
    elif variation == "not request":
        proposal["message_type"] = "action_result"
    elif variation == "null marker":
        package["extensions"][KEY] = None
    assert _schema_validator().is_valid(package) == (variation == "shape")
