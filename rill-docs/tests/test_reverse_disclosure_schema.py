"""Disclosure reservation shape does not prove publication or transmission."""

from __future__ import annotations

import pytest

from tests.test_recovery_vectors import ROOT, _schema_validator
from tests.test_schemas import load_json

EXTENSION = "rillswap/reverse-preimage-disclosure"


@pytest.mark.parametrize(
    "variation",
    [
        "shape",
        "bool version",
        "unknown version",
        "extra",
        "missing binding",
        "missing proposal",
        "unsigned",
        "not request",
        "not reverse",
        "null marker",
        "invalid binding",
    ],
)
def test_reverse_disclosure_closed_shape(variation: str) -> None:
    package = load_json(
        ROOT / "vectors" / "recovery" / "initial-ln-to-btc-no-prepayment-v1.json"
    )
    context = package["verification_context"]
    proposal = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": package["profile_id"],
        "network_identity": package["network_identity"],
        "session_id": context["handshake_init"]["session_id"],
        "message_id": "aa" * 32,
        "sender_session_key": context["client_session_xonly_key"],
        "sequence": 3,
        "in_reply_to": None,
        "contract_hash": package["contract_hash"],
        "message_type": "action_request",
        "payload": {},
        "required_features": [],
        "extensions": {},
        "signature": "22" * 64,
    }
    marker = {"version": 1, "funding_binding_hash": "bb" * 32, "proposal": proposal}
    package["extensions"][EXTENSION] = marker
    if variation == "bool version":
        marker["version"] = True
    elif variation == "unknown version":
        marker["version"] = 2
    elif variation == "extra":
        marker["payment_settled"] = True
    elif variation == "missing binding":
        del marker["funding_binding_hash"]
    elif variation == "missing proposal":
        del marker["proposal"]
    elif variation == "unsigned":
        proposal["signature"] = None
    elif variation == "not request":
        proposal["message_type"] = "action_result"
    elif variation == "not reverse":
        proposal["profile_id"] = "btc-to-ln/v1"
    elif variation == "null marker":
        package["extensions"][EXTENSION] = None
    elif variation == "invalid binding":
        marker["funding_binding_hash"] = "bb" * 31
    # Shape-only acceptance deliberately lacks a fallback and a real proposal:
    # core semantic verification must still refuse this apparent reservation.
    assert _schema_validator().is_valid(package) == (variation == "shape")
