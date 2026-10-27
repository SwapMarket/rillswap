"""Independent payload shapes and role/reply cycle, not signing authority."""

from __future__ import annotations

import copy

import jsonschema
import pytest

from tests.test_schemas import ROOT, load_json, schema_registry

VECTOR = load_json(ROOT / "vectors/wire/cooperative-claim-v1.json")
SCHEMA_ID = (
    "https://spec.rillswap.invalid/schemas/wire/cooperative-claim-v1.schema.json"
)


def _payload_valid(message: dict) -> bool:
    registry, _ = schema_registry()
    definition = (
        "actionRequest"
        if message["message_type"] == "action_request"
        else "actionResult"
    )
    return jsonschema.Draft202012Validator(
        {"$ref": f"{SCHEMA_ID}#/$defs/{definition}"}, registry=registry
    ).is_valid(message["payload"])


def _context_valid(name: str, message: dict) -> bool:
    messages = VECTOR["messages"]
    expected_role = "claimant" if name in ("propose", "complete") else "cosigner"
    if message["sender_role"] != expected_role or message["required_features"] != [
        "cooperative-claim/v1"
    ]:
        return False
    if (
        message["payload"]["cooperation_id"]
        != messages["propose"]["payload"]["cooperation_id"]
    ):
        return False
    if name in ("propose", "complete"):
        return message["in_reply_to"] is None
    prior = messages[message["prior_request"]]
    return (
        message["in_reply_to"] == prior["message_id"]
        and message["payload"]["action"] == prior["payload"]["action"]
    )


def test_shared_cycle_has_opposite_profile_roles_and_closed_payloads() -> None:
    assert [(p["claimant_role"], p["cosigner_role"]) for p in VECTOR["profiles"]] == [
        ("provider", "client"),
        ("client", "provider"),
    ]
    for name, message in VECTOR["messages"].items():
        assert _payload_valid(message)
        assert _context_valid(name, message)
    assert VECTOR["messages"]["complete"]["prior_request"] == "propose"
    assert VECTOR["messages"]["verified"]["prior_request"] == "complete"


@pytest.mark.parametrize("case", VECTOR["invalid"], ids=lambda case: case["name"])
def test_shared_invalid_payload_or_context(case: dict) -> None:
    message = copy.deepcopy(VECTOR["messages"][case["message"]])
    target = message
    path = case["field"].split(".")
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = case["replacement"]
    assert _payload_valid(message) == case["shape_valid"]
    assert not (_payload_valid(message) and _context_valid(case["message"], message))
