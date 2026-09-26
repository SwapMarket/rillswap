"""Versioned epoch binding without reinterpreting legacy handshake identifiers."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rill_core.wire.hashes import (
    EPOCH_SESSION_EXTENSION,
    EPOCH_SESSION_FEATURE,
    epoch_bound_session_id,
    handshake_init_hash,
)
from rill_core.wire.messages import HandshakeAccept, HandshakeInit
from rill_core.wire.types import NetworkIdentity

FIXTURE = Path(__file__).parents[1] / "fixtures/recovery-v1/initial-btc-to-ln-v1.json"
CONTEXT = json.loads(FIXTURE.read_text())["verification_context"]
LEGACY = CONTEXT["handshake_init"]
NETWORK = NetworkIdentity.model_validate(LEGACY["network_identity"])
PROVIDER = LEGACY["expected_provider_identity_xonly_key"]
CLIENT = LEGACY["client_session_xonly_key"]
EPOCH = CONTEXT["handshake_accept"]["provider_session_xonly_key"]
VECTOR = "6abb41432e6c051dc91efba1426d2dbc2ec44e6dd174b086f229981121e6dcea"
PROVIDER_SESSION = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"


def _fresh() -> dict:
    document = copy.deepcopy(LEGACY)
    document["required_features"] = [EPOCH_SESSION_FEATURE]
    document["extensions"] = {EPOCH_SESSION_EXTENSION: {"epoch_inbox_xonly_key": EPOCH}}
    document["session_id"] = VECTOR
    return document


def test_epoch_binding_matches_independent_sha256_jcs_vector() -> None:
    # Vector derived independently with stdlib SHA256 over sorted compact JSON,
    # not by calling this helper to generate the expected output.
    assert epoch_bound_session_id(NETWORK, PROVIDER, EPOCH, CLIENT).hex() == VECTOR
    init = HandshakeInit.model_validate_json(json.dumps(_fresh()), strict=True)
    assert init.epoch_inbox_xonly_key == EPOCH
    assert init.model_dump(mode="json") == _fresh()


@pytest.mark.parametrize("field", ["provider", "epoch", "client", "network"])
def test_epoch_identifier_commits_to_every_context_field(field: str) -> None:
    provider, epoch, client = PROVIDER, EPOCH, CLIENT
    network = NETWORK
    if field == "provider":
        provider, epoch = epoch, provider
    elif field == "epoch":
        epoch, client = client, epoch
    elif field == "client":
        client, provider = provider, client
    else:
        network = NETWORK.model_copy(update={"deployment_namespace": "another-deployment"})
    assert epoch_bound_session_id(network, provider, epoch, client).hex() != VECTOR


@pytest.mark.parametrize(
    "extension",
    [
        None,
        {},
        {"epoch_inbox_xonly_key": EPOCH, "extra": True},
        {"epoch_inbox_xonly_key": None},
        {"epoch_inbox_xonly_key": "ff" * 32},
    ],
)
def test_required_epoch_feature_refuses_absent_partial_or_unknown_binding(
    extension: object,
) -> None:
    document = _fresh()
    document["extensions"] = {EPOCH_SESSION_EXTENSION: extension}
    with pytest.raises(ValidationError):
        HandshakeInit.model_validate_json(json.dumps(document), strict=True)


def test_required_epoch_feature_cannot_keep_a_random_or_older_epoch_id() -> None:
    document = _fresh()
    document["session_id"] = LEGACY["session_id"]
    with pytest.raises(ValueError, match="session_id does not bind"):
        HandshakeInit.model_validate_json(json.dumps(document), strict=True)


@pytest.mark.parametrize("key", ["ff" * 32, "00" * 32, "ab", True, 3])
def test_hash_boundary_requires_canonical_curve_keys(key: object) -> None:
    with pytest.raises(ValidationError):
        epoch_bound_session_id(NETWORK, PROVIDER, key, CLIENT)  # type: ignore[arg-type]


def test_epoch_context_keys_must_be_distinct() -> None:
    with pytest.raises(ValueError, match="distinct"):
        epoch_bound_session_id(NETWORK, PROVIDER, PROVIDER, CLIENT)


def test_legacy_transcript_bytes_and_random_identifier_remain_unchanged() -> None:
    legacy = HandshakeInit.model_validate_json(json.dumps(LEGACY), strict=True)
    assert legacy.model_dump(mode="json") == LEGACY
    assert legacy.epoch_inbox_xonly_key is None
    assert handshake_init_hash(legacy).hex() == CONTEXT["handshake_accept"]["handshake_init_hash"]


def test_optional_extension_does_not_reclassify_legacy_admission() -> None:
    document = copy.deepcopy(LEGACY)
    document["extensions"] = {EPOCH_SESSION_EXTENSION: {"epoch_inbox_xonly_key": EPOCH}}
    init = HandshakeInit.model_validate_json(json.dumps(document), strict=True)
    assert init.session_id == LEGACY["session_id"]
    assert init.epoch_inbox_xonly_key is None


def _accept(init: HandshakeInit, *, required: tuple[str, ...]) -> HandshakeAccept:
    document = copy.deepcopy(CONTEXT["handshake_accept"])
    document.update(
        session_id=init.session_id,
        handshake_init_hash=handshake_init_hash(init).hex(),
        provider_session_xonly_key=PROVIDER_SESSION,
        required_features=list(required),
    )
    return HandshakeAccept.model_validate_json(json.dumps(document), strict=True)


@pytest.mark.parametrize("initiator_selected", [True, False])
def test_epoch_feature_cannot_be_introduced_or_dropped_by_one_party(
    *,
    initiator_selected: bool,
) -> None:
    init = HandshakeInit.model_validate_json(
        json.dumps(_fresh() if initiator_selected else LEGACY), strict=True
    )
    accept = _accept(init, required=() if initiator_selected else (EPOCH_SESSION_FEATURE,))
    with pytest.raises(ValueError, match="jointly negotiated"):
        accept.validate_against(init, supported_features={EPOCH_SESSION_FEATURE})


def test_epoch_negotiation_does_not_implicitly_enable_unknown_feature_support() -> None:
    init = HandshakeInit.model_validate_json(json.dumps(_fresh()), strict=True)
    accept = _accept(init, required=(EPOCH_SESSION_FEATURE,))
    with pytest.raises(ValueError, match="unknown feature"):
        accept.validate_against(init, supported_features=set())
    accept.validate_against(init, supported_features={EPOCH_SESSION_FEATURE})


def test_session_custody_cannot_reuse_a_retiring_epoch_key() -> None:
    init = HandshakeInit.model_validate_json(json.dumps(_fresh()), strict=True)
    accept = _accept(init, required=(EPOCH_SESSION_FEATURE,)).model_copy(
        update={"provider_session_xonly_key": EPOCH}
    )
    with pytest.raises(ValueError, match="epoch inbox keys must be distinct"):
        accept.validate_against(init, supported_features={EPOCH_SESSION_FEATURE})
