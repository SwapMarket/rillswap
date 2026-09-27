"""A cooperative commitment cannot be injected or stripped at handshake time."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE, handshake_init_hash
from rill_core.wire.messages import (
    ContractTerms,
    HandshakeAccept,
    HandshakeInit,
    require_supported_contract_features,
)

FIXTURE = Path(__file__).parents[1] / "fixtures/recovery-v1/initial-btc-to-ln-v1.json"
CONTEXT = json.loads(FIXTURE.read_text())["verification_context"]


def _handshake(
    client_features: tuple[str, ...], provider_features: tuple[str, ...]
) -> tuple[HandshakeInit, HandshakeAccept]:
    init_document = copy.deepcopy(CONTEXT["handshake_init"])
    init_document["required_features"] = list(client_features)
    init = HandshakeInit.model_validate_json(json.dumps(init_document), strict=True)
    accept_document = copy.deepcopy(CONTEXT["handshake_accept"])
    accept_document["handshake_init_hash"] = handshake_init_hash(init).hex()
    accept_document["required_features"] = list(provider_features)
    accept = HandshakeAccept.model_validate_json(json.dumps(accept_document), strict=True)
    return init, accept


@pytest.mark.parametrize(
    ("client_features", "provider_features"),
    [((COOPERATIVE_CLAIM_FEATURE,), ()), ((), (COOPERATIVE_CLAIM_FEATURE,))],
)
def test_cooperation_cannot_be_injected_or_stripped(
    client_features: tuple[str, ...], provider_features: tuple[str, ...]
) -> None:
    init, accept = _handshake(client_features, provider_features)
    with pytest.raises(ValueError, match="jointly negotiated"):
        accept.validate_against(init, supported_features={COOPERATIVE_CLAIM_FEATURE})


def test_old_client_cannot_accept_unknown_cooperation_and_both_can_negotiate() -> None:
    init, accept = _handshake(
        client_features=(COOPERATIVE_CLAIM_FEATURE,),
        provider_features=(COOPERATIVE_CLAIM_FEATURE,),
    )
    with pytest.raises(ValueError, match="unknown feature"):
        accept.validate_against(init, supported_features=set())
    accept.validate_against(init, supported_features={COOPERATIVE_CLAIM_FEATURE})
    legacy_init, legacy_accept = _handshake(client_features=(), provider_features=())
    legacy_accept.validate_against(legacy_init, supported_features=set())
    assert legacy_init.model_dump(mode="json") == CONTEXT["handshake_init"]
    assert legacy_accept.model_dump(mode="json") == CONTEXT["handshake_accept"]


def test_contract_feature_matches_both_authenticated_handshake_halves() -> None:
    record = json.loads(FIXTURE.read_text())
    terms_document = record["contract_terms"]
    init, accept = _handshake(
        client_features=(COOPERATIVE_CLAIM_FEATURE,),
        provider_features=(COOPERATIVE_CLAIM_FEATURE,),
    )
    terms_document["required_features"] = [COOPERATIVE_CLAIM_FEATURE]
    terms = ContractTerms.model_validate_json(json.dumps(terms_document), strict=True)
    require_supported_contract_features(terms, init, accept)
    legacy_init, legacy_accept = _handshake(client_features=(), provider_features=())
    for selected_init, selected_accept in (
        (init, legacy_accept),
        (legacy_init, accept),
        (legacy_init, legacy_accept),
    ):
        with pytest.raises(ValueError, match="not bound to both"):
            require_supported_contract_features(terms, selected_init, selected_accept)
    terms_document["required_features"] = []
    legacy_terms = ContractTerms.model_validate_json(json.dumps(terms_document), strict=True)
    require_supported_contract_features(legacy_terms, legacy_init, legacy_accept)
    with pytest.raises(ValueError, match="not bound to both"):
        require_supported_contract_features(legacy_terms, init, accept)
    terms_document["required_features"] = ["unknown-feature/v1"]
    unknown = ContractTerms.model_validate_json(json.dumps(terms_document), strict=True)
    with pytest.raises(ValueError, match="unsupported contract feature"):
        require_supported_contract_features(unknown, init, accept)
