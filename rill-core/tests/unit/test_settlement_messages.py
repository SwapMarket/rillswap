from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.settlement_messages import (
    AckPayload,
    FundingBindingPayload,
    TermsAcceptPayload,
    parse_observation,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "wire-v1" / "settlement-v1.json"
VECTORS = json.loads(FIXTURE.read_text())
PARSERS: dict[str, Any] = {
    "termsAccept": lambda raw: parse_model_json(TermsAcceptPayload, raw),
    "fundingBindingMessage": lambda raw: parse_model_json(FundingBindingPayload, raw),
    "ack": lambda raw: parse_model_json(AckPayload, raw),
    "observation": parse_observation,
}


@pytest.mark.parametrize("definition", sorted(PARSERS))
def test_shared_vectors_parse_exactly_like_the_schema(definition: str) -> None:
    parse = PARSERS[definition]
    for case in VECTORS["valid"][definition]:
        assert parse(canonicalize(case)).model_dump(mode="json") == case
    for case in VECTORS["invalid"][definition]:
        with pytest.raises((ValidationError, ValueError)):
            parse(canonicalize(case))


def test_fixture_copy_matches_the_specification_vectors() -> None:
    source = Path(__file__).parents[3] / "rill-docs" / "vectors" / "wire" / "settlement-v1.json"
    if not source.exists():
        pytest.skip("rill-docs not checked out beside rill-core")
    assert FIXTURE.read_bytes() == source.read_bytes()
