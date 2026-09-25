from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.messages import InvoiceBinding
from rill_core.wire.quotes import (
    FirmQuoteRequest,
    QuoteError,
    QuoteOffer,
    TermsOfferPayload,
    check_terms_offer,
    parse_quote_request,
)

G_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
VECTORS = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "wire-v1" / "quote-v1.json").read_text()
)
MODELS: dict[str, Any] = {
    "quoteRequest": parse_quote_request,
    "quoteOffer": lambda raw: parse_model_json(QuoteOffer, raw),
    "termsOffer": lambda raw: parse_model_json(TermsOfferPayload, raw),
    "error": lambda raw: parse_model_json(QuoteError, raw),
}


@pytest.mark.parametrize("definition", sorted(MODELS))
def test_shared_vectors_parse_exactly_like_the_schema(definition: str) -> None:
    parse = MODELS[definition]
    for case in VECTORS["valid"][definition]:
        parsed = parse(canonicalize(case))
        assert parsed.model_dump(mode="json") == case
    for case in VECTORS["invalid"][definition]:
        with pytest.raises((ValidationError, ValueError)):
            parse(canonicalize(case))


def _firm() -> FirmQuoteRequest:
    request = parse_quote_request(canonicalize(VECTORS["valid"]["quoteRequest"][1]))
    assert isinstance(request, FirmQuoteRequest)
    return request


def _offer() -> TermsOfferPayload:
    return parse_model_json(TermsOfferPayload, canonicalize(VECTORS["valid"]["termsOffer"][0]))


def test_terms_offer_honoring_the_request_passes() -> None:
    offer = _offer()
    check_terms_offer(
        _firm(),
        offer,
        handshake_hash=offer.terms.handshake_hash,
        invoice_binding=offer.terms.contract_terms.invoice_binding,
    )


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"lightning_principal_sat": "99999"}, "principal"),
        ({"client_contract_compressed_key": "02" + G_X}, "client contract key"),
        ({"recovery_authorization_xonly_key": "22" * 32}, "recovery key"),
        ({"client_destination_script": "5120" + "33" * 32}, "destination"),
        ({"limits": {"max_success_fee_sat": "999"}}, "success fee"),
        ({"limits": {"max_funding_fee_sat": "499"}}, "funding fee"),
        ({"limits": {"max_claim_fee_sat": "399"}}, "claim fee"),
        ({"limits": {"max_refund_fee_sat": "599"}}, "refund fee"),
        ({"limits": {"max_refund_lock_height": 1099}}, "refund lock height"),
    ],
)
def test_terms_offer_violating_the_request_is_refused(change: dict[str, Any], reason: str) -> None:
    raw = copy.deepcopy(VECTORS["valid"]["quoteRequest"][1])
    for key, value in change.items():
        if key == "limits":
            raw["limits"].update(value)
        else:
            raw[key] = value
    request = parse_quote_request(canonicalize(raw))
    assert isinstance(request, FirmQuoteRequest)
    offer = _offer()
    with pytest.raises(ValueError, match=reason):
        check_terms_offer(
            request,
            offer,
            handshake_hash=offer.terms.handshake_hash,
            invoice_binding=offer.terms.contract_terms.invoice_binding,
        )


def test_terms_offer_must_bind_the_session_and_decoded_invoice() -> None:
    offer = _offer()
    binding = offer.terms.contract_terms.invoice_binding
    with pytest.raises(ValueError, match="handshake hash"):
        check_terms_offer(_firm(), offer, handshake_hash="00" * 32, invoice_binding=binding)
    other = InvoiceBinding.model_validate_json(
        json.dumps(binding.model_dump(mode="json") | {"payment_hash": "44" * 32})
    )
    with pytest.raises(ValueError, match="invoice binding"):
        check_terms_offer(
            _firm(), offer, handshake_hash=offer.terms.handshake_hash, invoice_binding=other
        )


def test_unknown_request_mode_is_refused() -> None:
    with pytest.raises(ValueError, match="mode"):
        parse_quote_request(b'{"kind":"btc-to-ln","mode":"binding"}')


def test_fixture_copy_matches_the_specification_vectors() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "wire-v1" / "quote-v1.json"
    source = Path(__file__).parents[3] / "rill-docs" / "vectors" / "wire" / "quote-v1.json"
    if not source.exists():
        pytest.skip("rill-docs not checked out beside rill-core")
    assert fixture.read_bytes() == source.read_bytes()
