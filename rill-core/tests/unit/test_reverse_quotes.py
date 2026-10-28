"""RS-004 quote payloads: request parsing and the client's offer check."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import ContractTerms, InvoiceBinding
from rill_core.wire.quotes import TermsOfferPayload, parse_quote_request
from rill_core.wire.reverse_quotes import (
    ReverseFirmQuoteRequest,
    ReverseIndicativeQuoteRequest,
    ReverseQuoteOffer,
    check_reverse_claim_window,
    check_reverse_terms_offer,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"
REVERSE_TERMS: dict[str, Any] = json.loads(
    (FIXTURES / "recovery-v1" / "initial-ln-to-btc-no-prepayment-v1.json").read_text()
)["contract_terms"]
FORWARD_OFFER: dict[str, Any] = json.loads((FIXTURES / "wire-v1" / "quote-v1.json").read_text())[
    "valid"
]["termsOffer"][0]
HOLD_INVOICE = "lnbcrt1020u1" + "q" * 60
HASH = REVERSE_TERMS["invoice_binding"]["payment_hash"]


def _request(**changes: object) -> dict[str, Any]:
    document: dict[str, Any] = {
        "kind": "ln-to-btc",
        "mode": "firm",
        "nominal_payout_sat": "100000",
        "payment_hash": HASH,
        "client_contract_compressed_key": REVERSE_TERMS["client_contract_compressed_key"],
        "recovery_authorization_xonly_key": REVERSE_TERMS["recovery_authorization_xonly_key"],
        "client_destination_script": REVERSE_TERMS["client_destination_script"],
        "limits": {
            "max_success_fee_sat": "1500",
            "min_claim_fee_reserve_sat": "500",
            "max_claim_fee_sat": "400",
            "min_refund_lock_height": 1100,
            "max_incoming_htlc_expiry_height": 1130,
        },
        "extensions": {},
    }
    document.update(changes)
    return document


def _firm(**changes: object) -> ReverseFirmQuoteRequest:
    request = parse_quote_request(canonicalize(_request(**changes)))
    assert isinstance(request, ReverseFirmQuoteRequest)
    return request


def _offer(terms_changes: dict[str, Any] | None = None, **payload: object) -> TermsOfferPayload:
    terms = copy.deepcopy(REVERSE_TERMS)
    terms.update(terms_changes or {})
    document = copy.deepcopy(FORWARD_OFFER)
    document["terms"]["contract_terms"] = terms
    document["terms"]["contract_hash"] = contract_hash(
        parse_model_json(ContractTerms, canonicalize(terms))
    ).hex()
    document["hold_invoice"] = HOLD_INVOICE
    document.update(payload)
    return parse_model_json(TermsOfferPayload, canonicalize(document))


def _binding(**changes: object) -> InvoiceBinding:
    return InvoiceBinding.model_validate({**REVERSE_TERMS["invoice_binding"], **changes})


def test_reverse_requests_parse_by_kind_and_mode() -> None:
    indicative = parse_quote_request(
        canonicalize(
            {"kind": "ln-to-btc", "mode": "indicative", "nominal_payout_sat": "5", "extensions": {}}
        )
    )
    assert isinstance(indicative, ReverseIndicativeQuoteRequest)
    assert _firm().limits.min_refund_lock_height == 1100
    with pytest.raises(ValueError, match="kind or mode unsupported"):
        parse_quote_request(canonicalize({"kind": "ln-to-btc", "mode": "soft"}))
    for bad in (
        {"nominal_payout_sat": "0"},
        {"payment_hash": "zz" * 32},
        {"client_destination_script": "6a"},
        {"limits": {**_request()["limits"], "max_success_fee_sat": "-1"}},
    ):
        with pytest.raises((ValidationError, ValueError)):
            parse_quote_request(canonicalize(_request(**bad)))


def test_terms_offer_hold_invoice_is_required_for_ln_to_btc_only() -> None:
    offer = _offer()
    assert offer.hold_invoice == HOLD_INVOICE
    assert json.loads(offer.model_dump_json())["hold_invoice"] == HOLD_INVOICE
    with pytest.raises(ValidationError, match="requires a hold invoice"):
        _offer(hold_invoice=None)
    with pytest.raises(ValidationError, match="lowercase BOLT11"):
        _offer(hold_invoice="LNBC1")
    forward = parse_model_json(TermsOfferPayload, canonicalize(FORWARD_OFFER))
    assert forward.hold_invoice is None
    assert "hold_invoice" not in json.loads(forward.model_dump_json())  # RS-003 shape kept
    with pytest.raises(ValidationError, match="carries no hold invoice"):
        parse_model_json(
            TermsOfferPayload, canonicalize({**FORWARD_OFFER, "hold_invoice": HOLD_INVOICE})
        )


def test_reverse_terms_offer_honoring_the_request_passes() -> None:
    offer = _offer()
    check_reverse_terms_offer(
        _firm(), offer, handshake_hash=offer.terms.handshake_hash, invoice_binding=_binding()
    )


@pytest.mark.parametrize(
    ("request_changes", "terms_changes", "binding_changes", "reason"),
    [
        ({"nominal_payout_sat": "99000"}, {}, {}, "payout"),
        ({"payment_hash": "ab" * 32}, {}, {}, "payment hash"),
        ({}, {}, {"amount_msat": "101000000"}, "invoice binding"),
        (
            {"limits": {**_request()["limits"], "max_success_fee_sat": "1499"}},
            {},
            {},
            "success fee",
        ),
        (
            {"limits": {**_request()["limits"], "min_claim_fee_reserve_sat": "501"}},
            {},
            {},
            "claim fee reserve",
        ),
        ({"limits": {**_request()["limits"], "max_claim_fee_sat": "399"}}, {}, {}, "claim fee"),
        # Reserve 500 is above both the asked 100 and the 400 a claim may spend.
        (
            {"limits": {**_request()["limits"], "min_claim_fee_reserve_sat": "100"}},
            {},
            {},
            "inflated claim fee reserve",
        ),
        (
            {"limits": {**_request()["limits"], "min_refund_lock_height": 1101}},
            {},
            {},
            "refund lock height",
        ),
        (
            {"limits": {**_request()["limits"], "max_incoming_htlc_expiry_height": 1129}},
            {},
            {},
            "incoming HTLC expiry",
        ),
        ({"client_destination_script": "0014" + "32" * 20}, {}, {}, "destination"),
    ],
)
def test_reverse_terms_offer_violating_the_request_is_refused(
    request_changes: dict[str, Any],
    terms_changes: dict[str, Any],
    binding_changes: dict[str, Any],
    reason: str,
) -> None:
    offer = _offer(terms_changes)
    with pytest.raises(ValueError, match=reason):
        check_reverse_terms_offer(
            _firm(**request_changes),
            offer,
            handshake_hash=offer.terms.handshake_hash,
            invoice_binding=_binding(**binding_changes),
        )


def test_reverse_claim_fee_reserve_may_reach_the_spendable_claim_fee() -> None:
    # A provider pricing a higher next-block fee than the client may reserve up
    # to its signed claim fee cap, never beyond it.
    offer = _offer({"max_claim_fee_sat": "500"})
    limits = {
        **_request()["limits"],
        "min_claim_fee_reserve_sat": "100",
        "max_claim_fee_sat": "500",
    }
    check_reverse_terms_offer(
        _firm(limits=limits),
        offer,
        handshake_hash=offer.terms.handshake_hash,
        invoice_binding=_binding(),
    )


@pytest.mark.parametrize(
    ("tip", "min_delay", "reason"),
    [
        (1028, 72, None),  # exactly the requested 72 blocks remain
        (1029, 72, "refund delay is shorter"),  # a block found during negotiation
        (1086, 0, None),  # 14 blocks left: funding 2 + response 6 + claim 6
        (1087, 0, "no claim window"),
    ],
)
def test_reverse_claim_window_is_checked_at_a_fresh_tip(
    tip: int, min_delay: int, reason: str | None
) -> None:
    terms = _offer().terms.contract_terms
    assert isinstance(terms, ContractTerms)
    if reason is None:
        check_reverse_claim_window(terms, tip_height=tip, min_refund_delay_blocks=min_delay)
    else:
        with pytest.raises(ValueError, match=reason):
            check_reverse_claim_window(terms, tip_height=tip, min_refund_delay_blocks=min_delay)


def test_reverse_claim_window_refuses_margins_that_swallow_the_delay() -> None:
    timing = {**REVERSE_TERMS["timing_policy"], "claim_confirmation_blocks": 1_000}
    terms = _offer({"timing_policy": timing}).terms.contract_terms
    assert isinstance(terms, ContractTerms)
    with pytest.raises(ValueError, match="no claim window"):
        check_reverse_claim_window(terms, tip_height=1000, min_refund_delay_blocks=72)


def test_reverse_terms_offer_must_bind_the_session() -> None:
    offer = _offer()
    with pytest.raises(ValueError, match="handshake hash"):
        check_reverse_terms_offer(
            _firm(), offer, handshake_hash="00" * 32, invoice_binding=_binding()
        )


def test_reverse_quote_offer_windows_must_be_ordered() -> None:
    document = {
        "kind": "ln-to-btc",
        "indicative": True,
        "economics": REVERSE_TERMS["economics"],
        "funding_confirmations": 2,
        "settlement_confirmations": 3,
        "refund_resolution_confirmations": 4,
        "reference_height": 1000,
        "refund_delay_blocks": 100,
        "incoming_htlc_expiry_delta_blocks": 130,
        "max_funding_fee_sat": "1000",
        "max_claim_fee_sat": "400",
        "max_refund_fee_sat": "400",
        "expires_at": 1700000600,
        "extensions": {},
    }
    assert ReverseQuoteOffer.model_validate(document).refund_delay_blocks == 100
    with pytest.raises(ValidationError, match="after the refund delay"):
        ReverseQuoteOffer.model_validate({**document, "incoming_htlc_expiry_delta_blocks": 100})
