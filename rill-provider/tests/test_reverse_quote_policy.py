"""LN to BTC quote answers (RS-004): indicative offers, firm terms, closed refusals."""

from __future__ import annotations

import copy
from types import SimpleNamespace
from typing import Any

import pytest
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.messages import InvoiceBinding
from rill_core.wire.quotes import QuoteError, TermsOfferPayload, parse_quote_request
from rill_core.wire.reverse_quotes import (
    ReverseFirmQuoteRequest,
    ReverseQuoteOffer,
    check_reverse_terms_offer,
)
from test_quote_policy import CONTRACT, FIRM, HANDSHAKE, SIGNER, _context

from rill_provider.quote_policy import QuoteSchedule, QuoteTerms, answer_quote, hold_invoice_msat

HASH = "16b72cfab7dbca73cb348f4e59a74b5c56d6e95574c1e9ca84850d69f5fa9430"
SCHEDULE = QuoteSchedule(
    max_claim_fee_sat=400,
    reverse_refund_delay_blocks=144,
    refund_and_ln_resolution_blocks=40,
    claim_fee_reserve_sat=500,
)
TERMS = QuoteTerms(
    amount_bands=((1_000, 100_000),),
    base_fee_sat=50,
    proportional_millionths=1_500,
    schedule=SCHEDULE,
    tip_height=850,
    now=1_700_000_000,
    firm=SIGNER,
    profile="ln-to-btc/v1",
)
# D=100000, C=500, S=50+150=200, V=100500, H=100700
HOLD = InvoiceBinding.model_validate(
    {
        "bolt11_sha256": "78" * 32,
        "payment_hash": HASH,
        "amount_msat": "100700000",
        "payee_compressed_pubkey": "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",  # noqa: E501
        "created_at": 1_700_000_000,
        "expires_at": 1_700_001_800,
        "min_final_cltv_delta": 185,
    }
)
INDICATIVE = {"kind": "ln-to-btc", "mode": "indicative", "nominal_payout_sat": "100000"}
REVERSE_FIRM = {
    "kind": "ln-to-btc",
    "mode": "firm",
    "nominal_payout_sat": "100000",
    "payment_hash": HASH,
    "client_contract_compressed_key": CONTRACT["client_contract_compressed_key"],
    "recovery_authorization_xonly_key": CONTRACT["recovery_authorization_xonly_key"],
    "client_destination_script": CONTRACT["client_destination_script"],
    "limits": {
        "max_success_fee_sat": "200",
        "min_claim_fee_reserve_sat": "500",
        "max_claim_fee_sat": "400",
        "min_refund_lock_height": 993,
        "max_incoming_htlc_expiry_height": 1035,
    },
}


def _envelope(payload: dict[str, Any]) -> Any:  # noqa: ANN401 - only .payload is read
    return SimpleNamespace(payload=payload | {"extensions": {}})


def _with(**changes: Any) -> QuoteTerms:  # noqa: ANN401
    return QuoteTerms(**{name: getattr(TERMS, name) for name in TERMS.__slots__} | changes)


def _answer(
    payload: dict[str, Any],
    prior: int = 0,
    reserved: tuple[str, ...] = (),
    **changes: Any,  # noqa: ANN401
) -> Any:  # noqa: ANN401
    return answer_quote(
        _envelope(payload),
        tuple(_envelope(INDICATIVE) for _ in range(prior)),
        _context(reserved),
        _with(**changes),
    )


def _error(answer: Any) -> str:  # noqa: ANN401
    assert answer.message_type == "error"
    return parse_model_json(QuoteError, canonicalize(answer.payload)).code


def test_indicative_reverse_quote_prices_the_hold_invoice() -> None:
    answer = _answer(INDICATIVE)
    assert answer.message_type == "quote_offer"
    offer = parse_model_json(ReverseQuoteOffer, canonicalize(answer.payload))
    assert offer.economics.model_dump() == {
        "kind": "ln-to-btc",
        "contract_amount_sat": "100500",
        "nominal_payout_sat": "100000",
        "claim_fee_reserve_sat": "500",
        "success_fee_sat": "200",
        "mining_prepayment_sat": "0",
        "hold_invoice_sat": "100700",
    }
    assert (offer.refund_delay_blocks, offer.incoming_htlc_expiry_delta_blocks) == (144, 185)
    assert hold_invoice_msat(TERMS, 100_000) == 100_700_000
    assert _error(_answer(INDICATIVE | {"nominal_payout_sat": "999"})) == "amount_out_of_range"
    assert _error(_answer(INDICATIVE, tip_height=None)) == "capacity_unavailable"
    assert _error(_answer(INDICATIVE, prior=8)) == "unsupported_request"


def test_kind_must_match_the_served_profile() -> None:
    assert _error(_answer(INDICATIVE, profile="btc-to-ln/v1")) == "unsupported_request"
    assert _error(_answer(FIRM)) == "unsupported_request"  # a BTC to LN request here


def test_firm_reverse_request_gets_terms_binding_the_hold_invoice() -> None:
    answer = _answer(REVERSE_FIRM, hold=("lnbcrt1007u1hold", HOLD))
    assert answer.message_type == "terms_offer", answer.payload
    assert answer.payment_hash == HASH
    offer = parse_model_json(TermsOfferPayload, canonicalize(answer.payload))
    assert offer.hold_invoice == "lnbcrt1007u1hold"
    request = parse_quote_request(canonicalize(REVERSE_FIRM | {"extensions": {}}))
    assert isinstance(request, ReverseFirmQuoteRequest)
    check_reverse_terms_offer(request, offer, handshake_hash=HANDSHAKE, invoice_binding=HOLD)
    terms = offer.terms.contract_terms
    assert (terms.claimant, terms.refund_party) == ("client", "provider")
    assert terms.refund_lock_height == 850 + 144 - 1
    timing = terms.timing_policy.model_dump()
    assert timing["min_incoming_htlc_expiry_height"] == 850 + 185
    assert terms.terms_expiry == 1_700_000_000  # hold expiry minus the required remainder
    assert answer.contract_hash == offer.terms.contract_hash


def _limits(**changes: Any) -> dict[str, Any]:  # noqa: ANN401
    payload = copy.deepcopy(REVERSE_FIRM)
    payload["limits"].update(changes)
    return payload


@pytest.mark.parametrize(
    ("payload", "changes", "code"),
    [
        (REVERSE_FIRM, {"firm": None}, "unsupported_request"),
        (REVERSE_FIRM | {"nominal_payout_sat": "500"}, {}, "amount_out_of_range"),
        (REVERSE_FIRM, {"hold": None}, "capacity_unavailable"),
        (REVERSE_FIRM, {"hold": "unavailable"}, "capacity_unavailable"),
        (REVERSE_FIRM, {"tip_height": None}, "capacity_unavailable"),
        (  # the opened hold invoice must carry the request's hash and exactly H
            REVERSE_FIRM,
            {"hold": ("lnbcrt1", HOLD.model_copy(update={"payment_hash": "ab" * 32}))},
            "capacity_unavailable",
        ),
        (
            REVERSE_FIRM,
            {"hold": ("lnbcrt1", HOLD.model_copy(update={"amount_msat": "100600000"}))},
            "capacity_unavailable",
        ),
        (
            REVERSE_FIRM,
            {"hold": ("lnbcrt1", HOLD.model_copy(update={"min_final_cltv_delta": 184}))},
            "capacity_unavailable",
        ),
        (_limits(max_success_fee_sat="199"), {}, "limits_unsatisfiable"),
        (_limits(min_claim_fee_reserve_sat="501"), {}, "limits_unsatisfiable"),
        (_limits(max_claim_fee_sat="399"), {}, "limits_unsatisfiable"),
        (_limits(min_refund_lock_height=994), {}, "limits_unsatisfiable"),
        (_limits(max_incoming_htlc_expiry_height=1034), {}, "limits_unsatisfiable"),
        (
            REVERSE_FIRM
            | {"client_contract_compressed_key": CONTRACT["provider_contract_compressed_key"]},
            {},
            "request_unacceptable",
        ),
    ],
)
def test_firm_reverse_refusals_use_closed_codes(
    payload: dict[str, Any], changes: dict[str, Any], code: str
) -> None:
    hold = changes.pop("hold", ("lnbcrt1007u1hold", HOLD))
    assert _error(_answer(payload, hold=hold, **changes)) == code


def test_reserved_hash_and_later_firm_requests_are_refused() -> None:
    hold = ("lnbcrt1007u1hold", HOLD)
    assert _error(_answer(REVERSE_FIRM, reserved=(HASH,), hold=hold)) == "request_unacceptable"
    assert _error(_answer(REVERSE_FIRM, prior=1, hold=hold)) == "unsupported_request"


def test_reverse_schedule_windows_must_fit() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        QuoteSchedule(reverse_refund_delay_blocks=44)  # 2 + 36 + 6 = 44 does not fit
    with pytest.raises(ValueError, match="unsupported"):
        QuoteSchedule(hold_invoice_lifetime=100)  # shorter than the terms lifetime
    with pytest.raises(ValueError, match="unsupported"):
        QuoteSchedule(reverse_refund_delay_blocks=2000, refund_and_ln_resolution_blocks=20)
