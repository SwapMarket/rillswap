"""Quote answers always match the RS-003 models."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from rill_core.domain.amounts import MAX_SATS
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
from rill_core.wire.types import NetworkIdentity

from rill_provider.live_session_store import RequestContext
from rill_provider.quote_policy import (
    MAX_WIRE_INTEGER,
    FirmSigner,
    QuoteSchedule,
    QuoteTerms,
    answer_quote,
)

FIXTURE = json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())
CONTRACT = FIXTURE["contract_terms"]
BINDING = InvoiceBinding.model_validate_json(json.dumps(CONTRACT["invoice_binding"]), strict=True)
HANDSHAKE = "77" * 32
TERMS = QuoteTerms(
    amount_bands=((1_000, 100_000),),
    base_fee_sat=50,
    proportional_millionths=1_500,
    schedule=QuoteSchedule(),
    tip_height=500,
    now=1_700_000_000,
)
INDICATIVE = {"kind": "btc-to-ln", "mode": "indicative", "lightning_principal_sat": "100000"}
FIRM = {
    "kind": "btc-to-ln",
    "mode": "firm",
    "lightning_principal_sat": "100000",
    "invoice": "lnbcrt1mexample",
    "client_contract_compressed_key": CONTRACT["client_contract_compressed_key"],
    "recovery_authorization_xonly_key": CONTRACT["recovery_authorization_xonly_key"],
    "client_destination_script": CONTRACT["client_destination_script"],
    "limits": {
        "max_success_fee_sat": "1000",
        "max_funding_fee_sat": "500",
        "max_claim_fee_sat": "400",
        "max_refund_fee_sat": "600",
        "max_refund_lock_height": 1100,
    },
}
FIRM_SCHEDULE = QuoteSchedule(
    max_funding_fee_sat=500,
    max_claim_fee_sat=400,
    max_refund_fee_sat=600,
    max_refund_delay_blocks=288,
)
SIGNER = FirmSigner(
    network=NetworkIdentity.model_validate(CONTRACT["network_identity"]),
    provider_identity_key=CONTRACT["provider_identity_key"],
    provider_destination_script=CONTRACT["provider_destination_script"],
    sign=lambda _offer: "11" * 64,
)
FIRM_TERMS = QuoteTerms(
    amount_bands=((1_000, 100_000),),
    base_fee_sat=50,
    proportional_millionths=1_500,
    schedule=FIRM_SCHEDULE,
    tip_height=850,
    now=BINDING.created_at,
    firm=SIGNER,
    invoice=BINDING,
)


def _context(reserved: tuple[str, ...] = ()) -> RequestContext:
    return RequestContext(
        handshake_hash=HANDSHAKE,
        provider_contract_key=CONTRACT["provider_contract_compressed_key"],
        is_payment_hash_reserved=lambda digest: digest in reserved,
    )


def _envelope(payload: dict[str, Any]) -> Any:  # noqa: ANN401 - only .payload is read
    return SimpleNamespace(payload=payload | {"extensions": {}})


def _with(base: QuoteTerms, **changes: Any) -> QuoteTerms:  # noqa: ANN401
    return QuoteTerms(**{name: getattr(base, name) for name in base.__slots__} | changes)


def _answer(payload: dict[str, Any], prior: int = 0, **changes: Any) -> tuple[str, Any]:  # noqa: ANN401
    answer = answer_quote(
        _envelope(payload),
        tuple(_envelope(INDICATIVE) for _ in range(prior)),
        _context(),
        _with(TERMS, **changes),
    )
    model = QuoteOffer if answer.message_type == "quote_offer" else QuoteError
    return answer.message_type, parse_model_json(model, canonicalize(answer.payload))


def test_indicative_quote_prices_with_ceiling_fee_and_expires() -> None:
    kind, offer = _answer(INDICATIVE)
    assert kind == "quote_offer"
    assert offer.economics.success_fee_sat == "200"  # 50 + ceil(100000 * 1500 / 1e6)
    assert offer.economics.contract_amount_sat == "100200"
    assert offer.reference_height == 500
    assert offer.expires_at == TERMS.now + TERMS.schedule.lifetime
    _, odd = _answer(INDICATIVE | {"lightning_principal_sat": "1001"})
    assert odd.economics.success_fee_sat == "52"


@pytest.mark.parametrize(
    ("payload", "prior", "changes", "code"),
    [
        (INDICATIVE | {"lightning_principal_sat": "999"}, 0, {}, "amount_out_of_range"),
        (INDICATIVE | {"lightning_principal_sat": "0"}, 0, {}, "request_unacceptable"),
        (INDICATIVE | {"surprise": 1}, 0, {}, "request_unacceptable"),
        (INDICATIVE, 0, {"tip_height": None}, "capacity_unavailable"),
        (INDICATIVE, 8, {}, "unsupported_request"),
        (FIRM, 0, {}, "unsupported_request"),  # no firm signer configured
        (FIRM, 1, {}, "unsupported_request"),
    ],
)
def test_refusals_use_closed_codes(
    payload: dict[str, Any], prior: int, changes: dict[str, Any], code: str
) -> None:
    kind, error = _answer(payload, prior, **changes)
    assert kind == "error"
    assert error.code == code


def test_anything_after_a_firm_request_is_unsupported_even_if_malformed() -> None:
    answer = answer_quote(_envelope({"mode": "bogus"}), (_envelope(FIRM),), _context(), TERMS)
    assert (answer.message_type, answer.payload["code"]) == ("error", "unsupported_request")


def test_unrepresentable_offer_is_never_produced() -> None:
    kind, error = _answer(INDICATIVE, base_fee_sat=MAX_SATS)
    assert (kind, error.code) == ("error", "capacity_unavailable")
    kind, error = _answer(INDICATIVE, now=MAX_WIRE_INTEGER)
    assert (kind, error.code) == ("error", "capacity_unavailable")
    with pytest.raises(ValueError, match="schedule"):
        QuoteSchedule(funding_confirmations=MAX_WIRE_INTEGER + 1)
    with pytest.raises(ValueError, match="schedule"):
        QuoteSchedule(max_claim_fee_sat=MAX_SATS + 1)
    with pytest.raises(ValueError, match="schedule"):
        QuoteSchedule(lifetime=0)
    with pytest.raises(ValueError, match="schedule"):  # HTLC exposure cannot fit
        QuoteSchedule(max_refund_delay_blocks=200)


def _firm(payload: dict[str, Any] = FIRM, reserved: tuple[str, ...] = (), **changes: Any) -> Any:  # noqa: ANN401
    return answer_quote(_envelope(payload), (), _context(reserved), _with(FIRM_TERMS, **changes))


def test_firm_request_gets_terms_that_honor_it_and_reserve_the_hash() -> None:
    answer = _firm()
    assert answer.message_type == "terms_offer"
    assert answer.payment_hash == BINDING.payment_hash
    offer = parse_model_json(TermsOfferPayload, canonicalize(answer.payload))
    request = parse_quote_request(canonicalize(FIRM | {"extensions": {}}))
    assert isinstance(request, FirmQuoteRequest)
    check_terms_offer(request, offer, handshake_hash=HANDSHAKE, invoice_binding=BINDING)
    terms = offer.terms.contract_terms
    assert terms.refund_lock_height == 1100  # capped by the client limit
    assert terms.timing_policy.model_dump()["max_outgoing_htlc_expiry_height"] == 850 + 144
    assert terms.terms_expiry == BINDING.created_at + 120
    assert answer.contract_hash == offer.terms.contract_hash
    late = _firm(now=BINDING.expires_at - 1850)  # terms never outlive the needed invoice time
    late_terms = parse_model_json(TermsOfferPayload, canonicalize(late.payload)).terms
    assert late_terms.contract_terms.terms_expiry == BINDING.expires_at - 1800
    assert terms.provider_contract_compressed_key == CONTRACT["provider_contract_compressed_key"]
    assert offer.provider_terms_signature == "11" * 64


def _limits(**changes: Any) -> dict[str, Any]:  # noqa: ANN401
    payload = copy.deepcopy(FIRM)
    payload["limits"].update(changes)
    return payload


@pytest.mark.parametrize(
    ("payload", "reserved", "changes", "code"),
    [
        (FIRM | {"lightning_principal_sat": "100001"}, (), {}, "amount_out_of_range"),
        (FIRM | {"lightning_principal_sat": "99999"}, (), {}, "invoice_unacceptable"),
        (FIRM, (BINDING.payment_hash,), {}, "request_unacceptable"),  # no ownership oracle
        (FIRM, (), {"invoice": "rejected"}, "invoice_unacceptable"),
        (FIRM, (), {"invoice": "unavailable"}, "capacity_unavailable"),
        (FIRM, (), {"invoice": None}, "capacity_unavailable"),
        (FIRM, (), {"tip_height": None}, "capacity_unavailable"),
        (FIRM, (), {"now": BINDING.expires_at - 1799}, "invoice_unacceptable"),
        (FIRM, (), {"now": BINDING.created_at - 601}, "invoice_unacceptable"),
        (FIRM, (), {"tip_height": 950}, "limits_unsatisfiable"),
        (_limits(max_success_fee_sat="199"), (), {}, "limits_unsatisfiable"),
        (_limits(max_claim_fee_sat="399"), (), {}, "limits_unsatisfiable"),
        (
            FIRM | {"recovery_authorization_xonly_key": CONTRACT["provider_identity_key"]},
            (),
            {},
            "request_unacceptable",
        ),
    ],
)
def test_firm_refusals_use_closed_codes(
    payload: dict[str, Any], reserved: tuple[str, ...], changes: dict[str, Any], code: str
) -> None:
    answer = _firm(payload, reserved, **changes)
    assert answer.message_type == "error", answer.payload
    assert answer.payment_hash is None
    assert parse_model_json(QuoteError, canonicalize(answer.payload)).code == code
