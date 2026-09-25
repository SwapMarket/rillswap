"""Pure quote answers always match the RS-003 models."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.quotes import QuoteError, QuoteOffer

from rill_provider.quote_policy import QuoteSchedule, QuoteTerms, answer_quote

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
    "client_contract_compressed_key": "02"
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "recovery_authorization_xonly_key": "79be667ef9dcbbac55a06295ce870b07"
    "029bfcdb2dce28d959f2815b16f81798",
    "client_destination_script": "0014" + "31" * 20,
    "limits": {
        "max_success_fee_sat": "1000",
        "max_funding_fee_sat": "500",
        "max_claim_fee_sat": "400",
        "max_refund_fee_sat": "600",
        "max_refund_lock_height": 1100,
    },
}


def _envelope(payload: dict[str, Any]) -> Any:  # noqa: ANN401 - only .payload is read
    return SimpleNamespace(payload=payload | {"extensions": {}})


def _answer(payload: dict[str, Any], prior: int = 0, **changes: Any) -> tuple[str, Any]:  # noqa: ANN401
    terms = QuoteTerms(**{name: getattr(TERMS, name) for name in TERMS.__slots__} | changes)
    kind, body = answer_quote(
        _envelope(payload), tuple(_envelope(INDICATIVE) for _ in range(prior)), terms
    )
    model = QuoteOffer if kind == "quote_offer" else QuoteError
    return kind, parse_model_json(model, canonicalize(body))


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
        (FIRM, 0, {}, "unsupported_request"),
        (FIRM, 1, {}, "unsupported_request"),
    ],
)
def test_refusals_use_closed_codes(
    payload: dict[str, Any], prior: int, changes: dict[str, Any], code: str
) -> None:
    kind, error = _answer(payload, prior, **changes)
    assert kind == "error"
    assert error.code == code


def test_nothing_follows_a_firm_request() -> None:
    kind, body = answer_quote(_envelope(INDICATIVE), (_envelope(FIRM),), TERMS)
    assert (kind, body["code"]) == ("error", "unsupported_request")


def test_schedule_refuses_unrepresentable_values() -> None:
    with pytest.raises(ValueError, match="schedule"):
        QuoteSchedule(lifetime=0)
