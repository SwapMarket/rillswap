"""Balance-aware discounts: per-quote evidence, the rebate guard, and its wiring."""

from __future__ import annotations

import asyncio
import json
from dataclasses import fields, replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from evm_fixtures import evm_terms
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.quotes import FirmQuoteRequest, TermsOfferPayload
from test_dynamic_network_fees import EXTENSIONS, POLICY_FEES, priced
from test_evm_quote_policy import FORWARD_FIRM, _offered
from test_evm_quote_policy import FORWARD_TERMS as EVM_FORWARD_TERMS
from test_evm_quote_policy import HOLD as EVM_HOLD
from test_evm_quote_policy import REVERSE_FIRM as EVM_REVERSE_FIRM
from test_evm_quote_policy import REVERSE_TERMS as EVM_REVERSE_TERMS
from test_handshake_hold_invoice import POLICY as SERVICE_POLICY
from test_handshake_hold_invoice import _document, _service
from test_quote_policy import FIRM, FIRM_TERMS, _context, _envelope
from test_reverse_quote_policy import HOLD, REVERSE_FIRM
from test_reverse_quote_policy import TERMS as REVERSE_TERMS
from test_route_readiness import _Lightning, _ready

from rill_provider.balance_pricing import quantized_adjustment_sat
from rill_provider.dynamic_pricing import (
    DynamicPricing,
    FeeLimits,
    LiquiditySample,
    LiquiditySampler,
    TokenPricing,
)
from rill_provider.evm_quote_policy import answer_evm_quote, ln_to_erc20_hold_msat
from rill_provider.live_session_store import PricingCommitments, RequestContext
from rill_provider.provider_identity import AnnouncementTerms
from rill_provider.quote_policy import (
    ClaimFeeRate,
    QuoteTerms,
    answer_quote,
    granted_rebate,
    hold_invoice_msat,
    normal_success_fee,
    success_fee,
)

LIMITS = FeeLimits(
    min_service_fee_ppm=-1000,
    rebate_budget_sat=100_000,
    btc_reserve_target_sat=1_000_000,
    stable_reserve_target_usd=1_000,
)
TOKEN = evm_terms("erc20-to-ln/v1").evm_asset
USDC = TokenPricing(TOKEN.token_contract, TOKEN.token_decimals, 100_000_000_000)  # $100k/BTC


def _sample(
    outbound: int, reserve: int, *, name: str = "btc", capacity: int = 1_000_000
) -> LiquiditySample:
    return LiquiditySample(outbound, outbound, capacity, {name: (reserve, reserve)})


def _fee(  # noqa: PLR0913 - one scenario's explicit parts
    profile: str,
    sample: LiquiditySample,
    principal: int,
    *,
    volume: int = 0,
    committed: int = 0,
    limits: FeeLimits = LIMITS,
    token: TokenPricing | None = None,
) -> int:
    normal = 100 + -(-principal * 1000 // 1_000_000)  # 100 sat + 0.1 %
    pricing = DynamicPricing(limits, sample, volume, committed)
    return pricing.service_fee(
        profile=profile, normal_fee_sat=normal, principal_sat=principal, token=token
    )


@pytest.mark.parametrize(
    ("profile", "sample", "principal", "fee"),
    [
        # Too much outbound and an empty BTC reserve: BTC to LN repairs both.
        # The -950 sat discount is capped by the -0.1 % floor: a 100 sat rebate.
        ("btc-to-ln/v1", _sample(900_000, 0), 100_000, -100),
        # The opposite direction deepens both shortages: the normal fee, never more.
        ("ln-to-btc/v1", _sample(900_000, 0), 100_000, 200),
        # Outbound short, reserve healthy: an 83 sat repair is discounted by
        # six whole 12 sat steps (0.025 % of the principal), 72 sat.
        ("ln-to-btc/v1", _sample(300_000, 2_000_000), 50_000, 78),
        # Inside the band and above target: no shortage to repair.
        ("btc-to-ln/v1", _sample(500_000, 2_000_000), 50_000, 150),
    ],
)
def test_worked_examples(profile: str, sample: LiquiditySample, principal: int, fee: int) -> None:
    assert _fee(profile, sample, principal) == fee


@pytest.mark.parametrize(
    ("adjustment", "principal", "quantized"),
    [(-83, 50_000, -72), (-11, 50_000, 0), (5, 50_000, 5), (-1, 100, -1), (0, 10, 0)],
)
def test_discounts_move_in_coarse_steps_toward_zero(
    adjustment: int, principal: int, quantized: int
) -> None:
    assert quantized_adjustment_sat(adjustment, principal) == quantized


@pytest.mark.parametrize(
    ("volume", "fee"), [(0, 78), (50_000, 102), (100_000, 138), (200_000, 150)]
)
def test_open_offers_only_ever_shrink_the_discount(volume: int, fee: int) -> None:
    assert _fee("ln-to-btc/v1", _sample(300_000, 2_000_000), 50_000, volume=volume) == fee


@pytest.mark.parametrize(("committed", "fee"), [(99_960, -40), (100_000, 0), (200_000, 0)])
def test_the_rebate_budget_bounds_a_negative_fee(committed: int, fee: int) -> None:
    assert _fee("btc-to-ln/v1", _sample(900_000, 0), 100_000, committed=committed) == fee


@pytest.mark.parametrize(("outbound", "usd"), [(900_000, 500), (600_000, 900)])
def test_token_reserves_are_valued_at_one_usd_per_token(outbound: int, usd: int) -> None:
    # $1,000 at $100k/BTC is a 1,000,000 sat target, exactly the BTC case.
    tokens = _sample(outbound, usd * 10**6, name=USDC.contract)
    bitcoin = _sample(outbound, usd * 1_000)
    priced_tokens = _fee("erc20-to-ln/v1", tokens, 20_000, token=USDC)
    assert priced_tokens == _fee("btc-to-ln/v1", bitcoin, 20_000)
    assert priced_tokens < 120  # a real discount, not the normal fee


@pytest.mark.parametrize(
    ("sample", "limits", "token"),
    [
        (LiquiditySample(900_000, 900_000, 1_000_000, {}), LIMITS, None),  # reserve unobserved
        (_sample(900_000, 0), replace(LIMITS, btc_reserve_target_sat=None), None),
        (
            _sample(900_000, 0, name=USDC.contract),
            replace(LIMITS, stable_reserve_target_usd=None),
            USDC,
        ),
        (_sample(900_000, 0, name=USDC.contract), LIMITS, replace(USDC, rate_token_base_per_btc=0)),
        (_sample(0, 0, capacity=0), LIMITS, None),  # no channels
        (LiquiditySample(900_000, 800_000, 1_000_000, {"btc": (0, 0)}), LIMITS, None),
    ],
)
def test_unknown_or_unsupported_evidence_prices_the_normal_fee(
    sample: LiquiditySample, limits: FeeLimits, token: TokenPricing | None
) -> None:
    assert _fee("btc-to-ln/v1", sample, 100_000, limits=limits, token=token) == 200


def test_the_sampler_caches_values_and_failures(caplog: pytest.LogCaptureFixture) -> None:
    now = [0.0]
    first, second = _sample(1, 1), _sample(2, 2)
    read = Mock(side_effect=[first, RuntimeError("secret macaroon path"), second])
    sampler = LiquiditySampler(read, cache_seconds=15, clock=lambda: now[0])
    observed = []
    for at in (0, 14, 15, 29, 30):
        now[0] = at
        observed.append(sampler())
    assert observed == [first, first, None, None, second]
    assert read.call_count == 3
    assert "liquidity sample unavailable (RuntimeError)" in caplog.text
    assert "secret" not in caplog.text


def test_announcements_cannot_carry_private_pricing() -> None:
    announced = {field.name for field in fields(AnnouncementTerms)}
    private = {field.name for field in fields(FeeLimits)} | {"dynamic_fees"}
    assert not announced & private


DYNAMIC = DynamicPricing(LIMITS, _sample(500_000, 2_000_000), 0, 0)


@pytest.mark.parametrize(
    ("service", "dynamic", "committed", "rebate"),
    [
        (5, DYNAMIC, None, 0),  # no rebate needs no budget
        (0, None, None, 0),
        (-100, DYNAMIC, 0, 100),
        (-100, DYNAMIC, 99_900, 100),  # exactly the remaining budget
        (-100, DYNAMIC, 99_901, None),
        (-100, DYNAMIC, None, None),  # unknown commitments grant nothing
        (-100, None, 0, None),  # a rebate without configured limits is refused
    ],
)
def test_a_rebate_must_fit_the_budget_committed_in_this_transaction(
    service: int, dynamic: DynamicPricing | None, committed: int | None, rebate: int | None
) -> None:
    context = replace(_context(), rebates_committed_sat=committed)
    assert granted_rebate(replace(FIRM_TERMS, dynamic=dynamic), context, service) == rebate


def _rebated(terms: QuoteTerms, service: str = "-100") -> QuoteTerms:
    terms = priced(terms)
    assert terms.fee_breakdown is not None
    breakdown = terms.fee_breakdown.model_copy(update={"service_fee_sat": service})
    return replace(terms, fee_breakdown=breakdown, dynamic=DYNAMIC)


def _bitcoin_context(committed: int | None) -> RequestContext:
    return replace(_context(), cooperative=True, network_fees=True, rebates_committed_sat=committed)


@pytest.mark.parametrize("committed", [0, 99_901, None])
def test_a_forward_firm_offer_reports_the_rebate_it_grants(committed: int | None) -> None:
    request = FirmQuoteRequest.model_validate(FIRM | {"extensions": EXTENSIONS})
    terms = _rebated(FIRM_TERMS)
    answer = answer_quote(
        SimpleNamespace(payload=request.model_dump(mode="json")),
        (),
        _bitcoin_context(committed),
        terms,
    )
    if committed != 0:
        assert (answer.message_type, answer.payload["message"]) == (
            "error",
            "firm quotes temporarily unavailable",
        )
        assert answer.payload["code"] == "capacity_unavailable"
        assert answer.rebate_sat == 0
        return
    assert answer.message_type == "terms_offer", answer.payload
    assert answer.rebate_sat == 100
    offer = parse_model_json(TermsOfferPayload, canonicalize(answer.payload))
    assert offer.terms.contract_terms.economics.success_fee_sat == "54"  # -100 + 154 network
    assert success_fee(terms, 100_000) == 54
    assert normal_success_fee(terms, 100_000) == 354


def test_a_reverse_firm_offer_reports_the_rebate_its_hold_already_carries() -> None:
    terms = _rebated(REVERSE_TERMS)
    expected = hold_invoice_msat(terms, SimpleNamespace(**REVERSE_FIRM))
    assert expected == 100_554_000  # 300 sat less than the undiscounted hold
    hold = HOLD.model_copy(update={"amount_msat": str(expected), "expires_at": terms.now + 3600})
    request = REVERSE_FIRM | {
        "extensions": EXTENSIONS,
        "limits": REVERSE_FIRM["limits"] | {"max_success_fee_sat": "1000"},
    }
    answer = answer_quote(
        SimpleNamespace(payload=request),
        (),
        _bitcoin_context(0),
        replace(terms, hold=("lnbcrt1hold", hold)),
    )
    assert answer.message_type == "terms_offer", answer.payload
    assert answer.rebate_sat == 100


def test_route_readiness_is_bounded_by_the_normal_fee() -> None:
    lightning = _Lightning()
    _ready(lightning, _rebated(FIRM_TERMS))
    (call,) = lightning.calls
    # min(advertised service fee 200, 0.1 % routing cap) = 100, not the 54 sat
    # discounted success fee.
    assert call["fee_limit_sat"] == 100


def _evm_dynamic(outbound: int, reserve: int) -> DynamicPricing:
    return DynamicPricing(LIMITS, _sample(outbound, reserve, name=USDC.contract), 0, 0)


def test_an_evm_forward_rebate_lowers_the_token_lock() -> None:
    terms = replace(EVM_FORWARD_TERMS, dynamic=_evm_dynamic(900_000, 0))
    answer = answer_evm_quote(
        _envelope(FORWARD_FIRM), (), replace(_context(), rebates_committed_sat=0), terms
    )
    assert answer.message_type == "terms_offer", answer.payload
    assert answer.rebate_sat == 100
    assert _offered(answer).htlc_amount_token_base == 100_000_000 - 100_000  # -100 sat in tokens
    refused = answer_evm_quote(_envelope(FORWARD_FIRM), (), _context(), terms)
    assert refused.payload["message"] == "firm quotes temporarily unavailable"


def test_an_evm_reverse_hold_and_offer_agree_on_the_discount() -> None:
    from rill_core.wire.quotes import parse_quote_request  # noqa: PLC0415

    terms = replace(EVM_REVERSE_TERMS, dynamic=_evm_dynamic(100_000, 10**12))
    request = parse_quote_request(canonicalize(EVM_REVERSE_FIRM | {"extensions": {}}))
    hold_msat = ln_to_erc20_hold_msat(terms, request)  # type: ignore[arg-type]
    assert hold_msat == 99_900_000  # E + S with S = -100 sat
    hold = EVM_HOLD.model_copy(update={"amount_msat": str(hold_msat)})
    answer = answer_evm_quote(
        _envelope(EVM_REVERSE_FIRM),
        (),
        replace(_context(), rebates_committed_sat=0),
        replace(terms, hold=("lnbcrt1hold", hold)),
    )
    assert answer.message_type == "terms_offer", answer.payload
    assert answer.rebate_sat == 100
    assert _offered(answer).economics.model_dump()["hold_invoice_sat"] == "99900"


@pytest.mark.parametrize(("dynamic", "service"), [(None, "200"), (_sample(100_000, 10**9), "-100")])
def test_the_breakdown_freezes_the_discounted_service_fee(
    dynamic: LiquiditySample | None, service: str
) -> None:
    claim_fee = Mock(return_value=ClaimFeeRate(1000, 1000))
    svc, _ = _service(None, claim_fee=claim_fee)
    document = json.loads(_document(REVERSE_FIRM))
    document["payload"]["extensions"] = EXTENSIONS
    pricing = None if dynamic is None else DynamicPricing(LIMITS, dynamic, 0, 0)
    terms = replace(REVERSE_TERMS, fee_policy=POLICY_FEES, dynamic=pricing)
    frozen = asyncio.run(svc._network_pricing(canonicalize(document), terms))  # noqa: SLF001
    assert frozen.fee_breakdown is not None
    assert frozen.fee_breakdown.service_fee_sat == service
    assert int(service) <= POLICY_FEES.service_fee(100_000)


def _pricing_service(sample: Any, store_result: Any) -> tuple[Any, Mock]:  # noqa: ANN401
    service, store = _service(None, policy=replace(SERVICE_POLICY, dynamic_fees=LIMITS))
    service._liquidity_sample = sample  # noqa: SLF001
    if isinstance(store_result, Exception):
        store.pricing_commitments.side_effect = store_result
    else:
        store.pricing_commitments.return_value = store_result
    return service, store


def test_each_quote_prices_from_the_sample_and_this_stores_commitments() -> None:
    sample = _sample(1, 2)
    service, store = _pricing_service(lambda: sample, PricingCommitments(5_000, 300))
    pricing = asyncio.run(service._dynamic_pricing(1_700_000_000))  # noqa: SLF001
    assert pricing == DynamicPricing(LIMITS, sample, 5_000, 300)
    store.pricing_commitments.assert_called_once_with(1_700_000_000)


def _failing() -> LiquiditySample:
    raise RuntimeError("down")


@pytest.mark.parametrize(
    ("sample", "store_result"),
    [
        (lambda: None, PricingCommitments(0, 0)),  # balances unknown
        (_failing, PricingCommitments(0, 0)),
        (lambda: _sample(1, 2), PricingCommitments(None, 0)),  # an open offer unmeasured
        (lambda: _sample(1, 2), RuntimeError("store")),
    ],
)
def test_unknown_evidence_prices_quotes_normally(sample: Any, store_result: Any) -> None:  # noqa: ANN401
    service, _ = _pricing_service(sample, store_result)
    assert asyncio.run(service._dynamic_pricing(1_700_000_000)) is None  # noqa: SLF001


def test_without_dynamic_fees_nothing_is_sampled() -> None:
    sample = Mock()
    service, store = _service(None)
    service._liquidity_sample = sample  # noqa: SLF001
    assert asyncio.run(service._dynamic_pricing(1_700_000_000)) is None  # noqa: SLF001
    sample.assert_not_called()
    store.pricing_commitments.assert_not_called()
