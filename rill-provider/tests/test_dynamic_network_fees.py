"""Dynamic BTC fees bind offers, freeze invoices, and preserve legacy stores."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.fee_policy import (
    FEE_MODEL,
    FEE_POLICY_EXTENSION,
    BtcFeePolicy,
    FeeBreakdown,
    FeePolicyRequest,
)
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE, FEE_POLICY_FEATURE
from rill_core.wire.messages import ContractTerms
from rill_core.wire.quotes import FirmQuoteRequest, TermsOfferPayload, check_terms_offer
from test_handshake_hold_invoice import _document, _service
from test_live_session_store import POLICY, Harness
from test_live_session_store import harness as harness  # noqa: PLC0414 - shared store fixture
from test_quote_policy import FIRM, FIRM_TERMS, HANDSHAKE, _context
from test_reverse_quote_policy import HOLD, REVERSE_FIRM
from test_reverse_quote_policy import TERMS as REVERSE_TERMS

from rill_provider.live_session_store import LiveSessionStoreError
from rill_provider.operator_config import (
    BitcoinNetworkFees,
    HandshakeSelection,
    OperatorConfig,
    PublicTerms,
)
from rill_provider.quote_policy import ClaimFeeRate, QuoteTerms, answer_quote, hold_invoice_msat
from rill_provider.settlement_engine import EngineSettings, SettlementEngine

POLICY_FEES = BtcFeePolicy(
    model=FEE_MODEL,
    base_sat="50",
    proportional_millionths=1500,
    max_network_feerate_sat_kvb="5000",
    max_routing_fee_ppm=1000,
)
REQUEST = FeePolicyRequest(
    offer_event_id="11" * 32,
    policy_hash=POLICY_FEES.commitment(),
    max_network_feerate_sat_kvb="3000",
)
EXTENSIONS = {FEE_POLICY_EXTENSION: REQUEST.model_dump(mode="json")}


def priced(terms: QuoteTerms, rate: int = 1000) -> QuoteTerms:
    breakdown = FeeBreakdown(
        offer_event_id=REQUEST.offer_event_id,
        policy=POLICY_FEES,
        feerate_sat_kvb=str(rate),
        estimated_at=terms.now,
        issued_at=terms.now,
        service_fee_sat="200",
        network_fee_sat=str(-(-154 * rate // 1000)),
    )
    return replace(terms, fee_policy=POLICY_FEES, fee_breakdown=breakdown)


def forward_offer() -> tuple[FirmQuoteRequest, TermsOfferPayload]:
    request = FirmQuoteRequest.model_validate(FIRM | {"extensions": EXTENSIONS})
    answer = answer_quote(
        SimpleNamespace(payload=request.model_dump(mode="json")),
        (),
        replace(_context(), cooperative=True, network_fees=True),
        priced(FIRM_TERMS),
    )
    assert answer.message_type == "terms_offer", answer.payload
    return request, parse_model_json(TermsOfferPayload, canonicalize(answer.payload))


def test_firm_quote_adds_network_cost_without_changing_service_coefficients() -> None:
    request, offer = forward_offer()
    terms = offer.terms.contract_terms
    assert isinstance(terms, ContractTerms)
    assert terms.economics.success_fee_sat == "354"
    assert terms.economics.contract_amount_sat == "100354"
    assert terms.terms_expiry == FIRM_TERMS.now + 60
    assert terms.required_features == (FEE_POLICY_FEATURE, COOPERATIVE_CLAIM_FEATURE)
    check_terms_offer(
        request, offer, handshake_hash=HANDSHAKE, invoice_binding=terms.invoice_binding
    )


@pytest.mark.parametrize("featured", [False, True])
def test_custom_indicative_lifetimes_only_change_for_featured_quotes(*, featured: bool) -> None:
    terms = replace(FIRM_TERMS, schedule=replace(FIRM_TERMS.schedule, lifetime=300))
    if featured:
        terms = priced(terms)
    request = {
        "kind": "btc-to-ln",
        "mode": "indicative",
        "lightning_principal_sat": "100000",
        "extensions": EXTENSIONS if featured else {},
    }
    answer = answer_quote(
        SimpleNamespace(payload=request),
        (),
        replace(_context(), network_fees=featured),
        terms,
    )
    assert answer.message_type == "quote_offer"
    assert answer.payload["expires_at"] == terms.now + (60 if featured else 300)


def test_reverse_invoice_and_firm_quote_use_exactly_the_same_frozen_sample() -> None:
    terms = priced(REVERSE_TERMS)
    expected = hold_invoice_msat(terms, SimpleNamespace(**REVERSE_FIRM))
    assert expected == 100_854_000
    hold = HOLD.model_copy(update={"amount_msat": str(expected), "expires_at": terms.now + 3600})
    request = REVERSE_FIRM | {
        "extensions": EXTENSIONS,
        "limits": REVERSE_FIRM["limits"] | {"max_success_fee_sat": "1000"},
    }
    answer = answer_quote(
        SimpleNamespace(payload=request),
        (),
        replace(_context(), cooperative=True, network_fees=True),
        replace(terms, hold=("lnbcrt1hold", hold), now=terms.now + 5),
    )
    assert answer.message_type == "terms_offer", answer.payload
    offered = parse_model_json(TermsOfferPayload, canonicalize(answer.payload)).terms.contract_terms
    assert offered.invoice_binding.amount_msat == str(expected)
    assert offered.terms_expiry == REVERSE_TERMS.now + 60  # Backend work cannot renew it.


@pytest.mark.parametrize(
    "change", [{"policy_hash": "22" * 32}, {"max_network_feerate_sat_kvb": "999"}]
)
def test_request_limits_are_checked_before_returning_terms(change: dict[str, Any]) -> None:
    request = FIRM | {
        "extensions": {FEE_POLICY_EXTENSION: REQUEST.model_dump(mode="json") | change}
    }
    answer = answer_quote(
        SimpleNamespace(payload=request),
        (),
        replace(_context(), network_fees=True),
        priced(FIRM_TERMS),
    )
    assert answer.message_type == "error"


def test_network_quote_expiry_is_not_renewed_by_backend_preparation() -> None:
    terms = priced(FIRM_TERMS)
    answer = answer_quote(
        SimpleNamespace(payload=FIRM | {"extensions": EXTENSIONS}),
        (),
        replace(_context(), network_fees=True),
        replace(terms, now=terms.now + 60),
    )
    assert answer.message_type == "error"
    assert answer.payload["code"] == "capacity_unavailable"


def test_other_profiles_are_refused_before_parsing_bitcoin_fee_extensions() -> None:
    request = {
        "kind": "erc20-to-ln",
        "mode": "indicative",
        "lightning_principal_sat": "100000",
        "evm_asset": {"chain_id": 31337, "token_contract": "0x" + "11" * 20},
        "extensions": {FEE_POLICY_EXTENSION: None},
    }
    answer = answer_quote(SimpleNamespace(payload=request), (), _context(), FIRM_TERMS)
    assert answer.message_type == "error"
    assert answer.payload["code"] == "unsupported_request"


def test_each_request_samples_current_node_fees_outside_the_store() -> None:
    sample = Mock(side_effect=[ClaimFeeRate(1000, 1000), ClaimFeeRate(2000, 1000)])
    service, _ = _service(None, claim_fee=sample)
    document = json.loads(_document(REVERSE_FIRM))
    document["payload"]["extensions"] = EXTENSIONS

    async def run() -> None:
        terms = replace(REVERSE_TERMS, fee_policy=POLICY_FEES)
        first = await service._network_pricing(canonicalize(document), terms)  # noqa: SLF001
        second = await service._network_pricing(canonicalize(document), terms)  # noqa: SLF001
        assert first.fee_breakdown is not None
        assert second.fee_breakdown is not None
        assert first.fee_breakdown.network_fee_sat == "154"
        assert second.fee_breakdown.network_fee_sat == "308"

    asyncio.run(run())
    assert sample.call_count == 2


def test_routing_cannot_spend_network_component_or_exceed_advertised_ppm() -> None:
    _, offer = forward_offer()
    engine = object.__new__(SettlementEngine)
    engine._settings = EngineSettings(max_routing_fee_sat=1000)  # noqa: SLF001
    assert engine._fee_limit(354, offer.terms.contract_terms) == 100  # noqa: SLF001
    assert engine._fee_limit(354) == 354  # noqa: SLF001 - unchanged legacy contract


def test_new_pricing_store_never_silently_upgrades_or_downgrades(harness: Harness) -> None:
    harness.provision()
    original = harness.policy
    harness.policy = replace(original, features=original.features | {FEE_POLICY_FEATURE})
    with pytest.raises(LiveSessionStoreError, match="policy mismatch"):
        harness.acquire()
    harness.path = harness.path.with_name("network-fees.sqlite")
    harness.provision()
    with harness.acquire():
        pass
    harness.policy = original
    with pytest.raises(LiveSessionStoreError, match="policy mismatch"):
        harness.acquire()


def test_opt_in_binds_only_feature_not_changeable_pricing_coefficients() -> None:
    terms = PublicTerms(
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 100000),),
        base_fee_sat=50,
        proportional_millionths=1500,
        slot="s",
        network_fees=BitcoinNetworkFees(max_feerate_sat_kvb=5000, max_routing_fee_ppm=1000),
    )
    config = OperatorConfig.model_construct(
        terms=terms,
        handshake=HandshakeSelection(
            profile="btc-to-ln/v1",
            encryption_suites=tuple(POLICY.encryption_suites),
            capabilities=tuple(POLICY.capabilities),
        ),
    )
    assert FEE_POLICY_FEATURE in config.handshake_policy().features
    updated = config.model_copy(update={"terms": terms.model_copy(update={"base_fee_sat": 100})})
    assert updated.handshake_policy() == config.handshake_policy()
    assert updated.bitcoin_fee_policy() != config.bitcoin_fee_policy()
