"""ERC20 quote answers (RS-010): economics, timelocks, limits, and refusals."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest
from evm_fixtures import CLIENT, PAYMENT_HASH, PROVIDER, RECOVERY_KEY, evm_terms
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.evm_quotes import Erc20QuoteOffer, LnToErc20QuoteOffer
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import EvmContractTerms
from rill_core.wire.quotes import QuoteError, TermsOfferPayload
from test_quote_policy import BINDING, FIRM_TERMS, SIGNER, TERMS, _context, _envelope, _with
from test_reverse_quote_policy import HOLD as BTC_HOLD

from rill_provider.evm_quote_policy import (
    EvmQuoteContext,
    EvmSchedule,
    answer_evm_quote,
    ln_to_erc20_hold_msat,
)

if TYPE_CHECKING:
    from rill_provider.quote_policy import QuoteTerms

ASSET = evm_terms("erc20-to-ln/v1").evm_asset
HOLD = BTC_HOLD.model_copy(update={"amount_msat": "100200000"})  # H = E + S_sat, no reserve
RATE = 100_000_000_000  # 1 BTC = 100,000 fUSDC (6 decimals)
ASSET_REF = {"chain_id": ASSET.chain_id, "token_contract": ASSET.token_contract}
SCHEDULE = EvmSchedule(
    funding_confirmations=1,
    settlement_confirmations=1,
    forward_timelock_delay_blocks=60_000,  # 2 s blocks: 33 h
    reverse_timelock_delay_blocks=600,  # 20 min
    learn_and_claim_seconds=600,
    refund_and_ln_resolution_seconds=600,
)
EVM = EvmQuoteContext(
    assets=(ASSET,),
    rates={ASSET.token_contract: RATE},
    provider_evm_address=PROVIDER,
    schedule=SCHEDULE,
    tip=1_000,
)
FORWARD_INDICATIVE = {
    "kind": "erc20-to-ln",
    "mode": "indicative",
    "lightning_principal_sat": "100000",
    "evm_asset": ASSET_REF,
}
FORWARD_FIRM = {
    "kind": "erc20-to-ln",
    "mode": "firm",
    "lightning_principal_sat": "100000",
    "invoice": "lnbcrt1mexample",
    "evm_asset": ASSET_REF,
    "client_evm_address": CLIENT,
    "recovery_authorization_xonly_key": RECOVERY_KEY,
    "limits": {"max_success_fee_token_base": "1000000", "max_htlc_timelock_block": 100_000},
}
REVERSE_INDICATIVE = {
    "kind": "ln-to-erc20",
    "mode": "indicative",
    "payout_token_base": "100000000",  # 100 fUSDC = 100,000 sat
    "evm_asset": ASSET_REF,
}
REVERSE_FIRM = {
    "kind": "ln-to-erc20",
    "mode": "firm",
    "payout_token_base": "100000000",
    "payment_hash": HOLD.payment_hash,
    "evm_asset": ASSET_REF,
    "client_evm_address": CLIENT,
    "recovery_authorization_xonly_key": RECOVERY_KEY,
    "limits": {
        "max_success_fee_sat": "1000",
        "min_htlc_timelock_block": 1_100,
        "max_incoming_htlc_expiry_height": 2_000,
    },
}
FORWARD_TERMS = _with(FIRM_TERMS, profile="erc20-to-ln/v1", evm=EVM)
REVERSE_TERMS = _with(
    FIRM_TERMS,
    profile="ln-to-erc20/v1",
    evm=EVM,
    invoice=None,
    hold=("lnbcrt1hold", HOLD),
)


def _answer(payload: dict[str, Any], terms: Any, prior: int = 0, **changes: Any) -> Any:  # noqa: ANN401
    answer = answer_evm_quote(
        _envelope(payload),
        tuple(_envelope(FORWARD_INDICATIVE) for _ in range(prior)),
        _context(),
        _with(terms, **changes),
    )
    if answer.message_type == "error":
        return answer.message_type, parse_model_json(QuoteError, canonicalize(answer.payload))
    return answer.message_type, answer


def test_forward_indicative_offer_converts_at_the_rate() -> None:
    kind, answer = _answer(FORWARD_INDICATIVE, _with(TERMS, profile="erc20-to-ln/v1", evm=EVM))
    assert kind == "quote_offer"
    offer = parse_model_json(Erc20QuoteOffer, canonicalize(answer.payload))
    fee_sat = 50 + -(-100_000 * 1_500 // 10**6)  # 200
    assert offer.economics.success_fee_token_base == str(fee_sat * 1000)
    assert offer.economics.lock_amount_token_base == str(100_000_000 + fee_sat * 1000)
    assert (offer.evm_reference_block, offer.max_timelock_delay_blocks) == (1_000, 60_000)


def test_reverse_indicative_offer_prices_the_sat_equivalent() -> None:
    kind, answer = _answer(REVERSE_INDICATIVE, _with(TERMS, profile="ln-to-erc20/v1", evm=EVM))
    assert kind == "quote_offer"
    offer = parse_model_json(LnToErc20QuoteOffer, canonicalize(answer.payload))
    assert offer.economics.payout_sat_equivalent == "100000"
    assert offer.economics.hold_invoice_sat == str(100_000 + 200)
    assert offer.timelock_delay_blocks == 600


@pytest.mark.parametrize(
    ("payload", "terms", "changes", "code"),
    [
        (FORWARD_INDICATIVE, TERMS, {"profile": "erc20-to-ln/v1"}, "capacity_unavailable"),
        (
            FORWARD_INDICATIVE,
            TERMS,
            {"profile": "erc20-to-ln/v1", "evm": replace(EVM, tip=None)},
            "capacity_unavailable",
        ),
        (
            FORWARD_INDICATIVE,
            TERMS,
            {"profile": "erc20-to-ln/v1", "evm": replace(EVM, rates={})},
            "capacity_unavailable",
        ),
        (
            FORWARD_INDICATIVE | {"evm_asset": ASSET_REF | {"chain_id": 1}},
            TERMS,
            {"profile": "erc20-to-ln/v1", "evm": EVM},
            "unsupported_request",
        ),
        (
            FORWARD_INDICATIVE | {"lightning_principal_sat": "500"},
            TERMS,
            {"profile": "erc20-to-ln/v1", "evm": EVM},
            "amount_out_of_range",
        ),
        (
            REVERSE_INDICATIVE,
            TERMS,
            {"profile": "erc20-to-ln/v1", "evm": EVM},
            "unsupported_request",
        ),
        (
            REVERSE_INDICATIVE | {"payout_token_base": "100000"},
            TERMS,
            {"profile": "ln-to-erc20/v1", "evm": EVM},
            "amount_out_of_range",
        ),
    ],
)
def test_indicative_refusals(
    payload: dict[str, Any], terms: QuoteTerms, changes: dict[str, Any], code: str
) -> None:
    kind, error = _answer(payload, terms, **changes)
    assert (kind, error.code) == ("error", code)


def _offered(answer: Any) -> EvmContractTerms:  # noqa: ANN401
    offer = parse_model_json(TermsOfferPayload, canonicalize(answer.payload))
    terms = offer.terms.contract_terms
    assert isinstance(terms, EvmContractTerms)
    assert offer.terms.contract_hash == contract_hash(terms).hex()
    assert offer.provider_terms_signature == "11" * 64
    return terms


def test_forward_firm_offer_binds_invoice_timelock_and_reference_heights() -> None:
    kind, answer = _answer(FORWARD_FIRM, FORWARD_TERMS)
    assert kind == "terms_offer"
    assert answer.payment_hash == BINDING.payment_hash
    terms = _offered(answer)
    assert (terms.claimant, terms.refund_party) == ("provider", "client")
    assert (terms.client_evm_address, terms.provider_evm_address) == (CLIENT, PROVIDER)
    assert (terms.evm_reference_block, terms.btc_reference_height) == (1_000, FIRM_TERMS.tip_height)
    assert terms.htlc_timelock_block == 1_000 + 60_000
    assert terms.htlc_amount_token_base == 100_000_000 + 200 * 1000
    timing = terms.timing_policy.model_dump()
    assert timing["max_outgoing_htlc_expiry_height"] == FIRM_TERMS.tip_height + 144
    assert terms.required_features == ()
    assert "hold_invoice" not in answer.payload


def test_forward_firm_honors_the_client_timelock_cap_when_feasible() -> None:
    capped = FORWARD_FIRM | {
        "limits": {"max_success_fee_token_base": "1000000", "max_htlc_timelock_block": 50_000}
    }
    kind, answer = _answer(capped, FORWARD_TERMS)
    assert kind == "terms_offer"
    assert _offered(answer).htlc_timelock_block == 50_000


@pytest.mark.parametrize(
    ("payload", "changes", "code"),
    [
        (FORWARD_FIRM, {"firm": None}, "unsupported_request"),
        (FORWARD_FIRM, {"invoice": "rejected"}, "invoice_unacceptable"),
        (FORWARD_FIRM, {"evm": replace(EVM, tip=None)}, "capacity_unavailable"),
        (
            FORWARD_FIRM
            | {"limits": {"max_success_fee_token_base": "1", "max_htlc_timelock_block": 100_000}},
            {},
            "limits_unsatisfiable",
        ),
        (
            # 44 blocks of 2 s cannot cover 144 Bitcoin blocks plus the claim window.
            FORWARD_FIRM
            | {
                "limits": {
                    "max_success_fee_token_base": "1000000",
                    "max_htlc_timelock_block": 1_044,
                }
            },
            {},
            "limits_unsatisfiable",
        ),
        (FORWARD_FIRM | {"client_evm_address": PROVIDER}, {}, "request_unacceptable"),
        (REVERSE_FIRM, {}, "unsupported_request"),
    ],
)
def test_forward_firm_refusals(payload: dict[str, Any], changes: dict[str, Any], code: str) -> None:
    kind, error = _answer(payload, FORWARD_TERMS, **changes)
    assert (kind, error.code) == ("error", code)


def test_forward_firm_must_open_the_session() -> None:
    kind, error = _answer(FORWARD_FIRM, FORWARD_TERMS, prior=1)
    assert (kind, error.code) == ("error", "unsupported_request")


def test_reverse_firm_offer_carries_the_hold_and_the_timing_policy() -> None:
    kind, answer = _answer(REVERSE_FIRM, REVERSE_TERMS)
    assert kind == "terms_offer"
    assert answer.payload["hold_invoice"] == "lnbcrt1hold"
    assert answer.payment_hash == HOLD.payment_hash
    terms = _offered(answer)
    assert (terms.claimant, terms.refund_party) == ("client", "provider")
    assert terms.htlc_timelock_block == 1_000 + 600
    assert terms.htlc_amount_token_base == 100_000_000
    economics = terms.economics.model_dump()
    assert (economics["payout_sat_equivalent"], economics["hold_invoice_sat"]) == (
        "100000",
        "100200",
    )
    timing = terms.timing_policy.model_dump()
    assert timing["min_incoming_htlc_expiry_height"] == FIRM_TERMS.tip_height + 185


def test_reverse_hold_amount_matches_the_offered_economics() -> None:
    from rill_core.wire.quotes import parse_quote_request  # noqa: PLC0415

    request = parse_quote_request(canonicalize(REVERSE_FIRM | {"extensions": {}}))
    assert ln_to_erc20_hold_msat(REVERSE_TERMS, request) == 100_200_000  # type: ignore[arg-type]
    assert ln_to_erc20_hold_msat(_with(REVERSE_TERMS, evm=None), request) is None  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("payload", "changes", "code"),
    [
        (REVERSE_FIRM, {"hold": None}, "capacity_unavailable"),
        (REVERSE_FIRM, {"hold": "unavailable"}, "capacity_unavailable"),
        (
            REVERSE_FIRM,
            {"hold": ("lnbcrt1", HOLD.model_copy(update={"amount_msat": "100700000"}))},
            "capacity_unavailable",
        ),
        (
            REVERSE_FIRM | {"limits": REVERSE_FIRM["limits"] | {"max_success_fee_sat": "100"}},
            {},
            "limits_unsatisfiable",
        ),
        (
            REVERSE_FIRM | {"limits": REVERSE_FIRM["limits"] | {"min_htlc_timelock_block": 2_000}},
            {},
            "limits_unsatisfiable",
        ),
        (
            REVERSE_FIRM
            | {"limits": REVERSE_FIRM["limits"] | {"max_incoming_htlc_expiry_height": 900}},
            {},
            "limits_unsatisfiable",
        ),
        (REVERSE_FIRM | {"payment_hash": PAYMENT_HASH}, {}, "capacity_unavailable"),
        (FORWARD_FIRM, {}, "unsupported_request"),
    ],
)
def test_reverse_firm_refusals(payload: dict[str, Any], changes: dict[str, Any], code: str) -> None:
    kind, error = _answer(payload, REVERSE_TERMS, **changes)
    assert (kind, error.code) == ("error", code)


def test_reverse_firm_refuses_a_reserved_payment_hash() -> None:
    answer = answer_evm_quote(
        _envelope(REVERSE_FIRM), (), _context(reserved=(HOLD.payment_hash,)), REVERSE_TERMS
    )
    assert answer.payload["code"] == "request_unacceptable"


def test_schedule_refuses_confirmations_past_the_timelock() -> None:
    with pytest.raises(ValueError, match="fit before the timelock"):
        EvmSchedule(
            funding_confirmations=5,
            settlement_confirmations=1,
            forward_timelock_delay_blocks=5,
            reverse_timelock_delay_blocks=10,
            learn_and_claim_seconds=1,
            refund_and_ln_resolution_seconds=1,
        )
    assert SIGNER.provider_destination_script is not None
